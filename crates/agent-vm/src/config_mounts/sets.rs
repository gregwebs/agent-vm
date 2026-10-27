//! The mount-set graph: exact names, definitions, reference resolution,
//! iterative cycle rejection and index-compiled closures.
//!
//! `config_mounts` owns the *verified* configuration value and its diagnostics;
//! this private submodule owns the graph those diagnostics describe, so no caller
//! — the CLI included — can reach a second named-set resolver. The only
//! constructor is [`UserMounts::parse`].
//!
//! Two properties shape the implementation, and both are about cost rather than
//! what is valid:
//!
//! * **Every declared set's transitive closure is validated** at load, even
//!   unused and under `--no-config-mounts` (decision A2). A set whose own closure
//!   claims one guest path twice with differing declarations is a config error;
//!   two separately valid sets may still disagree at one guest path until a
//!   launch selects both.
//! * **That work is bounded** (decision R1). Guest-path lookup during closure
//!   compilation is an index, never `mount::claim`'s growing-vector scan, and one
//!   global leaf-visit budget turns a pathological config into a value-free
//!   config error instead of a hang. `mount::same_declaration` and
//!   `mount::claim_decision` stay the authority for whether two claims at one
//!   path agree; only the *lookup* is indexed.
//!
//! Nothing here opens, stats or canonicalizes a declared path. Closures and the
//! defaults list hold guest-path *indexes* into one immutable request arena, so a
//! shared child closure is iterated, never copied or re-expanded, and a diamond
//! DAG cannot flatten exponentially.

use super::{
    EntrySite, MountSelector, MountSetName, MountValues, SelectorError, UserMountsError,
    parse_selector,
};
use crate::mount::{
    ClaimDecision, ClaimFacts, ExtraMount, HostSyntax, MountOrigin, MountRequest, claim_decision,
    normalize_request, same_declaration,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use vstd::prelude::*;

verus! {
/// How many leaf visits the whole user file may spend validating its declared
/// closures (decision R1).
///
/// A *leaf visit* is one direct or cached-child candidate considered while
/// compiling one set's closure, including a candidate later deduplicated: the
/// counter is global, never reset per root, and counts repeated uses in different
/// parent closures again. 65,536 admits hundreds of ordinary small sets (100 sets
/// of 100 leaves costs 10,000) while bounding the worst admitted work to 65,536
/// guest-index lookups, insertions, six-field equivalence checks and cached leaf
/// IDs — so a crafted config cannot turn load into a hang.
pub const MAX_MOUNT_SET_EXPANSION_WORK: usize = 65_536;

/// Exhaustion polarity. Checked *before* an increment, so the counter can reach
/// the limit exactly and never overflow.
pub fn mount_set_expansion_work_allowed(used: usize) -> (r: bool)
    ensures r == (used < MAX_MOUNT_SET_EXPANSION_WORK),
{
    used < MAX_MOUNT_SET_EXPANSION_WORK
}

/// The colour of one set in the reference walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum VisitState {
    /// Not reached yet.
    Unseen,
    /// On the path being walked: a set we are inside of.
    Active,
    /// Finished, so a reference back to it is shared structure.
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum VisitDecision {
    /// Descend: this is the first time this set is seen.
    Enter,
    /// Refuse: the edge closes a cycle.
    Cycle,
    /// Do not descend: the set's closure is already compiled.
    Skip,
}

/// ADR-0018 kernel: the one decision the reference walk takes for one edge.
///
/// Total and exhaustive over the three colours, with `Active` — a set currently
/// on the walk's own path — exactly the forbidden cycle. A `Complete` set is a
/// shared subgraph, which a DAG may reference any number of times; that is what
/// distinguishes a legal diamond from a cycle. It is also why `tools` reference
/// cycles stay legal: what makes them legal is that they are a *different*
/// walker reaching a fixed point, and nothing here is reused for them.
///
/// Stated plainly: what is proved is the state-to-action correspondence, **not**
/// that the walker reaches the right states. The explicit stack, the colours and
/// the postorder order are trusted adapters with their own tests.
pub fn visit_decision(state: VisitState) -> (d: VisitDecision)
    ensures
        (state == VisitState::Unseen) == (d == VisitDecision::Enter),
        (state == VisitState::Active) == (d == VisitDecision::Cycle),
        (state == VisitState::Complete) == (d == VisitDecision::Skip),
{
    match state {
        VisitState::Unseen => VisitDecision::Enter,
        VisitState::Active => VisitDecision::Cycle,
        VisitState::Complete => VisitDecision::Skip,
    }
}
} // verus!

/// The one leaf-visit counter for the entire user file.
///
/// Plainly mutable and not a Verus value: the proved half is the exhaustion
/// predicate above, and `admit` is the trusted adapter that applies it before the
/// increment (so the counter can reach the limit and never overflow).
#[derive(Clone, Copy, Debug)]
struct ExpansionWork {
    used: usize,
}

impl ExpansionWork {
    fn fresh() -> Self {
        Self { used: 0 }
    }

    /// Admit one candidate leaf, or refuse the file.
    fn admit(&mut self) -> Result<(), UserMountsError> {
        if !mount_set_expansion_work_allowed(self.used) {
            return Err(UserMountsError::ExpansionWorkLimit);
        }
        self.used += 1;
        Ok(())
    }
}

/// Which child sets one closure or defaults list has already expanded.
///
/// Generation-stamped slots, not a growing `Vec` searched linearly: a list that
/// references N distinct children must cost N admissions, while a scan of
/// already-seen ids costs N(N-1)/2 membership comparisons — and a leaf-visit
/// budget cannot see that work at all, because an empty child closure contributes
/// no leaf.
///
/// The cost property is structural: one indexed slot read per admission, with the
/// generation stamp doing the "already seen" test in O(1) and no per-list reset.
/// `admissions` is the only counter, and it exists to show that *both* traversals
/// use this tracker (a revert of either to a growing `Vec` drops the count to
/// zero); it cannot witness what `admit` itself does. Nothing in-process can: a
/// counter the traversal increments itself is self-reported, so the linearity
/// evidence for the tracker is instruction scaling, not a kernel.
#[derive(Debug)]
struct ChildTracker {
    /// One slot per declared set, stamped with the generation that last admitted
    /// it. Never cleared per list.
    seen: Vec<u32>,
    generation: u32,
    #[cfg_attr(not(test), allow(dead_code))]
    admissions: usize,
}

impl ChildTracker {
    fn new(sets: usize) -> Self {
        Self {
            seen: vec![0; sets],
            generation: 0,
            admissions: 0,
        }
    }

    /// Start one membership list. The stamp advances instead of clearing the
    /// per-set slots, which would charge an O(sets) reset to every list; the one
    /// wrap is unreachable from a 1 MiB file (it needs 2^32 lists) and clears them
    /// once rather than panicking.
    fn next_list(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.seen.fill(0);
            self.generation = 1;
        }
    }

    /// Admit `child` into the current list: `true` the first time it appears.
    fn admit(&mut self, child: SetId) -> bool {
        self.admissions += 1;
        if self.seen[child.0] == self.generation {
            return false;
        }
        self.seen[child.0] = self.generation;
        true
    }
}

/// One definition's position, in name order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SetId(usize);

/// One declaration in the arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LeafId(usize);

/// One entry of a definition or of the defaults list, after name binding.
#[derive(Clone, Copy, Debug)]
enum Entry {
    Direct(LeafId),
    Reference(SetId),
}

struct SetDefinition {
    entries: Vec<Entry>,
}

/// One verified user file's mount configuration: the file, its optional defaults
/// and its validated set namespace.
///
/// [`Self::requests`] is the *automatic* selection (the defaults list) already
/// normalized and deduplicated, so a later claim against `--mount` needs no second
/// pass. [`Self::requests_for_set`] is the same for one named set. Neither mounts
/// anything by being present.
#[derive(Clone, Debug)]
pub(crate) struct UserMounts {
    file: PathBuf,
    /// `Some` iff the file has a top-level `mounts` key, present-empty included.
    defaults: Option<Vec<MountRequest>>,
    /// Name to definition, exact spelling, no folding.
    index: BTreeMap<MountSetName, SetId>,
    /// Per set, its unique leaves in first-seen order.
    closures: Vec<Vec<LeafId>>,
    /// Every declaration this file contains, normalized once.
    leaves: Vec<MountRequest>,
    /// Leaf visits admitted while compiling the closures, and the raw graph entry
    /// count. Retained rather than recomputed so a test can assert the *work* bound
    /// instead of a wall-clock time: the resource rule is about admitted
    /// comparisons, and only a counter can show its shape.
    #[cfg_attr(not(test), allow(dead_code))]
    work: usize,
    #[cfg_attr(not(test), allow(dead_code))]
    entries: usize,
    /// Reference admissions across both traversals, test-only for the same
    /// reason: the linearity guarantee is about raw-edge work that spends no leaf
    /// visit, and the count is what shows each traversal uses the indexed tracker
    /// rather than a growing `Vec`.
    #[cfg_attr(not(test), allow(dead_code))]
    references: usize,
}

impl UserMounts {
    pub(crate) fn file(&self) -> &Path {
        &self.file
    }

    /// The declarations this file selects automatically, after merging.
    pub(crate) fn requests(&self) -> &[MountRequest] {
        self.defaults.as_deref().unwrap_or_default()
    }

    /// How many declarations the defaults list selects after merging — the number
    /// a launch notice reports, not the number of `mounts` entries.
    pub(crate) fn len(&self) -> usize {
        self.requests().len()
    }

    /// Whether the file declares a defaults list at all. Presence, not contents,
    /// is the fact `--no-config-mounts` turns on: a sets-only file has no
    /// automatic selection to skip and must not be reported as skipped.
    pub(crate) fn has_defaults(&self) -> bool {
        self.defaults.is_some()
    }

    /// The declarations one named set expands to, or `None` when this file
    /// declares no such set.
    ///
    /// An exact lookup: no case folding, no trimming, no cwd path, no directory or
    /// tool discovery. The closure was validated at load, so this maps
    /// already-claimed leaves and is never a second validation pass.
    pub(crate) fn requests_for_set(&self, name: &MountSetName) -> Option<Vec<MountRequest>> {
        let set = self.index.get(name)?;
        Some(
            self.closures[set.0]
                .iter()
                .map(|leaf| self.leaves[leaf.0].clone())
                .collect(),
        )
    }

    /// Leaf visits this file's load admitted. Test-only: the resource bound is
    /// otherwise observable only as the refusal.
    #[cfg(test)]
    pub(crate) fn expansion_work(&self) -> usize {
        self.work
    }

    /// Raw graph entries walked (direct entries and references), test-only, so a
    /// reference-only chain can be shown linear rather than merely fast.
    #[cfg(test)]
    pub(crate) fn graph_entries(&self) -> usize {
        self.entries
    }

    /// Reference admissions across both traversals. One admission per reference
    /// however wide the fan-out is, and zero for a traversal that scans a growing
    /// `Vec` instead of using the tracker — the wiring property this counter can
    /// actually witness. What each admission costs is O(1) by the indexed slot's
    /// construction, not by this count. Test-only.
    #[cfg(test)]
    pub(crate) fn reference_admissions(&self) -> usize {
        self.references
    }

    /// Validate the file, both mount fields and the caller's host grammar.
    ///
    /// `pub(super)` on purpose: [`crate::config_mounts::from_verified_value`] is the
    /// only caller, and it demands the `AuthorizedConfig` token. Keeping the raw
    /// parser inside its owning module is what makes "no mount declaration is
    /// parsed from an unverified read" a compile-time property rather than a
    /// convention.
    ///
    /// Validation order is fixed, and each stage completes before the next, so the
    /// diagnostic a given file produces never depends on TOML key order: set names,
    /// set entries and their direct declarations, every reference (`UnknownSet`),
    /// the reference graph (`Cycle`), every declared closure (`Conflict`,
    /// `ExpansionWorkLimit`), and only then the defaults list.
    pub(super) fn parse(
        file: PathBuf,
        values: MountValues<'_>,
        syntax: HostSyntax<'_>,
    ) -> Result<Self, UserMountsError> {
        let mut work = ExpansionWork::fresh();
        let mut references = 0;
        Self::build(file, values, syntax, &mut work, &mut references)
    }

    /// [`Self::parse`], reporting the leaf visits it admitted even when it
    /// refuses. Test-only: on the error path the counter is otherwise observable
    /// only as the refusal, and the resource rule is about how far it got.
    #[cfg(test)]
    pub(super) fn parse_with_work(
        file: PathBuf,
        values: MountValues<'_>,
        syntax: HostSyntax<'_>,
    ) -> (Result<Self, UserMountsError>, usize) {
        let mut work = ExpansionWork::fresh();
        let mut references = 0;
        let parsed = Self::build(file, values, syntax, &mut work, &mut references);
        (parsed, work.used)
    }

    fn build(
        file: PathBuf,
        values: MountValues<'_>,
        syntax: HostSyntax<'_>,
        work: &mut ExpansionWork,
        references: &mut usize,
    ) -> Result<Self, UserMountsError> {
        let mut builder = Builder {
            file,
            leaves: Vec::new(),
            sites: Vec::new(),
            entries: 0,
        };

        // Names first, in sorted order, so a forward reference resolves and the
        // definition numbers do not depend on TOML's key order.
        let mut names: Vec<MountSetName> = Vec::new();
        let mut index: BTreeMap<MountSetName, SetId> = BTreeMap::new();
        let mut pairs: Vec<(&String, &toml::Value)> = Vec::new();
        if let Some(value) = values.sets {
            let table = value.as_table().ok_or(UserMountsError::SetsNotTable)?;
            pairs.extend(table.iter());
            pairs.sort_by(|a, b| a.0.cmp(b.0));
        }
        for (definition, (key, _)) in pairs.iter().enumerate() {
            let name =
                MountSetName::parse(key).map_err(|_| UserMountsError::SetName { definition })?;
            index.insert(name.clone(), SetId(definition));
            names.push(name);
        }

        // One name allocation per definition, shared by every leaf's origin: a
        // set's key may be as long as the rest of the file allows, so copying it
        // per leaf would multiply retained memory by the leaf count.
        let shared: Vec<Arc<str>> = names.iter().map(|name| Arc::from(name.as_str())).collect();

        let mut definitions: Vec<SetDefinition> = Vec::with_capacity(pairs.len());
        for (definition, (_, value)) in pairs.iter().enumerate() {
            let entries = value
                .as_array()
                .ok_or(UserMountsError::SetNotArray { definition })?;
            let mut bound: Vec<Entry> = Vec::with_capacity(entries.len());
            for (entry_index, entry) in entries.iter().enumerate() {
                let site = EntrySite::SetEntry {
                    definition,
                    index: entry_index,
                };
                let text = entry.as_str().ok_or(UserMountsError::SetNotString {
                    definition,
                    index: entry_index,
                })?;
                builder.entries += 1;
                bound.push(match parse_selector(text, syntax) {
                    Ok(MountSelector::Direct(mount)) => Entry::Direct(builder.push_leaf(
                        MountOrigin::UserSet {
                            file: builder.file.clone(),
                            set: Arc::clone(&shared[definition]),
                            index: entry_index,
                        },
                        site,
                        mount,
                    )?),
                    Ok(MountSelector::Set(target)) => match index.get(&target) {
                        Some(&target) => Entry::Reference(target),
                        None => return Err(UserMountsError::UnknownSet { site }),
                    },
                    Err(SelectorError::Direct(error)) => {
                        return Err(UserMountsError::Entry {
                            site,
                            kind: error.kind(),
                        });
                    }
                    Err(SelectorError::SetModifier) => {
                        return Err(UserMountsError::SetReferenceModified { site });
                    }
                });
            }
            definitions.push(SetDefinition { entries: bound });
        }

        let order = validate_references_and_cycles(&definitions)?;
        let closures = compile_closures(
            &definitions,
            &builder.leaves,
            &builder.sites,
            &order,
            work,
            references,
        )?;

        // Defaults last. They are validated even when a launch suppresses them, but
        // they are not charged to the per-set budget: their direct entries are
        // bounded by the file size, and every closure they can reference was
        // already admitted above.
        let defaults = match values.defaults {
            None => None,
            Some(value) => {
                let entries = value.as_array().ok_or(UserMountsError::NotArray)?;
                let mut bound: Vec<Entry> = Vec::with_capacity(entries.len());
                for (entry_index, entry) in entries.iter().enumerate() {
                    let site = EntrySite::Defaults { index: entry_index };
                    let text = entry
                        .as_str()
                        .ok_or(UserMountsError::NotString { index: entry_index })?;
                    bound.push(match parse_selector(text, syntax) {
                        Ok(MountSelector::Direct(mount)) => Entry::Direct(builder.push_leaf(
                            MountOrigin::UserConfig {
                                file: builder.file.clone(),
                                index: entry_index,
                            },
                            site,
                            mount,
                        )?),
                        Ok(MountSelector::Set(target)) => match index.get(&target) {
                            Some(&target) => Entry::Reference(target),
                            None => return Err(UserMountsError::UnknownSet { site }),
                        },
                        Err(SelectorError::Direct(error)) => {
                            return Err(UserMountsError::Entry {
                                site,
                                kind: error.kind(),
                            });
                        }
                        Err(SelectorError::SetModifier) => {
                            return Err(UserMountsError::SetReferenceModified { site });
                        }
                    });
                }
                Some(merge_entries(
                    &bound,
                    &builder.leaves,
                    &builder.sites,
                    &closures,
                    None,
                    references,
                )?)
            }
        };

        Ok(Self {
            file: builder.file,
            defaults,
            index,
            closures,
            leaves: builder.leaves,
            work: work.used,
            entries: builder.entries,
            references: *references,
        })
    }
}

/// The arena under construction: every declaration this file contains, its
/// diagnostic site, and the caller's host grammar.
struct Builder {
    file: PathBuf,
    leaves: Vec<MountRequest>,
    sites: Vec<EntrySite>,
    entries: usize,
}

impl Builder {
    /// Normalize one already-parsed direct declaration through the shared claim
    /// with nothing else in it.
    ///
    /// One leaf and no core paths is exactly the work an entry needs, and it
    /// deliberately avoids `mount::claim`'s growing-vector scan: a closure of *k*
    /// leaves compiled against an index is linear, while the same *k* through
    /// `claim` is quadratic and, once every declared closure is claimed, cubic.
    fn push_leaf(
        &mut self,
        origin: MountOrigin,
        site: EntrySite,
        mount: ExtraMount,
    ) -> Result<LeafId, UserMountsError> {
        let request = normalize_request(MountRequest { origin, mount })
            .map_err(|error| UserMountsError::from_claim(error, &site))?;
        self.leaves.push(request);
        self.sites.push(site);
        Ok(LeafId(self.leaves.len() - 1))
    }
}

/// Bind every entry's references and reject every cycle, dependency-first.
///
/// Explicit frames with a colour per set, never recursion: a 4,000-set chain must
/// not touch the Rust call stack. Every definition is a root, so a cycle in a
/// component nothing references is still refused; a set is appended to the
/// postorder only once complete, which is what makes the result dependency-first.
fn validate_references_and_cycles(
    definitions: &[SetDefinition],
) -> Result<Vec<SetId>, UserMountsError> {
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
            let entries = &definitions[set.0].entries;
            if *next == entries.len() {
                colors[set.0] = VisitState::Complete;
                order.push(*set);
                stack.pop();
                continue;
            }
            let index = *next;
            *next += 1;
            let Entry::Reference(target) = entries[index] else {
                continue;
            };
            match visit_decision(colors[target.0]) {
                VisitDecision::Enter => {
                    colors[target.0] = VisitState::Active;
                    stack.push((target, 0));
                }
                // The edge that closes the cycle, named by the entry that makes
                // it, so the reader can find the line without echoing a key.
                VisitDecision::Cycle => {
                    return Err(UserMountsError::Cycle {
                        site: EntrySite::SetEntry {
                            definition: set.0,
                            index,
                        },
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
/// A child's closure is iterated in its own first-seen order, so the merge is
/// associative and the first equivalent declaration keeps its origin. Repeated
/// references to the same child in one list are skipped: the child's closure is
/// already unique by guest path, so a second pass could contribute nothing but
/// duplicate candidates — and a reference to an empty closure costs no leaf.
fn compile_closures(
    definitions: &[SetDefinition],
    leaves: &[MountRequest],
    sites: &[EntrySite],
    order: &[SetId],
    work: &mut ExpansionWork,
    references: &mut usize,
) -> Result<Vec<Vec<LeafId>>, UserMountsError> {
    let mut closures: Vec<Vec<LeafId>> = vec![Vec::new(); definitions.len()];
    let mut compiled = vec![false; definitions.len()];
    let mut tracker = ChildTracker::new(definitions.len());
    for set in order {
        tracker.next_list();
        let mut index: BTreeMap<&Path, LeafId> = BTreeMap::new();
        let mut unique: Vec<LeafId> = Vec::new();
        for entry in &definitions[set.0].entries {
            match entry {
                Entry::Direct(leaf) => {
                    admit_candidate(&mut index, &mut unique, leaves, sites, *leaf, Some(work))?
                }
                Entry::Reference(child) => {
                    // A repeated reference to one child contributes nothing: the
                    // child's closure is already unique by guest path. Skipping it
                    // costs one membership probe, not a scan of the list.
                    if !tracker.admit(*child) {
                        continue;
                    }
                    if !compiled[child.0] {
                        // Cannot happen: `order` is dependency-first. Refusing
                        // keeps a wrong traversal fail-closed instead of quietly
                        // dropping a child's declarations from validation.
                        return Err(UserMountsError::ReferenceOrder);
                    }
                    for &leaf in &closures[child.0] {
                        admit_candidate(&mut index, &mut unique, leaves, sites, leaf, Some(work))?;
                    }
                }
            }
        }
        closures[set.0] = unique;
        compiled[set.0] = true;
    }
    *references += tracker.admissions;
    Ok(closures)
}

/// Merge one ordered entry list into unique leaves, indexed by normalized guest
/// path.
///
/// `charge` is `Some` while validating a declared set's closure and `None` for the
/// defaults list, whose direct entries are bounded by the file size and whose
/// referenced closures were all admitted already.
fn merge_entries(
    entries: &[Entry],
    leaves: &[MountRequest],
    sites: &[EntrySite],
    closures: &[Vec<LeafId>],
    charge: Option<&mut ExpansionWork>,
    references: &mut usize,
) -> Result<Vec<MountRequest>, UserMountsError> {
    let mut index: BTreeMap<&Path, LeafId> = BTreeMap::new();
    let mut unique: Vec<LeafId> = Vec::new();
    let mut tracker = ChildTracker::new(closures.len());
    tracker.next_list();
    let mut charge = charge;
    for entry in entries {
        match entry {
            Entry::Direct(leaf) => admit_candidate(
                &mut index,
                &mut unique,
                leaves,
                sites,
                *leaf,
                charge.as_deref_mut(),
            )?,
            Entry::Reference(child) => {
                if !tracker.admit(*child) {
                    continue;
                }
                for &leaf in &closures[child.0] {
                    admit_candidate(
                        &mut index,
                        &mut unique,
                        leaves,
                        sites,
                        leaf,
                        charge.as_deref_mut(),
                    )?;
                }
            }
        }
    }
    *references += tracker.admissions;
    Ok(unique
        .into_iter()
        .map(|leaf| leaves[leaf.0].clone())
        .collect())
}

/// Adjudicate one candidate leaf against the closure being built.
///
/// The order is the contract: charge the budget, look the guest path up in the
/// index, and only then reach the shared equivalence kernel. No candidate is
/// copied, compared or normalized before its visit is admitted, which is what
/// bounds a hostile file to the limit rather than to its size in comparisons.
fn admit_candidate<'a>(
    index: &mut BTreeMap<&'a Path, LeafId>,
    unique: &mut Vec<LeafId>,
    leaves: &'a [MountRequest],
    sites: &[EntrySite],
    candidate: LeafId,
    charge: Option<&mut ExpansionWork>,
) -> Result<(), UserMountsError> {
    if let Some(work) = charge {
        work.admit()?;
    }
    let guest: &'a Path = leaves[candidate.0].mount.guest.as_path();
    match index.get(guest) {
        None => {
            index.insert(guest, candidate);
            unique.push(candidate);
            Ok(())
        }
        Some(&first) => match claim_decision(ClaimFacts {
            same_guest: true,
            equivalent: same_declaration(&leaves[first.0].mount, &leaves[candidate.0].mount),
        }) {
            ClaimDecision::Merge => Ok(()),
            ClaimDecision::Conflict | ClaimDecision::Distinct => Err(UserMountsError::Conflict {
                site: sites[candidate.0].clone(),
                other: sites[first.0].clone(),
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_authority::{AuthorityTriggers, verify};
    use crate::config_mounts::{
        from_verified_value, from_verified_value_with_work, mount_set_name_bytes,
    };
    use crate::host_paths::read_bounded_regular_file_noting_symlink;
    use crate::mount::{MountPolicy, MountSpecErrorKind, Spelling};
    use proptest::prelude::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    /// One verified read of a throwaway `config.toml` whose *bytes* are `body`,
    /// handed to `f` as both the authorized token and the parsed mount values.
    ///
    /// The real token path, not a forged one: no other way to call
    /// [`UserMounts::parse`] exists, and a test able to bypass the verified read
    /// would not be testing that.
    fn with_authorized<T>(
        body: &str,
        f: impl FnOnce(&crate::config_authority::AuthorizedConfig<'_>, MountValues<'_>) -> T,
    ) -> T {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let file = root.path().join("config.toml");
        fs::write(&file, body).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let read = read_bounded_regular_file_noting_symlink(&file, 1 << 20).unwrap();
        let table: toml::Table = body.parse().expect("test body is TOML");
        let values = MountValues {
            defaults: table.get("mounts"),
            sets: table.get("mount_sets"),
        };
        let authorized = verify(
            &read,
            AuthorityTriggers {
                network: false,
                mounts: values.defaults.is_some(),
                mount_sets: values.sets.is_some(),
            },
        )
        .unwrap()
        .expect("a mount field makes the file authority-bearing");
        f(&authorized, values)
    }

    /// The one construction path a launch has: the verified facade that demands the
    /// token. The graph tests deliberately cannot reach a second one.
    fn parse_document(body: &str) -> Result<UserMounts, UserMountsError> {
        with_authorized(body, |authorized, values| {
            from_verified_value(authorized, values, Some(Path::new(HOME)))
        })
    }

    /// The same facade, also reporting how many leaf visits a refusal cost.
    fn parse_document_with_work(body: &str) -> (Result<UserMounts, UserMountsError>, usize) {
        with_authorized(body, |authorized, values| {
            from_verified_value_with_work(authorized, values, Some(Path::new(HOME)))
        })
    }

    /// A whole document: `[mount_sets]` definitions with no defaults list.
    fn sets(body: &str) -> Result<UserMounts, UserMountsError> {
        parse_document(&format!("[mount_sets]\n{body}"))
    }

    /// A whole document: a defaults list and `[mount_sets]` definitions.
    fn defaults_and_sets(defaults: &str, body: &str) -> Result<UserMounts, UserMountsError> {
        parse_document(&format!("mounts = {defaults}\n[mount_sets]\n{body}"))
    }

    /// The `$HOME` these fixtures' `~/` entries expand against.
    const HOME: &str = "/home/graph";

    fn rendered(result: Result<UserMounts, UserMountsError>) -> String {
        result.unwrap_err().to_string()
    }

    fn set(name: &str) -> MountSetName {
        MountSetName::parse(name).unwrap()
    }

    /// A set's expansion as `(source spelling, guest, read-only)` triples.
    fn expansion(mounts: &UserMounts, name: &str) -> Vec<(Spelling, String, bool)> {
        mounts
            .requests_for_set(&set(name))
            .unwrap_or_else(|| panic!("set {name} is declared"))
            .into_iter()
            .map(|request| {
                (
                    request.mount.source_spelling.clone(),
                    request.mount.guest.display().to_string(),
                    matches!(request.mount.policy, MountPolicy::BindReadOnly { .. }),
                )
            })
            .collect()
    }

    fn names(mounts: &UserMounts) -> Vec<(Spelling, String)> {
        mounts
            .requests()
            .iter()
            .map(|request| {
                (
                    request.mount.source_spelling.clone(),
                    request.mount.guest.display().to_string(),
                )
            })
            .collect()
    }

    /// Decision A1, against an independent literal table.
    ///
    /// Both directions are exercised: the accepted column must parse *and* keep its
    /// exact spelling, and the rejected column must fail. `A`/`a` distinctness and
    /// the tool/route words are acceptance facts, not conveniences.
    #[test]
    fn mount_set_name_grammar_matches_the_decided_table() {
        for accepted in [
            "agent",
            "pi-agent",
            "_local",
            "a.b",
            "A",
            "a",
            "0",
            "_",
            "a-",
            "a..b",
            "pi",
            "shell",
            "run",
            "doctor",
            "settings.json",
        ] {
            let name = MountSetName::parse(accepted).expect(accepted);
            assert_eq!(name.as_str(), accepted);
        }
        assert_ne!(set("A"), set("a"));
        for rejected in [
            "", ".", "..", "...", "agent:ro", "-agent", "--mount", "-", "../x", "./x", "~x", "~",
            "$X", "a/b", "a b", "a\tb", "a\nb", "a\0b", "*", "a\\b", "é", "aé", "Ａ", " a", "a ",
            "a:b",
        ] {
            assert!(MountSetName::parse(rejected).is_err(), "{rejected:?}");
        }
        // The rejected name is never echoed: the sentence is a fixed grammar
        // statement, so a key that happens to be a secret cannot be printed.
        let error = MountSetName::parse("s3cr3t:SENTINEL")
            .unwrap_err()
            .to_string();
        assert!(!error.contains("SENTINEL"), "{error}");
    }

    /// The kernel's executable form, at the byte boundaries A1 names.
    #[test]
    fn mount_set_name_bytes_accepts_exactly_the_decided_alphabet() {
        assert!(mount_set_name_bytes(b"a"));
        assert!(mount_set_name_bytes(b"_"));
        assert!(mount_set_name_bytes(b"0"));
        assert!(mount_set_name_bytes(b"a.b-c_D9"));
        assert!(!mount_set_name_bytes(b""));
        assert!(!mount_set_name_bytes(b".a"));
        assert!(!mount_set_name_bytes(b"-a"));
        assert!(!mount_set_name_bytes(b"a/b"));
        assert!(!mount_set_name_bytes(b"a:b"));
        assert!(!mount_set_name_bytes("é".as_bytes()));
        assert!(!mount_set_name_bytes("aＡ".as_bytes()));
        // An all-dot name needs no clause of its own: byte zero already fails.
        for dots in [".", "..", "...", "...."] {
            assert!(!mount_set_name_bytes(dots.as_bytes()), "{dots:?}");
        }
    }

    proptest! {
        /// The byte kernel against an independent `char`-based oracle.
        #[test]
        fn mount_set_name_bytes_matches_an_independent_oracle(
            bytes in proptest::collection::vec(any::<u8>(), 0..8),
        ) {
            let oracle = !bytes.is_empty()
                && (bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_')
                && bytes[1..].iter().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
                });
            prop_assert_eq!(mount_set_name_bytes(&bytes), oracle, "{:?}", bytes);
        }
    }

    /// The selector classification table: paths keep the path grammar, bare names
    /// are set lookups, and a name with any `:` is refused as a modifier.
    ///
    /// Written as an explicit literal table rather than by calling the kernel, so a
    /// wrong body is caught here as well as by the proof.
    #[test]
    fn selector_classification_matches_the_table() {
        let home = HostSyntax::AbsoluteOrHome { home: Some("/h") };
        for (entry, expected) in [
            ("agent", "set:agent"),
            ("pi-agent", "set:pi-agent"),
            ("  agent  ", "set:agent"),
            ("agent:ro", "modifier"),
            ("agent:fork", "modifier"),
            ("agent:/g", "modifier"),
            ("agent:exclude=x", "modifier"),
            ("agent:", "modifier"),
            ("unknown:ro", "modifier"),
            ("-agent", "direct"),
            ("-", "direct"),
            (".", "direct"),
            ("..", "direct"),
            ("../x", "direct"),
            ("./x", "direct"),
            ("~x", "direct"),
            ("~", "direct"),
            ("$X", "direct"),
            ("a/b", "direct"),
            ("a b", "direct"),
            ("", "direct"),
            (":/g", "direct"),
            ("/abs", "direct"),
            ("/abs:ro", "direct"),
            ("/abs:/g:fork", "direct"),
            ("/abs/ref/", "direct"),
            ("/abs/$HOME/x", "direct"),
            ("~/x", "direct"),
            ("~/x:ro", "direct"),
        ] {
            let actual = match parse_selector(entry, home) {
                Ok(MountSelector::Set(name)) => format!("set:{}", name.as_str()),
                Ok(MountSelector::Direct(_)) => "direct".to_string(),
                Err(SelectorError::SetModifier) => "modifier".to_string(),
                Err(SelectorError::Direct(_)) => "direct-refused".to_string(),
            };
            // `direct` and `direct-refused` are one classification: the path
            // grammar decides acceptance, not this table.
            let actual = match actual.as_str() {
                "direct-refused" => "direct".to_string(),
                other => other.to_string(),
            };
            assert_eq!(actual, expected, "{entry:?}");
        }
        // The path grammar's own verdicts, unchanged: every rejected relative
        // spelling is still the historical host refusal.
        for refused in ["-agent", "..", "~", "~x", "$X", "a/b", "a b", "", ":/g"] {
            assert!(
                matches!(
                    parse_selector(refused, HostSyntax::AbsoluteOnly),
                    Err(SelectorError::Direct(_))
                ),
                "{refused:?}"
            );
        }
        // A quoted literal `~/x` on the command line is *not* expanded, exactly as
        // before names existed.
        assert!(matches!(
            parse_selector("~/x", HostSyntax::AbsoluteOnly),
            Err(SelectorError::Direct(error)) if error.kind() == MountSpecErrorKind::HostNotAccepted
        ));
    }

    /// Definitions alone mount nothing, and an empty table or empty set is a
    /// namespace that selects nothing.
    #[test]
    fn definitions_alone_select_nothing() {
        for body in [
            "",
            "empty = []\n",
            "empty = []\nouter = [\"empty\", \"empty\"]\n",
        ] {
            let mounts = sets(body).expect(body);
            assert!(mounts.requests().is_empty(), "{body}");
            assert!(!mounts.has_defaults(), "{body}");
        }
        let mounts = defaults_and_sets("[]", "empty = []\n").unwrap();
        assert!(mounts.has_defaults());
        assert!(mounts.requests().is_empty());
        assert!(expansion(&mounts, "empty").is_empty());
    }

    /// Forward references, multi-hop nesting and a diamond all resolve, in list
    /// order, with the declaring leaf's own origin.
    #[test]
    fn forward_and_nested_references_resolve_in_list_order() {
        let mounts = sets(
            "agent = [\"docs\", \"/h/scratch:/scratch:rw\"]\n\
             docs = [\"/h/notes:/notes:ro\"]\n\
             deep = [\"agent\", \"docs\"]\n",
        )
        .unwrap();
        assert_eq!(
            expansion(&mounts, "agent"),
            [
                (Spelling::new("/h/notes"), "/notes".to_string(), true),
                (Spelling::new("/h/scratch"), "/scratch".to_string(), false),
            ]
        );
        // A shared child contributes once, and the parent's own order is kept.
        assert_eq!(
            expansion(&mounts, "deep"),
            [
                (Spelling::new("/h/notes"), "/notes".to_string(), true),
                (Spelling::new("/h/scratch"), "/scratch".to_string(), false),
            ]
        );
        // The origin names the declaring leaf's set, not the selected one.
        let requests = mounts.requests_for_set(&set("deep")).unwrap();
        assert_eq!(
            requests[0].origin,
            MountOrigin::UserSet {
                file: mounts.file().to_path_buf(),
                set: Arc::from("docs"),
                index: 0,
            }
        );
    }

    /// Every reference error: unknown in defaults, unknown in an unused set, a
    /// self cycle, a two-node cycle, a longer cycle and a disconnected one.
    #[test]
    fn reference_errors_are_named_by_site() {
        // `[mount_sets]` sorted: agent < deep < docs for the multi-hop fixture.
        assert_eq!(
            rendered(defaults_and_sets("[\"ref\"]", "")),
            "mounts[0]: unknown mount set name"
        );
        assert_eq!(
            rendered(defaults_and_sets("[\"/a:ro\", \"ref\"]", "")),
            "mounts[1]: unknown mount set name"
        );
        assert_eq!(
            rendered(sets("unused = [\"nope\"]\n")),
            "mount_sets[0][0]: unknown mount set name"
        );
        assert_eq!(
            rendered(sets("a = [\"a\"]\n")),
            "mount_sets[0][0]: mount-set reference cycle"
        );
        assert_eq!(
            rendered(sets("a = [\"b\"]\nb = [\"a\"]\n")),
            "mount_sets[1][0]: mount-set reference cycle"
        );
        assert_eq!(
            rendered(sets("a = [\"b\"]\nb = [\"c\"]\nc = [\"a\"]\n")),
            "mount_sets[2][0]: mount-set reference cycle"
        );
        // Disconnected from anything a launch would select, still refused.
        assert_eq!(
            rendered(sets("island = [\"island\"]\nroot = []\n")),
            "mount_sets[0][0]: mount-set reference cycle"
        );
        // Two sets that reference one shared child are a diamond, not a cycle.
        assert!(sets("a = [\"shared\"]\nb = [\"shared\"]\nshared = [\"/h/s:/s:ro\"]\n").is_ok());
    }

    /// A set entry's own grammar and modifier refusals name the set's coordinates.
    #[test]
    fn set_entries_keep_the_direct_grammar_and_refuse_modifiers() {
        assert_eq!(
            rendered(sets("a = [\"agent:ro\"]\n")),
            "mount_sets[0][0]: a mount-set reference is a bare name; modes, a guest path and \
             exclusions belong to the paths declared inside the set"
        );
        assert_eq!(
            rendered(sets("a = [\"/abs:ro:rw\"]\n")),
            "mount_sets[0][0]: conflicting modes `ro` and `rw`"
        );
        assert_eq!(
            rendered(sets("a = [\"./rel\"]\n")),
            "mount_sets[0][0]: host path must be absolute or start with ~/ (environment variables \
             and other relative paths are not expanded)"
        );
        assert_eq!(
            rendered(sets("a = [\"/abs:/a/../b\"]\n")),
            "mount_sets[0][0]: guest path must be absolute, must not be /, and must not contain \
             `..`, `:`, `;`, `,` or control characters"
        );
        assert_eq!(
            rendered(sets("a = 7\n")),
            "mount_sets[0]: must be an array of mount declarations or set names"
        );
        assert_eq!(
            rendered(sets("a = [7]\n")),
            "mount_sets[0][0]: must be a string"
        );
        assert_eq!(
            rendered(sets("a = [\"/abs:ro:x\"]\n")),
            "mount_sets[0][0]: unknown mode keyword (expected ro, rw, fork, follow-links, or \
             exclude=REL)"
        );
        assert_eq!(
            rendered(sets("a = [\"/abs:\"]\n")),
            "mount_sets[0][0]: empty segment (stray `:`); expected HOST[:GUEST][:MODE]..."
        );
        assert_eq!(
            rendered(sets("a = { b = 1 }\n")),
            "mount_sets[0]: must be an array of mount declarations or set names"
        );
        assert_eq!(
            rendered(parse_document("mount_sets = 7\n")),
            "mount_sets: must be a table of named arrays of mount declarations"
        );
    }

    /// An invalid definition *key* is named by its sorted position and never
    /// echoed, and the following definitions keep their numbers.
    #[test]
    fn invalid_set_names_are_numeric_and_value_free() {
        assert_eq!(
            rendered(sets("\"a b\" = []\n")),
            "mount_sets: definition 0 has an invalid name; a mount-set name is one or more ASCII \
             characters: [A-Za-z0-9_] first, then [A-Za-z0-9_.-]"
        );
        // A sentinel that cannot be a name at all, so the row tests the *invalid*
        // key path rather than a key that merely looks secret.
        const SENTINEL: &str = "s3cr3t SENTINEL/x";
        let error = rendered(sets(&format!("aa = []\n\"{SENTINEL}\" = []\n")));
        assert!(!error.contains(SENTINEL), "{error}");
        assert!(error.contains("definition 1"), "{error}");
        // Sorted, not TOML order: `aa` precedes `"ab c"`.
        assert!(rendered(sets("aa = []\n\"ab c\" = []\n")).contains("definition 1"));
    }

    /// Decision A2: a closure that disagrees with itself fails load even when no
    /// launch selects it, and two separately valid sets may still disagree until
    /// both are selected.
    #[test]
    fn per_set_closures_are_validated_independently() {
        assert_eq!(
            rendered(sets("a = [\"/h/x:/g:ro\", \"/h/y:/g:ro\"]\n")),
            "mount_sets[0][1]: claims the same guest path as mount_sets[0][0] with a different \
             declaration"
        );
        // Nested through a shared child, so the differing pair is not adjacent.
        assert_eq!(
            rendered(sets("a = [\"b\", \"/h/y:/g:ro\"]\nb = [\"/h/x:/g:ro\"]\n")),
            "mount_sets[0][1]: claims the same guest path as mount_sets[1][0] with a different \
             declaration"
        );
        // Identical declarations, reached twice, merge and keep the first origin.
        let mounts = sets("a = [\"/h/x:/g:ro\", \"b\"]\nb = [\"/h/x:/g//./:ro\"]\n").unwrap();
        assert_eq!(
            expansion(&mounts, "a"),
            [(Spelling::new("/h/x"), "/g".to_string(), true)]
        );
        // Two alternatives that only disagree at one guest path are each valid on
        // their own and are never claimed against each other at load.
        let mounts = sets("one = [\"/h/x:/g:ro\"]\ntwo = [\"/h/y:/g:ro\"]\n").unwrap();
        assert_eq!(expansion(&mounts, "one").len(), 1);
        assert_eq!(expansion(&mounts, "two").len(), 1);
        // Selecting both is refused by the shared claim, at load because both are
        // defaults-selected, and by `prepare` when argv selects the second.
        assert_eq!(
            rendered(defaults_and_sets(
                "[\"one\", \"two\"]",
                "one = [\"/h/x:/g:ro\"]\ntwo = [\"/h/y:/g:ro\"]\n"
            )),
            "mount_sets[1][0]: claims the same guest path as mount_sets[0][0] with a different \
             declaration"
        );
    }

    /// Defaults and a set that disagree at one guest path are refused at load,
    /// in either declaration order; identical ones merge with the first origin.
    #[test]
    fn defaults_and_selected_sets_share_one_claim() {
        // The sentence names the *second-seen* site first, so the row depends on
        // the list order and not on which kind of entry it was.
        assert_eq!(
            rendered(defaults_and_sets(
                "[\"/h/d:/g:ro\", \"s\"]",
                "s = [\"/h/s:/g:ro\"]\n"
            )),
            "mount_sets[0][0]: claims the same guest path as mounts[0] with a different declaration"
        );
        assert_eq!(
            rendered(defaults_and_sets(
                "[\"s\", \"/h/other:/g:ro\"]",
                "s = [\"/h/s:/g:ro\"]\n"
            )),
            "mounts[1]: claims the same guest path as mount_sets[0][0] with a different declaration"
        );
        // Identical in both places merges, and the first-seen origin is kept.
        let merged = defaults_and_sets("[\"s\", \"/h/s:/g:ro\"]", "s = [\"/h/s:/g:ro\"]\n")
            .expect("identical declarations merge");
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged.requests()[0].origin,
            MountOrigin::UserSet {
                file: merged.file().to_path_buf(),
                set: Arc::from("s"),
                index: 0,
            }
        );
        let mounts =
            defaults_and_sets("[\"s\", \"/h/d:/d:ro\"]", "s = [\"/h/s:/g:ro\"]\n").unwrap();
        assert_eq!(
            names(&mounts),
            [
                (Spelling::new("/h/s"), "/g".to_string()),
                (Spelling::new("/h/d"), "/d".to_string()),
            ]
        );
        // An unselected set is not claimed against the defaults, even when it
        // declares a different mount at the same guest path.
        let mounts =
            defaults_and_sets("[\"/h/d:/g:ro\"]", "s = [\"/h/s:/g:rw\", \"/h/s:/g2\"]\n").unwrap();
        assert_eq!(mounts.len(), 1);
    }

    /// `~/` expansion inside a set uses the captured host home and the same
    /// concatenation rules as the defaults list.
    #[test]
    fn set_entries_expand_the_host_home() {
        let mounts = sets("a = [\"~/ref:/g:ro\"]\n").unwrap();
        assert_eq!(
            expansion(&mounts, "a"),
            [(Spelling::new("/home/graph/ref"), "/g".to_string(), true)]
        );
        let mounts = sets("a = [\"~/ref/:/g:ro\"]\n").unwrap();
        assert_eq!(
            expansion(&mounts, "a"),
            [(Spelling::new("/home/graph/ref/"), "/g".to_string(), true)]
        );
        assert_eq!(
            with_authorized("[mount_sets]\na = [\"~/ref\"]\n", |authorized, values| {
                rendered(from_verified_value(authorized, values, None))
            }),
            "mount_sets[0][0]: a ~/ host path needs a UTF-8 $HOME"
        );
    }

    /// Every declared source may be absent: load never stats, opens or
    /// canonicalizes one, and an unselected set's source is never consulted.
    #[test]
    fn load_never_touches_a_source() {
        let missing = "/nonexistent-agent-vm-mount-set-probe";
        assert!(!Path::new(missing).exists());
        let mounts =
            defaults_and_sets("[\"a\"]", &format!("a = [\"{missing}:/g:fork\"]\n")).unwrap();
        assert_eq!(mounts.len(), 1);
        let mounts = sets(&format!("unused = [\"{missing}:/g:fork\"]\n")).unwrap();
        assert!(mounts.requests().is_empty());
    }

    /// Decision R1's boundary, over the real kernel and a real counter.
    #[test]
    fn mount_set_expansion_work_boundary() {
        for used in [0, 1, 65_534, 65_535] {
            assert!(mount_set_expansion_work_allowed(used), "{used}");
        }
        for used in [65_536, 65_537, usize::MAX] {
            assert!(!mount_set_expansion_work_allowed(used), "{used}");
        }
        // An exhausted counter refuses and does not advance.
        let mut work = ExpansionWork {
            used: MAX_MOUNT_SET_EXPANSION_WORK,
        };
        assert!(work.admit().is_err());
        assert_eq!(work.used, MAX_MOUNT_SET_EXPANSION_WORK);
        // A counter one below the limit admits exactly one more visit.
        let mut work = ExpansionWork {
            used: MAX_MOUNT_SET_EXPANSION_WORK - 1,
        };
        assert!(work.admit().is_ok());
        assert_eq!(work.used, MAX_MOUNT_SET_EXPANSION_WORK);
        assert!(work.admit().is_err());
        assert_eq!(work.used, MAX_MOUNT_SET_EXPANSION_WORK);
    }

    /// One *new* leaf per set, chained — the shape whose per-closure `claim` work
    /// is cubic, and the one the reviewer showed no other test supplied.
    ///
    /// The counter is the oracle, not the clock: 361 closures cost 361*362/2 =
    /// 65,341 admitted visits, so the 362nd closure is refused partway through,
    /// with a limit-specific sentence rather than a conflict or source error.
    #[test]
    fn mount_set_expansion_chain_is_bounded() {
        fn chain_document(length: usize) -> String {
            let mut body = String::new();
            for index in 0..length {
                if index + 1 < length {
                    body.push_str(&format!(
                        "s{index:04} = [\"/h/{index:04}:/g/{index:04}:ro\", \"s{:04}\"]\n",
                        index + 1
                    ));
                } else {
                    body.push_str(&format!(
                        "s{index:04} = [\"/h/{index:04}:/g/{index:04}:ro\"]\n"
                    ));
                }
            }
            body
        }

        let ok = parse_document(&format!("[mount_sets]\n{}", chain_document(361))).unwrap();
        assert_eq!(ok.expansion_work(), 65_341);
        assert_eq!(ok.graph_entries(), 361 * 2 - 1);

        let limit = "mount_sets: expansion work exceeds limit of 65536 leaf visits";
        // The refusal is the point of the bound, so the counter is asserted too:
        // the file spends every visit it is allowed and then refuses the 65,537th
        // candidate without admitting it.
        for length in [362, 4_000] {
            let (parsed, used) =
                parse_document_with_work(&format!("[mount_sets]\n{}", chain_document(length)));
            assert_eq!(rendered(parsed), limit, "{length}");
            assert_eq!(
                used,
                crate::config_mounts::sets::MAX_MOUNT_SET_EXPANSION_WORK,
                "{length}: the refusal happens after every admitted visit"
            );
        }
    }

    /// A chain of references with no leaves costs no leaf visit, and one whose only
    /// leaf is at the end costs one per set: graph entry processing is linear either
    /// way, which is what a leafless chain needs to stay cheap.
    #[test]
    fn mount_set_reference_only_chains_are_linear() {
        fn chain_document(length: usize, with_leaf: bool) -> String {
            let mut body = String::new();
            for index in 0..length {
                let mut entries: Vec<String> = Vec::new();
                if with_leaf && index + 1 == length {
                    entries.push("\"/h/leaf:/leaf:ro\"".to_string());
                }
                if index + 1 < length {
                    entries.push(format!("\"s{:04}\"", index + 1));
                }
                body.push_str(&format!("s{index:04} = [{}]\n", entries.join(", ")));
            }
            body
        }

        let empty =
            parse_document(&format!("[mount_sets]\n{}", chain_document(4_000, false))).unwrap();
        assert_eq!(empty.expansion_work(), 0);
        assert_eq!(empty.graph_entries(), 4_000 - 1);
        assert!(empty.requests_for_set(&set("s0000")).unwrap().is_empty());

        let one_leaf =
            parse_document(&format!("[mount_sets]\n{}", chain_document(4_000, true))).unwrap();
        assert_eq!(one_leaf.expansion_work(), 4_000);
        assert_eq!(one_leaf.graph_entries(), 4_000);
        assert_eq!(one_leaf.requests_for_set(&set("s0000")).unwrap().len(), 1);
    }

    /// A set's key is stored once, shared by every leaf's origin and by a clone of
    /// the model.
    ///
    /// The key's length is bounded only by the rest of the config file, and a set
    /// may list that key's leaves thousands of times, so a per-leaf `String` copy
    /// turns one 40 KB key into 80 MB of retained provenance — below both the file
    /// limit and the leaf-visit budget. The oracle is the allocation itself:
    /// `Arc::ptr_eq` across leaves and across a clone, and a strong count that only
    /// one shared name can reach.
    #[test]
    fn mount_set_key_is_stored_once_across_leaves_and_clones() {
        const LEAVES: usize = 2_000;
        let key = "a".repeat(40_000);
        let mut entries: Vec<String> =
            std::iter::repeat_n("\"/h:/g:ro\"".to_string(), LEAVES).collect();
        // A second *distinct* leaf, so the expansion keeps two entries and both
        // origins are observable through the selection.
        entries.push("\"/h:/other:ro\"".to_string());
        let body = format!("[mount_sets]\n{key} = [{}]\n", entries.join(", "));
        assert!(
            body.len() < 1 << 20,
            "the fixture stays inside the file bound"
        );
        let mounts = parse_document(&body).expect("a long key is valid");
        let name = MountSetName::parse(&key).unwrap();
        let selected = mounts.requests_for_set(&name).expect("the set exists");
        assert_eq!(selected.len(), 2, "the repeated leaf deduplicates");

        let shared = |request: &MountRequest| match &request.origin {
            MountOrigin::UserSet { set, .. } => Arc::clone(set),
            other => panic!("a set leaf must carry a set origin: {other:?}"),
        };
        let first = shared(&selected[0]);
        let second = shared(&selected[1]);
        assert_eq!(first.len(), 40_000, "the name is kept in full");
        assert!(
            Arc::ptr_eq(&first, &second),
            "two leaves of one set must share one name allocation"
        );
        // Every leaf of the definition holds a handle, so one allocation serves
        // them all; per-leaf copies would each be their own Arc.
        assert!(
            Arc::strong_count(&first) >= LEAVES,
            "expected the arena's {} leaves to share one name, saw {}",
            LEAVES,
            Arc::strong_count(&first)
        );

        // A cloned model is what `cli`/`run` hand to a launch: it must share the
        // same allocation rather than copy the key again.
        let cloned = mounts.clone();
        let again = cloned.requests_for_set(&name).expect("the set exists");
        assert!(
            Arc::ptr_eq(&first, &shared(&again[0])),
            "a clone must share the name"
        );
        assert!(
            Arc::strong_count(&first) >= LEAVES * 2,
            "both arenas must share one allocation, saw {}",
            Arc::strong_count(&first)
        );
    }

    /// Wide empty-child fan-out is linear in admissions, not quadratic in
    /// already-seen ids — in both traversals.
    ///
    /// One set listing N distinct empty children spends zero leaf visits (an empty
    /// closure contributes no leaf), so the leaf budget cannot see this work: it is
    /// the raw-edge processing the plan requires to be linear. The oracle is
    /// `admissions`: exactly one per reference, in *both* traversals. That kills a
    /// revert of either traversal to a growing `Vec` (the count drops to zero), and
    /// it is honest about being a wiring check, not a cost check — what each
    /// admission costs is O(1) by the indexed slot's construction, and a scan
    /// placed *inside* `admit` is invisible to any counter the traversal keeps
    /// itself (see ADR-0018: the tracker's linearity rests on instruction-scaling
    /// evidence, not on an in-process kernel).
    #[test]
    fn mount_set_wide_empty_fanout_is_linear() {
        const CHILDREN: usize = 20_000;
        let mut body = String::new();
        body.push_str("parent = [");
        for index in 0..CHILDREN {
            if index > 0 {
                body.push_str(", ");
            }
            body.push_str(&format!("\"c{index:05}\""));
        }
        body.push_str("]\n");
        for index in 0..CHILDREN {
            body.push_str(&format!("c{index:05} = []\n"));
        }
        let mounts =
            parse_document(&format!("[mount_sets]\n{body}")).expect("the fan-out is valid");
        assert_eq!(
            mounts.reference_admissions(),
            CHILDREN,
            "one admission per reference, not a scan of already-seen ids"
        );
        assert_eq!(mounts.expansion_work(), 0, "empty children spend no leaf");
        assert!(
            mounts.requests_for_set(&set("parent")).unwrap().is_empty(),
            "the parent selects nothing"
        );

        // The same fan-out in the *defaults* list, whose merge is a second
        // traversal with its own tracker.
        let mut defaults = String::from("mounts = [");
        for index in 0..CHILDREN {
            if index > 0 {
                defaults.push_str(", ");
            }
            defaults.push_str(&format!("\"c{index:05}\""));
        }
        defaults.push_str("]\n");
        let mounts = parse_document(&format!("{defaults}[mount_sets]\n{body}"))
            .expect("the defaults fan-out is valid");
        // One walk over the parent's list plus one over the defaults list: both
        // traversals must reach the same tracker.
        assert_eq!(
            mounts.reference_admissions(),
            CHILDREN * 2,
            "the defaults merge must use the tracker too"
        );
        assert!(mounts.requests().is_empty());

        // Repeated references to *one* child cost one admission each and never
        // grow a seen list.
        let mut repeated = String::from("mounts = [");
        for index in 0..CHILDREN {
            if index > 0 {
                repeated.push_str(", ");
            }
            repeated.push_str("\"leaf\"");
        }
        repeated.push_str("]\n[mount_sets]\nleaf = [\"/h:/g:ro\"]\n");
        let mounts = parse_document(&repeated).expect("repeated defaults are valid");
        assert_eq!(mounts.reference_admissions(), CHILDREN);
        assert_eq!(mounts.len(), 1, "one leaf, however often it is named");
    }

    /// The indexed merge adjudicates exactly what `mount::claim` does, over every
    /// six-field equivalence difference the parser can isolate and every duplicate
    /// shape.
    ///
    /// The oracle is the *existing* claim — ordinary requests parsed by the shared
    /// grammar and adjudicated by `mount::claim`'s growing-vector scan — so a
    /// defect in the new index adapter cannot hide behind itself.
    #[test]
    fn mount_set_indexed_claim_matches_claim() {
        // One side is the *existing* claim: ordinary requests parsed by the shared
        // grammar and adjudicated by `mount::claim`, which is the growing-vector
        // scan this module replaces with an index. The other side is the indexed
        // merge through a set. A defect in the new adapter therefore cannot hide
        // behind itself.
        //
        // Every six-field equivalence fact has a row where that fact alone
        // differs at one guest path (`/g`), except `host`: the host is a function
        // of the spelling at parse time, so no fixture can differ in the host
        // while keeping both spellings equal, and the `/a` versus `/a/` row in
        // fact differs in the spelling only (`Path` equality ignores a trailing
        // slash). The rest of the list covers duplicates, a distinct-guest
        // parent/child pair, a pair that differs by an intermediate component the
        // guest normalizer removes, and order.
        let lists: [&[&str]; 14] = [
            &[],
            &["/a:/g"],
            &["/a:/g", "/a:/g"],
            &["/a:/g:ro", "/a:/g:ro"],
            &["/a:/g:ro", "/a:/g:rw"],
            // Spelling only: `/a` and `/a/` are the same `Path`.
            &["/a:/g:ro", "/a/:/g:ro"],
            // Read-only versus follow-links (which implies read-only).
            &["/a:/g:ro", "/a:/g:follow-links"],
            // Fork alone, read-write otherwise: the only fixture that isolates
            // the fork fact, so an adapter that ignores it merges and the claim
            // side refuses.
            &["/a:/g:fork", "/a:/g"],
            // Fork versus read-only, for the two-fact shape.
            &["/a:/g:fork", "/a:/g:ro"],
            // Fork exclusions differ, everything else equal.
            &["/a:/g:fork:exclude=x", "/a:/g:fork"],
            // Same declaration after guest normalization: merge, first kept.
            &["/a:/g//./x:ro", "/a:/g/x:ro"],
            // The config route's `~/` spelling versus its expanded twin.
            &["~/a:/g:ro", "/home/graph/a:/g:ro"],
            // A writable parent with a distinct child: distinct guests, so both
            // are kept rather than refused, in list order.
            &["/a:/g", "/b:/g/x"],
            // Distinct declarations keep list order.
            &["/a:/a", "/b:/b", "/c:/c:fork"],
        ];
        for list in lists {
            let claimed = ordinary_claim(list);
            let indexed = indexed_merge(list);
            match (claimed, indexed) {
                (Ok(claimed), Ok(indexed)) => {
                    assert_eq!(
                        describe(&claimed),
                        describe(&indexed),
                        "{list:?}: the indexed merge must keep the same declarations"
                    );
                    assert_eq!(
                        first_kept(&claimed),
                        first_kept(&indexed),
                        "{list:?}: the first equivalent declaration must be the one kept"
                    );
                }
                (Err(claimed), Err(indexed)) => assert_eq!(
                    claimed, indexed,
                    "{list:?}: both routes must refuse the same pair"
                ),
                (claimed, indexed) => panic!(
                    "{list:?}: claim {} disagreed with the indexed merge {}",
                    if claimed.is_ok() {
                        "accepted"
                    } else {
                        "refused"
                    },
                    if indexed.is_ok() {
                        "accepted"
                    } else {
                        "refused"
                    }
                ),
            }
        }
    }

    /// The declarations of one list, as `claim` returns them: `(spelling, host,
    /// guest, policy, exclusions)`.
    fn describe(
        requests: &[MountRequest],
    ) -> Vec<(Spelling, PathBuf, PathBuf, MountPolicy, Vec<PathBuf>)> {
        requests
            .iter()
            .map(|request| {
                (
                    request.mount.source_spelling.clone(),
                    request.mount.host.clone(),
                    request.mount.guest.clone(),
                    request.mount.policy,
                    request.mount.exclusions.clone(),
                )
            })
            .collect()
    }

    /// Which list entry each kept declaration came from, so "the first equivalent
    /// declaration wins" is compared rather than assumed.
    fn first_kept(requests: &[MountRequest]) -> Vec<usize> {
        requests
            .iter()
            .map(|request| match &request.origin {
                MountOrigin::UserConfig { index, .. } | MountOrigin::UserSet { index, .. } => {
                    *index
                }
                // Neither route in this test tags anything `Cli`; naming it keeps
                // the match exhaustive rather than adding a catch-all.
                MountOrigin::Cli => usize::MAX,
            })
            .collect()
    }

    /// A refusal, reduced to the fact both routes must agree on: which list entry
    /// was refused against an earlier one. The two routes render different
    /// sentences on purpose (a launch names both origins, a load names two sites),
    /// so comparing wording would compare diagnostics rather than decisions.
    #[derive(Debug, PartialEq, Eq)]
    enum Refusal {
        /// The declaration at this index disagreed with an earlier one.
        Conflict { second: usize },
        /// A refusal this fixture family must not produce.
        Unexpected,
    }

    /// The existing growing-vector claim over one ordinary list, with the same
    /// per-entry origins the config route uses.
    fn ordinary_claim(list: &[&str]) -> Result<Vec<MountRequest>, Refusal> {
        let mut requests = Vec::with_capacity(list.len());
        for (index, entry) in list.iter().enumerate() {
            let mount = crate::mount::parse_mount_spec(
                entry,
                crate::mount::HostSyntax::AbsoluteOrHome { home: Some(HOME) },
            )
            .expect("the fixture entries are valid declarations");
            requests.push(MountRequest {
                origin: MountOrigin::UserConfig {
                    file: PathBuf::from("/home/u/.config/agent-vm/config.toml"),
                    index,
                },
                mount,
            });
        }
        crate::mount::claim(requests, &[]).map_err(|error| match error {
            crate::mount::ClaimError::Conflict {
                second: MountOrigin::UserConfig { index, .. },
                ..
            } => Refusal::Conflict { second: index },
            _ => Refusal::Unexpected,
        })
    }

    /// The same list through the indexed merge, reached through one set.
    fn indexed_merge(list: &[&str]) -> Result<Vec<MountRequest>, Refusal> {
        let body = list
            .iter()
            .map(|entry| format!("\"{entry}\""))
            .collect::<Vec<_>>()
            .join(", ");
        parse_document(&format!("[mount_sets]\ns = [{body}]\n"))
            .map(|mounts| {
                mounts
                    .requests_for_set(&set("s"))
                    .expect("the set is declared")
            })
            .map_err(|error| match error {
                UserMountsError::Conflict {
                    site: EntrySite::SetEntry { index, .. },
                    ..
                } => Refusal::Conflict { second: index },
                _ => Refusal::Unexpected,
            })
    }

    /// An enormous but well-shaped graph is refused by the budget, not by a hang or
    /// a stack overflow; a share-shaped graph well inside the budget flattens once.
    #[test]
    fn a_wide_graph_is_refused_without_recursion() {
        let mut body = String::from("shared = [\n");
        for index in 0..1_000 {
            body.push_str(&format!("\"/h/{index}:/g/{index}:ro\",\n"));
        }
        body.push_str("]\n");
        for index in 0..1_000 {
            body.push_str(&format!("s{index:04} = [\"shared\"]\n"));
        }
        assert_eq!(
            rendered(parse_document(&format!("[mount_sets]\n{body}"))),
            "mount_sets: expansion work exceeds limit of 65536 leaf visits"
        );
        let mounts =
            sets("shared = [\"/h/x:/x:ro\", \"/h/y:/y:ro\"]\na = [\"shared\"]\nb = [\"shared\"]\n")
                .unwrap();
        assert_eq!(expansion(&mounts, "a").len(), 2);
        assert_eq!(expansion(&mounts, "b").len(), 2);
        // shared (2) + a (2) + b (2): shared's closure is iterated, not re-expanded.
        assert_eq!(mounts.expansion_work(), 6);
    }

    /// An unknown name is never a directory, a tool or a relative path: a name
    /// exists only if the user declared it, and case matters.
    #[test]
    fn a_name_is_only_ever_a_declared_set() {
        let mounts = sets("pi = [\"/h/pi:/pi:ro\"]\n").unwrap();
        assert_eq!(mounts.requests_for_set(&set("pi")).unwrap().len(), 1);
        assert!(mounts.requests_for_set(&set("shell")).is_none());
        assert!(mounts.requests_for_set(&set("PI")).is_none());
    }

    /// `visit_decision`'s executable form, against an independent table.
    #[test]
    fn visit_decision_matches_the_three_colours() {
        for (state, expected) in [
            (VisitState::Unseen, VisitDecision::Enter),
            (VisitState::Active, VisitDecision::Cycle),
            (VisitState::Complete, VisitDecision::Skip),
        ] {
            assert_eq!(visit_decision(state), expected);
        }
        // Only `Active` refuses: a completed node is legal shared structure.
        assert_eq!(
            [VisitState::Unseen, VisitState::Active, VisitState::Complete]
                .into_iter()
                .filter(|state| visit_decision(*state) == VisitDecision::Cycle)
                .count(),
            1
        );
    }
}
