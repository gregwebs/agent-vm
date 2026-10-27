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
//!   launch selects both. The same holds for every tool's own list (#396): it is
//!   parsed and checked at load, whether or not any launch reaches that tool.
//! * **That work is bounded** (decision R1). Guest-path lookup during closure
//!   compilation, tool-list parsing and the launch-time tool-closure fold is an
//!   index, never `mount::claim`'s growing-vector scan, and **one** global
//!   leaf-visit budget — continued across all three stages, never reset per set,
//!   per tool or per launch — turns a pathological config into a value-free
//!   config error instead of a hang. `mount::same_declaration` and
//!   `mount::claim_decision` stay the authority for whether two claims at one
//!   path agree; only the *lookup* is indexed.
//!
//! Nothing here opens, stats or canonicalizes a declared path. Every list holds
//! shared [`ConfigMountLeaf`] handles, so a shared child closure is iterated,
//! never copied or re-expanded, a diamond DAG cannot flatten exponentially, and
//! many catalog entries inheriting one list cost one handle each rather than one
//! payload each.

use super::{
    ConfigMountLeaf, EntrySite, MountSelector, MountSetName, MountValues, ResolvedMountList,
    SelectorError, ToolMountLists, UserMountsError, parse_selector,
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
/// How many leaf visits the whole user file may spend admitting mount candidates
/// (decision R1, widened by #396).
///
/// A *leaf visit* is one candidate considered while compiling a set's closure,
/// while merging a tool's own list, or while folding one launch's tool closure —
/// including a candidate later deduplicated, and including the same leaf reached
/// through different parents. The counter is global, never reset per root, per
/// tool, per list or per launch: 65,536 admits hundreds of ordinary small sets
/// (100 sets of 100 leaves costs 10,000) while bounding the worst admitted work to
/// 65,536 guest-index lookups, insertions and six-field equivalence checks — so a
/// crafted config cannot turn load *or* catalog construction into a hang.
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

/// Where one admitted candidate sits in the shared budget, which decides the
/// sentence an exhaustion prints.
///
/// Two stages, not one flag, because the two refusals are deliberately different
/// text: the set stage's bytes predate #396 and are pinned, while a tool-list or
/// tool-closure exhaustion names the wider scope it was caused by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExpansionStage {
    /// Compiling one declared set's closure.
    SetClosure,
    /// Merging a tool's own list, or folding a launch's tool closure.
    ToolMounts,
}

/// The one leaf-visit counter for the entire user file, continued into catalog
/// construction.
///
/// Plainly mutable and not a Verus value: the proved half is the exhaustion
/// predicate above, and `admit` is the trusted adapter that applies it before the
/// increment (so the counter can reach the limit and never overflow).
///
/// `Copy` on purpose: a launch takes one *continuation* from the verified parser
/// ([`UserMounts::continuing_work`]) and spends it while building the catalog.
/// There is no way to mint a fresh counter in production — `configured` is the
/// only constructor outside tests — so a second, independent budget cannot appear
/// by accident.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MountExpansionWork {
    used: usize,
}

impl MountExpansionWork {
    /// The counter a catalog build starts from when no user mount model exists
    /// (the built-in defaults, which cannot carry tool mounts and therefore
    /// consume nothing).
    pub(crate) fn fresh() -> Self {
        Self::default()
    }

    /// The continuation of a verified parse's counter.
    pub(super) fn configured(used: usize) -> Self {
        Self { used }
    }

    /// How many candidates this budget has admitted, whether the last one was
    /// refused or not. A test-only reader: the resource rule is otherwise
    /// observable only as the refusal.
    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.used
    }

    /// Admit one candidate leaf, or refuse the stage that spent it.
    fn admit(&mut self, stage: ExpansionStage) -> Result<(), UserMountsError> {
        if !mount_set_expansion_work_allowed(self.used) {
            return Err(match stage {
                ExpansionStage::SetClosure => UserMountsError::ExpansionWorkLimit,
                ExpansionStage::ToolMounts => UserMountsError::ToolExpansionWorkLimit,
            });
        }
        self.used += 1;
        Ok(())
    }
}

/// Which child sets one closure, defaults list or tool list has already expanded.
///
/// Generation-stamped slots, not a growing `Vec` searched linearly: a list that
/// references N distinct children must cost N admissions, while a scan of
/// already-seen ids costs N(N-1)/2 membership comparisons — and a leaf-visit
/// budget cannot see that work at all, because an empty child closure contributes
/// no leaf.
///
/// The cost property is structural: one indexed slot read per admission, with the
/// generation stamp doing the "already seen" test in O(1). One instance serves
/// every list in the file — including every tool list (#396) — so a tool-scoped
/// map does not cost an O(number-of-sets) clear per list. `admissions` is the only
/// counter, and it exists to show that *every* traversal uses this tracker (a
/// revert of one to a growing `Vec` drops the count); it cannot witness what
/// `admit` itself does. Nothing in-process can: a counter the traversal increments
/// itself is self-reported, so the linearity evidence for the tracker is
/// instruction scaling, not a kernel.
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

/// One entry of a definition, the defaults list or a tool's own list, after name
/// binding.
#[derive(Clone, Copy, Debug)]
enum Entry {
    Direct(LeafId),
    Reference(SetId),
}

/// Which list an entry list came from, so one binder can serve all three and each
/// still names its own site and its own schema sentence.
#[derive(Clone, Copy, Debug)]
enum ListSite {
    Defaults,
    Tool { declaration: usize },
}

impl ListSite {
    fn entry(self, index: usize) -> EntrySite {
        match self {
            Self::Defaults => EntrySite::Defaults { index },
            Self::Tool { declaration } => EntrySite::ToolEntry { declaration, index },
        }
    }

    fn not_array(self) -> UserMountsError {
        match self {
            Self::Defaults => UserMountsError::NotArray,
            Self::Tool { declaration } => UserMountsError::ToolListNotArray { declaration },
        }
    }

    fn not_string(self, index: usize) -> UserMountsError {
        match self {
            Self::Defaults => UserMountsError::NotString { index },
            Self::Tool { declaration } => UserMountsError::ToolListNotString { declaration, index },
        }
    }
}

/// Whether a list merge spends the shared leaf-visit budget.
///
/// An enum rather than `Option<&mut MountExpansionWork>`, because the defaults
/// list's *exemption* is a documented decision (decision R1) and must not read as
/// a missing argument: its direct entries are bounded by the config file size and
/// every closure it can reference was already admitted when that closure was
/// compiled, so charging it again would double-count the same work.
enum Charge<'a> {
    /// The one historical exemption: the top-level defaults merge.
    Exempt,
    /// A tool's own list, and the launch-time tool-closure fold.
    ToolMounts(&'a mut MountExpansionWork),
}

struct SetDefinition {
    entries: Vec<Entry>,
}

/// One file's validated set namespace: exact names, and each declared set's
/// compiled closure in the table the dependency-first compiler filled.
///
/// Staged as soon as that table exists and *before* the defaults list and the
/// tool lists are bound, so all three selections call the same lookup
/// ([`Self::requests_for_set`]) rather than the binder resolving a name against a
/// raw name map. The set graph itself is compiled by
/// [`validate_references_and_cycles`] and [`compile_closures`] before this type
/// exists: a definition's reference cannot call the interface because the closure
/// it would return is what that walk is computing.
#[derive(Clone, Debug)]
struct SetNamespace {
    /// Name to definition, exact spelling, no folding.
    index: BTreeMap<MountSetName, SetId>,
    /// Per set, its unique leaves in first-seen order, as a shared list so a
    /// lookup is an `Arc` bump rather than a payload clone.
    closures: Vec<ResolvedMountList>,
}

/// One named set as a selection: the definition's position, which the per-list
/// child tracker needs, and the shared compiled closure itself.
///
/// One value rather than two lookups, so a list that skips a repeated reference
/// cannot disagree with the bytes it expands.
struct SetSelection {
    set: SetId,
    list: ResolvedMountList,
}

impl SetNamespace {
    /// The declarations one named set expands to, or `None` when this file
    /// declares no such set.
    ///
    /// An exact lookup: no case folding, no trimming, no cwd path, no directory or
    /// tool discovery, and no second parser. The closure was validated at load, so
    /// this hands out the already-compiled shared list — it is never a second
    /// validation pass — and it is the **only** name-to-selection interface: the
    /// defaults list, every tool list and `--mount` all select through it.
    fn requests_for_set(&self, name: &MountSetName) -> Option<SetSelection> {
        let set = *self.index.get(name)?;
        Some(SetSelection {
            set,
            list: self.closures[set.0].clone(),
        })
    }

    /// The compiled closure at a position an earlier `requests_for_set` returned.
    ///
    /// A table read, not a selection: no name is involved, so a merge that already
    /// resolved its references cannot reach a second lookup by using it.
    fn list(&self, set: SetId) -> &ResolvedMountList {
        &self.closures[set.0]
    }
}

/// One verified user file's mount configuration: the file, its optional defaults,
/// its validated set namespace and every tool's own list.
///
/// [`Self::defaults`] and [`Self::requests_for_set`] are *selection sources*
/// already normalized and deduplicated, so a later claim against `--mount` needs
/// no second pass. Neither mounts anything by being present, and neither does a
/// tool's own list until a launch of that tool folds it.
#[derive(Clone, Debug)]
pub(crate) struct UserMounts {
    file: PathBuf,
    /// `Some` iff the file has a top-level `mounts` key, present-empty included.
    defaults: Option<ResolvedMountList>,
    /// The validated namespace the defaults list and every tool list selected
    /// their sets from, kept for `--mount`.
    sets: SetNamespace,
    /// Each full `[[tools]]` definition's own list, indexed by declaration.
    tool_lists: ToolMountLists,
    /// Leaf visits admitted while parsing, and the raw graph entry count.
    /// Retained rather than recomputed so a test can assert the *work* bound
    /// instead of a wall-clock time: the resource rule is about admitted
    /// comparisons, and only a counter can show its shape.
    work: usize,
    #[cfg_attr(not(test), allow(dead_code))]
    entries: usize,
    /// Reference admissions across every traversal, test-only for the same
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

    /// The declarations this file selects automatically on every launch, after
    /// merging. A file with no top-level list selects nothing here even when its
    /// tools declare mounts: those are selected per tool.
    pub(crate) fn defaults(&self) -> Option<&ResolvedMountList> {
        self.defaults.as_ref()
    }

    /// How many declarations the defaults list selects after merging. The launch
    /// notice reports the *combined* automatic count instead, from
    /// `mount_selection`; this is for tests that assert the defaults half alone.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.defaults.as_ref().map_or(0, ResolvedMountList::len)
    }

    /// Whether the file declares a defaults list at all. Presence, not contents,
    /// is the fact `--no-config-mounts` turns on: a sets-only file has no
    /// automatic selection to skip and must not be reported as skipped.
    pub(crate) fn has_defaults(&self) -> bool {
        self.defaults.is_some()
    }

    /// The declarations one named set expands to, or `None` when this file
    /// declares no such set — the projection `--mount` uses of the one lookup,
    /// [`SetNamespace::requests_for_set`], which the defaults list and every tool
    /// list already called at load. A caller with no list to track needs only the
    /// closure, not the position.
    pub(crate) fn requests_for_set(&self, name: &MountSetName) -> Option<ResolvedMountList> {
        self.sets
            .requests_for_set(name)
            .map(|selected| selected.list)
    }

    /// Take the tool lists out, so they can live on the validated tools and the
    /// CLI's namespace clone need not retain a second declaration map.
    ///
    /// Takes `&mut self` and leaves the empty map behind, so calling it twice
    /// cannot duplicate a tool's mounts.
    pub(crate) fn take_tool_lists(&mut self) -> ToolMountLists {
        std::mem::take(&mut self.tool_lists)
    }

    /// The continuation of this parse's leaf-visit budget, for the *single*
    /// subsequent catalog build.
    ///
    /// Not a public way to mint leaves or authority: it can only start where the
    /// verified parse stopped, so the tool-closure fold cannot get a second budget.
    /// A fresh [`MountExpansionWork::fresh`] is what the compiled defaults use,
    /// because built-in tools cannot carry mounts and therefore consume nothing.
    pub(crate) fn continuing_work(&self) -> MountExpansionWork {
        MountExpansionWork::configured(self.work)
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

    /// Reference admissions across every traversal. One admission per reference
    /// however wide the fan-out is, and zero for a traversal that scans a growing
    /// `Vec` instead of using the tracker — the wiring property this counter can
    /// actually witness. What each admission costs is O(1) by the indexed slot's
    /// construction, not by this count. Test-only.
    #[cfg(test)]
    pub(crate) fn reference_admissions(&self) -> usize {
        self.references
    }

    /// Validate the file, every mount field and the caller's host grammar.
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
    /// `ExpansionWorkLimit`), then the defaults list, then each tool's own list in
    /// declaration order.
    pub(super) fn parse(
        file: PathBuf,
        values: MountValues<'_>,
        syntax: HostSyntax<'_>,
    ) -> Result<Self, UserMountsError> {
        let mut work = MountExpansionWork::fresh();
        Self::build(file, values, syntax, &mut work)
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
        let mut work = MountExpansionWork::fresh();
        let parsed = Self::build(file, values, syntax, &mut work);
        (parsed, work.used())
    }

    fn build(
        file: PathBuf,
        values: MountValues<'_>,
        syntax: HostSyntax<'_>,
        work: &mut MountExpansionWork,
    ) -> Result<Self, UserMountsError> {
        let mut builder = Builder {
            file,
            leaves: Vec::new(),
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
        // One tracker for every list in the file, so a tool-scoped map costs no
        // per-list allocation or reset.
        let mut tracker = ChildTracker::new(definitions.len());
        let closures = compile_closures(&definitions, &builder.leaves, &order, work, &mut tracker)?;

        // Stage the validated namespace now, before either automatic selection is
        // bound: from here on a set is selected by name only through
        // `SetNamespace::requests_for_set`, the same call `--mount` makes.
        let sets = SetNamespace { index, closures };

        // Defaults next. They are validated even when a launch suppresses them,
        // but they are not charged to the shared budget (decision R1, see
        // `Charge::Exempt`).
        let defaults = match bind_entries(
            values.defaults,
            ListSite::Defaults,
            &sets,
            syntax,
            &mut builder,
        )? {
            None => None,
            Some(bound) => Some(merge_entries(
                &bound,
                &builder.leaves,
                &sets,
                Charge::Exempt,
                &mut tracker,
            )?),
        };

        // Every tool's own list last, in declaration order, and charged: unlike
        // the defaults merge this is a *new* list each time, so a file that
        // repeats a large set across many tools must not escape the bound.
        let mut tool_lists = ToolMountLists::empty();
        let mut tools: Vec<&super::ToolMountValue<'_>> = values.tools.iter().collect();
        tools.sort_by_key(|tool| tool.declaration);
        for tool in tools {
            let bound = bind_entries(
                Some(tool.value),
                ListSite::Tool {
                    declaration: tool.declaration,
                },
                &sets,
                syntax,
                &mut builder,
            )?
            .expect("a present tool list binds to a present list");
            let list = merge_entries(
                &bound,
                &builder.leaves,
                &sets,
                Charge::ToolMounts(work),
                &mut tracker,
            )?;
            tool_lists.set(tool.declaration, list);
        }

        Ok(Self {
            file: builder.file,
            defaults,
            sets,
            tool_lists,
            work: work.used,
            entries: builder.entries,
            references: tracker.admissions,
        })
    }
}

/// The arena under construction: every declaration this file contains and the
/// caller's host grammar.
struct Builder {
    file: PathBuf,
    leaves: Vec<Arc<ConfigMountLeaf>>,
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
        self.leaves
            .push(Arc::new(ConfigMountLeaf { request, site }));
        Ok(LeafId(self.leaves.len() - 1))
    }
}

/// Bind one entry list's selectors, whether it is the defaults list or a tool's
/// own. `None` means the field was absent.
///
/// One binder for all three list kinds: a list differs only in the site it names
/// and the schema sentence it prints, so a second `split(':')`/selector match
/// would be a second grammar. It receives the *validated namespace*, never a raw
/// name map, so a set entry has exactly one way to become a selection — the same
/// call `--mount` makes.
fn bind_entries(
    value: Option<&toml::Value>,
    site: ListSite,
    sets: &SetNamespace,
    syntax: HostSyntax<'_>,
    builder: &mut Builder,
) -> Result<Option<Vec<Entry>>, UserMountsError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let entries = value.as_array().ok_or_else(|| site.not_array())?;
    let mut bound: Vec<Entry> = Vec::with_capacity(entries.len());
    for (entry_index, entry) in entries.iter().enumerate() {
        let entry_site = site.entry(entry_index);
        let text = entry.as_str().ok_or_else(|| site.not_string(entry_index))?;
        builder.entries += 1;
        bound.push(match parse_selector(text, syntax) {
            Ok(MountSelector::Direct(mount)) => Entry::Direct(builder.push_leaf(
                match site {
                    ListSite::Defaults => MountOrigin::UserConfig {
                        file: builder.file.clone(),
                        index: entry_index,
                    },
                    ListSite::Tool { declaration } => MountOrigin::UserTool {
                        file: builder.file.clone(),
                        declaration,
                        index: entry_index,
                    },
                },
                entry_site,
                mount,
            )?),
            Ok(MountSelector::Set(target)) => match sets.requests_for_set(&target) {
                Some(selected) => Entry::Reference(selected.set),
                None => return Err(UserMountsError::UnknownSet { site: entry_site }),
            },
            Err(SelectorError::Direct(error)) => {
                return Err(UserMountsError::Entry {
                    site: entry_site,
                    kind: error.kind(),
                });
            }
            Err(SelectorError::SetModifier) => {
                return Err(UserMountsError::SetReferenceModified { site: entry_site });
            }
        });
    }
    Ok(Some(bound))
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
    leaves: &[Arc<ConfigMountLeaf>],
    order: &[SetId],
    work: &mut MountExpansionWork,
    tracker: &mut ChildTracker,
) -> Result<Vec<ResolvedMountList>, UserMountsError> {
    let mut closures: Vec<ResolvedMountList> = vec![ResolvedMountList::empty(); definitions.len()];
    let mut compiled = vec![false; definitions.len()];
    for set in order {
        tracker.next_list();
        let mut index: BTreeMap<&Path, &Arc<ConfigMountLeaf>> = BTreeMap::new();
        let mut unique: Vec<&Arc<ConfigMountLeaf>> = Vec::new();
        for entry in &definitions[set.0].entries {
            match entry {
                Entry::Direct(leaf) => admit_candidate(
                    &mut index,
                    &mut unique,
                    &leaves[leaf.0],
                    Some((work, ExpansionStage::SetClosure)),
                )?,
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
                    for leaf in closures[child.0].leaves() {
                        admit_candidate(
                            &mut index,
                            &mut unique,
                            leaf,
                            Some((work, ExpansionStage::SetClosure)),
                        )?;
                    }
                }
            }
        }
        closures[set.0] = share(&unique);
        compiled[set.0] = true;
    }
    Ok(closures)
}

/// Merge one ordered entry list into unique leaves, indexed by normalized guest
/// path.
///
/// References are read out of the namespace the binder selected them from, by
/// position: the same shared closure `requests_for_set` returned, never a second
/// name lookup.
fn merge_entries(
    entries: &[Entry],
    leaves: &[Arc<ConfigMountLeaf>],
    sets: &SetNamespace,
    charge: Charge<'_>,
    tracker: &mut ChildTracker,
) -> Result<ResolvedMountList, UserMountsError> {
    let mut index: BTreeMap<&Path, &Arc<ConfigMountLeaf>> = BTreeMap::new();
    let mut unique: Vec<&Arc<ConfigMountLeaf>> = Vec::new();
    let mut charge = charge;
    tracker.next_list();
    for entry in entries {
        match entry {
            Entry::Direct(leaf) => {
                admit_candidate(&mut index, &mut unique, &leaves[leaf.0], charge.borrow())?
            }
            Entry::Reference(child) => {
                if !tracker.admit(*child) {
                    continue;
                }
                for leaf in sets.list(*child).leaves() {
                    admit_candidate(&mut index, &mut unique, leaf, charge.borrow())?;
                }
            }
        }
    }
    Ok(share(&unique))
}

impl Charge<'_> {
    /// Re-borrow for one candidate. `admit_candidate` charges before it looks the
    /// guest path up, so the budget bounds comparisons rather than being checked
    /// after them.
    fn borrow(&mut self) -> Option<(&mut MountExpansionWork, ExpansionStage)> {
        match self {
            Self::Exempt => None,
            Self::ToolMounts(work) => Some((work, ExpansionStage::ToolMounts)),
        }
    }
}

/// Fold one launch's own tool mount lists — already resolved, normalized and
/// deduplicated at load — into the single union its entry carries.
///
/// Not a second expander: it never parses a selector or walks a set edge. It
/// merges declarations that were individually valid in lists that can only
/// conflict when one launch selects them both, and it spends the *continued*
/// shared budget for every candidate, duplicates included, before the guest-index
/// lookup and the shared equivalence kernel.
pub(crate) fn merge_tool_mounts<'a>(
    lists: impl IntoIterator<Item = &'a ResolvedMountList>,
    work: &mut MountExpansionWork,
) -> Result<ResolvedMountList, UserMountsError> {
    let mut index: BTreeMap<&Path, &Arc<ConfigMountLeaf>> = BTreeMap::new();
    let mut unique: Vec<&Arc<ConfigMountLeaf>> = Vec::new();
    for list in lists {
        for leaf in list.leaves() {
            admit_candidate(
                &mut index,
                &mut unique,
                leaf,
                Some((work, ExpansionStage::ToolMounts)),
            )?;
        }
    }
    Ok(share(&unique))
}

fn share(unique: &[&Arc<ConfigMountLeaf>]) -> ResolvedMountList {
    ResolvedMountList::from_leaves(unique.iter().map(|leaf| Arc::clone(leaf)).collect())
}

/// Adjudicate one candidate leaf against the list being built.
///
/// The order is the contract: charge the budget, look the guest path up in the
/// index, and only then reach the shared equivalence kernel. No candidate is
/// copied, compared or normalized before its visit is admitted, which is what
/// bounds a hostile file to the limit rather than to its size in comparisons.
fn admit_candidate<'a>(
    index: &mut BTreeMap<&'a Path, &'a Arc<ConfigMountLeaf>>,
    unique: &mut Vec<&'a Arc<ConfigMountLeaf>>,
    candidate: &'a Arc<ConfigMountLeaf>,
    charge: Option<(&mut MountExpansionWork, ExpansionStage)>,
) -> Result<(), UserMountsError> {
    if let Some((work, stage)) = charge {
        work.admit(stage)?;
    }
    let guest: &'a Path = candidate.request.mount.guest.as_path();
    match index.get(guest) {
        None => {
            index.insert(guest, candidate);
            unique.push(candidate);
            Ok(())
        }
        Some(&first) => match claim_decision(ClaimFacts {
            same_guest: true,
            equivalent: same_declaration(&first.request.mount, &candidate.request.mount),
        }) {
            ClaimDecision::Merge => Ok(()),
            ClaimDecision::Conflict | ClaimDecision::Distinct => Err(UserMountsError::Conflict {
                site: candidate.site.clone(),
                other: first.site.clone(),
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
        let tool_values: Vec<super::super::ToolMountValue<'_>> = table
            .get("tools")
            .and_then(toml::Value::as_array)
            .map(|tools| {
                tools
                    .iter()
                    .enumerate()
                    .filter_map(|(declaration, tool)| {
                        tool.as_table()
                            .and_then(|table| table.get("mounts"))
                            .map(|value| super::super::ToolMountValue { declaration, value })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let values = MountValues {
            defaults: table.get("mounts"),
            sets: table.get("mount_sets"),
            tools: &tool_values,
        };
        let authorized = verify(
            &read,
            AuthorityTriggers {
                network: false,
                mounts: crate::config_authority::mount_authority_present(
                    crate::config_authority::MountAuthorityFacts {
                        top_level: values.defaults.is_some(),
                        tool_field: !tool_values.is_empty(),
                    },
                ),
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
            .requests()
            .map(|request| {
                (
                    request.mount.source_spelling.clone(),
                    request.mount.guest.display().to_string(),
                    matches!(request.mount.policy, MountPolicy::BindReadOnly { .. }),
                )
            })
            .collect()
    }

    /// The defaults list's declarations, or nothing. A test fixture helper: a
    /// launch also carries the tool facet, so production reads `defaults()`.
    fn defaults_requests(mounts: &UserMounts) -> Vec<&MountRequest> {
        mounts
            .defaults()
            .map(|list| list.requests().collect())
            .unwrap_or_default()
    }

    fn names(mounts: &UserMounts) -> Vec<(Spelling, String)> {
        defaults_requests(mounts)
            .into_iter()
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
            assert!(mounts.defaults().is_none(), "{body}");
            assert!(!mounts.has_defaults(), "{body}");
        }
        let mounts = defaults_and_sets("[]", "empty = []\n").unwrap();
        assert!(mounts.has_defaults());
        assert!(mounts.defaults().is_some_and(|list| list.is_empty()));
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
            requests.requests().next().unwrap().origin,
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
            merged
                .defaults()
                .expect("defaults exist")
                .requests()
                .next()
                .unwrap()
                .origin,
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
        assert!(mounts.defaults().is_none());
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
        let mut work = MountExpansionWork {
            used: MAX_MOUNT_SET_EXPANSION_WORK,
        };
        assert!(work.admit(ExpansionStage::SetClosure).is_err());
        assert_eq!(work.used, MAX_MOUNT_SET_EXPANSION_WORK);
        // A counter one below the limit admits exactly one more visit.
        let mut work = MountExpansionWork {
            used: MAX_MOUNT_SET_EXPANSION_WORK - 1,
        };
        assert!(work.admit(ExpansionStage::SetClosure).is_ok());
        assert_eq!(work.used, MAX_MOUNT_SET_EXPANSION_WORK);
        assert!(work.admit(ExpansionStage::SetClosure).is_err());
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
    /// may hold thousands of leaves, so a per-leaf `String` copy turns one 40 KB key
    /// into 80 MB of retained provenance — below both the file limit and the
    /// leaf-visit budget. The oracle is the allocation itself: `Arc::ptr_eq` across
    /// leaves and across a clone, and a strong count only one shared name can reach.
    ///
    /// The leaves are distinct guest paths (plus one exact duplicate, so the merge
    /// is still exercised) because a retained model holds a handle per *surviving*
    /// leaf: with identical declarations the merge would collapse them and the
    /// strong count would measure the deduplication instead of the sharing.
    #[test]
    fn mount_set_key_is_stored_once_across_leaves_and_clones() {
        const LEAVES: usize = 2_000;
        let key = "a".repeat(40_000);
        let mut entries: Vec<String> = (0..LEAVES)
            .map(|index| format!("\"/h:/g{index:05}:ro\""))
            .collect();
        // One exact duplicate of the first leaf: the merge keeps the first and
        // drops this one, so the count below is `LEAVES`, not `LEAVES + 1`.
        entries.push("\"/h:/g00000:ro\"".to_string());
        let body = format!("[mount_sets]\n{key} = [{}]\n", entries.join(", "));
        assert!(
            body.len() < 1 << 20,
            "the fixture stays inside the file bound"
        );
        let mounts = parse_document(&body).expect("a long key is valid");
        let name = MountSetName::parse(&key).unwrap();
        let selected = mounts.requests_for_set(&name).expect("the set exists");
        assert_eq!(selected.len(), LEAVES, "the exact duplicate merges away");

        let shared = |request: &MountRequest| match &request.origin {
            MountOrigin::UserSet { set, .. } => Arc::clone(set),
            other => panic!("a set leaf must carry a set origin: {other:?}"),
        };
        let leaf = |index: usize| selected.requests().nth(index).expect("leaf exists");
        let first = shared(leaf(0));
        let second = shared(leaf(1));
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
        // same allocations rather than copy the key — or even re-copy the leaf
        // handles — again.
        let before = Arc::strong_count(&first);
        let cloned = mounts.clone();
        let again = cloned.requests_for_set(&name).expect("the set exists");
        assert!(
            Arc::ptr_eq(
                &first,
                &shared(again.requests().next().expect("leaf exists"))
            ),
            "a clone must share the name"
        );
        assert_eq!(
            Arc::strong_count(&first),
            before,
            "cloning the model must not duplicate the leaf handles at all"
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
        assert!(mounts.defaults().is_some_and(|list| list.is_empty()));

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
                MountOrigin::UserConfig { index, .. }
                | MountOrigin::UserSet { index, .. }
                | MountOrigin::UserTool { index, .. } => *index,
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

    /// A fold refusal reduced to the fact both routes must agree on.
    fn index_refusal(error: &UserMountsError) -> Refusal {
        match error {
            UserMountsError::Conflict {
                site: EntrySite::ToolEntry { index, .. },
                ..
            } => Refusal::Conflict { second: *index },
            _ => Refusal::Unexpected,
        }
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
                    .requests()
                    .cloned()
                    .collect()
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

    /// Tool lists reuse the same selector, the same `~/` spelling rule and the
    /// same compiled set closures as the defaults list, and an inherited set leaf
    /// keeps the origin of the set that declared it.
    #[test]
    fn tool_lists_use_cached_set_closures_and_keep_leaf_origins() {
        let document = "[mount_sets]\n\
                        diamond = [\"nested\", \"nested\"]\n\
                        nested = [\"/h/n:/n:ro\", \"/h/n2:/n2:ro\"]\n\
                        empty = []\n\
                        [[tools]]\nname = \"a\"\ncommand = \"a\"\n\
                        mounts = [\"diamond\", \"/h/o:/o:rw\", \"~/home:/home:ro\"]\n";
        let mounts = parse_document(document).unwrap();
        // The set's compiled closure is what the tool list expands, so the two
        // agree declaration for declaration — a second expansion path would show
        // up as a difference here.
        let compiled = mounts.requests_for_set(&set("diamond")).expect("declared");
        let mut mounts = mounts;
        let list = mounts.take_tool_lists().get(0);
        assert_eq!(
            list.requests()
                .take(2)
                .map(|request| request.mount.guest.display().to_string())
                .collect::<Vec<_>>(),
            ["/n", "/n2",]
                .iter()
                .map(|guest| guest.to_string())
                .collect::<Vec<_>>()
        );
        for (from_tool, from_set) in list.requests().zip(compiled.requests()) {
            assert!(
                same_declaration(&from_tool.mount, &from_set.mount),
                "the tool list must reuse the compiled closure"
            );
            assert_eq!(from_tool.origin, from_set.origin);
        }
        // The `~/` spelling expands against the captured home, exactly as in the
        // defaults list and inside a set.
        assert_eq!(
            list.requests()
                .map(|request| request.mount.source_spelling.clone())
                .collect::<Vec<_>>(),
            [
                Spelling::new("/h/n"),
                Spelling::new("/h/n2"),
                Spelling::new("/h/o"),
                Spelling::new("/home/graph/home"),
            ]
        );
        // The direct leaves keep the tool site; the inherited ones the set's.
        let origins: Vec<String> = list
            .requests()
            .map(|request| request.origin.to_string())
            .collect();
        assert!(
            origins[0].starts_with("mount_sets[\"nested\"][0]"),
            "{origins:?}"
        );
        assert!(
            origins[1].starts_with("mount_sets[\"nested\"][1]"),
            "{origins:?}"
        );
        assert!(origins[2].starts_with("tools[0].mounts[1]"), "{origins:?}");
        assert!(origins[3].starts_with("tools[0].mounts[2]"), "{origins:?}");

        // A direct tool list shares the defaults list's selector: a bare name is a
        // set, and the same name with `:ro` is refused as a modifier.
        assert_eq!(
            rendered(parse_document(
                "[[tools]]\nname = \"a\"\ncommand = \"a\"\nmounts = [\"empty:ro\"]\n"
            )),
            "tools[0].mounts[0]: a mount-set reference is a bare name; modes, a guest path and \
             exclusions belong to the paths declared inside the set"
        );
        assert_eq!(
            rendered(parse_document(
                "[[tools]]\nname = \"a\"\ncommand = \"a\"\nmounts = [\"modified\"]\n"
            )),
            "tools[0].mounts[0]: unknown mount set name"
        );
        // An empty set costs no leaf and selects nothing.
        let mut mounts = parse_document(
            "[mount_sets]\nempty = []\n[[tools]]\nname = \"a\"\ncommand = \"a\"\n\
             mounts = [\"empty\"]\n",
        )
        .unwrap();
        assert!(mounts.take_tool_lists().get(0).is_empty());
    }

    /// The shared budget continues across set compilation, tool lists **and** the
    /// launch-time fold, and never resets per list, per tool or per launch.
    #[test]
    fn mount_budget_is_shared_by_sets_tool_lists_and_launch_folds() {
        // Sets first: one set with two leaves costs 2.
        let document = "[mount_sets]\ns = [\"/h/a:/a:ro\", \"/h/b:/b:ro\"]\n\
                        [[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = [\"s\", \"/h/c:/c:ro\"]\n";
        let mounts = parse_document(document).unwrap();
        // 2 for the set closure + 3 for the tool list (2 set leaves + 1 direct).
        assert_eq!(mounts.expansion_work(), 5);
        let mut mounts = mounts;
        let lists = mounts.take_tool_lists();
        let work = mounts.continuing_work();
        // The fold re-admits the tool list's three leaves: 5 + 3 = 8.
        let mut work = work;
        let folded = merge_tool_mounts([&lists.get(0)], &mut work).unwrap();
        assert_eq!(work.used(), 8);
        assert_eq!(folded.len(), 3);

        // Two launches of one entry each re-fold: the counter is continued, not
        // cloned per launch.
        let mut work = mounts.continuing_work();
        merge_tool_mounts([&lists.get(0)], &mut work).unwrap();
        merge_tool_mounts([&lists.get(0)], &mut work).unwrap();
        assert_eq!(work.used(), 5 + 3 + 3);
    }

    /// Many tools selecting one large set are bounded by the shared budget: the
    /// same leaf payloads are re-admitted per list rather than escaping the cap by
    /// being cached once.
    #[test]
    fn many_tools_selecting_one_large_set_are_budgeted() {
        const LEAVES: usize = 2_000;
        let mut body = String::from("[mount_sets]\nbig = [\n");
        for index in 0..LEAVES {
            body.push_str(&format!("\"/h/{index:05}:/g{index:05}:ro\",\n"));
        }
        body.push_str("]\n");
        // 40 tools each selecting the same set: 2,000 + 40*2,000 admissions, so
        // the file is refused long before it finishes.
        for index in 0..40 {
            body.push_str(&format!(
                "[[tools]]\nname = \"t{index:02}\"\ncommand = \"t\"\nmounts = [\"big\"]\n"
            ));
        }
        assert!(
            body.len() < 1 << 20,
            "the fixture stays inside the file bound"
        );
        assert_eq!(
            rendered(parse_document(&body)),
            "mounts: expansion work exceeds limit of 65536 leaf visits across mount sets and \
             tool mounts"
        );
        // The refusal is at the shared cap, not a per-list one: one tool alone is
        // comfortably inside it.
        let mut one = String::from("[mount_sets]\nbig = [\n");
        for index in 0..LEAVES {
            one.push_str(&format!("\"/h/{index:05}:/g{index:05}:ro\",\n"));
        }
        one.push_str("]\n[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = [\"big\"]\n");
        assert!(parse_document(&one).is_ok());
    }

    /// Wide empty-child fan-out **inside tool lists** stays linear: one tracker for
    /// every list in the file, so a tool-scoped map costs no per-list allocation and
    /// no O(number-of-sets) reset.
    #[test]
    fn empty_set_fanout_across_tool_lists_uses_indexed_tracking() {
        const CHILDREN: usize = 5_000;
        let mut body = String::from("[mount_sets]\n");
        for index in 0..CHILDREN {
            body.push_str(&format!("c{index:05} = []\n"));
        }
        let references = |count: usize| {
            (0..count)
                .map(|index| format!("\"c{index:05}\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        body.push_str(&format!("parent = [{}]\n", references(CHILDREN)));
        // Two tool lists each naming the parent once: the parent's closure is
        // empty, so no leaf visit is spent — the count is pure reference work.
        body.push_str(
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\nmounts = [\"parent\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\nmounts = [\"parent\"]\n",
        );
        let mounts = parse_document(&body).expect("the fan-out is valid");
        // parent's own compile (CHILDREN) + one admission per tool list = +2.
        assert_eq!(
            mounts.reference_admissions(),
            CHILDREN + 2,
            "every traversal must reach the one indexed tracker"
        );
        assert_eq!(mounts.expansion_work(), 0, "empty children spend no leaf");
        let mut mounts = mounts;
        let lists = mounts.take_tool_lists();
        assert!(lists.get(0).is_empty());
        assert!(lists.get(1).is_empty());
    }

    /// The indexed tool-closure merge agrees with the existing `claim` over tool
    /// lists: success, refusal, order and first-kept origin.
    ///
    /// A list that a single tool declares is validated at load, so it can only be
    /// internally valid here; a genuine cross-list conflict needs two tools, which
    /// is exactly the case the closure fold exists for.
    #[test]
    fn tool_mount_indexed_merge_matches_common_claim() {
        let valid: [&[&str]; 5] = [
            &["/a:/g"],
            &["/a:/g", "/a:/g"],
            &["/a:/g//./x:ro", "/a:/g/x:ro"],
            &["~/a:/g:ro", "/home/graph/a:/g:ro"],
            &["/a:/a", "/b:/b", "/c:/c:fork"],
        ];
        for list in valid {
            let entries = list
                .iter()
                .map(|entry| format!("\"{entry}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let body = format!("[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = [{entries}]\n");
            let mut mounts = parse_document(&body).expect("the tool list parses alone");
            let tool = mounts.take_tool_lists().get(0);
            let mut work = mounts.continuing_work();
            let kept: Vec<MountRequest> = merge_tool_mounts([&tool], &mut work)
                .expect("a valid list folds")
                .requests()
                .cloned()
                .collect();
            let claimed = ordinary_claim(list).expect("the same list claims");
            assert_eq!(describe(&kept), describe(&claimed), "{list:?}");
            assert_eq!(first_kept(&kept), first_kept(&claimed), "{list:?}");
        }

        // Cross-list conflicts: each declaration is valid in its own list, so only
        // the launch that selects both can be refused — and both routes must agree
        // on the decision and on which pair it was.
        for (first, second) in [
            ("/a:/g:ro", "/a:/g:rw"),
            ("/a:/g:fork", "/a:/g"),
            ("/a:/g:fork:exclude=x", "/a:/g:fork"),
            ("/a:/g:ro", "/b:/g:ro"),
        ] {
            let body = format!(
                "[[tools]]\nname = \"a\"\ncommand = \"a\"\nmounts = [\"{first}\"]\n\
                 [[tools]]\nname = \"b\"\ncommand = \"b\"\nmounts = [\"{second}\"]\n"
            );
            let mut mounts = parse_document(&body).expect("each list parses alone");
            let lists = mounts.take_tool_lists();
            let mut work = mounts.continuing_work();
            let folded = merge_tool_mounts([&lists.get(0), &lists.get(1)], &mut work);
            let claimed = ordinary_claim(&[first, second]);
            match (folded, claimed) {
                (Ok(folded), Ok(claimed)) => {
                    let kept: Vec<MountRequest> = folded.requests().cloned().collect();
                    assert_eq!(describe(&kept), describe(&claimed), "{first} {second}");
                }
                (Err(folded), Err(_)) => {
                    assert_eq!(
                        index_refusal(&folded),
                        Refusal::Conflict { second: 0 },
                        "{first} {second}: the second list's first entry is refused"
                    );
                }
                (folded, claimed) => panic!(
                    "{first} {second}: fold {} but claim {}",
                    folded.is_ok(),
                    claimed.is_ok()
                ),
            }
        }
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
