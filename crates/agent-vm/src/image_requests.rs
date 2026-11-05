//! Image-declared network requests (ADR-0060): the labels an image carries about
//! the hosts its software contacts, reported once per selected reference and
//! then as changes.
//!
//! These are requests in ADR-0039's sense, from a new source. The data-flow
//! invariant is the same and is the reason this module exists separately: the
//! only consumer of a parsed request is rendering, and the store below is
//! display state. No value derived from a label reaches egress policy, DNS, TLS
//! interception, credentials, the guest environment, the command, the task
//! description or provisioning.
//!
//! Two rules shape the output. Coverage filters **only** unmet additions, so a
//! removal or an ignored-label line is never suppressed (R7). And a group's
//! recorded set advances **only** when that group's own line printed, so a
//! change the user has not seen stays pending (R18).
mod baseline;

use crate::boot_image::ImageLabel;
use crate::network_requests::{
    GRANT_HINT, MAX_NETWORK_REQUESTS, NetworkRequest, NetworkRequestError, NetworkRequests,
    NetworkRequestsError, SCOPE,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use vstd::prelude::*;

/// Every request label key starts with this. That it is exactly 30 bytes is what
/// makes `rest.get(..6)` a byte-prefix test rather than a character test.
pub(crate) const REQUEST_LABEL_PREFIX: &str = "org.agent-vm.network-requests.";
/// The word after the prefix, byte-exact and case-sensitive (R2).
const IMAGE_WORD: &str = "image.";
const AGENT_WORD: &str = "agent.";

verus! {
/// The label budget (R4): only valid-kind labels are admitted, in key byte
/// order, and the first [`MAX_REQUEST_LABELS`] are parsed. The bound is
/// ADR-0060's; ADR-0018 records the contract.
pub(crate) const MAX_REQUEST_LABELS: usize = 64;

pub(crate) open spec fn request_label_count_within_limit_spec(count: usize) -> bool { count <= MAX_REQUEST_LABELS }
pub(crate) fn request_label_count_within_limit(count: usize) -> (ok: bool)
    ensures ok == request_label_count_within_limit_spec(count),
{
    count <= MAX_REQUEST_LABELS
}

/// What [`classify_key`] measures about one label key. Named fields rather than
/// four booleans, so an argument swap cannot invert the decision.
pub(crate) struct RequestLabelFacts {
    pub(crate) under_prefix: bool,
    pub(crate) image_word: bool,
    pub(crate) agent_word: bool,
    pub(crate) name_safe: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RequestLabelKind {
    NotRequest,
    Image,
    Agent,
    Unrecognized,
}

/// The spec is a `match` over the facts while the executable form is an
/// `if`/`else` chain, so the two texts can never be the same bytes: the mutation
/// anchor for the executable body stays unique in this file.
pub(crate) open spec fn request_label_kind_spec(f: RequestLabelFacts) -> RequestLabelKind {
    match (f.under_prefix, f.image_word && f.name_safe, f.agent_word && f.name_safe) {
        (false, _, _) => RequestLabelKind::NotRequest,
        (true, true, _) => RequestLabelKind::Image,
        (true, false, true) => RequestLabelKind::Agent,
        (true, false, false) => RequestLabelKind::Unrecognized,
    }
}

/// Precedence over untrusted key bytes (R2). The two words are distinct, so the
/// precondition holds for every key [`classify_key`] can build.
pub(crate) fn request_label_kind(f: RequestLabelFacts) -> (k: RequestLabelKind)
    requires !(f.image_word && f.agent_word),
    ensures k == request_label_kind_spec(f),
{
    if !f.under_prefix {
        RequestLabelKind::NotRequest
    } else if f.image_word && f.name_safe {
        RequestLabelKind::Image
    } else if f.agent_word && f.name_safe {
        RequestLabelKind::Agent
    } else {
        RequestLabelKind::Unrecognized
    }
}
}

/// A request label `NAME` that passed the byte rule, so rendering it cannot
/// carry a control byte, a newline or a byte of a rejected key.
///
/// The rule is `pi_credential_inspection`'s provider-identifier kernel: one
/// byte shape, one proof, and the launcher's existing 1–64 byte alphabet
/// (R2, ADR-0060).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LabelName(String);

/// The two key words. Declared in **key byte order** (`agent.` sorts before
/// `image.`) so a `BTreeMap`/`BTreeSet` over [`LabelKey`] iterates the order R8
/// prints invalid-label lines in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LabelWord {
    Agent,
    Image,
}

impl LabelWord {
    fn text(self) -> &'static str {
        match self {
            Self::Agent => AGENT_WORD,
            Self::Image => IMAGE_WORD,
        }
    }
}

/// A refused label, addressed by its validated key only. Rendering this is safe
/// by construction: the word is one of two literals and the name passed the
/// NAME byte rule (R10).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LabelKey {
    word: LabelWord,
    name: LabelName,
}

impl LabelKey {
    /// `org.agent-vm.network-requests.agent.codex` — the validatable form R8's
    /// invalid-label line names.
    fn text(&self) -> String {
        format!("{REQUEST_LABEL_PREFIX}{}{}", self.word.text(), self.name.0)
    }

    /// `agent.codex` — the wire form, without the invariant prefix.
    fn address(&self) -> String {
        format!("{}{}", self.word.text(), self.name.0)
    }
}

/// The closed reason set plus an optional field position. Both halves are fixed
/// text, so a refusal detail never carries a byte of the rejected value (R10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LabelRefusal {
    position: Option<usize>,
    reason: NetworkRequestError,
}

impl fmt::Display for LabelRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.position {
            Some(position) => write!(formatter, "entry {position}: {}", self.reason),
            None => formatter.write_str(&format!("{}", self.reason)),
        }
    }
}

/// One group of requests. Derived `Ord` is render order: *every launch* first,
/// then agent names in byte order.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RequestGroup {
    EveryLaunch,
    Agent(LabelName),
}

impl fmt::Display for RequestGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EveryLaunch => formatter.write_str("for every launch"),
            Self::Agent(name) => write!(formatter, "for {}", name.0),
        }
    }
}

/// The recorded sets of one reference; a group missing from the map has no
/// recorded set and uses the first form (R5).
pub(crate) type Groups = BTreeMap<RequestGroup, BTreeSet<NetworkRequest>>;

/// What an entry recorded about the labels it could not use (R8). Counts, never
/// raw keys: an unrecognized key cannot be named safely.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct IgnoredFacts {
    invalid: BTreeSet<LabelKey>,
    unrecognized: u64,
    excess: u64,
}

/// Everything the selected image's request labels declare, after admission.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeclaredImageRequests {
    groups: Groups,
    invalid: BTreeMap<LabelKey, LabelRefusal>,
    unrecognized: u64,
    excess: u64,
}

impl DeclaredImageRequests {
    /// Classify, admit and parse every label. Ordering by key bytes is the
    /// admission order R4 requires, so the map cannot be iterated in another.
    pub(crate) fn from_labels<'a>(labels: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let ordered: BTreeMap<&str, &str> = labels.into_iter().collect();
        let mut declared = Self::default();
        let mut admitted: usize = 0;
        for (key, value) in ordered {
            let (word, name) = match classify_key(key) {
                ClassifiedKey::NotRequest => continue,
                // Counted whatever its position, and it consumes no budget, so
                // early junk keys cannot crowd a valid group out (R4).
                ClassifiedKey::Unrecognized => {
                    declared.unrecognized += 1;
                    continue;
                }
                ClassifiedKey::Image(name) => (LabelWord::Image, name),
                ClassifiedKey::Agent(name) => (LabelWord::Agent, name),
            };
            if !request_label_count_within_limit(admitted + 1) {
                declared.excess += 1;
                continue;
            }
            admitted += 1;
            match parse_value(value) {
                Ok(requests) => {
                    let group = match word {
                        LabelWord::Image => RequestGroup::EveryLaunch,
                        LabelWord::Agent => RequestGroup::Agent(name.clone()),
                    };
                    declared.groups.entry(group).or_default().extend(requests);
                }
                Err(error) => {
                    declared.invalid.insert(
                        LabelKey { word, name },
                        LabelRefusal {
                            position: error.position(),
                            reason: error.reason(),
                        },
                    );
                }
            }
        }
        declared
    }

    pub(crate) fn groups(&self) -> &Groups {
        &self.groups
    }
    pub(crate) fn ignored_facts(&self) -> IgnoredFacts {
        IgnoredFacts {
            invalid: self.invalid.keys().cloned().collect(),
            unrecognized: self.unrecognized,
            excess: self.excess,
        }
    }

    /// R19's silent case: no group, no refused label and neither count.
    fn declares_nothing(&self) -> bool {
        self.groups.is_empty()
            && self.invalid.is_empty()
            && self.unrecognized == 0
            && self.excess == 0
    }
}

/// One key's classification. The label's address is carried only for a
/// valid-kind key, so no invalid [`LabelName`] is ever constructed.
enum ClassifiedKey {
    NotRequest,
    Unrecognized,
    Image(LabelName),
    Agent(LabelName),
}

impl ClassifiedKey {
    #[cfg(test)]
    fn kind(&self) -> RequestLabelKind {
        match self {
            Self::NotRequest => RequestLabelKind::NotRequest,
            Self::Unrecognized => RequestLabelKind::Unrecognized,
            Self::Image(_) => RequestLabelKind::Image,
            Self::Agent(_) => RequestLabelKind::Agent,
        }
    }
}

/// The trusted adapter around [`request_label_kind`] (ADR-0018). `str::get` is
/// panic-free on a non-boundary, which is what keeps a multibyte key a refusal
/// rather than a crash.
fn classify_key(key: &str) -> ClassifiedKey {
    let rest = key.strip_prefix(REQUEST_LABEL_PREFIX);
    let word = rest.and_then(|rest| rest.get(..6));
    let name = rest.and_then(|rest| rest.get(6..)).unwrap_or("");
    let kind = request_label_kind(RequestLabelFacts {
        under_prefix: rest.is_some(),
        image_word: word == Some(IMAGE_WORD),
        agent_word: word == Some(AGENT_WORD),
        name_safe: crate::pi_credential_inspection::provider_id_is_safe_bytes(name.as_bytes()),
    });
    match kind {
        RequestLabelKind::NotRequest => ClassifiedKey::NotRequest,
        RequestLabelKind::Unrecognized => ClassifiedKey::Unrecognized,
        RequestLabelKind::Image => ClassifiedKey::Image(LabelName(name.to_owned())),
        RequestLabelKind::Agent => ClassifiedKey::Agent(LabelName(name.to_owned())),
    }
}

/// The launcher's existing request grammar, unchanged (R3): an empty value is a
/// group that contacts nothing, and everything else satisfies the same limits
/// and refusals a tool declaration does.
fn parse_value(value: &str) -> Result<BTreeSet<NetworkRequest>, NetworkRequestsError> {
    if value.is_empty() {
        return Ok(BTreeSet::new());
    }
    // `take(MAX_NETWORK_REQUESTS + 1)`: the parser's own limit reports TooMany
    // without collecting an unbounded split of a hostile value.
    let fields: Vec<String> = value
        .split(',')
        .take(MAX_NETWORK_REQUESTS + 1)
        .map(str::to_owned)
        .collect();
    NetworkRequests::parse(&fields).map(|requests| requests.iter().cloned().collect())
}

/// The one place coverage touches the report (R7). Removals never pass through
/// here, and neither do ignored-label or count lines.
fn unmet_additions<'a>(
    added: impl Iterator<Item = &'a NetworkRequest>,
    covered: &dyn Fn(&NetworkRequest) -> bool,
) -> Vec<&'a NetworkRequest> {
    added.filter(|request| !covered(request)).collect()
}

/// The selection's store key and the labels of the content the launch boots.
pub(crate) struct LabelSource<'a> {
    /// The canonical **selected** reference (R15): not the approved digest, so a
    /// tag keeps one entry across refreshes.
    pub(crate) selection: String,
    pub(crate) labels: &'a HashMap<String, String>,
}

struct Composed {
    lines: Vec<String>,
    /// The groups whose own line rendered. This set, not a launch-wide flag, is
    /// what the write rule advances (R18).
    printed: BTreeSet<RequestGroup>,
}

fn compose(
    recorded: &Groups,
    recorded_ignored: Option<&IgnoredFacts>,
    current: &DeclaredImageRequests,
    display: &str,
    covered: &dyn Fn(&NetworkRequest) -> bool,
) -> Composed {
    let prefix = format!("==> Image network requests ({display})");
    let mut lines = Vec::new();
    let mut printed = BTreeSet::new();
    let mut shows_unmet = false;
    let absent = BTreeSet::new();
    let groups: BTreeSet<&RequestGroup> = recorded.keys().chain(current.groups.keys()).collect();
    for group in groups {
        let now = current.groups.get(group).unwrap_or(&absent);
        let mut terms: Vec<String> = Vec::new();
        let line = match recorded.get(group) {
            None => {
                let unmet = unmet_additions(now.iter(), covered);
                if unmet.is_empty() {
                    continue;
                }
                shows_unmet = true;
                for request in unmet {
                    terms.push(request.to_string());
                }
                format!("{prefix}: {group} {}", terms.join(", "))
            }
            Some(base) => {
                // Full sets, compared before coverage: an addition that is
                // covered is not shown, but a removal always is.
                let unmet = unmet_additions(now.difference(base), covered);
                let removed: Vec<&NetworkRequest> = base.difference(now).collect();
                if unmet.is_empty() && removed.is_empty() {
                    continue;
                }
                shows_unmet |= !unmet.is_empty();
                for request in unmet {
                    terms.push(format!("+{request}"));
                }
                for request in removed {
                    terms.push(format!("-{request}"));
                }
                format!("{prefix} changed: {group} {}", terms.join(", "))
            }
        };
        printed.insert(group.clone());
        lines.push(line);
    }
    let nothing = IgnoredFacts::default();
    let shown = recorded_ignored.unwrap_or(&nothing);
    for (key, refusal) in &current.invalid {
        if !shown.invalid.contains(key) {
            lines.push(format!(
                "{prefix}: ignored invalid label {} ({refusal})",
                key.text()
            ));
        }
    }
    if current.unrecognized > 0 && current.unrecognized != shown.unrecognized {
        lines.push(format!(
            "{prefix}: {}",
            unrecognized_line(current.unrecognized)
        ));
    }
    if current.excess > 0 && current.excess != shown.excess {
        lines.push(format!(
            "{prefix}: {}",
            excess_line(current.excess, ExcessWording::Launch)
        ));
    }
    if shows_unmet {
        lines.push(format!(
            "==>   image requests above are not covered by this launch's {SCOPE}; they never grant \
             access and the launch continues; each image reference is reported once, then as changes"
        ));
        lines.push(GRANT_HINT.to_owned());
    }
    Composed { lines, printed }
}

/// `1 label` / `2 labels`, from one place: the count lines differ only in what
/// they count.
fn with_plural(count: u64, singular: &str) -> String {
    if count == 1 {
        singular.to_owned()
    } else {
        format!("{singular}s")
    }
}

fn unrecognized_line(count: u64) -> String {
    format!(
        "ignored {count} {} under {REQUEST_LABEL_PREFIX} whose key is not image.NAME or agent.NAME",
        with_plural(count, "label")
    )
}

/// Which sentence the excess count needs. A launch says its report is partial; a
/// diagnostic may not claim the picture above it is complete (R20).
#[derive(Clone, Copy)]
enum ExcessWording {
    Launch,
    Doctor,
}

fn excess_line(count: u64, wording: ExcessWording) -> String {
    let limit = MAX_REQUEST_LABELS;
    let words = with_plural(count, "request label");
    match wording {
        ExcessWording::Launch => format!(
            "ignored {count} {words} beyond the first {limit} in key order; this report is partial"
        ),
        ExcessWording::Doctor => format!(
            "ignored {count} {words} beyond the first {limit} in key order; the requests above are \
             incomplete"
        ),
    }
}

/// Print this launch's image request report, then record what was shown.
///
/// Never fails on labels or on the store: the only error returned is `emit`'s
/// own, because a report that could not be shown must not be recorded as shown
/// (R13, R25).
pub(crate) fn report_before_boot(
    source: LabelSource<'_>,
    display: &ImageLabel,
    covered: impl Fn(&NetworkRequest) -> bool,
    emit: impl FnMut(String) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let current = DeclaredImageRequests::from_labels(
        source.labels.iter().map(|(k, v)| (k.as_str(), v.as_str())),
    );
    let store = baseline::Store::host();
    let loaded = store.load();
    let composed = {
        let recorded = loaded.find(&source.selection);
        // R19: no labels and no entry for this reference is silent, writes
        // nothing and creates no store file.
        if current.declares_nothing() && recorded.is_none() {
            return Ok(());
        }
        let no_groups = Groups::new();
        compose(
            recorded.map_or(&no_groups, |entry| &entry.baseline),
            recorded.map(|entry| &entry.ignored),
            &current,
            display.text(),
            &covered,
        )
    };
    // Computed before the lines are consumed: a failed emit must leave the write
    // rule seeing "nothing was shown" (R25).
    let any_shown = !composed.lines.is_empty();
    let mut emit = emit;
    for line in composed.lines {
        emit(line)?;
    }
    let Some(entries) = baseline::next_entries(
        loaded.entries,
        &source.selection,
        &current,
        &composed.printed,
        any_shown,
    ) else {
        return Ok(());
    };
    // why: the store is display state, so a refused or failed write changes
    // nothing except that this report repeats next launch — the designed
    // degradation (R13). Returning it would make a notice fatal.
    match store.save(loaded.disposition, &entries) {
        Ok(_) | Err(_) => {}
    }
    Ok(())
}

/// What doctor found in the image cache for the selection (R20). A best-effort
/// observation, not a re-validation: doctor never acquires, contacts a registry,
/// writes, or reads the display store.
pub(crate) enum CachedLabels {
    LocalPath,
    NotCached,
    Unreadable,
    ApprovalUnreadable,
    LocationUnknown,
    Present(HashMap<String, String>),
}

/// The `==> image network requests` section: every admitted group in full,
/// because doctor has no grants to compare against.
pub(crate) fn doctor_section(cached: &CachedLabels) -> String {
    let mut out = String::from("==> image network requests\n");
    let labels = match cached {
        CachedLabels::LocalPath => {
            out.push_str("a local rootfs or disk path declares no requests");
            return out;
        }
        CachedLabels::NotCached => {
            out.push_str("not cached; doctor does not acquire images");
            return out;
        }
        CachedLabels::Unreadable => {
            out.push_str("unknown: the cached image metadata could not be read");
            return out;
        }
        CachedLabels::ApprovalUnreadable => {
            out.push_str("unknown: the image approval record could not be read");
            return out;
        }
        CachedLabels::LocationUnknown => {
            out.push_str("unknown: the image cache location could not be determined");
            return out;
        }
        CachedLabels::Present(labels) => labels,
    };
    let declared =
        DeclaredImageRequests::from_labels(labels.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    if declared.declares_nothing() {
        out.push_str("the selected image declares no requests");
        return out;
    }
    for (group, requests) in &declared.groups {
        if requests.is_empty() {
            out.push_str(&format!("{group} (declares no requests)\n"));
        } else {
            let rendered: Vec<String> = requests.iter().map(ToString::to_string).collect();
            out.push_str(&format!("{group} {}\n", rendered.join(", ")));
        }
    }
    for (key, refusal) in &declared.invalid {
        out.push_str(&format!(
            "ignored invalid label {} ({refusal})\n",
            key.text()
        ));
    }
    if declared.unrecognized > 0 {
        out.push_str(&format!("{}\n", unrecognized_line(declared.unrecognized)));
    }
    if declared.excess > 0 {
        out.push_str(&format!(
            "{}\n",
            excess_line(declared.excess, ExcessWording::Doctor)
        ));
    }
    out.push_str(
        "requests never grant access; a launch reports those its grants do not cover, once per \
         image reference, then as changes",
    );
    out
}

#[cfg(test)]
mod tests;
