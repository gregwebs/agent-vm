//! The image-request display store (ADR-0060): one entry per canonical selected
//! reference, holding the set last **shown** for each group.
//!
//! Display state, never authority. Every failure path here degrades to "report
//! in full again": a damaged file is treated as holding no entries, a write
//! failure is swallowed by the caller, and a path that is not a regular file is
//! never replaced. Nothing in this module may fail a launch (R13).
use super::{
    DeclaredImageRequests, Groups, IgnoredFacts, LabelKey, LabelName, LabelWord, RequestGroup,
};
use crate::network_requests::{NetworkRequest, NetworkRequests};
use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use vstd::prelude::*;

/// The store file under the launcher's existing state root (R14).
pub(super) const FILE: &str = "image-network-requests.json";

/// R18(d): at most 64 groups are current, so anything past this is an empty
/// recorded set of a group that has since vanished from the labels.
pub(super) const MAX_RECORDED_GROUPS: usize = 128;

/// A reference field's bound, matching the approval key's (R16).
const MAX_REFERENCE_BYTES: usize = 4096;

/// Every request an entry can hold: 64 admitted labels of at most 64 requests
/// (R4, R3).
const MAX_ENTRY_REQUESTS: usize =
    super::MAX_REQUEST_LABELS * crate::network_requests::MAX_NETWORK_REQUESTS;

const STORE_VERSION: u32 = 1;

verus! {
/// R17: at most this many references, and at most this many bytes of exact
/// serialized output.
pub(crate) const MAX_BASELINE_REFERENCES: usize = 256;
pub(crate) const MAX_BASELINE_BYTES: usize = 8 * 1024 * 1024;

pub(crate) open spec fn baseline_store_admits_spec(count: usize, bytes: usize) -> bool { count <= MAX_BASELINE_REFERENCES && bytes <= MAX_BASELINE_BYTES }
/// Admitted iff both bounds hold. The predicate is proved over the numbers it is
/// given; it cannot repair a wrong measurement, which is why [`encode`] measures
/// the exact buffer it writes and the byte-bound tests assert the file's length.
pub(crate) fn baseline_store_admits(count: usize, bytes: usize) -> (ok: bool)
    ensures ok == baseline_store_admits_spec(count, bytes),
{
    count <= MAX_BASELINE_REFERENCES && bytes <= MAX_BASELINE_BYTES
}
}

/// Whether this path may be replaced (R26).
///
/// `host_paths::atomic_write` renames over the final name, which **replaces** an
/// existing symlink rather than following or refusing it, so the refusal has to
/// happen here, before any write. A directory is refused too even though the
/// rename would fail on its own: one rule, one place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Disposition {
    Writable,
    NonReplaceable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathState {
    Absent,
    Regular,
    NonReplaceable,
}

/// `symlink_metadata` never follows a final symlink. Anything that is neither
/// absent nor a regular file — a symlink of any kind, a directory, a FIFO, a
/// socket, a device — is never replaced, and an examination that fails for any
/// reason other than absence is treated the same way.
fn examine(path: &Path) -> PathState {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => PathState::Regular,
        Ok(_) => PathState::NonReplaceable,
        Err(error) if error.kind() == ErrorKind::NotFound => PathState::Absent,
        Err(_) => PathState::NonReplaceable,
    }
}

/// One reference's recorded facts (R16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    /// The canonical **selected** reference. Compared, never rendered.
    pub(super) reference: String,
    /// The set last shown for each group. A group absent from this map has no
    /// recorded set (first form next time); a group mapped to an empty set had
    /// its line show it vanishing, so its reappearance is a `+`.
    pub(super) baseline: Groups,
    pub(super) ignored: IgnoredFacts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Saved {
    Written,
    /// The path is not replaceable, so it was left exactly as it was.
    Refused,
    /// This entry could not be encoded within the store's bounds. Never written
    /// rather than written oversized: the next read would call it damaged.
    Unadmittable,
}

pub(super) struct Loaded {
    pub(super) entries: Vec<Entry>,
    pub(super) disposition: Disposition,
}

impl Loaded {
    pub(super) fn find(&self, reference: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.reference == reference)
    }
}

/// The store location, or `None` when the state root is unavailable — which is
/// also "never replace anything".
pub(super) struct Store {
    path: Option<PathBuf>,
}

impl Store {
    pub(super) fn host() -> Self {
        // why: the store is display state, and this is on the notice path. An
        // unavailable or refused state root ends the store's involvement rather
        // than the launch's.
        let path = match crate::host_paths::state_root() {
            Ok(Some(root)) => Some(root.join(FILE)),
            Ok(None) | Err(_) => None,
        };
        Self { path }
    }

    #[cfg(test)]
    pub(super) fn at(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    pub(super) fn load(&self) -> Loaded {
        let refused = Loaded {
            entries: Vec::new(),
            disposition: Disposition::NonReplaceable,
        };
        let Some(path) = &self.path else {
            return refused;
        };
        match examine(path) {
            PathState::NonReplaceable => refused,
            PathState::Absent => Loaded {
                entries: Vec::new(),
                disposition: Disposition::Writable,
            },
            // `O_NOFOLLOW` in the reader closes the window between the
            // examination and the open; a decode or read failure is a damaged
            // file, which is rewritable and holds no entries (R16).
            PathState::Regular => Loaded {
                entries: crate::host_paths::read_optional_bounded_regular_file_no_follow(
                    path,
                    MAX_BASELINE_BYTES as u64,
                )
                .ok()
                .flatten()
                .and_then(|bytes| decode(&bytes))
                .unwrap_or_default(),
                disposition: Disposition::Writable,
            },
        }
    }

    /// R26's other half: the path is examined again immediately before the
    /// replace, because it may have become a non-regular file since `load`.
    ///
    /// The examination and the rename are not atomic, so a non-regular file
    /// created in between is replaced. That is accepted, not closed: the state
    /// root is the user's own directory, anyone who can race there can also read
    /// and rewrite the store, and the store holds no authority.
    pub(super) fn save(
        &self,
        disposition: Disposition,
        entries: &[Entry],
    ) -> anyhow::Result<Saved> {
        let Some(path) = &self.path else {
            return Ok(Saved::Refused);
        };
        if disposition == Disposition::NonReplaceable || examine(path) == PathState::NonReplaceable
        {
            return Ok(Saved::Refused);
        }
        let Some(bytes) = encode(entries) else {
            return Ok(Saved::Unadmittable);
        };
        crate::host_paths::atomic_write(path, &bytes, 0o600)?;
        Ok(Saved::Written)
    }
}

/// The wire form. Every map is a `BTreeMap` and every field is written in
/// declaration order, so the same entries always serialize to the same bytes —
/// which is what makes the size bound a property of the content.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireStore {
    version: u32,
    references: Vec<WireEntry>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEntry {
    reference: String,
    /// `null` means no group line has been shown for this reference yet. The
    /// encoder never writes `{}`, and the decoder refuses it, so each state has
    /// exactly one encoding.
    baseline: Option<BTreeMap<String, Vec<String>>>,
    invalid: Vec<String>,
    unrecognized: u64,
    excess: u64,
}

fn group_key(group: &RequestGroup) -> String {
    match group {
        RequestGroup::EveryLaunch => "image".to_owned(),
        RequestGroup::Agent(name) => format!("{}{}", LabelWord::Agent.text(), name.0),
    }
}

fn parse_group_key(key: &str) -> Option<RequestGroup> {
    if key == "image" {
        return Some(RequestGroup::EveryLaunch);
    }
    let name = key.strip_prefix(LabelWord::Agent.text())?;
    parse_name(name).map(RequestGroup::Agent)
}

/// The NAME rule, re-applied on read: a store file is untrusted input, so a
/// group or invalid key whose name would not be a valid label NAME makes the
/// whole store damaged rather than reaching a rendering path.
fn parse_name(name: &str) -> Option<LabelName> {
    if crate::pi_credential_inspection::provider_id_is_safe_bytes(name.as_bytes()) {
        Some(LabelName(name.to_owned()))
    } else {
        None
    }
}

fn parse_label_key(text: &str) -> Option<LabelKey> {
    if let Some(name) = text.strip_prefix(LabelWord::Image.text()) {
        return parse_name(name).map(|name| LabelKey {
            word: LabelWord::Image,
            name,
        });
    }
    let name = text.strip_prefix(LabelWord::Agent.text())?;
    parse_name(name).map(|name| LabelKey {
        word: LabelWord::Agent,
        name,
    })
}

/// Only canonical spellings are accepted: a request that would render
/// differently than it is stored could not be compared with a later launch's.
///
/// The array must also be **strictly ascending in render order**, which is the
/// order a `BTreeSet` iterates and the only order the encoder writes. A
/// duplicate or reordered array is a second encoding of one recorded set, so it
/// is damage rather than a spelling variant.
fn parse_requests(texts: &[String]) -> Option<BTreeSet<NetworkRequest>> {
    if texts.len() > MAX_ENTRY_REQUESTS {
        return None;
    }
    let mut requests = BTreeSet::new();
    for text in texts {
        let parsed = NetworkRequests::parse(std::slice::from_ref(text)).ok()?;
        if parsed.len() != 1 {
            return None;
        }
        requests.extend(parsed.iter().cloned());
    }
    let rerendered: Vec<String> = requests.iter().map(ToString::to_string).collect();
    if rerendered != texts {
        return None;
    }
    Some(requests)
}

fn entry_is_well_formed(entry: &Entry) -> bool {
    if entry.reference.is_empty() || entry.reference.len() > MAX_REFERENCE_BYTES {
        return false;
    }
    if entry.baseline.len() > MAX_RECORDED_GROUPS {
        return false;
    }
    if entry.ignored.invalid.len() > super::MAX_REQUEST_LABELS {
        return false;
    }
    let requests: usize = entry.baseline.values().map(BTreeSet::len).sum();
    requests <= MAX_ENTRY_REQUESTS
}

fn encode_entry(entry: &Entry) -> WireEntry {
    WireEntry {
        reference: entry.reference.clone(),
        baseline: if entry.baseline.is_empty() {
            None
        } else {
            Some(
                entry
                    .baseline
                    .iter()
                    .map(|(group, requests)| {
                        let rendered = requests.iter().map(ToString::to_string).collect();
                        (group_key(group), rendered)
                    })
                    .collect(),
            )
        },
        invalid: entry
            .ignored
            .invalid
            .iter()
            .map(LabelKey::address)
            .collect(),
        unrecognized: entry.ignored.unrecognized,
        excess: entry.ignored.excess,
    }
}

fn decode_entry(wire: WireEntry) -> Option<Entry> {
    let baseline = match wire.baseline {
        None => Groups::new(),
        // `{}` is a second encoding of "no group shown"; refusing it keeps each
        // state a single value.
        Some(groups) if groups.is_empty() => return None,
        Some(groups) => groups
            .into_iter()
            .map(|(key, requests)| Some((parse_group_key(&key)?, parse_requests(&requests)?)))
            .collect::<Option<Groups>>()?,
    };
    let invalid = wire
        .invalid
        .iter()
        .map(|text| parse_label_key(text))
        .collect::<Option<BTreeSet<LabelKey>>>()?;
    // Same rule as the request arrays: a duplicate or reordered `invalid` list is
    // a second encoding of the same facts.
    let rerendered: Vec<String> = invalid.iter().map(LabelKey::address).collect();
    if rerendered != wire.invalid {
        return None;
    }
    let entry = Entry {
        reference: wire.reference,
        baseline,
        ignored: IgnoredFacts {
            invalid,
            unrecognized: wire.unrecognized,
            excess: wire.excess,
        },
    };
    entry_is_well_formed(&entry).then_some(entry)
}

/// Decode and validate; `None` means damaged, which the caller treats as "no
/// entries" (R16).
fn decode(bytes: &[u8]) -> Option<Vec<Entry>> {
    let wire: WireStore = serde_json::from_slice(bytes).ok()?;
    if wire.version != STORE_VERSION {
        return None;
    }
    // One state, one encoding: accept only the bytes the encoder writes. A
    // lenient parse cannot see duplicate group keys (the last one wins), a
    // reordered map, extra whitespace or reordered fields, and each of those is
    // a second encoding of one state. Our own writer is the only producer, so
    // every healthy store matches byte for byte; anything else is damage and is
    // reported in full rather than half-trusted.
    if serde_json::to_vec(&wire).ok()?.as_slice() != bytes {
        return None;
    }
    // The same predicate on read and write, measured on the bytes that were
    // read: a file larger than the bound is damaged, not truncated.
    if !baseline_store_admits(wire.references.len(), bytes.len()) {
        return None;
    }
    let mut seen = BTreeSet::new();
    let mut entries = Vec::with_capacity(wire.references.len());
    for reference in wire.references {
        let entry = decode_entry(reference)?;
        if !seen.insert(entry.reference.clone()) {
            return None;
        }
        entries.push(entry);
    }
    Some(entries)
}

/// Serialize the largest admitted prefix of `entries`.
///
/// The entries are most-recently-seen first, so dropping from the back drops the
/// least recently seen (R17). Under pressure the search is a binary search over
/// prefixes of **real serializations**, because the bound is on the bytes the
/// next reader sees — envelope and separators included — and none of that can be
/// recovered by summing per-entry lengths.
fn encode(entries: &[Entry]) -> Option<Vec<u8>> {
    if !entries.iter().all(entry_is_well_formed) {
        return None;
    }
    let serialize = |count: usize| {
        serde_json::to_vec(&WireStore {
            version: STORE_VERSION,
            references: entries[..count].iter().map(encode_entry).collect(),
        })
        .ok()
    };
    let admitted =
        |count: usize| serialize(count).filter(|bytes| baseline_store_admits(count, bytes.len()));
    if let Some(bytes) = admitted(entries.len()) {
        return Some(bytes);
    }
    // Serialized length grows strictly with the prefix and the count bound is
    // monotone, so admission is monotone in the prefix length.
    let (mut lo, mut hi) = (0usize, entries.len());
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if admitted(mid).is_some() {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    if lo == 0 { None } else { admitted(lo) }
}

/// R18's write rule. `None` means "write nothing".
pub(super) fn next_entries(
    mut entries: Vec<Entry>,
    reference: &str,
    current: &DeclaredImageRequests,
    printed: &BTreeSet<RequestGroup>,
    any_shown: bool,
) -> Option<Vec<Entry>> {
    let found = entries
        .iter()
        .position(|entry| entry.reference == reference);
    if !any_shown {
        // Nothing was shown, so no recorded set may move. The entry still moves
        // to the front when it is not already there, so that a reference the
        // user keeps launching is not the one evicted.
        return match found {
            None | Some(0) => None,
            Some(index) => {
                let entry = entries.remove(index);
                entries.insert(0, entry);
                Some(entries)
            }
        };
    }
    let mut baseline = found
        .map(|index| entries.remove(index).baseline)
        .unwrap_or_default();
    // Per group: only a group's own printed line advances that group's set. A
    // launch-wide rule would absorb a covered change the user never saw.
    for group in printed {
        baseline.insert(
            group.clone(),
            current.groups().get(group).cloned().unwrap_or_default(),
        );
    }
    retain_recorded_groups(&mut baseline, current);
    entries.insert(
        0,
        Entry {
            reference: reference.to_owned(),
            baseline,
            ignored: current.ignored_facts(),
        },
    );
    Some(entries)
}

/// R18(d): drop only empty recorded sets of groups absent from the labels, last
/// in group order first. A non-empty set is never dropped — that would discard
/// removal information — and a dropped group's later reappearance prints the same
/// requests in the first form instead of as a `+`.
fn retain_recorded_groups(baseline: &mut Groups, current: &DeclaredImageRequests) {
    let over = baseline.len().saturating_sub(MAX_RECORDED_GROUPS);
    if over == 0 {
        return;
    }
    let dropped: Vec<RequestGroup> = baseline
        .iter()
        .rev()
        .filter(|(group, set)| set.is_empty() && !current.groups().contains_key(*group))
        .map(|(group, _)| group.clone())
        .take(over)
        .collect();
    for group in dropped {
        baseline.remove(&group);
    }
}

#[cfg(test)]
mod tests;
