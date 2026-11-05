//! Store codec, disposition, bound and write-rule tables (A13, A25, R17, R18,
//! R26). Production code lives in `image_requests/baseline.rs`.
use super::*;
use crate::image_requests::{
    DeclaredImageRequests, Groups, IgnoredFacts, LabelKey, LabelName, LabelWord, RequestGroup,
};
use std::os::unix::fs::{FileTypeExt, PermissionsExt, symlink};

// A tiny convenience so the tables read as data: a labelled group.
fn agent(name: &str) -> RequestGroup {
    RequestGroup::Agent(LabelName(name.to_owned()))
}

fn request(host: &str) -> NetworkRequest {
    let parsed = NetworkRequests::parse(&[host.to_owned()]).expect("grammatical fixture");
    parsed.iter().next().cloned().expect("one request")
}

fn set(hosts: &[&str]) -> BTreeSet<NetworkRequest> {
    hosts.iter().map(|host| request(host)).collect()
}

fn key(name: &str) -> String {
    format!("{}{}", "org.agent-vm.network-requests.", name)
}

fn declared(raw: &[(&str, &str)]) -> DeclaredImageRequests {
    let labels: Vec<(String, String)> = raw
        .iter()
        .map(|(name, value)| (key(name), (*value).to_owned()))
        .collect();
    DeclaredImageRequests::from_labels(labels.iter().map(|(k, v)| (k.as_str(), v.as_str())))
}

fn entry(reference: &str, raw: Vec<(RequestGroup, &[&str])>) -> Entry {
    Entry {
        reference: reference.to_owned(),
        baseline: raw
            .into_iter()
            .map(|(group, hosts)| (group, set(hosts)))
            .collect(),
        ignored: IgnoredFacts::default(),
    }
}

/// The exact bytes `encode` would write, independently of its bound search.
fn serialized(entries: &[Entry]) -> Vec<u8> {
    serde_json::to_vec(&WireStore {
        version: STORE_VERSION,
        references: entries.iter().map(encode_entry).collect(),
    })
    .expect("the fixture serializes")
}

fn tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("av505-store-")
        .tempdir_in("/tmp")
        .expect("temp dir")
}

// ---------------------------------------------------------------------------
// R16 — the codec
// ---------------------------------------------------------------------------

/// A round trip preserves both distinctions the store exists for: an entry with
/// no recorded set (`null`) and a group with an empty recorded set (`[]`).
#[test]
fn codec_round_trips_no_set_empty_set_and_a_full_set() {
    let never_shown = Entry {
        reference: "ghcr.io/x/a:latest".to_owned(),
        baseline: Groups::new(),
        ignored: IgnoredFacts::default(),
    };
    let mixed = entry(
        "ghcr.io/x/b:latest",
        vec![
            (RequestGroup::EveryLaunch, &["deb.debian.org"]),
            (agent("codex"), &[]),
            (agent("pi"), &["pi.dev", "tcp://h.example:8443"]),
        ],
    );
    let source = vec![never_shown.clone(), mixed.clone()];
    let bytes = serialized(&source);
    assert!(String::from_utf8_lossy(&bytes).contains("\"baseline\":null"));
    assert!(String::from_utf8_lossy(&bytes).contains("\"agent.codex\":[]"));
    let decoded = decode(&bytes).expect("a valid store decodes");
    assert_eq!(decoded, source);
    assert!(decoded[0].baseline.is_empty(), "no group shown yet");
    assert_eq!(
        decoded[1].baseline[&agent("codex")],
        BTreeSet::new(),
        "an empty recorded set survives the round trip"
    );
    // The recorded ignored facts survive too.
    let mut with_ignored = mixed.clone();
    with_ignored.ignored = IgnoredFacts {
        invalid: [LabelKey {
            word: LabelWord::Agent,
            name: LabelName("bad".to_owned()),
        }]
        .into_iter()
        .collect(),
        unrecognized: 3,
        excess: 1,
    };
    let decoded = decode(&serialized(&[with_ignored.clone()])).expect("decodes");
    assert_eq!(decoded, vec![with_ignored]);
    // An empty store is valid and empty.
    assert_eq!(decode(&serialized(&[])), Some(Vec::new()));
}

/// Every damage class the store contract names, in one table: each is `None`,
/// which the loader turns into "no entries, rewritable".
#[test]
fn codec_refuses_every_damage_class() {
    let valid = entry("ghcr.io/x/a:latest", vec![(agent("codex"), &["a.example"])]);
    let copy = valid.clone();
    let good = serialized(std::slice::from_ref(&valid));
    let text = String::from_utf8(good.clone()).unwrap();
    let damaged: Vec<(&str, Vec<u8>)> = vec![
        ("garbage", b"not json at all".to_vec()),
        ("empty file", Vec::new()),
        (
            "wrong version",
            text.replace("\"version\":1", "\"version\":2").into_bytes(),
        ),
        (
            "unknown store field",
            text.replace("\"version\":1", "\"version\":1,\"extra\":true")
                .into_bytes(),
        ),
        (
            "unknown entry field",
            text.replace("\"excess\":0", "\"excess\":0,\"extra\":true")
                .into_bytes(),
        ),
        // `{}` is a second encoding of "no group shown"; only `null` is written.
        (
            "empty baseline object",
            br#"{"version":1,"references":[{"reference":"r","baseline":{},"invalid":[],"unrecognized":0,"excess":0}]}"#.to_vec(),
        ),
        // Non-canonical request spellings would not compare with a later launch.
        (
            "uppercase request",
            text.replace("a.example", "A.example").into_bytes(),
        ),
        (
            "request with default port spelled out",
            text.replace("a.example", "a.example:443").into_bytes(),
        ),
        // A group name that would not be a valid label NAME.
        (
            "unsafe group name",
            text.replace("\"agent.codex\"", "\"agent.Codex\"").into_bytes(),
        ),
        (
            "unknown group key",
            text.replace("\"agent.codex\"", "\"every\"")
                .into_bytes(),
        ),
        // A reference field over its bound.
        (
            "oversized reference",
            br#"{"version":1,"references":[{"reference":""#.to_vec()
                .into_iter()
                .chain(std::iter::repeat_n(b'x', 4097))
                .chain(br#"","baseline":null,"invalid":[],"unrecognized":0,"excess":0}]}"#.iter().copied())
                .collect(),
        ),
        (
            "empty reference",
            text.replace("ghcr.io/x/a:latest", "").into_bytes(),
        ),
    ];
    assert!(decode(&good).is_some(), "the unmutated store must decode");
    for (name, bytes) in damaged {
        assert_eq!(decode(&bytes), None, "damage class {name:?} was accepted");
    }
    // Duplicate references.
    let twice = serialized(&[valid.clone(), copy]);
    assert_eq!(decode(&twice), None);
    // More than 8 MiB: valid JSON, so only the byte bound can refuse it.
    let mut oversized = good.clone();
    oversized.resize(MAX_BASELINE_BYTES + 1, b' ');
    assert_eq!(decode(&oversized), None);
}

/// One state, one encoding: every way of spelling the same state that a lenient
/// parse would accept is damage. This is what the ADR's sentence means — not
/// only a canonical request *spelling*, but the group keys' order and uniqueness,
/// each array's order and uniqueness, and the envelope's exact bytes.
#[test]
fn codec_refuses_every_second_encoding_of_one_state() {
    let full = Entry {
        reference: "r".to_owned(),
        baseline: [
            (agent("alpha"), set(&["a.example", "b.example"])),
            (agent("zeta"), set(&["c.example"])),
        ]
        .into_iter()
        .collect(),
        ignored: IgnoredFacts {
            invalid: [
                LabelKey {
                    word: LabelWord::Agent,
                    name: LabelName("bad".to_owned()),
                },
                LabelKey {
                    word: LabelWord::Agent,
                    name: LabelName("zed".to_owned()),
                },
            ]
            .into_iter()
            .collect(),
            unrecognized: 0,
            excess: 0,
        },
    };
    let good = serialized(std::slice::from_ref(&full));
    assert!(decode(&good).is_some(), "the unmutated store must decode");
    let text = String::from_utf8(good).unwrap();
    let alpha = "\"agent.alpha\":[\"a.example\",\"b.example\"]";
    let zeta = "\"agent.zeta\":[\"c.example\"]";
    assert!(text.contains(&format!("{alpha},{zeta}")), "{text}");
    let pretty = serde_json::to_string_pretty(&WireStore {
        version: STORE_VERSION,
        references: vec![encode_entry(&full)],
    })
    .expect("the fixture serializes");
    let cases: Vec<(&str, String)> = vec![
        (
            "duplicate request in one group",
            text.replace("\"a.example\",\"b.example\"", "\"a.example\",\"a.example\""),
        ),
        (
            "unsorted requests in one group",
            text.replace("\"a.example\",\"b.example\"", "\"b.example\",\"a.example\""),
        ),
        (
            "duplicate group key",
            text.replace(
                "\"agent.alpha\":[\"a.example\",\"b.example\"]",
                "\"agent.alpha\":[\"a.example\",\"b.example\"],\"agent.alpha\":[\"c.example\"]",
            ),
        ),
        (
            "unsorted group keys",
            text.replace(&format!("{alpha},{zeta}"), &format!("{zeta},{alpha}")),
        ),
        (
            "duplicate invalid key",
            text.replace("\"agent.bad\",\"agent.zed\"", "\"agent.bad\",\"agent.bad\""),
        ),
        (
            "unsorted invalid keys",
            text.replace("\"agent.bad\",\"agent.zed\"", "\"agent.zed\",\"agent.bad\""),
        ),
        ("pretty printed", pretty),
    ];
    for (name, damaged) in cases {
        assert_ne!(
            damaged.as_bytes(),
            text.as_bytes(),
            "{name}: fixture unchanged"
        );
        assert_eq!(
            decode(damaged.as_bytes()),
            None,
            "second encoding {name:?} was accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// R26 — the disposition table
// ---------------------------------------------------------------------------

fn fifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("NUL-free path");
    // SAFETY: an owned NUL-free path and a mode; mkfifo creates an entry at a
    // path this test owns.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0, "mkfifo");
}

/// Absent and regular are replaceable; every other shape is refused and left
/// exactly as it was — including a symlink's target, which is never read or
/// modified.
#[test]
fn disposition_table_refuses_every_non_regular_path() {
    let dir = tempdir();
    let root = dir.path();
    let store = entry("REF", vec![(agent("codex"), &["a.example"])]);

    // Absent: writable, and the write creates the file.
    let absent = root.join("absent.json");
    let writer = Store::at(absent.clone());
    assert_eq!(writer.load().disposition, Disposition::Writable);
    assert_eq!(
        writer
            .save(Disposition::Writable, std::slice::from_ref(&store))
            .unwrap(),
        Saved::Written
    );
    assert!(absent.is_file());
    assert_eq!(
        std::fs::metadata(&absent).unwrap().permissions().mode() & 0o777,
        0o600,
        "the store is written 0600"
    );

    // Regular and valid: writable, and the entry reads back.
    let regular = root.join("regular.json");
    std::fs::write(&regular, serialized(std::slice::from_ref(&store))).unwrap();
    let loaded = Store::at(regular.clone()).load();
    assert_eq!(loaded.disposition, Disposition::Writable);
    assert_eq!(loaded.find("REF"), Some(&store));

    // Regular but damaged: writable with no entries, so the next report is full.
    let damaged = root.join("damaged.json");
    std::fs::write(&damaged, b"{").unwrap();
    let loaded = Store::at(damaged.clone()).load();
    assert_eq!(loaded.disposition, Disposition::Writable);
    assert!(loaded.entries.is_empty());

    // A symlink to a regular file outside the root: refused, link and target
    // untouched.
    let target = root.join("target.json");
    std::fs::write(&target, b"untouched").unwrap();
    let link = root.join("link.json");
    symlink(&target, &link).unwrap();
    let refused = Store::at(link.clone());
    let loaded = refused.load();
    assert_eq!(loaded.disposition, Disposition::NonReplaceable);
    assert!(loaded.entries.is_empty());
    assert_eq!(
        refused
            .save(loaded.disposition, std::slice::from_ref(&store))
            .unwrap(),
        Saved::Refused
    );
    assert!(link.is_symlink());
    assert_eq!(std::fs::read_link(&link).unwrap(), target);
    assert_eq!(std::fs::read(&target).unwrap(), b"untouched");

    // A dangling symlink: the same.
    let dangling = root.join("dangling.json");
    symlink(root.join("nowhere.json"), &dangling).unwrap();
    let refused = Store::at(dangling.clone());
    assert_eq!(refused.load().disposition, Disposition::NonReplaceable);
    assert_eq!(
        refused
            .save(Disposition::Writable, std::slice::from_ref(&store))
            .unwrap(),
        Saved::Refused
    );
    assert!(dangling.is_symlink());

    // A symlink to a directory: the same.
    let target_dir = root.join("target-dir");
    std::fs::create_dir(&target_dir).unwrap();
    let link_dir = root.join("link-dir.json");
    symlink(&target_dir, &link_dir).unwrap();
    let refused = Store::at(link_dir.clone());
    assert_eq!(refused.load().disposition, Disposition::NonReplaceable);
    assert_eq!(
        refused
            .save(Disposition::Writable, std::slice::from_ref(&store))
            .unwrap(),
        Saved::Refused
    );
    assert!(link_dir.is_symlink());

    // A directory: refused, and still there afterwards.
    let directory = root.join("dir.json");
    std::fs::create_dir(&directory).unwrap();
    let refused = Store::at(directory.clone());
    assert_eq!(refused.load().disposition, Disposition::NonReplaceable);
    assert_eq!(
        refused
            .save(Disposition::Writable, std::slice::from_ref(&store))
            .unwrap(),
        Saved::Refused
    );
    assert!(directory.is_dir());

    // A FIFO: refused, and still a FIFO.
    let pipe = root.join("fifo.json");
    fifo(&pipe);
    let refused = Store::at(pipe.clone());
    assert_eq!(refused.load().disposition, Disposition::NonReplaceable);
    assert_eq!(
        refused
            .save(Disposition::Writable, std::slice::from_ref(&store))
            .unwrap(),
        Saved::Refused
    );
    assert!(
        std::fs::symlink_metadata(&pipe)
            .unwrap()
            .file_type()
            .is_fifo()
    );
}

/// A path that becomes non-regular between load and save is refused too: the
/// re-examination before the replace is the second half of R26.
#[test]
fn a_path_that_turns_non_regular_between_load_and_save_is_refused() {
    let dir = tempdir();
    let path = dir.path().join("store.json");
    let writer = Store::at(path.clone());
    assert_eq!(writer.load().disposition, Disposition::Writable);
    let target = dir.path().join("target.json");
    std::fs::write(&target, b"untouched").unwrap();
    symlink(&target, &path).unwrap();
    let store = entry("REF", vec![(agent("codex"), &["a.example"])]);
    assert_eq!(
        writer.save(Disposition::Writable, &[store]).unwrap(),
        Saved::Refused
    );
    assert!(path.is_symlink());
    assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
}

// ---------------------------------------------------------------------------
// R17, A25 — the bounds
// ---------------------------------------------------------------------------

/// The longest request there is: a 253-byte canonical name at an explicit port.
fn long_request(index: usize) -> String {
    let head = format!("{index:04x}");
    let fill = "a".repeat(63 - head.len());
    format!(
        "tcp://{head}{fill}.{}.{}.{}:8443",
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    )
}

fn long_set(count: usize) -> BTreeSet<NetworkRequest> {
    (0..count)
        .map(|index| request(&long_request(index)))
        .collect()
}

fn bulk(reference: String, requests: &BTreeSet<NetworkRequest>) -> Entry {
    Entry {
        reference,
        baseline: [(RequestGroup::EveryLaunch, requests.clone())]
            .into_iter()
            .collect(),
        ignored: IgnoredFacts::default(),
    }
}

/// A multi-entry store whose exact serialization is `target` bytes.
///
/// The last entry's reference is the fine-tuning knob: it has thousands of bytes
/// of room to grow, and one byte of reference length is one byte of store. When
/// the gap is larger than that room, requests are dropped in batches, so the
/// search converges in a couple of serializations rather than one per byte.
fn tuned_store(target: usize) -> Vec<Entry> {
    let pool = long_set(MAX_ENTRY_REQUESTS);
    let mut entries: Vec<Entry> = Vec::new();
    while serialized(&entries).len() < target {
        let reference = format!("e{:04}{}", entries.len(), "y".repeat(396));
        entries.push(bulk(reference, &pool));
    }
    loop {
        let size = serialized(&entries).len();
        if size == target {
            return entries;
        }
        let last = entries.last_mut().expect("at least one entry");
        if size > target {
            let delta = size - target;
            let room = last.reference.len().saturating_sub(1);
            if delta <= room {
                last.reference = "x".repeat(last.reference.len() - delta);
            } else {
                let pops = (delta - room).div_ceil(268).max(1);
                let group = last
                    .baseline
                    .get_mut(&RequestGroup::EveryLaunch)
                    .expect("a bulk entry declares the every-launch group");
                for _ in 0..pops {
                    assert!(group.pop_last().is_some(), "the tuning pool is exhausted");
                }
            }
        } else {
            let grow = target - size;
            let len = last.reference.len() + grow;
            assert!(
                len <= MAX_REFERENCE_BYTES,
                "the reference bound is the tuning limit"
            );
            last.reference = "x".repeat(len);
        }
    }
}

/// The written **file's** length at B−1 and B, both valid on read back, and the
/// least-recent entry dropped at B+1 (A25).
#[test]
fn admission_byte_bound_writes_b_minus_one_and_b_and_drops_at_b_plus_one() {
    let dir = tempdir();
    for target in [MAX_BASELINE_BYTES - 1, MAX_BASELINE_BYTES] {
        let entries = tuned_store(target);
        assert!(entries.len() < MAX_BASELINE_REFERENCES);
        let path = dir.path().join(format!("store-{target}.json"));
        let writer = Store::at(path.clone());
        assert_eq!(
            writer.save(Disposition::Writable, &entries).unwrap(),
            Saved::Written
        );
        let written = std::fs::read(&path).expect("the store was written");
        assert_eq!(
            written.len(),
            target,
            "the written length is exactly the bound"
        );
        let decoded = decode(&written).expect("a B-byte store reads back valid");
        assert_eq!(decoded.len(), entries.len());
        assert_eq!(decoded, entries);
    }

    let entries = tuned_store(MAX_BASELINE_BYTES + 1);
    let path = dir.path().join("store-over.json");
    let writer = Store::at(path.clone());
    assert_eq!(
        writer.save(Disposition::Writable, &entries).unwrap(),
        Saved::Written
    );
    let written = std::fs::read(&path).expect("the store was written");
    assert!(
        written.len() <= MAX_BASELINE_BYTES,
        "an over-bound write drops entries instead of exceeding the bound: {}",
        written.len()
    );
    let decoded = decode(&written).expect("the written store reads back valid");
    assert!(
        decoded.len() < entries.len(),
        "the least recent entry was dropped"
    );
    assert_eq!(decoded[0], entries[0], "the newest entry is never dropped");

    // A hand-written regular file one byte over the bound is damaged.
    let mut oversized = written.clone();
    oversized.resize(MAX_BASELINE_BYTES + 1, b' ');
    assert_eq!(decode(&oversized), None);
}

/// A maximal single entry — 4096 requests and 128 group keys — is below the
/// store bound, which is what makes `Unadmittable` unreachable in practice.
#[test]
fn admission_a_maximal_entry_fits_below_the_byte_bound() {
    let pool = long_set(MAX_ENTRY_REQUESTS);
    let mut maximal = entry("REF", vec![]);
    // 4096 requests spread over 64 non-empty groups, plus 64 empty (vanished)
    // groups to reach the recorded-group bound.
    let hosts: Vec<NetworkRequest> = pool.iter().cloned().collect();
    for index in 0..64 {
        let chunk: BTreeSet<NetworkRequest> = hosts[index * 64..(index + 1) * 64]
            .iter()
            .cloned()
            .collect();
        maximal
            .baseline
            .insert(agent(&format!("g{index:02}")), chunk);
        maximal
            .baseline
            .insert(agent(&format!("z{index:02}")), BTreeSet::new());
    }
    assert_eq!(maximal.baseline.len(), 128);
    let bytes = serialized(&[maximal.clone()]);
    assert!(
        bytes.len() < MAX_BASELINE_BYTES,
        "a maximal entry is {} bytes",
        bytes.len()
    );
    assert_eq!(
        encode(&[maximal.clone()]).map(|bytes| bytes.len()),
        Some(bytes.len())
    );
    assert_eq!(decode(&bytes), Some(vec![maximal]));
}

/// The count bound, on write: 256 stored entries plus one new one keep 256, and
/// the 257th is reached by the predicate rather than truncated beforehand.
#[test]
fn admission_encode_keeps_256_and_drops_the_257th() {
    let entries: Vec<Entry> = (0..MAX_BASELINE_REFERENCES)
        .map(|index| {
            entry(
                &format!("ref{index:03}"),
                vec![(agent("codex"), &["a.example"])],
            )
        })
        .collect();
    assert_eq!(entries.len(), 256);
    let written = next_entries(
        entries,
        "ref-new",
        &declared(&[("agent.codex", "a.example")]),
        &[agent("codex")].into_iter().collect::<BTreeSet<_>>(),
        true,
    )
    .expect("a shown line writes");
    assert_eq!(written.len(), 257, "the write rule does not pre-truncate");
    let bytes = encode(&written).expect("the store is admissible");
    let decoded = decode(&bytes).expect("the written store reads back valid");
    assert_eq!(decoded.len(), MAX_BASELINE_REFERENCES);
    assert_eq!(decoded[0].reference, "ref-new", "the new entry is first");
    assert!(
        !decoded.iter().any(|entry| entry.reference == "ref255"),
        "the least recently seen entry is dropped"
    );
}

/// The count bound, on read: 257 hand-written references are damaged.
#[test]
fn admission_decode_refuses_257_references() {
    let entries: Vec<Entry> = (0..MAX_BASELINE_REFERENCES + 1)
        .map(|index| {
            entry(
                &format!("ref{index:03}"),
                vec![(agent("codex"), &["a.example"])],
            )
        })
        .collect();
    assert_eq!(entries.len(), 257);
    let bytes = serialized(&entries);
    assert!(
        bytes.len() < MAX_BASELINE_BYTES,
        "only the count bound can refuse this"
    );
    assert_eq!(decode(&bytes), None);
}

// ---------------------------------------------------------------------------
// R18 — the write rule
// ---------------------------------------------------------------------------

/// One group's recorded set after a write, for every combination of (recorded
/// set: none, empty, non-empty) × (group in the labels) × (its own line
/// printed) × (another group's line printed).
#[test]
fn write_rule_table_per_group() {
    // (name, recorded, in labels, own line printed, another group printed,
    // expected recorded state)
    type Case<'a> = (
        &'a str,
        Option<&'a [&'a str]>,
        bool,
        bool,
        bool,
        Option<&'a [&'a str]>,
    );
    let cases: Vec<Case<'_>> = vec![
        // No recorded set: only the group's own line records one.
        (
            "no set, in labels, own printed",
            None,
            true,
            true,
            false,
            Some(&["a.example"]),
        ),
        (
            "no set, in labels, own printed, other too",
            None,
            true,
            true,
            true,
            Some(&["a.example"]),
        ),
        (
            "no set, in labels, other printed",
            None,
            true,
            false,
            true,
            None,
        ),
        (
            "no set, in labels, nothing printed",
            None,
            true,
            false,
            false,
            None,
        ),
        (
            "no set, absent, own printed",
            None,
            false,
            true,
            false,
            Some(&[]),
        ),
        (
            "no set, absent, nothing printed",
            None,
            false,
            false,
            false,
            None,
        ),
        // An empty recorded set stays empty unless the group's own line prints.
        (
            "empty, in labels, own printed",
            Some(&[]),
            true,
            true,
            false,
            Some(&["a.example"]),
        ),
        (
            "empty, in labels, other printed",
            Some(&[]),
            true,
            false,
            true,
            Some(&[]),
        ),
        (
            "empty, absent, nothing printed",
            Some(&[]),
            false,
            false,
            false,
            Some(&[]),
        ),
        // A non-empty recorded set advances only on its own line, and never
        // absorbs another group's line.
        (
            "full, in labels, own printed",
            Some(&["b.example"]),
            true,
            true,
            false,
            Some(&["a.example"]),
        ),
        (
            "full, in labels, other printed (pending)",
            Some(&["b.example"]),
            true,
            false,
            true,
            Some(&["b.example"]),
        ),
        (
            "full, absent, own printed",
            Some(&["b.example"]),
            false,
            true,
            false,
            Some(&[]),
        ),
    ];
    for (name, recorded, in_labels, own_printed, other_printed, expected) in cases {
        let current = declared(&[("agent.codex", if in_labels { "a.example" } else { "" })]);
        let current = if in_labels {
            current
        } else {
            declared(&[("agent.pi", "pi.dev")])
        };
        let mut printed: BTreeSet<RequestGroup> = BTreeSet::new();
        if own_printed {
            printed.insert(agent("codex"));
        }
        if other_printed {
            printed.insert(agent("pi"));
        }
        let any_shown = own_printed || other_printed;
        let baseline: Groups = recorded
            .map(|hosts| [(agent("codex"), set(hosts))].into_iter().collect())
            .unwrap_or_default();
        let stored = vec![Entry {
            reference: "REF".to_owned(),
            baseline: baseline.clone(),
            ignored: IgnoredFacts::default(),
        }];
        // `None` is "write nothing", which leaves the recorded set alone.
        let recorded_now = match next_entries(stored, "REF", &current, &printed, any_shown) {
            Some(written) => {
                assert_eq!(written.len(), 1, "{name}");
                written[0].baseline.get(&agent("codex")).cloned()
            }
            None => baseline.get(&agent("codex")).cloned(),
        };
        match expected {
            None => assert!(recorded_now.is_none(), "{name}: recorded set appeared"),
            Some(hosts) => assert_eq!(recorded_now, Some(set(hosts)), "{name}: wrong recorded set"),
        }
    }
}

/// The entry-level half of the write rule: when nothing is written, when only
/// recency moves, and that the ignored facts follow the current labels.
#[test]
fn write_rule_entry_level() {
    let current = declared(&[("agent.codex", "a.example")]);
    let printed: BTreeSet<RequestGroup> = [agent("codex")].into_iter().collect();

    // No entry and nothing shown: nothing is written, so no file appears.
    assert!(next_entries(Vec::new(), "REF", &current, &BTreeSet::new(), false).is_none());

    // An existing entry that is already first and nothing shown: no write.
    let first = entry("REF", vec![(agent("codex"), &["b.example"])]);
    assert!(
        next_entries(
            vec![first.clone()],
            "REF",
            &current,
            &BTreeSet::new(),
            false
        )
        .is_none()
    );

    // An existing entry that is not first: moved first with its content
    // unchanged, so a pending change stays pending.
    let other = entry("OTHER", vec![(agent("codex"), &["c.example"])]);
    let moved = next_entries(
        vec![other.clone(), first.clone()],
        "REF",
        &current,
        &BTreeSet::new(),
        false,
    )
    .expect("recency moves the entry");
    assert_eq!(moved[0], first);
    assert_eq!(moved[1], other);

    // Any line shown: the entry is first, its groups advance by `printed`, and
    // the ignored facts become the current ones.
    let with_ignored = entry("REF", vec![(agent("codex"), &["b.example"])]);
    let mut current_with_junk = declared(&[("agent.codex", "a.example"), ("Agent.x", "junk")]);
    current_with_junk = {
        let mut declared = current_with_junk;
        declared.unrecognized = 1;
        declared
    };
    let written = next_entries(
        vec![other.clone(), with_ignored],
        "REF",
        &current_with_junk,
        &printed,
        true,
    )
    .expect("a shown line writes");
    assert_eq!(written[0].reference, "REF");
    assert_eq!(written[0].baseline[&agent("codex")], set(&["a.example"]));
    assert_eq!(written[0].ignored.unrecognized, 1);
    assert_eq!(written[0].ignored.invalid.len(), 0);
    assert_eq!(written[1], other);
}

/// R18(d): only empty sets of groups absent from the labels are dropped, last in
/// group order first, and only until the entry holds 128 groups.
#[test]
fn write_rule_records_at_most_128_groups() {
    let mut stored = entry("REF", vec![]);
    // 130 empty recorded sets of vanished groups, plus two non-empty ones.
    for index in 0..130 {
        stored
            .baseline
            .insert(agent(&format!("gone{index:03}")), BTreeSet::new());
    }
    stored.baseline.insert(agent("live"), set(&["a.example"]));
    stored
        .baseline
        .insert(RequestGroup::EveryLaunch, set(&["deb.debian.org"]));
    assert_eq!(stored.baseline.len(), 132);

    // 40 current groups, none of them printed, so every recorded set stands.
    let mut raw: Vec<(String, String)> = (0..40)
        .map(|index| (format!("agent.now{index:02}"), format!("h{index}.example")))
        .collect();
    raw.push(("agent.x".to_owned(), "x.example".to_owned()));
    let labels: Vec<(String, String)> = raw
        .iter()
        .map(|(name, value)| (key(name), value.clone()))
        .collect();
    let current =
        DeclaredImageRequests::from_labels(labels.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let printed: BTreeSet<RequestGroup> = [agent("x")].into_iter().collect();
    let written = next_entries(vec![stored], "REF", &current, &printed, true).expect("writes");
    let baseline = &written[0].baseline;
    // 128 remains: the ordering dropped `gone` sets from the end of group order
    // first, and touched no non-empty set.
    assert_eq!(baseline.len(), MAX_RECORDED_GROUPS);
    assert!(baseline.contains_key(&agent("live")));
    assert!(baseline.contains_key(&RequestGroup::EveryLaunch));
    assert!(
        baseline.contains_key(&agent("gone000")),
        "the earliest groups stay"
    );
    assert!(baseline.contains_key(&agent("gone124")));
    // Five were dropped, from the end of group order first: the five latest
    // vanished groups, never a non-empty set.
    for index in 125..130 {
        assert!(
            !baseline.contains_key(&agent(&format!("gone{index:03}"))),
            "gone{index:03} should have been dropped"
        );
    }
}
