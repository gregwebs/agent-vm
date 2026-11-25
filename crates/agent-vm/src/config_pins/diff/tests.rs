//! V13-V15: what the review transcript says, and that it says nothing else.
//!
//! Every fixture is built here from bytes and a hand-written `pins.json`
//! literal, so the expected text cannot inherit a bug from `Current`'s encoder
//! or from the store writer.

use std::collections::BTreeMap;
use std::path::Path;

use proptest::prelude::*;

use super::*;
use crate::config_pins::{Current, LiveGeneration, StoreId};
use crate::config_sources::{Declaration, SourceAlias, SourceScope};

const PATH: &str = "/w/app/conf/agent-vm.toml";

fn key() -> PinKey {
    PinKey::for_source(Path::new(PATH)).unwrap()
}

fn hash(bytes: &[u8]) -> ContentHash {
    ContentHash::of(bytes)
}

/// The context line `PendingSource::for_tests` fixtures render: their alias is
/// `repo`, they are `sources[0]`, and they are a checkout-scoped `allow = false`
/// source.
const DECLARED: &str = "==> declared: sources[0] repo, scope checkout, allow = false\n";

fn generation() -> LiveGeneration {
    LiveGeneration {
        store_id: StoreId::parse_hex("11111111111111111111111111111111").unwrap(),
        reset_epoch: 1,
    }
}

/// A locked diff state holding one key, decoded from a manifest literal.
///
/// `readable` names the approved bodies whose snapshot the store could produce;
/// every other approved body is recorded `unavailable`, the way
/// `read_for_diff` reports one.
fn state(path: &str, active: &[u8], approved: &[&[u8]], readable: &[&[u8]]) -> DiffState {
    let approvals: Vec<String> = approved
        .iter()
        .map(|body| {
            format!(
                r#"{{"sha256":"{}","approved_ms":1,"active_ms":1}}"#,
                hash(body).hex()
            )
        })
        .collect();
    let manifest = format!(
        r#"{{"v":1,"store_id":"{id}","reset_epoch":1,"sources":[{{"path":"{path}","active":"{active}","approved":[{approvals}]}}]}}"#,
        id = generation().store_id.hex(),
        active = hash(active).hex(),
        approvals = approvals.join(","),
    );
    let current = Current::decode(manifest.as_bytes()).expect("the fixture manifest decodes");
    let mut snapshots = BTreeMap::new();
    let mut unavailable = BTreeMap::new();
    for body in approved {
        if readable.contains(body) {
            snapshots.insert(
                hash(body),
                std::str::from_utf8(body)
                    .expect("a readable snapshot fixture is UTF-8")
                    .to_owned(),
            );
        } else {
            unavailable.insert(hash(body), Unavailable::Missing);
        }
    }
    DiffState {
        generation: generation(),
        current,
        snapshots,
        unavailable,
    }
}

fn empty_state() -> DiffState {
    DiffState {
        generation: generation(),
        current: Current::empty(generation()),
        snapshots: BTreeMap::new(),
        unavailable: BTreeMap::new(),
    }
}

fn render(state: &DiffState, candidate: &[u8]) -> Result<String, TooLarge> {
    let pin_key = key();
    let source = PendingSource::for_tests(pin_key, candidate.to_vec());
    let review = PendingReview::of(&source, state);
    render_review(std::slice::from_ref(&review))
}

fn review_of(state: &DiffState, candidate: &[u8]) -> String {
    render(state, candidate).expect("the fixture is within every cap")
}

fn hash_of(candidate: &[u8]) -> String {
    hash(candidate).hex()
}

fn bytes(n: usize, line: &str) -> Vec<u8> {
    line.repeat(n).into_bytes()
}

// ---- V13: rendering exactness ----

#[test]
fn a_first_review_diffs_the_whole_candidate_against_empty_content() {
    let transcript = review_of(&empty_state(), b"a = 1\nb = 2\n");
    assert_eq!(
        transcript,
        format!(
            concat!(
                "==> source {PATH}: never approved\n",
                "{DECLARED}",
                "--- {PATH}\t(never approved: empty)\n",
                "+++ {PATH}\t(current sha256:{hash})\n",
                "@@ -0,0 +1,2 @@\n",
                "+a = 1\n",
                "+b = 2\n"
            ),
            DECLARED = DECLARED,
            PATH = PATH,
            hash = hash_of(b"a = 1\nb = 2\n")
        )
    );
}

#[test]
fn a_one_line_edit_shows_three_lines_of_context() {
    let base = b"l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\n";
    let candidate = b"l1\nl2\nl3\nl4\nL5\nl6\nl7\nl8\nl9\n";
    let transcript = review_of(&state(PATH, base, &[base], &[base]), candidate);
    assert_eq!(
        transcript,
        format!(
            concat!(
                "==> source {PATH}: changed since it was last approved\n",
                "{DECLARED}",
                "--- {PATH}\t(last approved sha256:{base_hash})\n",
                "+++ {PATH}\t(current sha256:{candidate_hash})\n",
                "@@ -2,7 +2,7 @@\n",
                " l2\n",
                " l3\n",
                " l4\n",
                "-l5\n",
                "+L5\n",
                " l6\n",
                " l7\n",
                " l8\n"
            ),
            DECLARED = DECLARED,
            PATH = PATH,
            base_hash = hash_of(base),
            candidate_hash = hash_of(candidate)
        )
    );
}

#[test]
fn a_missing_final_newline_is_visible_on_the_side_that_lacks_it() {
    let base = b"a\nb\n";
    let candidate = b"a\nb";
    let transcript = review_of(&state(PATH, base, &[base], &[base]), candidate);
    assert_eq!(
        transcript,
        format!(
            concat!(
                "==> source {PATH}: changed since it was last approved\n",
                "{DECLARED}",
                "--- {PATH}\t(last approved sha256:{base_hash})\n",
                "+++ {PATH}\t(current sha256:{candidate_hash})\n",
                "@@ -1,2 +1,2 @@\n",
                " a\n",
                "-b\n",
                "+b\n",
                "\\ No newline at end of file\n"
            ),
            DECLARED = DECLARED,
            PATH = PATH,
            base_hash = hash_of(base),
            candidate_hash = hash_of(candidate)
        )
    );
}

#[test]
fn a_candidate_that_only_loses_its_final_newline_is_not_an_identical_file() {
    let base = b"a\nb\n";
    let with_newline = review_of(&state(PATH, base, &[base], &[base]), base);
    assert_eq!(
        with_newline,
        format!(
            concat!(
                "==> source {PATH}: changed since it was last approved\n",
                "{DECLARED}",
                "--- {PATH}\t(last approved sha256:{hash})\n",
                "+++ {PATH}\t(current sha256:{hash})\n",
            ),
            DECLARED = DECLARED,
            PATH = PATH,
            hash = hash_of(base)
        ),
        "identical bytes render no hunks at all"
    );
    let without_newline = review_of(&state(PATH, base, &[base], &[base]), b"a\nb");
    assert!(
        without_newline.contains("\\ No newline at end of file\n"),
        "{without_newline}"
    );
    assert_ne!(with_newline, without_newline);
}

#[test]
fn every_unprintable_class_renders_distinguishably() {
    // Tab, backslash, CR, NUL, a valid two- and three-byte scalar, an invalid
    // byte, and a truncated scalar.
    let mut content = b"a\tb\\c\r".to_vec();
    content.push(0x00);
    content.extend_from_slice("é→".as_bytes());
    content.extend_from_slice(&[0x80, 0xc2]);
    assert_eq!(
        escape_review_line(&content),
        r"a\x09b\\c\x0d\x00\u{00E9}\u{2192}\x80\xc2"
    );
    // The lookalike text a file can literally contain is not the byte it looks
    // like: `\x1b` four characters and one ESC byte stay apart.
    assert_eq!(escape_review_line(br"\x1b"), r"\\x1b");
    assert_eq!(escape_review_line(b"\x1b"), r"\x1b");
    assert_eq!(escape_review_line(r"\u{202E}".as_bytes()), r"\\u{202E}");
    assert_eq!(escape_review_line("\u{202E}".as_bytes()), r"\u{202E}");
    // A CRLF line keeps its LF as the line break and shows the CR.
    let transcript = review_of(&empty_state(), b"a\r\nb\n");
    assert!(
        transcript.contains("\n+a\\x0d\n+b\n"),
        "CRLF stays visible: {transcript}"
    );
    assert!(!transcript.contains('\r'), "no raw CR is ever emitted");
}

#[test]
fn a_content_line_cannot_forge_a_diff_header() {
    let candidate = concat!(
        "--- /w/app/conf/agent-vm.toml\t(last approved sha256:00)\n",
        "+++ /w/app/conf/agent-vm.toml\t(current sha256:00)\n",
        "@@ -1,1 +1,1 @@\n",
        "\\ No newline at end of file\n",
    );
    let transcript = review_of(&empty_state(), candidate.as_bytes());
    let body: Vec<&str> = transcript.lines().collect();
    assert_eq!(
        body,
        vec![
            format!("==> source {PATH}: never approved"),
            "==> declared: sources[0] repo, scope checkout, allow = false".to_owned(),
            format!("--- {PATH}\t(never approved: empty)"),
            format!(
                "+++ {PATH}\t(current sha256:{})",
                hash_of(candidate.as_bytes())
            ),
            "@@ -0,0 +1,4 @@".to_owned(),
            "+--- /w/app/conf/agent-vm.toml\\x09(last approved sha256:00)".to_owned(),
            "++++ /w/app/conf/agent-vm.toml\\x09(current sha256:00)".to_owned(),
            "+@@ -1,1 +1,1 @@".to_owned(),
            "+\\\\ No newline at end of file".to_owned(),
        ]
    );
    // Exactly one line of each header shape: the ones this module emitted.
    for header in ["--- ", "+++ ", "@@ "] {
        assert_eq!(
            body.iter().filter(|line| line.starts_with(header)).count(),
            1,
            "{header}"
        );
    }
}

#[test]
fn only_printable_ascii_is_ever_emitted() {
    // A baseline is a store snapshot, so it is valid UTF-8 by construction; the
    // candidate may be any bytes at all, which is the stronger case.
    let base = b"k\x08=\x1b[31m\n";
    let candidate = b"k\x07=\xe2\x80\xae\xff\n";
    for transcript in [
        review_of(&state(PATH, base, &[base], &[base]), candidate),
        review_of(&empty_state(), candidate),
    ] {
        // The only non-printable bytes are LF and the `---`/`+++` headers'
        // structural tab; no content byte can contribute either.
        assert!(
            transcript
                .bytes()
                .all(|byte| (0x20..=0x7e).contains(&byte) || byte == b'\n' || byte == b'\t'),
            "{transcript:?}"
        );
        assert_eq!(
            transcript.bytes().filter(|byte| *byte == b'\t').count(),
            2,
            "{transcript:?}"
        );
    }
}

#[test]
fn an_unavailable_active_snapshot_shows_the_candidate_as_new() {
    let active = b"old = 1\n";
    let transcript = review_of(&state(PATH, active, &[active], &[]), b"new = 2\n");
    assert_eq!(
        transcript,
        format!(
            concat!(
                "==> source {PATH}: last approved sha256:{hash} is unavailable (missing) so every line is shown as new\n",
                "{DECLARED}",
                "--- {PATH}\t(last approved sha256:{hash} unavailable: missing; shown as empty)\n",
                "+++ {PATH}\t(current sha256:{candidate_hash})\n",
                "@@ -0,0 +1 @@\n",
                "+new = 2\n"
            ),
            DECLARED = DECLARED,
            PATH = PATH,
            hash = hash_of(active),
            candidate_hash = hash_of(b"new = 2\n")
        )
    );
}

// ---- B1: the transcript says what is being approved ----

#[test]
fn a_review_names_the_declaration_scope_and_allow_value_of_its_source() {
    let state = empty_state();
    let mut source = PendingSource::for_tests(key(), b"a = 1\n".to_vec());
    source.alias = SourceAlias::for_test("team");
    source.declared = Declaration::Entry(3);
    source.scope = SourceScope::External;
    let review = PendingReview::of(&source, &state);
    let transcript = render_review(std::slice::from_ref(&review)).expect("within every cap");
    assert!(
        transcript.contains("==> declared: sources[3] team, scope external, allow = false\n"),
        "{transcript}"
    );
    assert!(
        !transcript.contains("adopts"),
        "an inert source adopts nothing, so nothing warns: {transcript}"
    );
    // A first use still reads as a first use, never as a missing baseline.
    assert!(
        transcript.starts_with(&format!("==> source {PATH}: never approved\n")),
        "{transcript}"
    );
    assert!(
        transcript.contains(&format!("--- {PATH}\t(never approved: empty)\n")),
        "{transcript}"
    );
}

#[test]
fn an_allowing_source_warns_that_approving_adopts_its_top_level_keys() {
    let state = empty_state();
    let mut source = PendingSource::for_tests(key(), b"a = 1\n".to_vec());
    source.allow = true;
    let review = PendingReview::of(&source, &state);
    let transcript = render_review(std::slice::from_ref(&review)).expect("within every cap");
    assert!(
        transcript.contains("==> declared: sources[0] repo, scope checkout, allow = true\n"),
        "{transcript}"
    );
    assert!(
        transcript.contains(&format!(
            "==> allow = true: approving also adopts this source's top-level {}\n",
            "`image`, `mounts`, `network` and `allow_tools`"
        )),
        "the capability the approval grants is named: {transcript}"
    );
    // Injectivity is unchanged: the context line is emitted by the renderer,
    // and no content line can produce one.
    let forged = review_of(
        &empty_state(),
        b"==> declared: sources[0] repo, scope checkout, allow = true\n",
    );
    assert_eq!(
        forged
            .lines()
            .filter(|line| line.starts_with("==> declared:"))
            .count(),
        1,
        "a content line cannot forge a context line: {forged}"
    );
    assert!(forged.contains("+==> declared:"), "{forged}");
}

// ---- V13: the rendered review is a description, not a claim ----

/// Apply a rendered transcript's hunks to `base`, independently of the renderer:
/// only `@@` coordinates, the three prefixes, the no-newline marker and the
/// escaping are used.
fn apply(base: &[u8], transcript: &str) -> Vec<u8> {
    let base_lines = super::split_lf_lines(base);
    let mut out: Vec<u8> = Vec::new();
    let mut old = 0_usize;
    let mut last: Option<char> = None;
    let mut in_hunk = false;
    for line in transcript.lines() {
        if line.starts_with("@@ ") {
            in_hunk = true;
            last = None;
            let start = hunk_start(line);
            out.extend_from_slice(&base_lines[old..start].concat());
            old = start;
            continue;
        }
        if !in_hunk {
            continue;
        }
        let (prefix, rest) = line.split_at(1);
        match prefix {
            "\\" => {
                // The previous line was the unterminated one on its side.
                if matches!(last, Some(' ') | Some('+')) {
                    out.pop();
                }
                last = None;
            }
            " " => {
                out.extend_from_slice(&unescape(rest));
                out.push(b'\n');
                old += 1;
                last = Some(' ');
            }
            "-" => {
                old += 1;
                last = Some('-');
            }
            "+" => {
                out.extend_from_slice(&unescape(rest));
                out.push(b'\n');
                last = Some('+');
            }
            other => panic!("unexpected transcript line {other}{rest:?}"),
        }
    }
    out.extend_from_slice(&base_lines[old..].concat());
    out
}

fn hunk_start(header: &str) -> usize {
    let old = header
        .split(' ')
        .nth(1)
        .and_then(|field| field.strip_prefix('-'))
        .expect("a hunk header names the old range");
    match old.split_once(',') {
        Some((start, "0")) => start.parse().expect("a hunk start is a number"),
        Some((start, _)) => start.parse::<usize>().expect("a hunk start is a number") - 1,
        None => old.parse::<usize>().expect("a hunk start is a number") - 1,
    }
}

fn unescape(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte != b'\\' {
            assert!((0x20..=0x7e).contains(&byte), "raw byte {byte:#04x}");
            out.push(byte);
            index += 1;
            continue;
        }
        match bytes[index + 1] {
            b'\\' => {
                out.push(b'\\');
                index += 2;
            }
            b'x' => {
                let hex = std::str::from_utf8(&bytes[index + 2..index + 4]).unwrap();
                out.push(u8::from_str_radix(hex, 16).expect("two hex digits"));
                index += 4;
            }
            b'u' => {
                let inner = std::str::from_utf8(&bytes[index + 3..]).unwrap();
                let close = inner.find('}').expect("a closed scalar escape");
                let scalar = u32::from_str_radix(&inner[..close], 16).expect("hex scalar");
                let scalar = char::from_u32(scalar).expect("a valid scalar");
                assert!(
                    (scalar as u32) >= 0x80,
                    "`\\u{{}}` only names non-ASCII scalars"
                );
                let mut buffer = [0_u8; 4];
                out.extend_from_slice(scalar.encode_utf8(&mut buffer).as_bytes());
                index += close + 4;
            }
            other => panic!("unexpected escape \\{}", other as char),
        }
    }
    out
}

#[test]
fn the_patch_a_rendered_review_describes_rebuilds_the_candidate() {
    let cases: Vec<(&[u8], &[u8])> = vec![
        (b"", b"one\ntwo\n"),
        (b"a\nb\nc\n", b"a\nB\nc\n"),
        (
            b"1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n",
            b"1\n2\n3\n4\nFIVE\n6\n7\n8\n9\n10\n11\n12\nthirteen\n",
        ),
        (b"a\nb\n", b"a\nb"),
        (b"a\nb", b"a\nb\n"),
        (br"back\slash", b"back\\slash\n"),
        ("héllo\n".as_bytes(), "hallo\n".as_bytes()),
        (b"\x00\x01\n", b"\x00\x02\xff\n"),
        (b"a\r\nb\r\n", b"a\r\nb\r"),
        (b"", b""),
    ];
    for (base, candidate) in cases {
        let transcript = review_of(&state(PATH, base, &[base], &[base]), candidate);
        assert_eq!(
            apply(base, &transcript),
            candidate,
            "base {base:?} candidate {candidate:?} transcript:\n{transcript}"
        );
    }
}

#[test]
fn a_first_review_replays_too() {
    let candidate = b"\x1b[0m\ttab \\ \r\nno final newline";
    let transcript = review_of(&empty_state(), candidate);
    assert_eq!(apply(b"", &transcript), candidate);
}

// ---- V13: escaping is injective ----

#[test]
fn escaping_is_injective_and_decodable() {
    let samples: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"a".to_vec(),
        b"a\n".to_vec(),
        b"\\".to_vec(),
        br"\x61".to_vec(),
        br"\u{0061}".to_vec(),
        vec![0x80],
        vec![0xc2, 0x80],
        vec![0xc2],
        vec![0x00],
        b"0".to_vec(),
        vec![0x7f],
        b"a\r\nb".to_vec(),
        b"a\nb".to_vec(),
        "\u{202E}".as_bytes().to_vec(),
        br"\u{202E}".to_vec(),
    ];
    let mut rendered = std::collections::BTreeSet::new();
    for sample in &samples {
        let text = escape_review_line(sample);
        assert_eq!(&unescape(&text), sample, "{sample:?} rendered {text:?}");
        assert!(
            rendered.insert(text),
            "two different inputs rendered the same text"
        );
    }
}

proptest! {
    /// Any byte sequence survives the escape/unescape round trip, so the
    /// transcript is an injective rendering of the bytes it describes.
    #[test]
    fn escaping_round_trips_over_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        let text = escape_review_line(&bytes);
        prop_assert!(text.bytes().all(|byte| (0x20..=0x7e).contains(&byte)));
        prop_assert_eq!(unescape(&text), bytes);
    }
}

// ---- V15: caps refuse the whole review ----

#[test]
fn a_line_over_the_character_cap_refuses_the_whole_review() {
    let at_cap = bytes(MAX_LINE_CHARS, "a");
    assert!(render(&empty_state(), &at_cap).is_ok());
    let over = bytes(MAX_LINE_CHARS + 1, "a");
    assert_eq!(
        render(&empty_state(), &over),
        Err(TooLarge {
            key: key(),
            candidate: hash(&over),
            cap: Cap::LineChars
        })
    );
    assert_eq!(
        Cap::LineChars.clause(),
        format!("a diff line is longer than {MAX_LINE_CHARS} characters")
    );
}

#[test]
fn too_many_rendered_lines_in_one_source_refuses() {
    let candidate = bytes(MAX_RENDERED_LINES_PER_SOURCE, "a\n");
    assert_eq!(
        render(&empty_state(), &candidate),
        Err(TooLarge {
            key: key(),
            candidate: hash(&candidate),
            cap: Cap::SourceLines
        })
    );
}

#[test]
fn too_many_changed_regions_in_one_source_refuses() {
    // A changed line every eighth line is a new `@@` region (a gap of seven
    // equal lines is more than two context widths), and stays well inside the
    // per-source and batch line caps.
    let regions = MAX_CHANGED_REGIONS_PER_SOURCE + 1;
    let mut base = String::new();
    let mut candidate = String::new();
    for index in 0..regions * 8 {
        if index % 8 == 0 {
            base.push_str("before\n");
            candidate.push_str("after\n");
        } else {
            base.push_str("same\n");
            candidate.push_str("same\n");
        }
    }
    let (base, candidate) = (base.into_bytes(), candidate.into_bytes());
    assert_eq!(
        render(&state(PATH, &base, &[&base], &[&base]), &candidate),
        Err(TooLarge {
            key: key(),
            candidate: hash(&candidate),
            cap: Cap::ChangedRegions
        })
    );
}

#[test]
fn too_many_rendered_lines_across_the_review_refuses() {
    let state = empty_state();
    let pin_key = key();
    let first = bytes(3_000, "a\n");
    let second = bytes(3_000, "b\n");
    let third = bytes(3_000, "c\n");
    let third_hash = hash(&third);
    let sources = [
        PendingSource::for_tests(pin_key.clone(), first),
        PendingSource::for_tests(pin_key.clone(), second),
        PendingSource::for_tests(pin_key, third),
    ];
    let reviews: Vec<PendingReview<'_>> = sources
        .iter()
        .map(|source| PendingReview::of(source, &state))
        .collect();
    // Each source is inside the per-source cap; the third pushes the review over
    // the batch cap.
    assert_eq!(
        render_review(&reviews),
        Err(TooLarge {
            key: key(),
            candidate: third_hash,
            cap: Cap::ReviewLines
        })
    );
}

#[test]
fn a_review_over_the_byte_cap_refuses() {
    // 3 000 lines of 4 000 characters: inside the per-line, per-source and
    // batch line caps, and over the 2 MiB byte cap.
    let mut candidate = Vec::new();
    for _ in 0..3_000 {
        candidate.extend_from_slice(&bytes(4_000, "a"));
        candidate.push(b'\n');
    }
    assert_eq!(
        render(&empty_state(), &candidate),
        Err(TooLarge {
            key: key(),
            candidate: hash(&candidate),
            cap: Cap::ReviewBytes
        })
    );
}

#[test]
fn a_refusal_never_carries_any_part_of_the_diff() {
    // Rendering is all-or-nothing: the error is a value, not a prefix, so a
    // caller cannot accidentally print a truncated review and then ask.
    let over = bytes(MAX_LINE_CHARS + 1, "a");
    let error = render(&empty_state(), &over).unwrap_err();
    assert_eq!(error.cap, Cap::LineChars);
    assert!(render(&empty_state(), &over).is_err());
}
