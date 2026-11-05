//! ADR-0059: the `egress_reference` tests, and the A37 source guard over the
//! production files.
//!
//! Tests live in their own modules by construction, not by a rule the code has to
//! detect: `egress_reference.rs` and `egress_reference/sets.rs` hold only
//! production code, and their tests live in `egress_reference/tests.rs` and
//! `egress_reference/sets/tests.rs`, so the guard's scans of
//! `include_str!("../egress_reference.rs")` and `include_str!("sets.rs")` cover
//! production in full and need no boundary marker to look for.
//!
//! What those scans can and cannot say is bounded (ADR-0018): they match tokens
//! in the text, so they catch accidental drift and the named regressions, and
//! they do **not** establish that no allowance can be minted. A token split
//! across lines, an alias or re-export, a macro, a helper in the parent module,
//! or a `//`-leading line that closes an earlier block comment each mint while
//! the scan is green. Provenance and data flow are structural review (A46).

use self::test_support::{resolve_ok, set_ref, tool_ref, user_tools};
use super::*;
use crate::config::RESERVED_TOOL_NAMES;
use proptest::prelude::*;
use std::path::Path;

pub(crate) mod test_support {
    use crate::egress_reference::*;

    /// A namespace built straight from `(name, requests)` pairs, for tests in
    /// other modules that need a resolvable tool without a whole config file.
    ///
    /// No sets: a `set:` reference against one of these namespaces is `UnknownSet`
    /// by construction, which is what the tool-side tests want.
    pub(crate) fn user_tools(
        file: &std::path::Path,
        tools: &[(&str, &[&str])],
    ) -> UserToolRequests {
        user_namespace(file, tools, None)
    }

    /// The same, with `[egress_sets]` declarations, through the real parse and the
    /// real compile: a fixture that hand-built the closures could disagree with
    /// what a file does.
    pub(crate) fn user_namespace(
        file: &std::path::Path,
        tools: &[(&str, &[&str])],
        egress_sets: Option<&str>,
    ) -> UserToolRequests {
        let mut requests = BTreeMap::new();
        for (name, raw) in tools {
            let raw: Vec<String> = raw.iter().map(|request| (*request).to_owned()).collect();
            requests.insert((*name).to_owned(), NetworkRequests::parse(&raw).unwrap());
        }
        let table: toml::Table = egress_sets.unwrap_or_default().parse().expect("test TOML");
        let parsed = sets::parse(&toml::Value::Table(table)).expect("test [egress_sets] is valid");
        UserToolRequests {
            trust: ReferenceTrust::verified_for_test(file),
            sets: Box::new(
                sets::compile(parsed, |name| tool_expansion(&requests, name))
                    .expect("test egress sets compile"),
            ),
            requests,
        }
    }

    /// The tool reference one claimed `tool:NAME` becomes, spelled here rather
    /// than constructed inline so the private payload is reached in one place.
    pub(crate) fn tool_ref(name: &str) -> EgressReference {
        EgressReference(Target::Tool(name.to_owned()))
    }

    /// The set reference one claimed `set:NAME` becomes.
    pub(super) fn set_ref(name: &str) -> EgressReference {
        EgressReference(Target::Set(
            super::super::sets::EgressSetName::parse(name).expect("a valid egress-set name"),
        ))
    }

    pub(crate) fn resolve_ok(
        texts: &[&str],
        user_tools: Option<&UserToolRequests>,
    ) -> ResolvedAllowances {
        let entries = texts
            .iter()
            .map(|text| AllowanceEntry::parse(text).unwrap())
            .collect();
        resolve(entries, user_tools).unwrap()
    }
}

/// A test-only membership oracle, for other modules' `#[cfg(test)]` helpers.
/// It lives in the test module because the production file holds no test-only
/// code at all (A37).
impl ResolvedAllowances {
    pub(crate) fn contains(&self, allowance: &Allowance) -> bool {
        self.entries
            .iter()
            .any(|entry| &entry.allowance == allowance)
    }
}

const USER_FILE: &str = "/home/u/.config/agent-vm/config.toml";

/// An independently written oracle for the kernel, because a spec function
/// erases under a plain build: this is the executable form the proof is
/// *about*, restated without the spec.
fn oracle(bytes: &[u8]) -> bool {
    bytes.len() >= 5 && bytes[..5].eq_ignore_ascii_case(b"tool:") && !bytes[5..].starts_with(b"//")
}

#[test]
fn reference_claim_matches_byte_oracle() {
    const ALPHABET: &[u8] = b"tToOlL:/xX.-\x00\x1b\xc3";
    for length in 0..=7usize {
        for combo in 0..(ALPHABET.len() as u64).pow(length as u32) {
            let mut bytes = Vec::with_capacity(length);
            let mut rest = combo;
            for _ in 0..length {
                bytes.push(ALPHABET[(rest % ALPHABET.len() as u64) as usize]);
                rest /= ALPHABET.len() as u64;
            }
            assert_eq!(
                reference_claim(&bytes),
                oracle(&bytes),
                "claim disagreed for {bytes:?}"
            );
        }
    }
    // The boundary cases that decide the two grammars, written out.
    for (bytes, claimed) in [
        (&b"tool:"[..], true),
        (&b"TOOL:"[..], true),
        (&b"ToOl:"[..], true),
        (&b"tool:443"[..], true),
        (&b"tool://x.example"[..], false),
        (&b"tool:/"[..], true),
        (&b"tool:x"[..], true),
        (&b"tool"[..], false),
        (&b"toolx"[..], false),
        (&b""[..], false),
        (&b"tcp://tool:443"[..], false),
    ] {
        assert_eq!(reference_claim(bytes), claimed, "{bytes:?}");
    }
}

proptest! {
    #[test]
    fn reference_claim_matches_byte_oracle_on_arbitrary_bytes(
        bytes in proptest::collection::vec(
            prop_oneof![
                Just(b't'), Just(b'T'), Just(b'o'), Just(b'O'), Just(b'l'), Just(b'L'),
                Just(b':'), Just(b'/'), any::<u8>(),
            ],
            0..=12,
        )
    ) {
        prop_assert_eq!(reference_claim(&bytes), oracle(&bytes));
    }
}

/// A1, A3, A4, A5: the parse table. Only `tool:NAME` moves grammar; every
/// other text keeps `Allowance::parse`'s exact result.
#[test]
fn reference_parse_table() {
    for (text, expected) in [
        ("tool:codex", "codex"),
        ("TOOL:codex", "codex"),
        ("Tool:codex", "codex"),
        // The name is byte-exact: the prefix folds case, the name does not.
        ("tool:Codex", "Codex"),
        ("tool:443", "443"),
        ("tool:0", "0"),
    ] {
        let entry = AllowanceEntry::parse(text).unwrap();
        let AllowanceEntry::Reference(reference) = &entry else {
            panic!("{text} was not claimed")
        };
        assert_eq!(reference, &tool_ref(expected));
        assert_eq!(reference.to_string(), format!("tool:{expected}"));
    }
    // Not claimed: the grammar decides, exactly as before.
    for text in ["tcp://tool:443", "tool.:443", "tool", "toolx", "tools"] {
        match AllowanceEntry::parse(text).unwrap() {
            AllowanceEntry::Literal(allowance) => assert_eq!(
                allowance.to_string(),
                Allowance::parse(text).unwrap().to_string()
            ),
            AllowanceEntry::Reference(reference) => {
                panic!("{text} was claimed as {reference}")
            }
        }
    }
    assert_eq!(
        Allowance::parse("tool:443").unwrap().to_string(),
        "tcp://tool:443",
        "the old meaning of `tool:443` must stay the literal meaning"
    );
    assert_eq!(
        AllowanceEntry::parse("tool:443").unwrap(),
        AllowanceEntry::Reference(tool_ref("443"))
    );
    // A4: the scheme refusal keeps its own text.
    assert_eq!(
        AllowanceEntry::parse("tool://x.example"),
        Err(EntryError::Allowance(AllowanceError::UnsupportedScheme))
    );
    assert_eq!(
        AllowanceEntry::parse("tool://x.example")
            .unwrap_err()
            .to_string(),
        Allowance::parse("tool://x.example")
            .unwrap_err()
            .to_string()
    );
}

/// A5, and A20's no-echo half: every name no tool can have is one fixed
/// malformed-reference text, never an unknown-name error.
///
/// The expected text is written out again, independently of
/// [`MALFORMED`]: an oracle that interpolates the production constant moves
/// with it, so this test would keep passing after the sentence changed.
#[test]
fn malformed_reference_names_are_one_fixed_text() {
    const SENTINEL: &str = "SENTINEL7";
    const MALFORMED_INDEPENDENT: &str = "an egress reference must be tool:NAME with a valid tool name (no whitespace, control characters or '/', not starting with '-', and not `.`, `..`, `*` or a reserved subcommand name)";
    assert_eq!(
        MALFORMED, MALFORMED_INDEPENDENT,
        "the sentence A5 pins is the sentence the crate ships"
    );
    for name in [
        "",
        "-x",
        "a/b",
        "a b",
        "*",
        ".",
        "..",
        "run",
        "help",
        "tools",
        "setup",
        "\x1b",
        "a\u{1b}b",
        "a\tb",
        "-",
        "\u{1b}SENTINEL7",
    ] {
        let error = AllowanceEntry::parse(&format!("tool:{name}")).unwrap_err();
        assert_eq!(error, EntryError::MalformedReference, "for name {name:?}");
        assert_eq!(error.to_string(), MALFORMED_INDEPENDENT);
        assert!(!error.to_string().contains(SENTINEL));
    }
}

/// A6: the reference name rule and the `[[tools]]` name rule are one rule,
/// over a corpus that includes every reserved subcommand.
#[test]
fn reference_names_match_tool_names() {
    let mut corpus: Vec<String> = RESERVED_TOOL_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    corpus.extend(
        [
            "codex", "Codex", "443", "8443", "0", "a.b", "a-b", "*", ".", "..", "run", "-x", "a/b",
            "a b", "\t", "café", "a:b", "", "shell", "x_y", "0x10",
        ]
        .iter()
        .map(|name| (*name).to_owned()),
    );
    for name in corpus {
        assert_eq!(
            crate::config::tool_name_rejection(&name).is_none(),
            matches!(
                AllowanceEntry::parse(&format!("tool:{name}")),
                Ok(AllowanceEntry::Reference(_))
            ),
            "the two name rules disagreed for {name:?}"
        );
    }
}

/// An independently written oracle for the `set:` kernel, restated without the
/// spec function for the same reason as [`oracle`].
fn set_oracle(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4].eq_ignore_ascii_case(b"set:") && !bytes[4..].starts_with(b"//")
}

/// A1: the `set:` claim agrees with the byte oracle everywhere the decision can
/// depend on a byte.
#[test]
fn set_claim_matches_byte_oracle() {
    const ALPHABET: &[u8] = b"sSeEtT:/xX.-\x00\x1b\xc3";
    for length in 0..=7usize {
        for combo in 0..(ALPHABET.len() as u64).pow(length as u32) {
            let mut bytes = Vec::with_capacity(length);
            let mut rest = combo;
            for _ in 0..length {
                bytes.push(ALPHABET[(rest % ALPHABET.len() as u64) as usize]);
                rest /= ALPHABET.len() as u64;
            }
            assert_eq!(
                set_reference_claim(&bytes),
                set_oracle(&bytes),
                "claim disagreed for {bytes:?}"
            );
        }
    }
    for (bytes, claimed) in [
        (&b"set:"[..], true),
        (&b"SET:"[..], true),
        (&b"SeT:"[..], true),
        (&b"set:443"[..], true),
        (&b"set://x.example"[..], false),
        (&b"set:/"[..], true),
        (&b"set:x"[..], true),
        (&b"set"[..], false),
        (&b"setx"[..], false),
        (&b""[..], false),
        (&b"sett:443"[..], false),
        (&b"tcp://set:443"[..], false),
        // The neighbour kernel's text: a claim here would route `tool:` twice.
        (&b"tool:443"[..], false),
        (&b"TOOL:443"[..], false),
    ] {
        assert_eq!(set_reference_claim(bytes), claimed, "{bytes:?}");
    }
}

proptest! {
    #[test]
    fn set_claim_matches_byte_oracle_on_arbitrary_bytes(
        bytes in proptest::collection::vec(
            prop_oneof![
                Just(b's'), Just(b'S'), Just(b'e'), Just(b'E'), Just(b't'), Just(b'T'),
                Just(b':'), Just(b'/'), any::<u8>(),
            ],
            0..=12,
        )
    ) {
        prop_assert_eq!(set_reference_claim(&bytes), set_oracle(&bytes));
    }
}

/// A7's deterministic corpus: every prefix whose two readings a reader could
/// confuse, each of which one kernel claims at most.
const CROSS_PREFIX_CORPUS: [&str; 13] = [
    "set:443",
    "SET:8443",
    "tool:443",
    "set:tool:x",
    "tool:set:x",
    "tcp://set:443",
    "tcp://tool:443",
    "set://tool:1",
    "tool://set:1",
    "sett:443",
    "toolset:1",
    "set:",
    "tool:",
];

/// A3: no byte string is claimed by both kernels, so the adapter's order cannot
/// change a decision.
#[test]
fn tool_and_set_claims_are_disjoint() {
    // Exhaustive over the alphabet both prefixes are spelled from, to the length
    // at which the third byte that separates them has been read.
    const ALPHABET: &[u8] = b"sSeEtToOlL:";
    for length in 0..=5usize {
        for combo in 0..(ALPHABET.len() as u64).pow(length as u32) {
            let mut bytes = Vec::with_capacity(length);
            let mut rest = combo;
            for _ in 0..length {
                bytes.push(ALPHABET[(rest % ALPHABET.len() as u64) as usize]);
                rest /= ALPHABET.len() as u64;
            }
            assert!(
                !(reference_claim(&bytes) && set_reference_claim(&bytes)),
                "{bytes:?} was claimed twice"
            );
        }
    }
    for text in CROSS_PREFIX_CORPUS {
        assert!(
            !(reference_claim(text.as_bytes()) && set_reference_claim(text.as_bytes())),
            "{text:?} was claimed twice"
        );
    }
}

proptest! {
    #[test]
    fn tool_and_set_claims_are_disjoint_on_arbitrary_bytes(
        bytes in proptest::collection::vec(
            prop_oneof![
                Just(b't'), Just(b'T'), Just(b's'), Just(b'S'), Just(b'e'), Just(b'E'),
                Just(b'o'), Just(b'O'), Just(b'l'), Just(b'L'), Just(b':'), Just(b'/'),
                any::<u8>(),
            ],
            0..=12,
        )
    ) {
        prop_assert!(!(reference_claim(&bytes) && set_reference_claim(&bytes)));
    }
}

/// A4, R3 and R4: which `set:` text is a reference, which name it holds, and
/// what a `set:` scheme still is.
#[test]
fn set_reference_parse_table() {
    for (text, expected) in [
        ("set:corp", "corp"),
        ("SET:corp", "corp"),
        ("Set:8443", "8443"),
        ("set:0", "0"),
        ("set:0443", "0443"),
        ("set:53", "53"),
        ("set:65536", "65536"),
        // The prefix folds case; the name does not.
        ("set:Corp", "Corp"),
    ] {
        let entry = AllowanceEntry::parse(text).unwrap();
        let AllowanceEntry::Reference(reference) = &entry else {
            panic!("{text} was not claimed")
        };
        assert_eq!(reference, &set_ref(expected));
        assert_eq!(reference.to_string(), format!("set:{expected}"));
    }
    // `Corp` and `corp` are distinct names, not one folded name.
    assert_ne!(set_ref("Corp"), set_ref("corp"));
    // Not claimed: the grammar decides, exactly as before. `tcp://set:443` is
    // the rewrite the upgrade note gives, so it must keep meaning what it did.
    for text in [
        "tcp://set:443",
        "set.:443",
        "set",
        "setx",
        "sets",
        "sett:443",
    ] {
        match AllowanceEntry::parse(text).unwrap() {
            AllowanceEntry::Literal(allowance) => assert_eq!(
                allowance.to_string(),
                Allowance::parse(text).unwrap().to_string()
            ),
            AllowanceEntry::Reference(reference) => {
                panic!("{text} was claimed as {reference}")
            }
        }
    }
    assert_eq!(
        Allowance::parse("set:8443").unwrap().to_string(),
        "tcp://set:8443",
        "the old meaning of `set:8443` must stay the literal meaning"
    );
    // A4/R4: `set://…` keeps `Allowance::parse`'s scheme refusal byte for byte.
    assert_eq!(
        AllowanceEntry::parse("set://x.example"),
        Err(EntryError::Allowance(AllowanceError::UnsupportedScheme))
    );
    assert_eq!(
        AllowanceEntry::parse("set://x.example")
            .unwrap_err()
            .to_string(),
        Allowance::parse("set://x.example").unwrap_err().to_string()
    );
}

/// A5, A28 and A36's unit half: every name no set can have is one fixed
/// malformed-reference text, which echoes neither the name nor a sentinel.
#[test]
fn malformed_set_names_are_one_fixed_text() {
    const SENTINEL: &str = "SENTINEL7";
    const MALFORMED_INDEPENDENT: &str = "an egress reference must be set:NAME with a valid egress-set name ([A-Za-z0-9_] first, then [A-Za-z0-9_.-])";
    assert_eq!(
        MALFORMED_SET, MALFORMED_INDEPENDENT,
        "the sentence A5 pins is the sentence the crate ships"
    );
    for name in [
        "",
        "-x",
        ".x",
        "a/b",
        "a b",
        "a:b",
        "café",
        "\x1bSENTINEL7",
        "..",
        "*",
        "a\tb",
    ] {
        let error = AllowanceEntry::parse(&format!("set:{name}")).unwrap_err();
        assert_eq!(
            error,
            EntryError::MalformedSetReference,
            "for name {name:?}"
        );
        assert_eq!(error.to_string(), MALFORMED_INDEPENDENT);
        assert!(!error.to_string().contains(SENTINEL));
    }
}

/// A6: the reference name rule and the mount-set name rule are one rule.
///
/// Differential on purpose: the two namespaces have separate types, and the only
/// way to keep them from drifting is to ask the proved predicate both ways.
#[test]
fn set_reference_names_match_mount_set_names() {
    let mut corpus: Vec<String> = [
        "corp", "Corp", "CORP", "8443", "0", "0443", "65536", "a.b", "a-b", "_x", "x_", ".", "..",
        "-x", ".x", "a/b", "a b", "a:b", "café", "", "\t", "0x10", "a",
    ]
    .iter()
    .map(|name| (*name).to_owned())
    .collect();
    corpus.extend(
        crate::config::TOP_LEVEL_FIELDS
            .iter()
            .map(|f| (*f).to_owned()),
    );
    for name in corpus {
        let reference_accepts = matches!(
            AllowanceEntry::parse(&format!("set:{name}")),
            Ok(AllowanceEntry::Reference(_))
        );
        assert_eq!(
            crate::config_mounts::mount_set_name_bytes(name.as_bytes()),
            reference_accepts,
            "the two name rules disagreed for {name:?}"
        );
    }
}

/// A7: the same claimed-set property for `set:` that the `tool:` helper states —
/// claimed text is either the fixed malformed error or the reference, and the
/// grammar's own reading is an error or the hostname `set` on an explicit port
/// (the R5 break set), never an allowance that survives as written.
fn claimed_text_is_only_an_error_or_the_set_hostname(text: &str) {
    let claimed = set_reference_claim(text.as_bytes());
    let literal = Allowance::parse(text);
    if !claimed {
        // The *other* kernel's text is not this helper's to interpret: assert
        // only that it was delegated, and let the tool helper judge its own.
        if reference_claim(text.as_bytes()) {
            assert!(
                !matches!(AllowanceEntry::parse(text), Ok(AllowanceEntry::Literal(_))),
                "tool-claimed text reached the allowance grammar as a literal: {text:?}"
            );
            return;
        }
        match (AllowanceEntry::parse(text), literal) {
            (Ok(AllowanceEntry::Literal(entry)), Ok(allowance)) => assert_eq!(entry, allowance),
            (Err(EntryError::Allowance(entry)), Err(error)) => assert_eq!(entry, error),
            (other, _) => {
                panic!("unclaimed text left the grammar: {text:?} -> {other:?}")
            }
        }
        return;
    }
    let name = text
        .get(SET_PREFIX_LEN..)
        .expect("the claim fixes four ASCII bytes, so this is a char boundary");
    let name_is_valid = crate::config_mounts::mount_set_name_bytes(name.as_bytes());
    let entry = AllowanceEntry::parse(text);
    match &entry {
        Ok(AllowanceEntry::Reference(reference)) => {
            assert!(
                name_is_valid,
                "claimed {text:?} became a reference, but `mount_set_name_bytes` rejects the name {name:?}"
            );
            assert!(
                matches!(&reference.0, Target::Set(set) if set.as_str() == name),
                "a claimed reference must hold exactly the bytes after the prefix"
            );
        }
        Err(EntryError::MalformedSetReference) => assert!(
            !name_is_valid,
            "claimed {text:?} was refused as malformed, but the name {name:?} is valid"
        ),
        other => panic!("claimed text did not reach the reference rule: {text:?} -> {other:?}"),
    }
    match literal {
        Err(_) => {}
        Ok(Allowance::Hostname(hostname)) => {
            let rendered = hostname.to_string();
            let port = rendered
                .strip_prefix("tcp://set:")
                .unwrap_or_else(|| panic!("claimed {text:?} parsed as {rendered}"));
            let port: u16 = port.parse().unwrap();
            assert!(port >= 1 && port != 53 && port != 853, "{text:?} -> {port}");
        }
        Ok(Allowance::Address(_)) => panic!("claimed an address: {text:?}"),
    }
}

#[test]
fn set_claims_only_errors_or_the_set_hostname() {
    // (a) a restricted alphabet with every prefix the grammar cares about.
    const ALPHABET: &[u8] = b"set:/.0123456789";
    for prefix in ["", "set:", "SET:", "set://", "tcp://"] {
        for length in 0..=4usize {
            for combo in 0..(ALPHABET.len() as u64).pow(length as u32) {
                let mut text = prefix.to_owned();
                let mut rest = combo;
                for _ in 0..length {
                    text.push(ALPHABET[(rest % ALPHABET.len() as u64) as usize] as char);
                    rest /= ALPHABET.len() as u64;
                }
                claimed_text_is_only_an_error_or_the_set_hostname(&text);
            }
        }
    }
    // (b) targeted combinations, and A7's cross-prefix corpus.
    for prefix in [
        "set:", "SET:", "Set:", "sEt:", "seT:", "sET:", "set:/", "set://", "SET://", "tcp://",
        "xset:", "s e t:",
    ] {
        for suffix in [
            "",
            "a",
            "ab",
            "abc",
            "-x",
            "a b",
            "a\tb",
            "\u{1b}",
            "\u{0}",
            "café",
            "\u{1b}SENTINEL7",
            "/",
            "//x",
            ".",
            "..",
            "*",
            "corp",
            "443",
            "8443",
            "0",
            "65536",
            "a/../b",
            "a:b",
            "tool:x",
        ] {
            claimed_text_is_only_an_error_or_the_set_hostname(&format!("{prefix}{suffix}"));
        }
    }
    for text in CROSS_PREFIX_CORPUS {
        claimed_text_is_only_an_error_or_the_set_hostname(text);
    }
}

proptest! {
    #[test]
    fn set_claims_only_errors_or_the_set_hostname_on_any_string(text in any::<String>()) {
        claimed_text_is_only_an_error_or_the_set_hostname(&text);
    }

    #[test]
    fn set_claims_only_errors_or_the_set_hostname_on_long_strings(text in ".{0,300}") {
        claimed_text_is_only_an_error_or_the_set_hostname(&text);
    }
}

/// A2: the claimed set is exactly "allowance errors" plus "the hostname
/// `tool` on an explicit port", i.e. the R27 break set — and claimed text is
/// *routed*: the branch is the one `config::tool_name_rejection` implies for
/// this name, so a valid claimed name is a reference and an invalid one the
/// fixed malformed error, never a fall-through to the old grammar and never
/// "whichever of the two the adapter happened to pick". This pins routing; it
/// does not and cannot prove that expansions re-parse (the A37 source check
/// pins the call site, and no test can pin the data flow).
fn claimed_text_is_only_an_error_or_the_tool_hostname(text: &str) {
    let claimed = reference_claim(text.as_bytes());
    let literal = Allowance::parse(text);
    if !claimed {
        // The *other* kernel's text is not this helper's to interpret: assert
        // only that it was delegated, and let the set helper judge its own.
        if set_reference_claim(text.as_bytes()) {
            assert!(
                !matches!(AllowanceEntry::parse(text), Ok(AllowanceEntry::Literal(_))),
                "set-claimed text reached the allowance grammar as a literal: {text:?}"
            );
            return;
        }
        // Unclaimed text is handed to the grammar unchanged: same `Ok`, or
        // the same error variant.
        match (AllowanceEntry::parse(text), literal) {
            (Ok(AllowanceEntry::Literal(entry)), Ok(allowance)) => assert_eq!(entry, allowance),
            (Err(EntryError::Allowance(entry)), Err(error)) => assert_eq!(entry, error),
            (other, _) => {
                panic!("unclaimed text left the grammar: {text:?} -> {other:?}")
            }
        }
        return;
    }
    // Claimed. Both halves of the adapter: the *name* rule decides between a
    // reference and the fixed malformed error, and the old grammar's result
    // must be an error or the R27 hostname. An adapter that let part of the
    // claimed set fall through to `Allowance::parse` would show up here as a
    // `Literal`, which is why the entry result is checked and not only the
    // grammar's.
    //
    // The branch is not "either claimed outcome": it is the one the shared
    // name predicate implies, so a valid name wrongly refused as malformed and
    // an invalid name wrongly accepted as a reference both fail here.
    let name = text
        .get(PREFIX_LEN..)
        .expect("the claim fixes five ASCII bytes, so this is a char boundary");
    let name_is_valid = tool_name_rejection(name).is_none();
    let entry = AllowanceEntry::parse(text);
    match &entry {
        Ok(AllowanceEntry::Reference(reference)) => {
            assert!(
                name_is_valid,
                "claimed {text:?} became a reference, but `tool_name_rejection` rejects the name {name:?}"
            );
            assert!(
                matches!(&reference.0, Target::Tool(name) if Some(name.as_str()) == text.get(PREFIX_LEN..)),
                "a claimed reference must hold exactly the bytes after the prefix"
            );
        }
        Err(EntryError::MalformedReference) => assert!(
            !name_is_valid,
            "claimed {text:?} was refused as malformed, but `tool_name_rejection` accepts the name {name:?}"
        ),
        other => panic!("claimed text did not reach the reference rule: {text:?} -> {other:?}"),
    }
    // The display form is the oracle, independently of `HostnameAllowance`'s
    // internals.
    match literal {
        Err(_) => {}
        Ok(Allowance::Hostname(hostname)) => {
            let rendered = hostname.to_string();
            let port = rendered
                .strip_prefix("tcp://tool:")
                .unwrap_or_else(|| panic!("claimed {text:?} parsed as {rendered}"));
            let port: u16 = port.parse().unwrap();
            assert!(port >= 1 && port != 53 && port != 853, "{text:?} -> {port}");
        }
        Ok(Allowance::Address(_)) => panic!("claimed an address: {text:?}"),
    }
}

#[test]
fn reference_claims_only_errors_or_the_tool_hostname() {
    // (a) a restricted alphabet with every prefix the grammar cares about.
    const ALPHABET: &[u8] = b"tool:/.0123456789";
    for prefix in ["", "tool:", "TOOL:", "tool://", "tcp://"] {
        for length in 0..=4usize {
            for combo in 0..(ALPHABET.len() as u64).pow(length as u32) {
                let mut text = prefix.to_owned();
                let mut rest = combo;
                for _ in 0..length {
                    text.push(ALPHABET[(rest % ALPHABET.len() as u64) as usize] as char);
                    rest /= ALPHABET.len() as u64;
                }
                claimed_text_is_only_an_error_or_the_tool_hostname(&text);
            }
        }
    }
    // (b) targeted combinations a whole-string generator rarely produces:
    // every mixed-case prefix, the `//` boundaries, controls, non-ASCII and
    // every name length 0–7.
    for prefix in [
        "tool:", "TOOL:", "Tool:", "tOoL:", "tOOL:", "TOOl:", "tool:/", "tool://", "TOOL://",
        "tcp://", "xtool:", "t o o l:",
    ] {
        for suffix in [
            "",
            "a",
            "ab",
            "abc",
            "-x",
            "a b",
            "a\tb",
            "\u{1b}",
            "\u{0}",
            "café",
            "\u{1b}SENTINEL7",
            "/",
            "//x",
            ".",
            "..",
            "*",
            "run",
            "help",
            "443",
            "8443",
            "0",
            "65536",
            "a/../b",
            "a:b",
        ] {
            claimed_text_is_only_an_error_or_the_tool_hostname(&format!("{prefix}{suffix}"));
        }
    }
    for text in [
        "tool:443",
        "TOOL:443",
        "Tool:080",
        "tool:0",
        "tool:53",
        "tool:853",
        "tool:65536",
        "tool:000443",
        "tool:codex",
        "tool://x",
        "tool:/x",
        "tool:/",
        "tool:",
        "tool",
        "tcp://tool:443",
    ] {
        claimed_text_is_only_an_error_or_the_tool_hostname(text);
    }
    // A7: the same cross-prefix corpus both helpers run, so neither can quietly
    // treat the other's claims as its own.
    for text in CROSS_PREFIX_CORPUS {
        claimed_text_is_only_an_error_or_the_tool_hostname(text);
    }
}

proptest! {
    // (b) arbitrary strings: controls, non-ASCII, the whole range.
    #[test]
    fn reference_claims_only_errors_or_the_tool_hostname_on_any_string(
        text in any::<String>()
    ) {
        claimed_text_is_only_an_error_or_the_tool_hostname(&text);
    }

    #[test]
    fn reference_claims_only_errors_or_the_tool_hostname_on_long_strings(
        text in ".{0,300}"
    ) {
        claimed_text_is_only_an_error_or_the_tool_hostname(&text);
    }
}

/// A7 and R6: expansion order, display, and exact port pinning including 443.
#[test]
fn expansion_is_port_pinned() {
    let tools = user_tools(
        Path::new(USER_FILE),
        &[("fetcher", &["b.example", "a.example:8443"])],
    );
    let resolved = resolve_ok(&["tool:fetcher"], Some(&tools));
    let rendered: Vec<String> = resolved.allowances().map(ToString::to_string).collect();
    assert_eq!(
        rendered,
        vec!["tcp://a.example:8443", "tcp://b.example:443"],
        "request order is the sorted request set, and 443 stays explicit"
    );
    for allowance in resolved.allowances() {
        assert!(
            matches!(allowance, Allowance::Hostname(_)),
            "an expansion must be a hostname allowance: {allowance}"
        );
        // Port-pinned, including 443: an expanded name is never bare.
        assert!(allowance.to_string().starts_with("tcp://"), "{allowance}");
    }
    assert_eq!(resolved.references().len(), 1);
}

/// A21: dedupe by canonical value, and an allowance granted both directly
/// and through a reference is one entry attributed to both.
#[test]
fn resolve_dedupes_and_attributes() {
    let tools = user_tools(
        Path::new(USER_FILE),
        &[("codex", &["api.openai.com", "auth.openai.com"])],
    );
    let resolved = resolve_ok(
        &["tool:codex", "tool:codex", "tcp://api.openai.com:443"],
        Some(&tools),
    );
    let rendered: Vec<String> = resolved.allowances().map(ToString::to_string).collect();
    assert_eq!(
        rendered,
        vec!["tcp://api.openai.com:443", "tcp://auth.openai.com:443"]
    );
    let codex = tool_ref("codex");
    assert_eq!(resolved.references().collect::<Vec<_>>(), vec![&codex]);
    let name: DomainName = "api.openai.com".parse().unwrap();
    let origin = resolved.hostname_origin(&name);
    assert!(origin.direct, "the literal entry granted it directly");
    assert_eq!(origin.via.len(), 1, "and via tool:codex");
    assert_eq!(origin.via[0].to_string(), "tool:codex");
    let other: DomainName = "auth.openai.com".parse().unwrap();
    let origin = resolved.hostname_origin(&other);
    assert!(!origin.direct);
    assert_eq!(origin.via.len(), 1);
    // A numeric literal keeps its own attribution shape.
    let resolved = resolve_ok(&["10.0.0.5", "tool:codex"], Some(&tools));
    assert!(
        resolved
            .entry_origin(&Allowance::parse("10.0.0.5").unwrap())
            .direct
    );
}

/// A32 (the tool half) and A45: a repeated reference is applied once, and the
/// count that proves it is not part of the value.
///
/// The counter exists because a per-repeat re-application would change nothing a
/// caller can see: `insert` folds repeated values and repeated provenance, so the
/// only difference is work.
#[test]
fn repeated_tool_references_apply_once() {
    let tools = user_tools(
        Path::new(USER_FILE),
        &[("fetcher", &["b.example", "a.example:8443"])],
    );
    let once = resolve_ok(&["tool:fetcher", "10.0.0.9"], Some(&tools));
    let repeated = resolve_ok(
        &["tool:fetcher", "tool:fetcher", "10.0.0.9", "tool:fetcher"],
        Some(&tools),
    );
    assert_eq!(once, repeated, "equality ignores the insertion count");
    // Two expanded allowances plus one literal. Re-applying the cached expansion
    // per repeat would give 2 + 2 + 1 + 2.
    assert_eq!(once.insertions, 3);
    assert_eq!(repeated.insertions, 3);
    assert_eq!(repeated.references().len(), 1);
}

/// A45: two resolutions that grant the same thing compare equal whatever they
/// cost, and a different grant still compares unequal.
#[test]
fn insertion_count_is_not_part_of_the_value() {
    let tools = user_tools(Path::new(USER_FILE), &[("codex", &["api.openai.com"])]);
    // A repeated *literal* always inserts — only references are skipped — so the
    // two resolutions differ in cost while granting exactly the same thing.
    let short = resolve_ok(&["tool:codex", "10.0.0.5"], Some(&tools));
    let long = resolve_ok(&["tool:codex", "10.0.0.5", "10.0.0.5"], Some(&tools));
    assert_eq!((short.insertions, long.insertions), (2, 3));
    assert_eq!(short, long);
    let other = resolve_ok(&["10.0.0.5"], Some(&tools));
    assert_ne!(short, other);
}

/// A31's unit half, R22: a `set:` reference resolves against the user file's own
/// `[egress_sets]`, and each failure keeps its position and its fixed sentence.
#[test]
fn set_resolution_errors_and_precedence() {
    let parse = |text: &str| AllowanceEntry::parse(text).unwrap();
    const SENTINEL: &str = "SENTINEL7";
    // R22: no user config file at all is `NoUserSets`, not `NoUserConfig`: the
    // namespace a set needs is the sets one.
    let failure = resolve(vec![parse("set:corp")], None).unwrap_err();
    assert_eq!(failure.index, 0);
    assert_eq!(failure.error, EntryError::NoUserSets);
    assert_eq!(
        failure.error.to_string(),
        "an egress reference resolves only against the user config's own [egress_sets], and no user config file was found"
    );
    // A namespace with no `[egress_sets]` declares no set, so a well-formed name
    // is unknown; the position is the entry's, and the name is never echoed.
    let tools = user_tools(Path::new(USER_FILE), &[("codex", &["api.openai.com"])]);
    let failure = resolve(
        vec![parse("10.0.0.5"), parse(&format!("set:{SENTINEL}"))],
        Some(&tools),
    )
    .unwrap_err();
    assert_eq!(failure.index, 1);
    assert_eq!(failure.error, EntryError::UnknownSet);
    assert_eq!(
        failure.error.to_string(),
        "an egress reference must name a set declared in the user config's own [egress_sets]; project and built-in configs cannot declare sets"
    );
    assert!(!failure.error.to_string().contains(SENTINEL));
}

/// A32 and R23/R36: a set reference is applied once however often it is written,
/// and a set and a tool in the same list cost exactly one expansion each.
///
/// The expected `insertions` is the discriminator: re-applying a cached expansion
/// per repeat would grant the same allowances but cost 14 inserts instead of 6.
#[test]
fn repeated_references_apply_once() {
    let tools = test_support::user_namespace(
        Path::new(USER_FILE),
        &[("fetcher", &["one.example", "two.example"])],
        Some("s = [\"10.0.0.1\", \"10.0.0.2\", \"10.0.0.3\"]\n"),
    );
    let repeated = resolve_ok(
        &[
            "set:s",
            "set:s",
            "tool:fetcher",
            "tool:fetcher",
            "10.0.0.9",
            "set:s",
        ],
        Some(&tools),
    );
    let once = resolve_ok(&["set:s", "tool:fetcher", "10.0.0.9"], Some(&tools));
    // Three allowances from the set, two from the tool, one literal.
    assert_eq!(repeated.insertions, 6);
    assert_eq!(
        once, repeated,
        "the repeats granted nothing the first did not"
    );
    assert_eq!(repeated.references().len(), 2);
    assert_eq!(
        repeated
            .references()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["set:s", "tool:fetcher"]
    );
    assert_eq!(
        repeated
            .allowances()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        [
            "10.0.0.1/32",
            "10.0.0.2/32",
            "10.0.0.3/32",
            "tcp://one.example:443",
            "tcp://two.example:443",
            "10.0.0.9/32"
        ]
    );
    // The same set chosen from a CLI list reaches the same closure, on the same
    // rows: a set is one reference with its closure as the expansion (R24).
    let from_cli = resolve_ok(&["set:s"], Some(&tools));
    assert_eq!(from_cli.references().len(), 1);
    assert_eq!(from_cli.insertions, 3);
}

/// A31's set lookup and R24: a declared set resolves to its compiled closure,
/// and `doctor`'s expansion view is that same closure.
#[test]
fn a_declared_set_resolves_to_its_closure() {
    let tools = test_support::user_namespace(
        Path::new(USER_FILE),
        &[],
        Some("corp = [\"10.0.0.5\", \"10.0.0.5/32\"]\n"),
    );
    let resolved = resolve_ok(&["set:corp"], Some(&tools));
    assert_eq!(
        resolved
            .allowances()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["10.0.0.5/32"]
    );
    assert_eq!(
        resolved
            .expansions()
            .map(|(reference, expansion)| (
                reference.to_string(),
                expansion
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            ))
            .collect::<Vec<_>>(),
        [("set:corp".to_owned(), vec!["10.0.0.5/32".to_owned()])]
    );
}

/// A14, A18 and the A19 unit half: which reason wins, in which order.
#[test]
fn resolution_errors_and_precedence() {
    let empty = user_tools(Path::new(USER_FILE), &[("shell", &[])]);
    let with = user_tools(Path::new(USER_FILE), &[("codex", &["api.openai.com"])]);
    let parse = |text: &str| AllowanceEntry::parse(text).unwrap();
    for (texts, tools, index, error) in [
        (vec!["tool:x"], None, 0, EntryError::NoUserConfig),
        (vec!["tool:nope"], Some(&with), 0, EntryError::UnknownTool),
        (vec!["tool:shell"], Some(&empty), 0, EntryError::NoRequests),
        (
            vec!["tool:codex", "tool:nope"],
            Some(&with),
            1,
            EntryError::UnknownTool,
        ),
    ] {
        let entries: Vec<AllowanceEntry> = texts.iter().map(|text| parse(text)).collect();
        let failure = resolve(entries, tools).unwrap_err();
        assert_eq!(failure.index, index, "for {texts:?}");
        assert_eq!(failure.error, error, "for {texts:?}");
    }
    // A18's exact bytes.
    let failure = resolve(vec![parse("tool:x")], None).unwrap_err();
    assert_eq!(
        failure.error.to_string(),
        "an egress reference resolves only against the user config's own [[tools]], and no user config file was found"
    );
}

/// R14's entry-syntax-before-resolution rule is the CLI path's job (it parses
/// every text first), but the ordering inside one list of references is ours.
#[test]
fn first_failing_reference_wins() {
    let tools = user_tools(Path::new(USER_FILE), &[("shell", &[])]);
    let entries = ["tool:nope", "tool:shell"]
        .iter()
        .map(|text| AllowanceEntry::parse(text).unwrap())
        .collect();
    let failure = resolve(entries, Some(&tools)).unwrap_err();
    assert_eq!(failure.index, 0);
    assert_eq!(failure.error, EntryError::UnknownTool);
}

/// An untrusted file refuses before it names anything, and the file it names
/// is the one the trust token carries. The name is sentinel-bearing, so a
/// refusal that leaked it would be caught here rather than only in the
/// malformed case (A20).
#[test]
fn an_untrusted_verdict_precedes_lookup() {
    const SENTINEL: &str = "SENTINEL7";
    let trust = ReferenceTrust::for_test_untrusted(
        Path::new(USER_FILE),
        UntrustedConfig::Refused {
            refusal: crate::config_authority::AuthorityRefusal::ThroughSymlink,
            subject: crate::config_authority::AuthoritySubject::EgressReference,
        },
    );
    let namespace = UserToolRequests::new(trust, &[], None).unwrap();
    let failure = resolve(
        vec![AllowanceEntry::parse(&format!("tool:{SENTINEL}")).unwrap()],
        Some(&namespace),
    )
    .unwrap_err();
    assert_eq!(failure.index, 0);
    assert_eq!(
        failure.error.to_string(),
        format!(
            "config: \"{USER_FILE}\": an egress reference requires config.toml to be a regular file, but it is reached through a symbolic link; its target may be writable by a guest or project, so review the [[tools]] network_requests before trusting the file (a symlinked config without an egress reference still works)"
        ),
        "the trust check must precede the unknown-name check"
    );
    assert!(!failure.error.to_string().contains(SENTINEL));
}

/// R21 for sets specifically: the trust check is not a property of `tool:`
/// references.
///
/// The set below **is** declared in the namespace, so the only thing that can
/// refuse this entry is the file's verdict — a trust check written for tools only
/// resolves the set successfully and fails here. That is why this case is at the
/// unit level: the launch-level A30 would still catch a tool-only check, but the
/// unit module on its own reported green (review B, mutation 6).
#[test]
fn a_set_reference_is_refused_for_an_untrusted_file() {
    const SENTINEL: &str = "SENTINEL7";
    let trust = ReferenceTrust::for_test_untrusted(
        Path::new(USER_FILE),
        UntrustedConfig::Refused {
            refusal: crate::config_authority::AuthorityRefusal::ThroughSymlink,
            subject: crate::config_authority::AuthoritySubject::EgressReference,
        },
    );
    let declarations: toml::Table = format!("{SENTINEL} = [\"10.0.0.1\"]")
        .parse()
        .expect("test TOML");
    let parsed = super::sets::parse(&toml::Value::Table(declarations))
        .expect("a literal-only set compiles without the file's tools");
    let namespace = UserToolRequests::new(trust, &[], Some(parsed)).expect("literal-only set");

    let failure = resolve(
        vec![AllowanceEntry::parse(&format!("set:{SENTINEL}")).unwrap()],
        Some(&namespace),
    )
    .unwrap_err();
    assert_eq!(failure.index, 0);
    assert!(
        matches!(failure.error, EntryError::Untrusted { .. }),
        "{failure:?}"
    );
    // The tool case's sentence, byte for byte: one variant, one text, both kinds.
    assert_eq!(
        failure.error.to_string(),
        format!(
            "config: \"{USER_FILE}\": an egress reference requires config.toml to be a regular \
             file, but it is reached through a symbolic link; its target may be writable by a \
             guest or project, so review the [[tools]] network_requests before trusting the file \
             (a symlinked config without an egress reference still works)"
        )
    );
    assert!(!failure.error.to_string().contains(SENTINEL));
}

/// Tokens a re-parsing resolver must not reach: the merged catalog, a catalogue
/// entry, the direct hostname constructor, and a socket API.
///
/// One entry per obligation, so a violation names the specific reach and the
/// self-test below exercises every entry independently. A single `std::net` case
/// once hid a removed direct-constructor ban for three review rounds.
const FORBIDDEN: [&str; 10] = [
    "LaunchCatalog",
    "ResolvedTools",
    "CatalogEntry",
    "HostnameAllowance::from_target",
    ".from_target(",
    "std::net",
    "TcpStream",
    "UdpSocket",
    "to_socket_addrs",
    "lookup_host",
];

/// The same ten obligations, written out again, independently of [`FORBIDDEN`].
///
/// An oracle that *is* the list moves with it: deleting an entry would leave the
/// self-test looping over what is left and passing, which is how removing the
/// direct-constructor ban stayed invisible. This list is what makes such a
/// deletion a red test.
const OBLIGATIONS: [&str; 10] = [
    "LaunchCatalog",
    "ResolvedTools",
    "CatalogEntry",
    "HostnameAllowance::from_target",
    ".from_target(",
    "std::net",
    "TcpStream",
    "UdpSocket",
    "to_socket_addrs",
    "lookup_host",
];

/// Every [`FORBIDDEN`] token appearing on a line of `source` that is not a
/// leading `//` comment.
///
/// The `//` exemption exists so the production module's own documentation can
/// name what the file must not do; rustfmt keeps a doc comment on its own lines,
/// so prose stays on lines this skips. That is the only exemption. There is no
/// lexical reasoning here at all — no comment, string, raw-string or lifetime
/// state — so a match inside any other line, including inside a trailing
/// comment or a string, is a violation.
///
/// The price of having no lexer: the exemption is *textual*, so a line whose
/// first non-whitespace characters are `//` is skipped even when it closes a
/// block comment opened on an earlier line and then continues as live code. This
/// scan cannot see that, and closing it would mean reintroducing the lexical
/// reasoning this repo removed once already. ADR-0018 names the hole.
fn forbidden_violations(source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for (index, line) in source.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for forbidden in FORBIDDEN {
            if line.contains(forbidden) {
                violations.push(format!(
                    "line {}: production code reaches `{forbidden}`; a reference must not",
                    index + 1
                ));
            }
        }
    }
    violations
}

/// The obligation specific to `egress_reference/sets.rs` (#511 R29): the text of
/// the set graph contains no `Allowance::parse(`.
///
/// A token in text, not a proof about authority — see [`set_violations`] for what
/// that excludes and ADR-0018 for the hole it leaves open.
///
/// A filename-scoped list rather than a shared one, because `Allowance::parse(`
/// *is* how the entry side re-enters the grammar (`fn expand`), so the same token
/// means opposite things in the two files.
const SET_OBLIGATIONS: [&str; 1] = ["Allowance::parse("];

/// The same one obligation, written out again, independently of
/// [`SET_OBLIGATIONS`].
const SET_OBLIGATIONS_ORACLE: [&str; 1] = ["Allowance::parse("];

/// Every [`FORBIDDEN`] token or [`SET_OBLIGATIONS`] token on a line of `source`
/// that is not a leading `//` comment.
///
/// Same exemption, same reasoning and the same textual hole as
/// [`forbidden_violations`]. What this establishes is a property of the file's
/// text — no forbidden token, no `Allowance::parse(` outside `fn expand` — and
/// not a property of its data flow.
fn set_violations(source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for (index, line) in source.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for forbidden in FORBIDDEN.iter().chain(SET_OBLIGATIONS.iter()) {
            if line.contains(forbidden) {
                violations.push(format!(
                    "line {}: the egress-set graph reaches `{forbidden}`; it may only forward \
                     allowances the file already declared",
                    index + 1
                ));
            }
        }
    }
    violations
}

/// The text of the first `fn expand(` in `source`, through the next line that is
/// exactly `}` in column 0 — how rustfmt formats a top-level item's closing
/// brace.
///
/// A region, not a parsed body: [`seam_violations`] reports a missing function
/// **and** a region it cannot delimit, so a formatting change outside these two
/// assumptions fails the build and sends a human to look rather than silently
/// scanning nothing. The *first* occurrence wins, so a second `fn expand(`
/// written above the real one moves the region instead of failing it — this
/// catches accidental drift, and review is what catches authorship.
fn expand_region(source: &str) -> Option<&str> {
    let start = source.find("fn expand(")?;
    let rest = &source[start..];
    let mut end = 0usize;
    for line in rest.split_inclusive('\n') {
        end += line.len();
        if line.trim_end() == "}" {
            return Some(&rest[..end]);
        }
    }
    None
}

/// A37's obligations about the production file: the resolver is still here, and
/// its expansion still re-enters the proved grammar.
///
/// What this can and cannot say: it pins that `Allowance::parse(` occurs in
/// `fn expand`'s region, which is the strongest statement source text supports
/// here — no value test can distinguish a re-parse from an equivalent direct
/// constructor, and this check does not prove data flow, does not reason about
/// macro expansion, and is defeated by an edit that also edits it. Review is the
/// control for semantic changes.
fn seam_violations(source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for required in ["fn resolve(", "fn expand("] {
        if !source.contains(required) {
            violations.push(format!("the production file lost `{required}`"));
        }
    }
    match expand_region(source) {
        Some(region) if !region.contains("Allowance::parse(") => violations.push(
            "`fn expand` no longer re-enters `Allowance::parse(` (R7)".to_owned(),
        ),
        Some(_) => {}
        None => violations.push(
            "`fn expand`'s body could not be delimited: no `fn expand(` or no closing brace on its own line".to_owned(),
        ),
    }
    violations
}

/// Both A37 checks over the whole production file.
fn production_violations(source: &str) -> Vec<String> {
    let mut violations = forbidden_violations(source);
    violations.extend(seam_violations(source));
    violations
}

/// A37: the resolver really is here, and it really does re-enter the grammar
/// rather than reach for a catalog, a catalogue entry, or a socket.
///
/// The boundary this relies on is structural, not textual: every test and every
/// test-only helper lives in `egress_reference/tests.rs`, so
/// `include_str!("../egress_reference.rs")` is production code by construction
/// and no marker, prefix or lexer has to decide where production ends.
#[test]
fn the_resolver_reparses_and_never_reads_a_catalog() {
    let violations = production_violations(include_str!("../egress_reference.rs"));
    assert!(
        violations.is_empty(),
        "the A37 check found violations: {violations:?}"
    );
}

/// A37, as amended: the set graph's **source text** contains no forbidden token
/// and no `Allowance::parse(` outside the permitted seam.
///
/// That is the whole claim. It is a pattern check over text, so it holds only
/// for edits that leave the token readable on one non-comment line: a token split
/// across lines, a re-export or alias, a `macro_rules!` wrapper, a helper in the
/// parent module, and a `//`-leading line that closes a block comment opened
/// earlier all reach an allowance while this test stays green. The property the
/// old name claimed — that the graph cannot mint an allowance — is not
/// established here and is not establishable by text; allowance provenance and
/// data flow are **structural review** (ADR-0018, A46).
#[test]
fn the_set_graph_source_contains_no_forbidden_token() {
    let violations = set_violations(include_str!("sets.rs"));
    assert!(
        violations.is_empty(),
        "the A37 check over sets.rs found violations: {violations:?}"
    );
}

/// The A37 guard is only a guard if it rejects the edits it exists to reject,
/// so each obligation gets its own case over a synthetic source string; the file
/// on disk is never edited.
///
/// This is a **pattern check**, and the claim stops there. It catches accidental
/// drift and the named regressions below; it does not prove data flow, it does
/// not reason about macro expansion, and an edit that also edits the check
/// defeats it. Review is the control for semantic changes.
#[test]
fn the_tripwire_rejects_forbidden_edits_to_production() {
    assert_eq!(
        &FORBIDDEN[..],
        &OBLIGATIONS[..],
        "the forbidden list lost, gained or swapped an obligation"
    );
    assert_eq!(
        &SET_OBLIGATIONS[..],
        &SET_OBLIGATIONS_ORACLE[..],
        "the set-graph obligation list lost, gained or swapped an entry"
    );

    // Every forbidden token, independently: a code line is flagged, the same
    // text as a leading `//` comment is not, and the same text after code is a
    // violation rather than prose.
    for forbidden in OBLIGATIONS {
        let code = format!("    let _ = {forbidden};\n");
        let flagged = forbidden_violations(&code);
        assert_eq!(
            flagged.len(),
            1,
            "`{forbidden}` was not flagged: {flagged:?}"
        );
        assert!(flagged[0].contains(forbidden), "{flagged:?}");
        let comment = format!("    // production must not reach {forbidden}\n");
        assert!(
            forbidden_violations(&comment).is_empty(),
            "`{forbidden}` was flagged inside a leading comment"
        );
        let trailing = format!("    let _ = 1; // {forbidden}\n");
        assert_eq!(
            forbidden_violations(&trailing).len(),
            1,
            "a trailing comment is not the leading-comment exemption"
        );
    }

    // The expansion seam. A synthetic function is found and holds the call; a
    // replaced call, an absent function and an undelimitable body are each a
    // violation.
    let seam = "fn resolve() {}\nfn expand(requests: &NetworkRequests) {\n    let _ = Allowance::parse(&text);\n}\n";
    assert!(
        production_violations(seam).is_empty(),
        "the unmutated seam must pass: {:?}",
        production_violations(seam)
    );
    let rejected = |source: &str, needle: &str| {
        let violations = production_violations(source);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(needle)),
            "the check missed `{needle}`: {violations:?}"
        );
    };
    rejected(
        &seam.replace("Allowance::parse(", "H::from_target("),
        "no longer re-enters",
    );
    rejected(
        &seam.replace("fn expand(", "fn expansion("),
        "lost `fn expand(`",
    );
    rejected(
        &seam.replace("fn resolve(", "fn resolution("),
        "lost `fn resolve(`",
    );
    rejected(
        "fn resolve() {}\nfn expand() {\n    let _ = Allowance::parse(&text);\n",
        "could not be delimited",
    );

    // The set graph's own obligation, independently: a code line is flagged, the
    // same text as a leading `//` comment is not, and the mount token forms are
    // still refused there.
    for forbidden in SET_OBLIGATIONS_ORACLE {
        let code = format!("    let _ = {forbidden}text);\n");
        let flagged = set_violations(&code);
        assert_eq!(
            flagged.len(),
            1,
            "`{forbidden}` was not flagged in sets.rs: {flagged:?}"
        );
        assert!(flagged[0].contains(forbidden), "{flagged:?}");
        let comment = format!("    // the set graph must not call {forbidden}\n");
        assert!(
            set_violations(&comment).is_empty(),
            "`{forbidden}` was flagged inside a leading comment"
        );
    }
    for forbidden in OBLIGATIONS {
        let code = format!("    let _ = {forbidden};\n");
        assert_eq!(
            set_violations(&code).len(),
            1,
            "`{forbidden}` was not flagged in sets.rs"
        );
    }

    // And the files that ship pass both checks — the guard tests above assert the
    // same thing, restated here so this self-test stands alone.
    assert!(
        production_violations(include_str!("../egress_reference.rs")).is_empty(),
        "the production file itself must pass"
    );
    assert!(
        set_violations(include_str!("sets.rs")).is_empty(),
        "the set graph itself must pass"
    );
}

/// `render_list` is the one list grammar the diagnostics share.
#[test]
fn render_list_matches_the_shared_grammar() {
    let references: Vec<EgressReference> = ["a", "b", "c", "d"]
        .iter()
        .map(|tool| tool_ref(tool))
        .collect();
    for (count, expected) in [
        (0usize, ""),
        (1, "tool:a"),
        (2, "tool:a and tool:b"),
        (3, "tool:a, tool:b and tool:c"),
        (4, "tool:a, tool:b, tool:c and tool:d"),
    ] {
        let borrowed: Vec<&EgressReference> = references[..count].iter().collect();
        assert_eq!(render_list(&borrowed), expected);
    }
}
