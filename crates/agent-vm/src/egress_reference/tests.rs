//! The `egress_reference` tests, and the A37 source guard over the production
//! files.
//!
//! Tests live in their own modules by construction, not by a rule the code has to
//! detect: `egress_reference.rs` and `egress_reference/sets.rs` hold only
//! production code, and their tests live in `egress_reference/tests.rs` and
//! `egress_reference/sets/tests.rs`, so the guard's scans of
//! `include_str!("../egress_reference.rs")` and `include_str!("sets.rs")` cover
//! production in full and need no boundary marker to look for.
//!
//! #735 (ADR-0075) removed the `tool:` reference, so what is left to test is the
//! `set:` claim, the set graph, and the one converter from an authorized tool's
//! `network_requests` into allowances ([`expand`]).
//!
//! What those scans can and cannot say is bounded (ADR-0018): they match tokens
//! in the text, so they catch accidental drift and the named regressions, and
//! they do **not** establish that no allowance can be minted. A token split
//! across lines, an alias or re-export, a macro, a helper in the parent module,
//! or a `//`-leading line that closes an earlier block comment each mint while
//! the scan is green. Provenance and data flow are structural review (A46).

use self::test_support::{resolve_ok, set_ref};
use super::*;
use proptest::prelude::*;
use std::path::Path;

pub(crate) mod test_support {
    use crate::egress_reference::*;

    /// A namespace over one file's `[egress_sets]` declarations, through the
    /// real parse and the real compile: a fixture that hand-built the closures
    /// could disagree with what a file does.
    ///
    /// The `(name, requests)` list is accepted and ignored: #735 removed the
    /// `[[tools]] network_requests` map a `tool:NAME` reference used to resolve
    /// against (ADR-0075), and existing fixtures still pass it. A set body that
    /// names `tool:…` is now a *grammar* error, so such fixtures were rewritten.
    pub(crate) fn user_namespace(
        file: &std::path::Path,
        _tools: &[(&str, &[&str])],
        egress_sets: Option<&str>,
    ) -> EgressNamespace {
        let table: toml::Table = egress_sets.unwrap_or_default().parse().expect("test TOML");
        let parsed = sets::parse(&toml::Value::Table(table)).expect("test [egress_sets] is valid");
        EgressNamespace::new(ReferenceTrust::verified_for_test(file), Some(parsed))
            .expect("test egress sets compile")
    }

    /// The set-less namespace the retired `tool:NAME` fixtures still construct.
    ///
    /// Kept so their *hostname* half keeps compiling; the resolution assertions
    /// those tests made moved to `tool:`-as-ordinary-text (V12).
    #[allow(dead_code)]
    pub(crate) fn user_tools(
        file: &std::path::Path,
        _tools: &[(&str, &[&str])],
    ) -> EgressNamespace {
        user_namespace(file, &[], None)
    }

    /// The set reference one claimed `set:NAME` becomes, spelled here rather
    /// than constructed inline so the private payload is reached in one place.
    pub(super) fn set_ref(name: &str) -> EgressReference {
        EgressReference(
            super::super::sets::EgressSetName::parse(name).expect("a valid egress-set name"),
        )
    }

    pub(crate) fn resolve_ok(
        texts: &[&str],
        user_sets: Option<&EgressNamespace>,
    ) -> ResolvedAllowances {
        let entries = texts
            .iter()
            .map(|text| AllowanceEntry::parse(text).unwrap())
            .collect();
        resolve(entries, user_sets).unwrap()
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

/// An independently written oracle for the `set:` kernel, because a spec function
/// erases under a plain build: this is the executable form the proof is *about*,
/// restated without the spec.
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
    // The boundary cases that decide the grammar, written out.
    for (bytes, claimed) in [
        (&b"set:"[..], true),
        (&b"SET:"[..], true),
        (&b"SeT:"[..], true),
        (&b"set:8443"[..], true),
        (&b"set://x.example"[..], false),
        (&b"set:/"[..], true),
        (&b"set:x"[..], true),
        (&b"set"[..], false),
        (&b"setx"[..], false),
        (&b""[..], false),
        (&b"tcp://set:443"[..], false),
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

/// #735: `set:` is the only claimed prefix, so no other text is a reference —
/// including the `tool:` texts that used to be one.
#[test]
fn set_is_the_only_claim() {
    for text in [
        "tool:codex",
        "tool:443",
        "TOOL:codex",
        "tool://x.example",
        "router:443",
        "sett:443",
    ] {
        assert!(!set_reference_claim(text.as_bytes()), "{text}");
        assert!(
            !matches!(
                AllowanceEntry::parse(text),
                Ok(AllowanceEntry::Reference(_))
            ),
            "{text} was claimed as a reference"
        );
    }
}

/// #631: a collapsed notice line names a set by its own name, without the
/// prefix, because `NAME (count)` must not read as an allowance.
#[test]
fn notice_labels_drop_the_set_prefix() {
    assert_eq!(set_ref("anthropic").notice_label(), "anthropic");
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
    // Not claimed: the grammar decides, exactly as before.
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

/// A7: claimed set text is either the fixed malformed error or the reference,
/// and the grammar's own reading is an error or the hostname `set` on an
/// explicit port (the R5 break set), never an allowance that survives as written.
fn claimed_text_is_only_an_error_or_the_set_hostname(text: &str) {
    let claimed = set_reference_claim(text.as_bytes());
    let literal = Allowance::parse(text);
    if !claimed {
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
            assert_eq!(
                reference.set_name().as_str(),
                name,
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
    // (b) targeted combinations, including the retired `tool:` prefix.
    for prefix in [
        "set:", "SET:", "Set:", "sEt:", "seT:", "sET:", "set:/", "set://", "SET://", "tcp://",
        "xset:", "s e t:", "tool:", "TOOL:",
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

/// V12: `tool:NAME` reverted to the ordinary allowance grammar the moment the
/// `tool:` claim was removed (ADR-0075's breaking change).
///
/// The three outcomes are fixed by the grammar's own adapters, not by this
/// module: a non-numeric name fails as a malformed port, a numeric port is the
/// literal hostname `tool`, and the `tool://` scheme is still refused.
#[test]
fn tool_names_are_no_longer_claimed_so_the_grammar_decides() {
    for text in ["tool:codex", "tool:fetcher", "tool:"] {
        let error = AllowanceEntry::parse(text).unwrap_err();
        assert_eq!(
            error,
            EntryError::Allowance(AllowanceError::MalformedPort),
            "{text}"
        );
        assert_eq!(error.to_string(), "port must be a decimal number 1-65535");
    }
    for (port, expected) in [
        ("tool:443", "tcp://tool:443"),
        ("tool:8443", "tcp://tool:8443"),
        ("TOOL:443", "tcp://tool:443"),
    ] {
        let entry = AllowanceEntry::parse(port).unwrap();
        let AllowanceEntry::Literal(allowance) = &entry else {
            panic!("{port} was claimed as a reference")
        };
        assert_eq!(allowance.to_string(), expected);
    }
    assert_eq!(
        AllowanceEntry::parse("tool://x.example"),
        Err(EntryError::Allowance(AllowanceError::UnsupportedScheme))
    );
    for refused in ["tool:0", "tool:53", "tool:853", "tool:65536", "tool:000443"] {
        assert!(
            matches!(
                AllowanceEntry::parse(refused),
                Err(EntryError::Allowance(_))
            ),
            "{refused} must be refused by the allowance grammar"
        );
    }
}

/// A37's `expand` contract, restated from the outside: an authorized tool's own
/// requests become hostname allowances pinned to their declared ports, and 443
/// stays explicit rather than becoming a bare name.
#[test]
fn expansion_is_port_pinned() {
    let requests =
        NetworkRequests::parse(&["b.example".to_owned(), "a.example:8443".to_owned()]).unwrap();
    let expanded = expand(&requests).expect("declared requests expand");
    let rendered: Vec<String> = expanded.iter().map(ToString::to_string).collect();
    assert_eq!(
        rendered,
        vec!["tcp://a.example:8443", "tcp://b.example:443"],
        "request order is the sorted request set, and 443 stays explicit"
    );
    for allowance in &expanded {
        assert!(
            matches!(allowance, Allowance::Hostname(_)),
            "an expansion must be a hostname allowance: {allowance}"
        );
        assert!(allowance.to_string().starts_with("tcp://"), "{allowance}");
    }
    assert_eq!(expand(&NetworkRequests::parse(&[]).unwrap()).unwrap(), []);
}

/// A21: dedupe by canonical value, and an allowance granted both directly and
/// through a reference is one entry attributed to both.
#[test]
fn resolve_dedupes_and_attributes() {
    let tools = test_support::user_namespace(
        Path::new(USER_FILE),
        &[],
        Some("corp = [\"10.0.0.1\", \"10.0.0.2\"]\n"),
    );
    let resolved = resolve_ok(&["set:corp", "set:corp", "10.0.0.1"], Some(&tools));
    let rendered: Vec<String> = resolved.allowances().map(ToString::to_string).collect();
    assert_eq!(rendered, vec!["10.0.0.1/32", "10.0.0.2/32"]);
    let corp = set_ref("corp");
    assert_eq!(resolved.references().collect::<Vec<_>>(), vec![&corp]);
    let allowance = Allowance::parse("10.0.0.1").unwrap();
    let origin = resolved.entry_origin(&allowance);
    assert!(origin.direct, "the literal entry granted it directly");
    assert_eq!(origin.via.len(), 1, "and via set:corp");
    assert_eq!(origin.via[0].to_string(), "set:corp");
}

/// A45 and R23: a repeated reference is applied once, and the count that proves
/// it is not part of the value.
#[test]
fn repeated_references_apply_once() {
    let tools = test_support::user_namespace(
        Path::new(USER_FILE),
        &[],
        Some("s = [\"10.0.0.1\", \"10.0.0.2\", \"10.0.0.3\"]\n"),
    );
    let repeated = resolve_ok(&["set:s", "set:s", "10.0.0.9", "set:s"], Some(&tools));
    let once = resolve_ok(&["set:s", "10.0.0.9"], Some(&tools));
    assert_eq!(repeated.insertions, 4);
    assert_eq!(
        once, repeated,
        "the repeats granted nothing the first did not"
    );
    assert_eq!(repeated.references().len(), 1);
    assert_eq!(
        repeated
            .references()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["set:s"]
    );
    assert_eq!(
        repeated
            .allowances()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32", "10.0.0.9/32"]
    );
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

/// A31's unit half, R22: each failure keeps its position and its fixed sentence.
#[test]
fn set_resolution_errors_and_precedence() {
    let parse = |text: &str| AllowanceEntry::parse(text).unwrap();
    const SENTINEL: &str = "SENTINEL7";
    // R22: no user config file at all is `NoUserSets`.
    let failure = resolve(vec![parse("set:corp")], None).unwrap_err();
    assert_eq!(failure.index, 0);
    assert_eq!(failure.error, EntryError::NoUserSets);
    assert_eq!(
        failure.error.to_string(),
        "an egress reference resolves only against the user config's own [egress_sets], and no user config file was found"
    );
    // A namespace with no `[egress_sets]` declares no set, so a well-formed name
    // is unknown; the position is the entry's, and the name is never echoed.
    let tools = test_support::user_namespace(Path::new(USER_FILE), &[], None);
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

/// An untrusted file refuses the reference for the file, before it looks the
/// name up, and the sentence names `[egress_sets]` — the only table a `set:`
/// reference reads since #735.
#[test]
fn a_set_reference_is_refused_for_an_untrusted_file() {
    const SENTINEL: &str = "SENTINEL7";
    let trust = ReferenceTrust::for_test_untrusted(
        Path::new(USER_FILE),
        crate::config_authority::Measurement::Refused(
            crate::config_authority::AuthorityRefusal::ThroughSymlink,
        ),
    );
    let declarations: toml::Table = format!("{SENTINEL} = [\"10.0.0.1\"]")
        .parse()
        .expect("test TOML");
    let parsed =
        super::sets::parse(&toml::Value::Table(declarations)).expect("a literal-only set compiles");
    let namespace = EgressNamespace::new(trust, Some(parsed)).expect("literal-only set");

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
    // The declared set exists, so only the verdict can refuse this entry.
    assert_eq!(
        failure.error.to_string(),
        format!(
            "config: \"{USER_FILE}\": an egress reference requires config.toml to be a regular \
             file, but it is reached through a symbolic link; its target may be writable by a \
             guest or project, so review the [egress_sets] table before trusting the file \
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
/// so prose stays on lines this skips. That is the only exemption.
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
/// A filename-scoped list rather than a shared one, because `Allowance::parse(`
/// *is* how the entry side re-enters the grammar (`fn expand`), so the same token
/// means opposite things in the two files.
const SET_OBLIGATIONS: [&str; 1] = ["Allowance::parse("];

/// The same one obligation, written out again, independently of
/// [`SET_OBLIGATIONS`].
const SET_OBLIGATIONS_ORACLE: [&str; 1] = ["Allowance::parse("];

/// Every [`FORBIDDEN`] token or [`SET_OBLIGATIONS`] token on a line of `source`
/// that is not a leading `//` comment.
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

    // The set graph's own obligation, independently.
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

    // And the files that ship pass both checks.
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
        .map(|set| set_ref(set))
        .collect();
    for (count, expected) in [
        (0usize, ""),
        (1, "set:a"),
        (2, "set:a and set:b"),
        (3, "set:a, set:b and set:c"),
        (4, "set:a, set:b, set:c and set:d"),
    ] {
        let borrowed: Vec<&EgressReference> = references[..count].iter().collect();
        assert_eq!(render_list(&borrowed), expected);
    }
}
