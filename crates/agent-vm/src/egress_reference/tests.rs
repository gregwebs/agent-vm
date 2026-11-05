//! ADR-0059: the `egress_reference` tests, and the A37 source guard over the
//! production file.
//!
//! Tests live in their own module by construction, not by a rule the code has to
//! detect: `egress_reference.rs` holds only production code, so the guard's scan
//! of `include_str!("../egress_reference.rs")` covers production in full and
//! needs no boundary marker to look for.

use self::test_support::{resolve_ok, user_tools};
use super::*;
use crate::config::RESERVED_TOOL_NAMES;
use proptest::prelude::*;
use std::path::Path;

pub(crate) mod test_support {
    use crate::egress_reference::*;

    /// A namespace built straight from `(name, requests)` pairs, for tests in
    /// other modules that need a resolvable tool without a whole config file.
    pub(crate) fn user_tools(
        file: &std::path::Path,
        tools: &[(&str, &[&str])],
    ) -> UserToolRequests {
        let mut requests = BTreeMap::new();
        for (name, raw) in tools {
            let raw: Vec<String> = raw.iter().map(|request| (*request).to_owned()).collect();
            requests.insert((*name).to_owned(), NetworkRequests::parse(&raw).unwrap());
        }
        UserToolRequests {
            trust: ReferenceTrust::verified_for_test(file),
            requests,
        }
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
        assert_eq!(
            reference,
            &EgressReference {
                tool: expected.to_owned()
            }
        );
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
        AllowanceEntry::Reference(EgressReference {
            tool: "443".to_owned()
        })
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
            assert_eq!(
                text.get(PREFIX_LEN..),
                Some(reference.tool()),
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
    let codex = EgressReference {
        tool: "codex".to_owned(),
    };
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
    let namespace = UserToolRequests::new(trust, &[]);
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
/// comment or a string, is a violation, and nothing can be hidden from the scan
/// by a token form the scan does not model.
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

    // And the file that ships passes both checks — the guard test above asserts
    // the same thing, restated here so this self-test stands alone.
    assert!(
        production_violations(include_str!("../egress_reference.rs")).is_empty(),
        "the production file itself must pass"
    );
}

/// `render_list` is the one list grammar the diagnostics share.
#[test]
fn render_list_matches_the_shared_grammar() {
    let references: Vec<EgressReference> = ["a", "b", "c", "d"]
        .iter()
        .map(|tool| EgressReference {
            tool: (*tool).to_owned(),
        })
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
