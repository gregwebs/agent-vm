//! #511: the `[egress_sets]` graph's tests, and the A37 guard's second half.
//!
//! Test code lives here, not in `egress_reference/sets.rs`: the A37 source guard
//! scans that file as production, and a `#[cfg(test)]` item would be a place a
//! forbidden reach could hide from it.

use super::*;

/// One `[egress_sets]` body as a TOML table, i.e. what `RawConfig`'s untyped field
/// holds.
fn table(text: &str) -> toml::Value {
    let table: toml::Table = text.parse().expect("test body is TOML");
    toml::Value::Table(table)
}

fn parse(text: &str) -> Result<ParsedEgressSets, EgressSetError> {
    super::parse(&table(text))
}

/// Compile one body, through the production entry point.
///
/// #735 removed the tool-expansion callback with the `tool:` reference
/// (ADR-0075), so a set's closure is literals and other sets only.
fn compile(text: &str) -> Result<EgressSets, EgressSetError> {
    super::compile(parse(text)?)
}

fn load(text: &str) -> EgressSets {
    compile(text).unwrap_or_else(|error| panic!("fixture must compile: {error}"))
}

fn rendered(sets: &EgressSets, name: &str) -> Vec<String> {
    let name = EgressSetName::parse(name).expect("a valid set name");
    sets.closure(&name)
        .expect("the closure the fixture declares")
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// A set of `count` distinct address literals, the width the budget tests need.
fn literals(count: usize) -> String {
    (0..count)
        .map(|i| format!("\"10.0.{}.{}\"", i / 256, i % 256))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A14: every top-level field name is refused as a set name, by name and at the
/// position TOML gave it.
#[test]
fn top_level_keys_are_reserved_set_names() {
    for field in crate::config::TOP_LEVEL_FIELDS {
        let error = parse(&format!("{field} = []")).unwrap_err();
        assert_eq!(
            error,
            EgressSetError::TopLevelKey {
                definition: 0,
                key: field,
            },
            "{field}"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "egress_sets[0]: {field} is not an egress set; a top-level {field} must be written \
                 before the first table header (keys after [egress_sets] belong to it)"
            )
        );
    }
    // Numbering follows the sorted key order, so a reserved key is named at the
    // position a reader counting sorted definitions would find it in. The source
    // order here is `network`, `tools`, `a`; sorted it is `a`, `network`, `tools`,
    // so `network` is definition 1 and `tools` — also reserved — is never
    // reached. Written in source order, the expected number would be 0.
    //
    // What this establishes is the numbering, which is what a reader counts. It
    // does not establish that `parse`'s explicit `sort_by` is load-bearing:
    // `toml::Table` is a sorted map in this build (`Cargo.toml` deliberately omits
    // the parser's `preserve_order` feature), so removing the sort changes no
    // observable — measured, and recorded as an equivalent mutant rather than a
    // survivor. The explicit sort states the contract for the day the parser's map
    // order stops being sorted.
    let error = parse("network = []\ntools = []\na = []").unwrap_err();
    assert_eq!(
        error,
        EgressSetError::TopLevelKey {
            definition: 1,
            key: "network",
        }
    );
    // The same sort decides which definition's *value* a schema error names: `z`
    // is written first and is definition 1.
    assert_eq!(
        parse("z = 7\na = []"),
        Err(EgressSetError::NotArray { definition: 1 })
    );
    // Every name is checked before any value, so an invalid key in the later
    // definition wins over an earlier definition's schema error.
    assert_eq!(
        parse("a = 7\n\"z bad\" = []"),
        Err(EgressSetError::Name { definition: 1 })
    );
}

/// R11, and the trap USAGE's "TOML scoping trap" bullet documents: reservation
/// is exactly the six top-level field names, nothing more. A key of `[network]`
/// is an ordinary set name — `allow_egress` most of all, because a bare
/// `allow_egress` written after the `[egress_sets]` header is a *set* with that
/// name, not a network grant.
///
/// The defect this catches is a `[network]` key added to `TOP_LEVEL_FIELDS`: that
/// would refuse a name USAGE promises is legal, and it would turn the documented
/// silent trap into a load error.
#[test]
fn network_setting_keys_are_ordinary_set_names() {
    for key in crate::user_network::SETTINGS {
        let sets = load(&format!("{key} = [\"10.0.0.5\"]"));
        assert_eq!(rendered(&sets, key), ["10.0.0.5/32"], "{key}");
    }
}

/// A14: an invalid key is refused by its numeric position, and the sentence
/// carries no byte of it.
#[test]
fn invalid_set_names_are_numeric_and_value_free() {
    const SENTINEL: &str = "SENTINEL7";
    for key in [
        "\"\"",
        "\"-x\"",
        "\".x\"",
        "\"a/b\"",
        "\"a b\"",
        "\"a:b\"",
        "\"caf\u{e9}\"",
        "\"\\u001bSENTINEL7\"",
        "\"..\"",
    ] {
        let error = parse(&format!("{key} = []")).unwrap_err();
        assert!(
            matches!(error, EgressSetError::Name { .. }),
            "{key}: {error:?}"
        );
        let text = error.to_string();
        assert_eq!(
            text,
            "egress_sets: definition 0 has an invalid name; an egress-set name is one or more \
             ASCII characters: [A-Za-z0-9_] first, then [A-Za-z0-9_.-]",
            "{key}"
        );
        assert!(!text.contains(SENTINEL), "{text}");
    }
    // A numeric name is a name, not a malformed one: the grammar is character
    // shape only.
    let sets = load("8443 = [\"10.0.0.1\"]\n0 = []");
    assert_eq!(rendered(&sets, "8443"), ["10.0.0.1/32"]);
    assert!(rendered(&sets, "0").is_empty());
}

/// A16: schema errors and entry errors are named by their site, in the order
/// within one definition that the loader promises.
#[test]
fn schema_and_entry_errors_are_named_by_site() {
    assert_eq!(
        parse(""),
        Ok(ParsedEgressSets {
            names: Vec::new(),
            definitions: Vec::new(),
            order: Vec::new(),
        })
    );
    assert_eq!(
        super::parse(&toml::Value::Integer(7)),
        Err(EgressSetError::NotTable)
    );
    assert_eq!(
        EgressSetError::NotTable.to_string(),
        "egress_sets: must be a table of named arrays of egress allowances and references"
    );
    assert_eq!(
        parse("a = \"10.0.0.1\""),
        Err(EgressSetError::NotArray { definition: 0 })
    );
    assert_eq!(
        EgressSetError::NotArray { definition: 0 }.to_string(),
        "egress_sets[0]: must be an array of strings"
    );
    assert_eq!(
        parse("a = [7]"),
        Err(EgressSetError::NotString {
            definition: 0,
            index: 0,
        })
    );
    assert_eq!(
        EgressSetError::NotString {
            definition: 0,
            index: 0
        }
        .to_string(),
        "egress_sets[0][0]: must be a string"
    );
    // The entry's own error, rendered by the entry's own `Display`.
    let error = parse("a = [\"10.0.0.1\", \"not an allowance\"]").unwrap_err();
    assert_eq!(
        error,
        EgressSetError::Entry {
            definition: 0,
            index: 1,
            error: crate::egress_reference::EntryError::Allowance(
                crate::egress_grammar::AllowanceError::MalformedAddress
            ),
        }
    );
    // Not-a-string wins over the entry syntax of a later entry, and the shape of
    // the *definition* wins over both.
    assert_eq!(
        parse("a = [\"bad entry\", 7]"),
        Err(EgressSetError::Entry {
            definition: 0,
            index: 0,
            error: crate::egress_reference::EntryError::Allowance(
                crate::egress_grammar::AllowanceError::MalformedAddress
            ),
        })
    );
    assert_eq!(
        parse("a = 7\nb = [\"bad entry\"]"),
        Err(EgressSetError::NotArray { definition: 0 })
    );
}

/// A17: a definition may name a set declared before or after it, and a name the
/// file does not declare is the unknown-set sentence at the entry's site.
#[test]
fn forward_and_nested_references_resolve() {
    let sets = load("a = [\"set:b\", \"10.0.0.1\"]\nb = [\"10.0.0.2\"]");
    assert_eq!(rendered(&sets, "a"), ["10.0.0.2/32", "10.0.0.1/32"]);
    assert_eq!(rendered(&sets, "b"), ["10.0.0.2/32"]);
    // A definition may also name a set declared *later*, and one declared before.
    let sets = load("a = [\"set:b\"]\nb = [\"10.0.0.2\", \"set:a2\"]\na2 = [\"10.0.0.3\"]");
    assert_eq!(rendered(&sets, "b"), ["10.0.0.2/32", "10.0.0.3/32"]);
    assert_eq!(rendered(&sets, "a"), ["10.0.0.2/32", "10.0.0.3/32"]);
}

/// A17, the chain itself: `a -> b -> c` in reverse declaration order.
#[test]
fn a_nested_chain_resolves_forward() {
    let sets =
        load("a = [\"set:b\", \"10.0.0.1\"]\nb = [\"set:c\", \"10.0.0.2\"]\nc = [\"10.0.0.3\"]");
    assert_eq!(
        rendered(&sets, "a"),
        ["10.0.0.3/32", "10.0.0.2/32", "10.0.0.1/32"],
        "a child's closure is iterated in its own first-seen order"
    );
    // Work: c 1, b 1 + 1, a 1 + 2 = 6. Each set charges its own entries and its
    // child's closure, never the whole graph.
    assert_eq!(sets.work, 6);
}

#[test]
fn unknown_set_is_named_by_site() {
    let error = parse("a = [\"10.0.0.1\"]\nb = [\"10.0.0.2\", \"set:nope\"]").unwrap_err();
    assert_eq!(
        error,
        EgressSetError::Entry {
            definition: 1,
            index: 1,
            error: crate::egress_reference::EntryError::UnknownSet,
        }
    );
    assert_eq!(
        error.to_string(),
        "egress_sets[1][1]: an egress reference must name a set declared in the user config's own \
         [egress_sets]; project and built-in configs cannot declare sets"
    );
}

/// A18: every cycle is refused, at the entry that closes it, whether or not
/// anything references the component it sits in.
#[test]
fn cycles_are_refused_by_site() {
    // A self-reference at [0][0].
    assert_eq!(
        parse("a = [\"set:a\"]"),
        Err(EgressSetError::Cycle {
            definition: 0,
            index: 0,
        })
    );
    // `a <-> b`, closed by `b`'s first entry.
    assert_eq!(
        parse("a = [\"set:b\"]\nb = [\"set:a\"]"),
        Err(EgressSetError::Cycle {
            definition: 1,
            index: 0,
        })
    );
    // A cycle inside an unreferenced component, in the last-sorted definition: it
    // is still a root, so it is still walked.
    assert_eq!(
        parse("a = [\"10.0.0.1\"]\nzz = [\"set:zz\"]"),
        Err(EgressSetError::Cycle {
            definition: 1,
            index: 0,
        })
    );
    let error = parse("a = [\"set:b\"]\nb = [\"set:a\"]").unwrap_err();
    assert_eq!(
        error.to_string(),
        "egress_sets[1][0]: egress-set reference cycle"
    );
    // A diamond is not a cycle: shared structure is what `Skip` means.
    let sets = load("a = [\"set:c\"]\nb = [\"set:c\"]\nc = [\"10.0.0.1\"]");
    assert_eq!(rendered(&sets, "a"), ["10.0.0.1/32"]);
    assert_eq!(rendered(&sets, "b"), ["10.0.0.1/32"]);
}

/// A19: a 10,000-set chain walks on a 2 MiB stack.
///
/// The edges point **forward**, so the first root in sorted order descends all
/// 10,000 sets before it reaches the literal: the walk's own stack reaches depth
/// 10,000 here. That is what this exercises — depth. A memoized recursive DFS is
/// semantically equivalent and **overflows this stack at this depth** (measured),
/// so the fixture does fail the obvious rewrite; it still cannot see the
/// implementation, so "the walk is iterative" stays review (A46, against `walk`
/// and the mount graph's precedent).
#[test]
fn a_long_chain_loads() {
    const DEPTH: usize = 10_000;
    let mut body = String::new();
    for i in 0..DEPTH - 1 {
        body.push_str(&format!("s{i:05} = [\"set:s{:05}\"]\n", i + 1));
    }
    body.push_str(&format!("s{:05} = [\"10.0.0.1\"]\n", DEPTH - 1));
    let sets = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let sets = load(&body);
            assert_eq!(sets.work, DEPTH, "one visit per link in the chain");
            rendered(&sets, "s00000")
        })
        .unwrap()
        .join()
        .expect("the walk must not overflow a 2 MiB stack");
    assert_eq!(sets, ["10.0.0.1/32"]);
}

/// A20: every declaration is compiled, unused ones included, so a bad entry
/// inside a set nothing references still fails the load.
#[test]
fn unused_sets_are_compiled() {
    let error = compile("a = [\"10.0.0.1\"]\nb = []\nzz = [\"tool:nope\"]").unwrap_err();
    assert_eq!(
        error.to_string(),
        "egress_sets[2][0]: port must be a decimal number 1-65535"
    );
    // The same entry with a number instead of a name: `tool` is then an ordinary
    // hostname, so the unused set compiles and grants nothing.
    let sets = load("a = [\"10.0.0.1\"]\nb = []\nzz = [\"tool:443\"]");
    assert_eq!(rendered(&sets, "a"), ["10.0.0.1/32"]);
    assert!(rendered(&sets, "b").is_empty());
    assert_eq!(rendered(&sets, "zz"), ["tcp://tool:443"]);
}

/// A23: the budget predicate against a table.
#[test]
fn expansion_work_allowed_matches_the_table() {
    for (used, allowed) in [
        (0usize, true),
        (1, true),
        (65_535, true),
        (65_536, false),
        (65_537, false),
        (usize::MAX, false),
    ] {
        assert_eq!(
            egress_set_expansion_work_allowed(used),
            allowed,
            "work {used}"
        );
    }
    assert_eq!(MAX_EGRESS_SET_EXPANSION_WORK, 65_536);
}

/// A22(i): the literal boundary is exactly 65,536 visits, and the visit after it
/// is refused with the fixed sentence.
#[test]
fn egress_set_expansion_work_boundary() {
    let mut body = format!("a = [{}]\n", literals(256));
    // 255 children of 256 allowances each: 256 + 255 * 256 = 65,536.
    for i in 0..255 {
        body.push_str(&format!("b{i:03} = [\"set:a\"]\n"));
    }
    let sets = load(&body);
    assert_eq!(sets.work, 65_536);
    assert_eq!(rendered(&sets, "b254").len(), 256);

    // One literal more, in the last-sorted definition, is the 65,537th visit.
    body.push_str("c = [\"10.9.9.9\"]\n");
    assert_eq!(compile(&body), Err(EgressSetError::ExpansionWorkLimit));
    assert_eq!(
        compile(&body).unwrap_err().to_string(),
        "egress_sets: expansion work exceeds limit of 65536 allowance visits"
    );
}

/// A22(ii): a child's closure is charged per allowance, so the budget can be
/// straddled by one entry of ten.
#[test]
fn egress_set_expansion_work_child_straddles_the_budget() {
    // One charge per candidate allowance: 256 for `a`, 253 children folding all
    // 256 of `a`'s, 492 for `c`, and `z` folding `w`'s ten — exactly 65,536.
    let mut body = format!("a = [{}]\n", literals(256));
    for i in 0..253 {
        body.push_str(&format!("b{i:03} = [\"set:a\"]\n"));
    }
    body.push_str(&format!("c = [{}]\n", literals(492)));
    body.push_str(&format!("w = [{}]\n", literals(10)));
    body.push_str("z = [\"set:w\"]\n");

    let sets = load(&body);
    assert_eq!(sets.work, 65_536);
    assert_eq!(rendered(&sets, "z").len(), 10);

    // One more literal in the child exhausts the budget on the parent's fold.
    body.push_str("w2 = []\n");
    let mut over = body.replace(
        &format!("w = [{}]", literals(10)),
        &format!("w = [{}]", literals(11)),
    );
    over.push_str("");
    assert_eq!(compile(&over), Err(EgressSetError::ExpansionWorkLimit));
}

/// A24: repeats and empty fan-out are free.
#[test]
fn repeated_references_are_free_and_empty_fanout_costs_nothing() {
    let mut body = String::new();
    for i in 0..1_000 {
        body.push_str(&format!("e{i:03} = []\n"));
    }
    let children: Vec<String> = (0..1_000).map(|i| format!("\"set:e{i:03}\"")).collect();
    body.push_str(&format!("w = [{}, \"set:e000\"]\n", children.join(", ")));
    body.push_str("r = [\"10.0.0.1\"]\n");
    body.push_str("q = [\"set:r\", \"set:r\", \"set:r\"]\n");
    let sets = load(&body);
    // r 1 + q 1; the thousand empty children and every repeat cost nothing.
    assert_eq!(sets.work, 2);
    assert_eq!(rendered(&sets, "q"), ["10.0.0.1/32"]);
    assert_eq!(rendered(&sets, "w"), Vec::<String>::new());
}

/// A25(i): the issue's example, with its exact closures and its exact cost.
#[test]
fn issue_example_closures() {
    let sets = load(
        "agents = [\"set:codex\", \"set:claude\", \"set:corp\"]\n\
         codex = [\"tcp://api.openai.com:443\"]\n\
         claude = [\"tcp://api.anthropic.com:443\"]\n\
         corp = [\"git.corp.example\", \"tcp://registry.corp.example:8443\", \"10.0.0.5\"]",
    );
    assert_eq!(
        rendered(&sets, "corp"),
        [
            "git.corp.example",
            "tcp://registry.corp.example:8443",
            "10.0.0.5/32"
        ]
    );
    assert_eq!(
        rendered(&sets, "agents"),
        [
            "tcp://api.openai.com:443",
            "tcp://api.anthropic.com:443",
            "git.corp.example",
            "tcp://registry.corp.example:8443",
            "10.0.0.5/32"
        ]
    );
    // Three `set:` references plus five literals; each reference is one visit and
    // each child's own literals are folded into the parent's closure.
    assert_eq!(sets.work, 10);
}

/// A25(ii): dedup is by canonical allowance value, not by entry text, and the
/// first occurrence keeps its position.
#[test]
fn canonical_dedup_across_sources_keeps_first_seen_order() {
    let sets = load(
        "m = [\"API.example.com.\", \"api.example.com\", \"10.0.0.5\", \"10.0.0.5/32\", \
         \"tcp://api.example.com:443\", \"tcp://api.example.com:443\", \"set:n\"]\n\
         n = [\"tcp://api.example.com:443\", \"10.0.0.5/32\", \"b.example\"]",
    );
    assert_eq!(
        rendered(&sets, "n"),
        ["tcp://api.example.com:443", "10.0.0.5/32", "b.example"]
    );
    assert_eq!(
        rendered(&sets, "m"),
        [
            "api.example.com",
            "10.0.0.5/32",
            "tcp://api.example.com:443",
            "b.example"
        ]
    );
    // m's 5 literal entries + 3 from n, and the `set:n` reference itself, whose
    // own 3 literals are folded again into m.
    assert_eq!(sets.work, 12);

    // The canonical value carries the transport and the port: the same endpoint
    // under `tcp://` and `udp://` is two allowances, and two ports of one
    // transport and endpoint are two more. A dedup key that dropped either
    // component would collapse a pair here. (A *hostname* cannot be the operand
    // for a transport pair: `udp://HOST:PORT` is refused, TLS is TCP-only, so the
    // pair is an address.) The last entry repeats an earlier canonical value and
    // must fold.
    let sets = load(
        "p = [\"tcp://10.0.0.5:443\", \"udp://10.0.0.5:443\", \
         \"tcp://api.example.com:8443\", \"tcp://api.example.com:9443\", \
         \"udp://10.0.0.5:443\"]",
    );
    assert_eq!(
        rendered(&sets, "p"),
        [
            "tcp://[10.0.0.5/32]:443",
            "udp://[10.0.0.5/32]:443",
            "tcp://api.example.com:8443",
            "tcp://api.example.com:9443"
        ]
    );
    assert_eq!(sets.work, 5);
}

/// A26(b), restated for #735: a `set:` reference is bound during *parse*, so an
/// unknown set anywhere in the file is reported before any closure is folded —
/// the budget is the only compile-stage error left, and it is reported for the
/// first definition that exceeds it.
#[test]
fn parse_errors_precede_the_budget_and_the_budget_is_first_exceeded_first() {
    let mut exhausting = format!("a = [{}]\n", literals(256));
    for i in 0..255 {
        exhausting.push_str(&format!("b{i:03} = [\"set:a\"]\n"));
    }
    exhausting.push_str("c = [\"10.9.9.9\"]\n");

    let first = format!("0bad = [\"set:nope\"]\n{exhausting}");
    let error = compile(&first).unwrap_err();
    assert_eq!(
        error.to_string(),
        "egress_sets[0][0]: an egress reference must name a set declared in the user \
         config's own [egress_sets]; project and built-in configs cannot declare sets"
    );

    // `zbad` sorts last, but parse binds every reference before compile folds any
    // closure, so the unknown set still wins over the exhaustion `exhausting`
    // alone produces.
    let last = format!("{exhausting}zbad = [\"set:nope\"]\n");
    assert_eq!(
        compile(&last),
        Err(EgressSetError::Entry {
            definition: 257,
            index: 0,
            error: crate::egress_reference::EntryError::UnknownSet,
        })
    );
    assert_eq!(
        compile(&exhausting),
        Err(EgressSetError::ExpansionWorkLimit)
    );
}

/// A36's unit half: no load diagnostic echoes a key, a set name or an entry.
///
/// Every case names the phase and the **error variant** it must reach, so a
/// fixture that failed earlier for an unrelated reason cannot satisfy the
/// sentinel assertion with a message that never had the sentinel in it. The
/// sentinel sits in a key, in a set name and in a tool name — the three values a
/// diagnostic could plausibly repeat.
///
/// This is not every error family. The budget sentence, `ReferenceOrder`, and the
/// resolution prefixes carry fixed words by construction and are pinned elsewhere
/// (`config_launch_driven::set_refusals_never_echo_the_entry_or_its_name`); what
/// this test covers is the parse and compile diagnostics that render a site.
#[test]
fn set_errors_never_echo_keys_or_entries() {
    use crate::egress_reference::EntryError;
    const SENTINEL: &str = "SENTINEL7";
    let echo = |label: &str, text: &str| {
        assert!(
            !text.contains(SENTINEL),
            "{label} echoed the sentinel: {text}"
        );
    };

    // Parse phase: schema, name, entry syntax, unknown set, and a cycle whose own
    // definition name carries the sentinel.
    for (body, expected) in [
        (
            format!("\"{SENTINEL}\" = 7"),
            EgressSetError::NotArray { definition: 0 },
        ),
        (
            format!("\"\\u001b{SENTINEL}\" = []"),
            EgressSetError::Name { definition: 0 },
        ),
        (
            format!("a = [{{\"s\" = \"{SENTINEL}\"}}]"),
            EgressSetError::NotString {
                definition: 0,
                index: 0,
            },
        ),
        (
            format!("a = [\"\\u001b{SENTINEL}\"]"),
            EgressSetError::Entry {
                definition: 0,
                index: 0,
                error: EntryError::Allowance(
                    crate::egress_grammar::AllowanceError::MalformedAddress,
                ),
            },
        ),
        (
            format!("a = [\"set:{SENTINEL}\"]"),
            EgressSetError::Entry {
                definition: 0,
                index: 0,
                error: EntryError::UnknownSet,
            },
        ),
        (
            format!("{SENTINEL} = [\"10.0.0.1\", \"set:{SENTINEL}\"]"),
            EgressSetError::Cycle {
                definition: 0,
                index: 1,
            },
        ),
    ] {
        let error = parse(&body).unwrap_err();
        assert_eq!(error, expected, "{body:?}");
        echo(&body, &error.to_string());
    }

    // Compile phase, which is where a name could leak: the grammar refuses the
    // text before any name is looked up, and the sentence is fixed.
    let body = format!("a = [\"tool:{SENTINEL}\"]");
    let error = compile(&body).unwrap_err();
    assert_eq!(
        error,
        EgressSetError::Entry {
            definition: 0,
            index: 0,
            error: EntryError::Allowance(crate::egress_grammar::AllowanceError::MalformedPort),
        }
    );
    echo(&body, &error.to_string());
}
