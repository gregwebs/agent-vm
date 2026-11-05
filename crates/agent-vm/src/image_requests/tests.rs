//! Unit tables and the two-group invariant enumeration for the image request
//! report.
//!
//! Production code lives in `image_requests.rs` and `image_requests/baseline.rs`,
//! and every test and test-only helper lives here, so the tripwire's
//! `include_str!` scans production by construction (the `egress_reference`
//! precedent). Two `#[cfg(test)]` items do exist in production —
//! `ClassifiedKey::kind` and `Store::at` — and both are inside the scanned text,
//! which is what keeps the guard whole: the scan reads the file, not a
//! test-stripped view of it.
use super::*;

const DISPLAY: &str = "ghcr.io/x/standard:latest";

fn key(name: &str) -> String {
    format!("{REQUEST_LABEL_PREFIX}{name}")
}

fn labels(pairs: Vec<(String, String)>) -> DeclaredImageRequests {
    DeclaredImageRequests::from_labels(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
}

/// Labels whose keys are given whole, for the keys that are not request labels.
fn declare_raw(raw: &[(&str, &str)]) -> DeclaredImageRequests {
    DeclaredImageRequests::from_labels(raw.iter().copied())
}

fn declare(raw: &[(&str, &str)]) -> DeclaredImageRequests {
    labels(
        raw.iter()
            .map(|(name, value)| (key(name), (*value).to_owned()))
            .collect(),
    )
}

fn req(list: &[&str]) -> BTreeSet<NetworkRequest> {
    let raw: Vec<String> = list.iter().map(|text| (*text).to_owned()).collect();
    NetworkRequests::parse(&raw)
        .expect("fixture requests are grammatical")
        .iter()
        .cloned()
        .collect()
}

fn agent(name: &str) -> RequestGroup {
    RequestGroup::Agent(LabelName(name.to_owned()))
}

fn groups(entries: Vec<(RequestGroup, &[&str])>) -> Groups {
    entries
        .into_iter()
        .map(|(group, list)| (group, req(list)))
        .collect()
}

const NONE: &[&str] = &[];

fn compose_with(
    recorded: &Groups,
    recorded_ignored: Option<&IgnoredFacts>,
    current: &DeclaredImageRequests,
    covered: impl Fn(&NetworkRequest) -> bool,
) -> Composed {
    compose(recorded, recorded_ignored, current, DISPLAY, &covered)
}

/// One launch through the real `compose` and `next_entries`, the way
/// `report_before_boot` runs them: the entry is found by reference, the ignored
/// facts are the recorded ones, and "write nothing" leaves the store alone.
fn launch_once(
    entries: &mut Vec<super::baseline::Entry>,
    current: &DeclaredImageRequests,
    covered: impl Fn(&NetworkRequest) -> bool,
) -> Vec<String> {
    let recorded = entries.iter().find(|entry| entry.reference == "REF");
    let none = Groups::new();
    let composed = compose(
        recorded.map_or(&none, |entry| &entry.baseline),
        recorded.map(|entry| &entry.ignored),
        current,
        DISPLAY,
        &covered,
    );
    let written = super::baseline::next_entries(
        entries.clone(),
        "REF",
        current,
        &composed.printed,
        !composed.lines.is_empty(),
    );
    if let Some(next) = written {
        *entries = next;
    }
    composed.lines
}

fn recorded_entry(entries: &[super::baseline::Entry]) -> &super::baseline::Entry {
    entries
        .iter()
        .find(|entry| entry.reference == "REF")
        .expect("the launch recorded an entry")
}

fn first(group: &str, requests: &str) -> String {
    format!("==> Image network requests ({DISPLAY}): {group} {requests}")
}

fn changed(group: &str, terms: &str) -> String {
    format!("==> Image network requests ({DISPLAY}) changed: {group} {terms}")
}

/// The two trailer lines, written out independently of the constants that
/// produce them.
const TRAILER_NOTICE: &str = "==>   image requests above are not covered by this launch's public or same-name grants (no lookup; DNS, private-answer and TLS client limits still apply); they never grant access and the launch continues; each image reference is reported once, then as changes";
const TRAILER_GRANT: &str = "==>   to grant: --allow-egress HOST or tcp://HOST:PORT, or --allow-internet-egress; IP/CIDR, --allow-lan and --allow-host grants are not matched to names";

fn trailer() -> Vec<String> {
    vec![TRAILER_NOTICE.to_owned(), TRAILER_GRANT.to_owned()]
}

// ---------------------------------------------------------------------------
// R2 — key classification
// ---------------------------------------------------------------------------

/// The whole classification table, including the shapes D3's admission rule has
/// to survive: a wrong word, an empty name, an unsafe name and a key outside the
/// prefix.
#[test]
fn key_kind_table() {
    let longest = "a".repeat(MAX_REQUEST_LABELS);
    let overlong = "a".repeat(MAX_REQUEST_LABELS + 1);
    let rows = vec![
        ("image.base".to_owned(), RequestLabelKind::Image),
        ("agent.codex".to_owned(), RequestLabelKind::Agent),
        ("agent.pi".to_owned(), RequestLabelKind::Agent),
        ("agent.sk-live-abc".to_owned(), RequestLabelKind::Agent),
        ("image.a.b-c_d".to_owned(), RequestLabelKind::Image),
        (format!("agent.{longest}"), RequestLabelKind::Agent),
        // A NAME is 1..=64 bytes, so an empty, overlong or unsafe one is a
        // refusal, never a group.
        ("agent.Bad".to_owned(), RequestLabelKind::Unrecognized),
        (format!("agent.{overlong}"), RequestLabelKind::Unrecognized),
        ("agent.".to_owned(), RequestLabelKind::Unrecognized),
        ("image.".to_owned(), RequestLabelKind::Unrecognized),
        ("agent.bad name".to_owned(), RequestLabelKind::Unrecognized),
        ("agent.bad/name".to_owned(), RequestLabelKind::Unrecognized),
        ("agent.\u{00e9}".to_owned(), RequestLabelKind::Unrecognized),
        ("image.\u{202e}x".to_owned(), RequestLabelKind::Unrecognized),
        // The word must be exactly six bytes and case-sensitive.
        ("Agent.x".to_owned(), RequestLabelKind::Unrecognized),
        ("IMAGE.x".to_owned(), RequestLabelKind::Unrecognized),
        ("imag.x".to_owned(), RequestLabelKind::Unrecognized),
        ("imagex".to_owned(), RequestLabelKind::Unrecognized),
        ("foo".to_owned(), RequestLabelKind::Unrecognized),
        ("".to_owned(), RequestLabelKind::Unrecognized),
    ];
    for (name, expected) in rows {
        assert_eq!(classify_key(&key(&name)).kind(), expected, "key {name:?}");
    }
    // Outside the prefix, including a maintained label and two near misses.
    for outside in [
        "maintainer",
        "org.agent-vm.image.x",
        "org.agent-vm.network-request.image.x",
        "rg.agent-vm.network-requests.image.x",
        "org.agent-vm.network-requests",
    ] {
        assert_eq!(
            classify_key(outside).kind(),
            RequestLabelKind::NotRequest,
            "key {outside:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// R3 — value grammar, and the group union
// ---------------------------------------------------------------------------

/// Labels are parsed by the launcher's existing request grammar, so every class
/// it refuses is refused here, and an empty value is a group with no requests.
#[test]
fn value_grammar_table() {
    let declare_one = |value: &str| declare(&[("agent.codex", value)]);
    assert!(declare_one("").groups()[&agent("codex")].is_empty());
    assert!(declare_one("").invalid.is_empty());

    for value in [
        "a.example, b.example",
        "a.example,",
        ",a.example",
        "10.0.0.1",
        "10.0.0.0/8",
        "a.example:53",
        "a.example:853",
        "a.example:0",
        "udp://a.example",
        "http://a.example",
        "host.microsandbox.internal",
        "a.example:notaport",
        "a.example:65536",
        "a.example:1 2",
    ] {
        let declared = declare_one(value);
        assert!(
            declared.groups.is_empty(),
            "{value:?} must contribute no requests"
        );
        assert_eq!(declared.invalid.len(), 1, "{value:?} must be one refusal");
        let refusal = declared.invalid.values().next().unwrap().to_string();
        // The raw value never appears in the rendered refusal (R10). The host
        // alias is the one exception and is not an echo: its *fixed* reason text
        // names the alias the grammar refuses.
        if !value.contains("host.microsandbox.internal") {
            assert!(!refusal.contains(value), "{refusal:?} echoed {value:?}");
        }
    }

    // More than 64 fields is refused by the grammar's own limit, with no
    // position, so the bare reason is what renders.
    let many = (0..=crate::network_requests::MAX_NETWORK_REQUESTS)
        .map(|index| format!("h{index}.example"))
        .collect::<Vec<_>>()
        .join(",");
    let declared = declare_one(&many);
    assert!(declared.groups.is_empty());
    let refusal = declared.invalid.values().next().unwrap();
    assert_eq!(refusal.position, None);
    assert!(!refusal.to_string().contains("entry"));

    // Ports other than 443 render with their scheme and port.
    let declared = declare_one("a.example,tcp://b.example:8443");
    let rendered: Vec<String> = declared.groups()[&agent("codex")]
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(rendered, ["a.example", "tcp://b.example:8443"]);
}

/// *every launch* is the union of every admitted `image.*` label, which is how a
/// stacked image layer cannot overwrite its parent's requests.
#[test]
fn image_labels_union_into_one_group() {
    let declared = declare(&[
        ("image.base", "deb.debian.org"),
        ("image.rust-dev", "static.rust-lang.org,deb.debian.org"),
        ("agent.codex", "api.openai.com"),
    ]);
    assert_eq!(
        declared.groups()[&RequestGroup::EveryLaunch]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["deb.debian.org", "static.rust-lang.org"]
    );
    assert_eq!(
        declared.groups()[&agent("codex")]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["api.openai.com"]
    );
}

// ---------------------------------------------------------------------------
// R4 — label budget
// ---------------------------------------------------------------------------

/// Sixty-five valid-kind labels: the first 64 in key byte order are parsed and
/// the 65th is counted as excess.
#[test]
fn label_budget_admits_64_valid_kind_labels_and_counts_the_65th_as_excess() {
    let mut raw: Vec<(String, String)> = (0..MAX_REQUEST_LABELS)
        .map(|index| {
            (
                key(&format!("agent.a{index:02}")),
                format!("h{index}.example"),
            )
        })
        .collect();
    raw.push((key("agent.zz"), "late.example".to_owned()));
    let declared = labels(raw);
    assert_eq!(declared.excess, 1);
    assert_eq!(declared.unrecognized, 0);
    assert_eq!(declared.invalid.len(), 0);
    assert_eq!(declared.groups.len(), MAX_REQUEST_LABELS);
    assert!(
        !declared.groups.contains_key(&agent("zz")),
        "the 65th label is counted, never parsed"
    );
    assert_eq!(declared.groups[&agent("a00")].len(), 1);
}

/// Unrecognized keys consume no budget, so 64 lexically early junk keys cannot
/// hide a valid group — and they are counted instead (A24).
#[test]
fn label_budget_is_not_consumed_by_unrecognized_keys() {
    let mut raw: Vec<(String, String)> = (0..64)
        .map(|index| {
            (
                key(&format!("Agent.a{index:02}")),
                "junk.example".to_owned(),
            )
        })
        .collect();
    raw.push((key("agent.zz"), "late.example".to_owned()));
    let declared = labels(raw);
    assert_eq!(declared.unrecognized, 64);
    assert_eq!(declared.excess, 0);
    assert_eq!(
        declared.groups()[&agent("zz")]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["late.example"]
    );
    let composed = compose_with(&Groups::new(), None, &declared, |_| false);
    assert_eq!(
        composed.lines,
        vec![
            first("for zz", "late.example"),
            format!(
                "==> Image network requests ({DISPLAY}): ignored 64 labels under \
                 {REQUEST_LABEL_PREFIX} whose key is not image.NAME or agent.NAME"
            ),
            TRAILER_NOTICE.to_owned(),
            TRAILER_GRANT.to_owned(),
        ]
    );
}

/// A valid-kind label whose value is refused still consumes its place in the
/// budget: `admitted` counts the key, not the parse. Sixty-four refused values
/// therefore hide nothing, and the 65th key is excess rather than a group.
#[test]
fn invalid_admitted_values_consume_the_label_budget() {
    let mut raw: Vec<(String, String)> = (0..MAX_REQUEST_LABELS)
        .map(|index| (key(&format!("agent.a{index:02}")), "10.0.0.1".to_owned()))
        .collect();
    raw.push((key("agent.zz"), "late.example".to_owned()));
    let declared = labels(raw.clone());
    assert_eq!(declared.invalid.len(), MAX_REQUEST_LABELS);
    assert_eq!(declared.excess, 1);
    assert!(declared.groups.is_empty(), "the 65th key is not parsed");
    assert_eq!(declared.unrecognized, 0);

    let composed = compose_with(&Groups::new(), None, &declared, |_| false);
    assert_eq!(
        composed
            .lines
            .iter()
            .filter(|line| line.contains("ignored invalid label"))
            .count(),
        MAX_REQUEST_LABELS,
        "one refused line per admitted key"
    );
    assert_eq!(
        composed.lines.len(),
        MAX_REQUEST_LABELS + 1,
        "64 refused lines and one excess line, with no group and no trailer: {:?}",
        composed.lines
    );
    assert!(composed.lines.iter().all(|line| !line.contains("for zz")));

    // Doctor applies the same budget to the same labels.
    let section = doctor_section(&CachedLabels::Present(raw.into_iter().collect()));
    assert_eq!(
        section
            .lines()
            .filter(|line| line.starts_with("ignored invalid label"))
            .count(),
        MAX_REQUEST_LABELS
    );
    assert!(section.contains("the requests above are incomplete"));
    assert!(!section.contains("for zz"));
}

/// Keys outside the prefix neither consume budget nor are counted.
#[test]
fn labels_outside_the_prefix_are_ignored_silently() {
    let declared = declare_raw(&[
        ("maintainer", "someone@example.com"),
        ("org.agent-vm.image.base", "deb.debian.org"),
    ]);
    assert!(declared.declares_nothing());
}

// ---------------------------------------------------------------------------
// R5, R6 — the two forms, per group
// ---------------------------------------------------------------------------

#[test]
fn compose_first_form_lists_unmet_requests_only() {
    let current = declare(&[
        ("image.base", "deb.debian.org"),
        ("agent.codex", "api.openai.com,chatgpt.com"),
    ]);
    let composed = compose_with(&Groups::new(), None, &current, |request| {
        request.to_string() == "chatgpt.com"
    });
    let mut expected = vec![
        first("for every launch", "deb.debian.org"),
        first("for codex", "api.openai.com"),
    ];
    expected.extend(trailer());
    assert_eq!(composed.lines, expected);
    assert_eq!(
        composed.printed,
        [RequestGroup::EveryLaunch, agent("codex")]
            .into_iter()
            .collect()
    );
}

/// A group with no recorded set and nothing unmet prints nothing, so the form is
/// chosen per group: a first-form line can share a launch with a change line.
#[test]
fn compose_mixes_first_and_change_forms_in_group_order() {
    let recorded = groups(vec![(agent("codex"), &["a.example"])]);
    let current = declare(&[
        ("agent.codex", "a.example,b.example"),
        ("agent.pi", "pi.dev"),
    ]);
    let composed = compose_with(&recorded, None, &current, |_| false);
    let mut expected = vec![
        changed("for codex", "+b.example"),
        first("for pi", "pi.dev"),
    ];
    expected.extend(trailer());
    assert_eq!(composed.lines, expected);
    assert_eq!(
        composed.printed,
        [agent("codex"), agent("pi")].into_iter().collect()
    );
}

#[test]
fn compose_change_form_reports_additions_then_removals() {
    let recorded = groups(vec![(agent("codex"), &["b.example", "c.example"])]);
    let current = declare(&[("agent.codex", "a.example,b.example")]);
    let composed = compose_with(&recorded, None, &current, |_| false);
    let mut expected = vec![changed("for codex", "+a.example, -c.example")];
    expected.extend(trailer());
    assert_eq!(composed.lines, expected);
}

/// A recorded group that vanishes lists every recorded request as a removal and
/// prints no trailer: no unmet request was shown.
#[test]
fn compose_vanished_group_lists_only_removals() {
    let recorded = groups(vec![
        (RequestGroup::EveryLaunch, &["deb.debian.org"]),
        (agent("codex"), &["a.example"]),
    ]);
    let current = declare(&[("image.base", "deb.debian.org")]);
    let composed = compose_with(&recorded, None, &current, |_| false);
    assert_eq!(composed.lines, vec![changed("for codex", "-a.example")]);
    assert_eq!(composed.printed, [agent("codex")].into_iter().collect());
}

/// A group whose recorded set is empty (its line showed it vanishing) reports
/// its additions with `+`, where a group that was never shown uses the first
/// form.
#[test]
fn compose_recorded_empty_group_uses_the_change_form() {
    let recorded = groups(vec![(agent("codex"), NONE)]);
    let current = declare(&[("agent.codex", "a.example")]);
    let composed = compose_with(&recorded, None, &current, |_| false);
    let mut expected = vec![changed("for codex", "+a.example")];
    expected.extend(trailer());
    assert_eq!(composed.lines, expected);
}

/// A host that moves between groups is compared in each group separately, so one
/// launch can show the same host as a removal and as an addition.
#[test]
fn compose_moved_host_is_compared_in_each_group() {
    let recorded = groups(vec![(agent("codex"), &["a.example"])]);
    let current = declare(&[("agent.pi", "a.example")]);
    let composed = compose_with(&recorded, None, &current, |_| false);
    let mut expected = vec![
        changed("for codex", "-a.example"),
        first("for pi", "a.example"),
    ];
    expected.extend(trailer());
    assert_eq!(composed.lines, expected);
}

/// A recorded empty group that stays absent, and a declared-empty group with no
/// recorded set, both have nothing to list.
#[test]
fn compose_silent_groups_produce_no_line() {
    let recorded = groups(vec![(agent("codex"), NONE)]);
    let current = declare(&[("agent.pi", "")]);
    let composed = compose_with(&recorded, None, &current, |_| false);
    assert!(composed.lines.is_empty());
    assert!(composed.printed.is_empty());
}

// ---------------------------------------------------------------------------
// R7, R9 — precedence and the trailer
// ---------------------------------------------------------------------------

/// Coverage filters additions only: it removes covered first-form requests and
/// covered `+` terms, and it never suppresses a `-`.
#[test]
fn compose_covered_first_form_omits_covered_requests() {
    let current = declare(&[
        ("agent.codex", "a.example,b.example"),
        ("agent.pi", "pi.dev"),
    ]);
    let composed = compose_with(&Groups::new(), None, &current, |request| {
        request.to_string() == "a.example"
    });
    // `pi` was never covered either, so it keeps its first form.
    let mut expected = vec![first("for codex", "b.example"), first("for pi", "pi.dev")];
    expected.extend(trailer());
    assert_eq!(composed.lines, expected);
    assert_eq!(
        composed.printed,
        [agent("codex"), agent("pi")].into_iter().collect()
    );
}

#[test]
fn compose_covered_change_form_omits_covered_additions() {
    let recorded = groups(vec![(agent("codex"), &["a.example"])]);
    let current = declare(&[("agent.codex", "a.example,b.example")]);
    let composed = compose_with(&recorded, None, &current, |request| {
        request.to_string() == "b.example"
    });
    assert!(
        composed.lines.is_empty(),
        "a fully covered change prints nothing: {:?}",
        composed.lines
    );
    assert!(composed.printed.is_empty());
}

/// R7's example: with internet egress, a removal still prints and the trailer
/// does not.
#[test]
fn compose_removal_survives_full_coverage() {
    let recorded = groups(vec![(agent("codex"), &["a.example", "b.example"])]);
    let current = declare(&[("agent.codex", "a.example")]);
    let composed = compose_with(&recorded, None, &current, |_| true);
    assert_eq!(composed.lines, vec![changed("for codex", "-b.example")]);
}

/// R7's asymmetric case: the recorded set is `{a}` and the labels now declare
/// only `{b}`, with **both** covered. The addition is covered and silent; the
/// removal is required and prints. A rule that drops removals when the addition
/// is covered prints nothing here, which every other removal fixture misses.
#[test]
fn compose_removal_survives_when_the_addition_is_covered() {
    let recorded = groups(vec![(agent("codex"), &["a.example"])]);
    let current = declare(&[("agent.codex", "b.example")]);
    let composed = compose_with(&recorded, None, &current, |_| true);
    assert_eq!(
        composed.lines,
        vec![changed("for codex", "-a.example")],
        "a covered addition never suppresses the removal"
    );
    assert_eq!(composed.printed, [agent("codex")].into_iter().collect());
}

/// The precedence table, one row per combination of (form, coverage, removal).
#[test]
fn compose_precedence_table() {
    let cases: Vec<(Groups, DeclaredImageRequests, bool, Vec<String>)> = vec![
        // No recorded set, everything covered: silent.
        (
            Groups::new(),
            declare(&[("agent.codex", "a.example")]),
            true,
            vec![],
        ),
        // No recorded set, one unmet: first form + trailer.
        (
            Groups::new(),
            declare(&[("agent.codex", "a.example")]),
            false,
            vec![first("for codex", "a.example")]
                .into_iter()
                .chain(trailer())
                .collect(),
        ),
        // Recorded, only covered additions: silent, and the change stays pending.
        (
            groups(vec![(agent("codex"), &["a.example"])]),
            declare(&[("agent.codex", "a.example,b.example")]),
            true,
            vec![],
        ),
        // Recorded, an unmet addition: change form + trailer.
        (
            groups(vec![(agent("codex"), &["a.example"])]),
            declare(&[("agent.codex", "a.example,b.example")]),
            false,
            vec![changed("for codex", "+b.example")]
                .into_iter()
                .chain(trailer())
                .collect(),
        ),
        // Recorded, a removal under full coverage: no trailer.
        (
            groups(vec![(agent("codex"), &["a.example", "b.example"])]),
            declare(&[("agent.codex", "a.example")]),
            true,
            vec![changed("for codex", "-b.example")],
        ),
        // Recorded, an unmet addition and a removal: both, in order.
        (
            groups(vec![(agent("codex"), &["a.example", "c.example"])]),
            declare(&[("agent.codex", "a.example,b.example")]),
            false,
            vec![changed("for codex", "+b.example, -c.example")]
                .into_iter()
                .chain(trailer())
                .collect(),
        ),
        // Recorded unchanged under full coverage: silent.
        (
            groups(vec![(agent("codex"), &["a.example"])]),
            declare(&[("agent.codex", "a.example")]),
            true,
            vec![],
        ),
    ];
    for (index, (recorded, current, covered, expected)) in cases.into_iter().enumerate() {
        let composed = compose_with(&recorded, None, &current, move |_| covered);
        assert_eq!(composed.lines, expected, "precedence row {index}");
    }
}

// ---------------------------------------------------------------------------
// R8 — ignored and count lines
// ---------------------------------------------------------------------------

/// Two refused labels, both in key byte order, then the unrecognized count: no
/// group line (everything is covered) and no trailer.
#[test]
fn compose_invalid_and_count_lines_are_shown_once() {
    let current = declare(&[
        ("agent.codex", "a.example, b.example"),
        ("agent.bad", "10.0.0.1"),
        ("Agent.x", "junk"),
    ]);
    let composed = compose_with(&Groups::new(), None, &current, |_| true);
    assert_eq!(composed.lines.len(), 3, "{:?}", composed.lines);
    assert_eq!(
        composed.lines[0],
        format!(
            "==> Image network requests ({DISPLAY}): ignored invalid label \
             {REQUEST_LABEL_PREFIX}agent.bad (entry 0: an IP address or CIDR is network authority, \
             not a request; name the host (HOST, tcp://HOST or tcp://HOST:PORT))"
        )
    );
    assert_eq!(
        composed.lines[1],
        format!(
            "==> Image network requests ({DISPLAY}): ignored invalid label \
             {REQUEST_LABEL_PREFIX}agent.codex (entry 1: not a hostname (one or more labels of ASCII \
             letters, digits and '-', not ending in a numeric label; write non-ASCII names as \
             A-labels; no wildcards))"
        )
    );
    assert_eq!(
        composed.lines[2],
        format!(
            "==> Image network requests ({DISPLAY}): ignored 1 label under \
             {REQUEST_LABEL_PREFIX} whose key is not image.NAME or agent.NAME"
        )
    );

    // Recorded facts silence the same lines next launch.
    let recorded_ignored = current.ignored_facts();
    let again = compose_with(&Groups::new(), Some(&recorded_ignored), &current, |_| true);
    assert!(again.lines.is_empty(), "{:?}", again.lines);

    // A changed count prints again.
    let recounted_declaration = declare(&[
        ("agent.codex", "a.example, b.example"),
        ("agent.bad", "10.0.0.1"),
        ("Agent.x", "junk"),
        ("Agent.y", "junk"),
    ]);
    let recounted = compose_with(
        &Groups::new(),
        Some(&recorded_ignored),
        &recounted_declaration,
        |_| true,
    );
    assert_eq!(recounted.lines.len(), 1, "{:?}", recounted.lines);
    assert!(recounted.lines[0].contains("ignored 2 labels under"));
}

#[test]
fn compose_excess_line_says_the_report_is_partial() {
    let mut current = declare(&[("agent.codex", "a.example")]);
    current.excess = 1;
    let composed = compose_with(
        &groups(vec![(agent("codex"), &["a.example"])]),
        None,
        &current,
        |_| true,
    );
    assert_eq!(
        composed.lines,
        vec![format!(
            "==> Image network requests ({DISPLAY}): ignored 1 request label beyond the first 64 in \
             key order; this report is partial"
        )]
    );
}

/// The excess and unrecognized counts are counts: each must print when it
/// changes **in either direction**, and only then. A launch with more excess than
/// the recorded one is not the only change that matters — 2→1 is one too.
#[test]
fn count_lines_react_to_every_change_in_both_directions() {
    let excess = |count: u64| {
        let plural = if count == 1 { "label" } else { "labels" };
        format!(
            "==> Image network requests ({DISPLAY}): ignored {count} request {plural} beyond the \
             first 64 in key order; this report is partial"
        )
    };
    let excess_labels = |count: usize| -> Vec<(String, String)> {
        (0..count)
            .map(|index| {
                (
                    key(&format!("image.c{index:02}")),
                    format!("h{index}.example"),
                )
            })
            .collect()
    };
    // Everything is covered, so the only line any of these launches can print is
    // a count line: the group line is silent and no trailer prints.
    let mut entries = Vec::new();
    assert_eq!(
        launch_once(&mut entries, &labels(excess_labels(65)), |_| true),
        vec![excess(1)]
    );
    assert_eq!(
        launch_once(&mut entries, &labels(excess_labels(66)), |_| true),
        vec![excess(2)],
        "1→2 prints"
    );
    assert_eq!(
        launch_once(&mut entries, &labels(excess_labels(65)), |_| true),
        vec![excess(1)],
        "2→1 prints"
    );
    assert!(
        launch_once(&mut entries, &labels(excess_labels(65)), |_| true).is_empty(),
        "an unchanged count is silent"
    );

    let unrecognized = |count: u64| {
        let plural = if count == 1 { "label" } else { "labels" };
        format!(
            "==> Image network requests ({DISPLAY}): ignored {count} {plural} under \
             {REQUEST_LABEL_PREFIX} whose key is not image.NAME or agent.NAME"
        )
    };
    let junk = |count: usize| -> Vec<(String, String)> {
        let mut raw: Vec<(String, String)> = (0..count)
            .map(|index| (key(&format!("Agent.a{index:02}")), "junk".to_owned()))
            .collect();
        raw.push((key("agent.ok"), "ok.example".to_owned()));
        raw
    };
    let mut entries = Vec::new();
    assert_eq!(
        launch_once(&mut entries, &labels(junk(1)), |_| true),
        vec![unrecognized(1)]
    );
    assert_eq!(
        launch_once(&mut entries, &labels(junk(2)), |_| true),
        vec![unrecognized(2)],
        "1→2 prints"
    );
    assert_eq!(
        launch_once(&mut entries, &labels(junk(1)), |_| true),
        vec![unrecognized(1)],
        "2→1 prints"
    );
    assert!(
        launch_once(&mut entries, &labels(junk(1)), |_| true).is_empty(),
        "an unchanged count is silent"
    );
}

/// A refusal with the grammar's own `TooMany` reason is an ignored label like any
/// other: it prints once, and the next launch with the same label is silent. The
/// defect this pins is a rule that treats `TooMany` as always worth repeating.
#[test]
fn a_too_many_refusal_prints_once_and_the_next_launch_is_silent() {
    let many = (0..=crate::network_requests::MAX_NETWORK_REQUESTS)
        .map(|index| format!("h{index}.example"))
        .collect::<Vec<_>>()
        .join(",");
    let current = declare(&[("agent.codex", many.as_str())]);
    let refusal = current.invalid.values().next().expect("one refusal");
    assert_eq!(refusal.position, None, "TooMany has no field position");
    let mut entries = Vec::new();
    let first = launch_once(&mut entries, &current, |_| true);
    assert_eq!(first.len(), 1, "{first:?}");
    assert!(first[0].contains("ignored invalid label"));
    assert!(
        launch_once(&mut entries, &current, |_| true).is_empty(),
        "the same over-long value must not print again"
    );
}

// ---------------------------------------------------------------------------
// R10 — no echo of rejected or unsafe bytes
// ---------------------------------------------------------------------------

/// The report contains only fixed text, counts, the reference, canonical
/// requests and validated NAMEs.
#[test]
fn compose_never_echoes_rejected_or_unsafe_bytes() {
    let sentinel = "SENTINEL505\u{1b}[31m\u{202e}\0\n";
    let current = labels(vec![
        (
            key("agent.codex"),
            format!("{sentinel}x.example,api.openai.com"),
        ),
        (key(&format!("agent.{sentinel}")), "evil.example".to_owned()),
        (key(&format!("Agent.{sentinel}")), "evil.example".to_owned()),
        (
            format!("{REQUEST_LABEL_PREFIX}{sentinel}"),
            "evil.example".to_owned(),
        ),
        (key("agent.ok"), "ok.example".to_owned()),
    ]);
    let composed = compose_with(&Groups::new(), None, &current, |_| false);
    let doctor = doctor_section(&CachedLabels::Present(
        [
            (
                format!("{REQUEST_LABEL_PREFIX}agent.codex"),
                format!("{sentinel}x.example"),
            ),
            (
                format!("{REQUEST_LABEL_PREFIX}agent.sk-live-abc"),
                "bad value".to_owned(),
            ),
        ]
        .into_iter()
        .collect(),
    ));
    for line in composed.lines.iter().chain(std::iter::once(&doctor)) {
        for byte in line.bytes() {
            assert!(
                byte == b' ' || byte.is_ascii_graphic() || byte == b'\n',
                "a report line carries a non-printable byte {byte:#04x}: {line:?}"
            );
        }
        assert!(!line.contains("SENTINEL505"), "leaked: {line:?}");
        assert!(!line.contains('\u{202e}'), "leaked: {line:?}");
    }
    // The valid control does print, secret-looking or not (ADR-0039 frames this
    // as protection against untrusted framing, not secret detection).
    let control = declare(&[
        ("agent.codex", "sk-test-sensitivevalue"),
        ("agent.sk-live-abc", "bad value"),
    ]);
    let composed = compose_with(&Groups::new(), None, &control, |_| false);
    assert!(
        composed
            .lines
            .contains(&first("for codex", "sk-test-sensitivevalue")),
        "{:?}",
        composed.lines
    );
    assert!(
        composed
            .lines
            .iter()
            .any(|line| line.contains(&format!("{REQUEST_LABEL_PREFIX}agent.sk-live-abc"))),
        "{:?}",
        composed.lines
    );
}

// ---------------------------------------------------------------------------
// A26 — maximal rendering
// ---------------------------------------------------------------------------

/// Sixty-four `image.*` labels of 64 requests each give one first-form line with
/// 4096 requests; the disjoint refresh gives one change line with 8192 terms.
/// Then 64 agent groups are replaced by 64 disjoint ones in one launch.
#[test]
fn compose_renders_the_maximal_report_without_truncation() {
    let mut raw: Vec<(String, String)> = Vec::new();
    for label in 0..64 {
        let chunk = (0..64)
            .map(|offset| format!("h{}.example", label * 64 + offset))
            .collect::<Vec<_>>()
            .join(",");
        raw.push((key(&format!("image.c{label:02}")), chunk));
    }
    let current = labels(raw);
    assert_eq!(current.groups()[&RequestGroup::EveryLaunch].len(), 4096);
    let composed = compose_with(&Groups::new(), None, &current, |_| false);
    assert_eq!(
        composed.lines.len(),
        3,
        "one group line and two trailer lines"
    );
    assert_eq!(composed.lines[0].matches(", ").count(), 4095);
    assert!(composed.lines[0].starts_with(&first("for every launch", "")));

    let recorded: Groups = current.groups().clone();
    let mut next: Vec<(String, String)> = Vec::new();
    for label in 0..64 {
        let chunk = (0..64)
            .map(|offset| format!("g{}.example", label * 64 + offset))
            .collect::<Vec<_>>()
            .join(",");
        next.push((key(&format!("image.c{label:02}")), chunk));
    }
    let refreshed = labels(next);
    let composed = compose_with(&recorded, None, &refreshed, |_| false);
    let change = &composed.lines[0];
    assert_eq!(change.matches(", ").count(), 8191);
    assert_eq!(change.matches(" +").count(), 4096);
    assert_eq!(change.matches(" -").count(), 4096);

    let mut before: Vec<(String, String)> = Vec::new();
    let mut after: Vec<(String, String)> = Vec::new();
    for index in 0..64 {
        before.push((
            key(&format!("agent.x{index:02}")),
            format!("old{index}.example"),
        ));
        after.push((
            key(&format!("agent.y{index:02}")),
            format!("new{index}.example"),
        ));
    }
    let recorded = labels(before).groups().clone();
    let declared_after = labels(after);
    let composed = compose_with(&recorded, None, &declared_after, |_| false);
    assert_eq!(composed.lines.len(), 64 + 64 + 2);
    assert_eq!(composed.printed.len(), 128);
    for (index, line) in composed.lines.iter().take(64).enumerate() {
        assert_eq!(
            line,
            &changed(&format!("for x{index:02}"), &format!("-old{index}.example"))
        );
    }
    for (index, line) in composed.lines.iter().skip(64).take(64).enumerate() {
        assert_eq!(
            line,
            &first(&format!("for y{index:02}"), &format!("new{index}.example"))
        );
    }
}

// ---------------------------------------------------------------------------
// R18(d) — a dropped group's reappearance is first-form
// ---------------------------------------------------------------------------

/// At the 128-group bound, the empty recorded sets of vanished groups are
/// dropped. A group reintroduced afterwards has no recorded set — so it must use
/// the first form, never `+host`, even though the store was full when it was
/// dropped. The store must then record it like any other first-form group.
#[test]
fn a_group_reintroduced_after_the_eviction_uses_the_first_form() {
    // 64 non-empty recorded sets and 128 empty ones whose groups have vanished.
    let mut recorded = Groups::new();
    for index in 0..64 {
        let host = format!("h{index}.example");
        recorded.insert(agent(&format!("a{index:02}")), req(&[host.as_str()]));
    }
    for index in 0..128 {
        recorded.insert(agent(&format!("z{index:03}")), BTreeSet::new());
    }
    assert_eq!(recorded.len(), 192);
    let stored = super::baseline::Entry {
        reference: "REF".to_owned(),
        baseline: recorded,
        ignored: IgnoredFacts::default(),
    };
    // One printed line presses the entry over the bound: 193 groups become 128,
    // dropping 65 empty sets of vanished groups, last in group order first.
    let keeper = declare(&[("agent.keeper", "k.example")]);
    let written = super::baseline::next_entries(
        vec![stored],
        "REF",
        &keeper,
        &[agent("keeper")].into_iter().collect(),
        true,
    )
    .expect("a shown line writes");
    let baseline = &written[0].baseline;
    assert_eq!(baseline.len(), super::baseline::MAX_RECORDED_GROUPS);
    assert!(baseline.contains_key(&agent("keeper")));
    assert!(
        baseline.contains_key(&agent("z000")),
        "the earliest vanished group stays until the bound needs it"
    );
    assert!(
        !baseline.contains_key(&agent("z063")),
        "z063 was evicted, last in group order first"
    );
    assert!(
        !baseline.contains_key(&agent("z127")),
        "every later vanished group was evicted too"
    );

    // The evicted group comes back. There is no recorded set for it, so the
    // report is the first form with no `+` — and the write records it.
    let mut entries = written;
    let reintroduced = declare(&[("agent.z063", "z.example")]);
    let lines = launch_once(&mut entries, &reintroduced, |_| false);
    let expected_first = first("for z063", "z.example");
    assert!(
        lines.contains(&expected_first),
        "a dropped group's reappearance is first-form, never a change: {lines:?}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("for z063 ") && line.contains('+')),
        "no `+` term for the reintroduced group: {lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line.contains("changed: for z063")),
        "the reintroduced group is not a change line: {lines:?}"
    );
    assert_eq!(
        recorded_entry(&entries).baseline[&agent("z063")],
        req(&["z.example"]),
        "the reappearance is recorded like any first-form group"
    );
}

// ---------------------------------------------------------------------------
// A27 — the two-group invariant enumeration
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DemoGroup {
    X,
    Y,
}

const DEMO_GROUPS: [DemoGroup; 2] = [DemoGroup::X, DemoGroup::Y];
const DEMO_HOSTS: [&str; 2] = ["a.example", "b.example"];

fn group_key_of(group: DemoGroup) -> &'static str {
    match group {
        DemoGroup::X => "agent.x",
        DemoGroup::Y => "agent.y",
    }
}

/// A group's state in one launch: absent, empty, or holding a subset of the two
/// hosts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GroupState {
    present: bool,
    hosts: [bool; 2],
}

const GROUP_STATES: [GroupState; 5] = [
    GroupState {
        present: false,
        hosts: [false, false],
    },
    GroupState {
        present: true,
        hosts: [false, false],
    },
    GroupState {
        present: true,
        hosts: [true, false],
    },
    GroupState {
        present: true,
        hosts: [false, true],
    },
    GroupState {
        present: true,
        hosts: [true, true],
    },
];

fn render_state(state: GroupState) -> Option<String> {
    if !state.present {
        return None;
    }
    let selected: Vec<&str> = DEMO_HOSTS
        .iter()
        .copied()
        .zip(state.hosts)
        .filter_map(|(host, present)| present.then_some(host))
        .collect();
    Some(selected.join(","))
}

/// One launch state: 25 label combinations × 4 grant subsets.
struct Launch {
    current: DeclaredImageRequests,
    states: [GroupState; 2],
    grants: [bool; 2],
}

impl Launch {
    fn holds(&self, group: DemoGroup, host: usize) -> bool {
        self.states[group as usize].hosts[host]
    }
}

fn launch_states() -> Vec<Launch> {
    let mut launches = Vec::with_capacity(100);
    for x in GROUP_STATES {
        for y in GROUP_STATES {
            for grants in [[false, false], [true, false], [false, true], [true, true]] {
                let mut raw: Vec<(String, String)> = Vec::new();
                for (group, state) in [(DemoGroup::X, x), (DemoGroup::Y, y)] {
                    if let Some(value) = render_state(state) {
                        raw.push((key(group_key_of(group)), value));
                    }
                }
                launches.push(Launch {
                    current: labels(raw),
                    states: [x, y],
                    grants,
                });
            }
        }
    }
    launches
}

/// What one launch rendered, read back out of the report: the oracle is driven by
/// the lines, never by production state. A bare term can only appear in the first
/// form and a signed term only in the change form, and every line's terms are
/// unique, so a line whose shape is wrong fails here rather than being
/// re-interpreted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Rendered {
    bare: [[bool; 2]; 2],
    added: [[bool; 2]; 2],
    removed: [[bool; 2]; 2],
    groups_with_a_line: [bool; 2],
    trailer: bool,
}

impl Rendered {
    fn shown(&self, slot: usize, host: usize) -> bool {
        self.bare[slot][host] || self.added[slot][host]
    }
}

fn read_rendered(prefix: &str, lines: &[String]) -> Rendered {
    let mut rendered = Rendered::default();
    for line in lines {
        if line.starts_with("==>   image requests above") {
            rendered.trailer = true;
            continue;
        }
        let Some(rest) = line.strip_prefix(prefix) else {
            continue;
        };
        let (change_form, terms) = match rest.strip_prefix(" changed: ") {
            Some(rest) => (true, rest),
            None => match rest.strip_prefix(": ") {
                Some(rest) => (false, rest),
                None => continue,
            },
        };
        let after_for = terms
            .strip_prefix("for ")
            .unwrap_or_else(|| panic!("no group in {line:?}"));
        let space = after_for
            .find(' ')
            .unwrap_or_else(|| panic!("no request in {line:?}"));
        let group = match &after_for[..space] {
            "x" => DemoGroup::X,
            "y" => DemoGroup::Y,
            // The first form also carries `ignored invalid label …` and the count
            // lines; this universe declares neither, so anything else here is a
            // report shape the oracle does not model.
            _other if !change_form => continue,
            other => panic!("unexpected group {other:?} in {line:?}"),
        };
        let slot = group as usize;
        rendered.groups_with_a_line[slot] = true;
        let mut seen_removal = false;
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for term in after_for[space + 1..].split(", ") {
            assert!(seen.insert(term), "duplicate term in {line:?}");
            let (sign, host) = match term.as_bytes().first() {
                Some(b'+') => (Some('+'), &term[1..]),
                Some(b'-') => (Some('-'), &term[1..]),
                _ => (None, term),
            };
            let host = DEMO_HOSTS
                .iter()
                .position(|candidate| *candidate == host)
                .unwrap_or_else(|| panic!("unexpected request in {line:?}"));
            match sign {
                Some('+') => {
                    assert!(change_form, "a `+` term in a first-form line: {line:?}");
                    assert!(!seen_removal, "a `+` term after a `-` term: {line:?}");
                    rendered.added[slot][host] = true;
                }
                Some('-') => {
                    assert!(change_form, "a `-` term in a first-form line: {line:?}");
                    seen_removal = true;
                    rendered.removed[slot][host] = true;
                }
                _ => {
                    assert!(!change_form, "a bare term in a change line: {line:?}");
                    rendered.bare[slot][host] = true;
                }
            }
        }
    }
    rendered
}

/// The independent model of one group's recorded set and of the lines R5–R7
/// require, driven only by the labels, the grants and what was rendered before.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct OracleGroup {
    has_set: bool,
    set: [bool; 2],
}

impl OracleGroup {
    /// The oracle state as a memo key: three bits per group.
    fn key(self) -> u8 {
        (u8::from(self.has_set) << 2) | (u8::from(self.set[0]) << 1) | u8::from(self.set[1])
    }
}

/// The exact report the rules require, as one comparable value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Expected {
    bare: [[bool; 2]; 2],
    added: [[bool; 2]; 2],
    removed: [[bool; 2]; 2],
    printed: [bool; 2],
    trailer: bool,
}

impl Expected {
    fn of(rendered: &Rendered) -> Self {
        Self {
            bare: rendered.bare,
            added: rendered.added,
            removed: rendered.removed,
            printed: rendered.groups_with_a_line,
            trailer: rendered.trailer,
        }
    }
}

/// R5/R6/R7's output rule, as an oracle: the exact form and exact terms for every
/// group, not just "the unmet additions appeared".
///
/// For a group with no recorded set, every request that is in the labels and
/// unmet is listed bare. For a group with a recorded set, the line lists `+` for
/// each unmet request that is not recorded and `-` for each recorded request that
/// left the labels — removals are **required**, not optional, and a covered or
/// recorded addition must not be added again. The trailer prints iff any unmet
/// addition was shown. The group's recorded set then becomes its current labels,
/// but only when its own line rendered.
fn expected_report(launch: &Launch, oracle: &mut [OracleGroup; 2]) -> Expected {
    let mut expected = Expected::default();
    for (slot, _group) in DEMO_GROUPS.into_iter().enumerate() {
        let now = launch.states[slot].hosts;
        let recorded = oracle[slot].set;
        for host in 0..2 {
            let unmet = now[host] && !launch.grants[host];
            expected.removed[slot][host] = recorded[host] && !now[host];
            // A group with no recorded set uses the first form (bare terms); a
            // group with one uses `+` for each unmet request it has not recorded.
            expected.added[slot][host] = unmet && oracle[slot].has_set && !recorded[host];
            expected.bare[slot][host] = unmet && !oracle[slot].has_set;
        }
        let line_expected = expected.added[slot].iter().any(|shown| *shown)
            || expected.bare[slot].iter().any(|shown| *shown)
            || expected.removed[slot].iter().any(|shown| *shown);
        expected.printed[slot] = line_expected;
        expected.trailer |= expected.added[slot].iter().any(|shown| *shown)
            || expected.bare[slot].iter().any(|shown| *shown);
        if line_expected {
            oracle[slot] = OracleGroup {
                has_set: true,
                set: now,
            };
        }
    }
    expected
}

#[derive(Debug, Default, Clone, Copy)]
struct PairProgress {
    absorbed: bool,
    shown_since_removal: bool,
}

fn group_of(group: DemoGroup) -> RequestGroup {
    match group {
        DemoGroup::X => agent("x"),
        DemoGroup::Y => agent("y"),
    }
}

fn set_code(set: Option<&BTreeSet<NetworkRequest>>) -> u8 {
    let Some(set) = set else { return 0 };
    let has = |host: &str| set.iter().any(|request| request.name().as_str() == host);
    match (has("a.example"), has("b.example")) {
        (false, false) => 1,
        (true, false) => 2,
        (false, true) => 3,
        (true, true) => 4,
    }
}

fn decode_set(code: u8) -> BTreeSet<NetworkRequest> {
    match code {
        1 => req(NONE),
        2 => req(&["a.example"]),
        3 => req(&["b.example"]),
        _ => req(&["a.example", "b.example"]),
    }
}

/// One real store: the code is the finite memo key, and `entries` is the value
/// `next_entries` actually produced. The previous model kept only the code and
/// fabricated `reference: "REF"`, so a write rule that stored the wrong
/// reference, the wrong ignored facts or a wrong set still "worked". This one
/// travels the real entry and asserts the projection is lossless.
#[derive(Clone, Debug)]
struct RecordedState {
    code: [u8; 2],
    entries: Vec<super::baseline::Entry>,
}

fn code_of(baseline: &Groups) -> [u8; 2] {
    [
        set_code(baseline.get(&group_of(DemoGroup::X))),
        set_code(baseline.get(&group_of(DemoGroup::Y))),
    ]
}

impl RecordedState {
    fn of(entries: Vec<super::baseline::Entry>) -> Self {
        let none = Groups::new();
        let baseline = entries
            .iter()
            .find(|entry| entry.reference == "REF")
            .map_or(&none, |entry| &entry.baseline);
        Self {
            code: code_of(baseline),
            entries,
        }
    }

    /// The property the memo key relies on: two real stores with one code differ
    /// in nothing the report, the write rule or the decoder can observe. Every
    /// entry field is checked, not just the two sets.
    fn assert_projection(&self) {
        let none = Groups::new();
        let baseline = self
            .entries
            .iter()
            .find(|entry| entry.reference == "REF")
            .map_or(&none, |entry| &entry.baseline);
        for (slot, group) in DEMO_GROUPS.into_iter().enumerate() {
            let expected = match self.code[slot] {
                0 => None,
                code => Some(decode_set(code)),
            };
            assert_eq!(
                baseline.get(&group_of(group)),
                expected.as_ref(),
                "group {group:?}: the code must preserve its recorded set exactly"
            );
        }
        for entry in &self.entries {
            assert_eq!(
                entry.reference, "REF",
                "the write rule must key the entry by the selection it was handed"
            );
            assert_eq!(
                entry.ignored,
                IgnoredFacts::default(),
                "the ignored facts are observable and must be carried, not projected away"
            );
            assert!(
                entry
                    .baseline
                    .keys()
                    .all(|group| *group == group_of(DemoGroup::X)
                        || *group == group_of(DemoGroup::Y)),
                "the store must not gain a group this universe did not declare"
            );
        }
    }
}

/// One transition, computed by the real `compose` and `next_entries` from the
/// store state a launch would read.
fn compute_transition(state: &RecordedState, launch: &Launch) -> (RecordedState, Rendered) {
    let prefix = format!("==> Image network requests ({DISPLAY})");
    // `report_before_boot`'s read, by reference: a write rule that stored any
    // other reference is a miss here, exactly as it is in production.
    let recorded = state.entries.iter().find(|entry| entry.reference == "REF");
    let covered = |request: &NetworkRequest| match request.name().as_str() {
        "a.example" => launch.grants[0],
        "b.example" => launch.grants[1],
        _ => false,
    };
    let none = Groups::new();
    let composed = compose(
        recorded.map_or(&none, |entry| &entry.baseline),
        recorded.map(|entry| &entry.ignored),
        &launch.current,
        DISPLAY,
        &covered,
    );
    let rendered = read_rendered(&prefix, &composed.lines);
    let written = super::baseline::next_entries(
        state.entries.clone(),
        "REF",
        &launch.current,
        &composed.printed,
        !composed.lines.is_empty(),
    );
    let next = match written {
        Some(entries) => RecordedState::of(entries),
        // "Write nothing" leaves the store exactly as it was.
        None => state.clone(),
    };
    next.assert_projection();
    (next, rendered)
}

/// R25 over every three-launch sequence from an empty store: two groups, two
/// hosts, five states per group and four grant subsets, 100³ = 10⁶ sequences.
///
/// Two oracles run per launch. The exact one ([`check_oracle`]) demands the
/// required removals, the exact first/change form and the exact trailer. The
/// pair invariant tracks three things per (group, request), all derived from the
/// labels, the grants and the rendered lines: whether the pair is absorbed (a
/// line of **its own** group rendered while the pair was in that group's labels),
/// whether it has been shown as unmet since the last shown removal of it, and
/// whether a removal of it has been shown.
///
/// The store has finitely many relevant states (five per group), so each
/// (state, launch) transition is computed once by the real code and reused. The
/// memo key is that code, and reuse first asserts the two real stores are
/// identical, so a projection that loses an entry field cannot hide behind it.
#[test]
fn write_rule_invariant_holds_over_every_three_launch_sequence() {
    let started = std::time::Instant::now();
    let launches = launch_states();
    assert_eq!(launches.len(), 100);
    // (next code, rendered) for each (store code, launch).
    let mut transitions: std::collections::HashMap<([u8; 2], usize), ([u8; 2], Rendered)> =
        std::collections::HashMap::new();
    // The one real store each code stands for. Inserted once per code, so the
    // hot path moves a two-byte code, not an entry vector.
    let mut real_stores: std::collections::HashMap<[u8; 2], Vec<super::baseline::Entry>> =
        std::collections::HashMap::new();
    real_stores.insert([0, 0], Vec::new());
    // The report and the oracle transition are pure functions of (store code,
    // launch, oracle state), so the exact check runs once per distinct input
    // rather than once per sequence. The pair invariant below still runs on
    // every sequence.
    let mut oracle_checks: std::collections::HashMap<([u8; 2], usize, [u8; 2]), [OracleGroup; 2]> =
        std::collections::HashMap::new();
    let mut sequences: u64 = 0;
    for first in 0..launches.len() {
        for second in 0..launches.len() {
            for third in 0..launches.len() {
                sequences += 1;
                let mut state = [0u8; 2];
                let mut oracle = [OracleGroup::default(); 2];
                let mut pairs = [[PairProgress::default(); 2]; 2];
                for index in [first, second, third] {
                    let launch = &launches[index];
                    let (next_code, rendered) = match transitions.get(&(state, index)) {
                        Some(known) => *known,
                        None => {
                            let from = RecordedState {
                                code: state,
                                entries: real_stores.get(&state).cloned().unwrap_or_default(),
                            };
                            let (next, rendered) = compute_transition(&from, launch);
                            // The memo key is sound only if one code stands for
                            // one real store; the first store seen for a code is
                            // the one every later visit must equal.
                            match real_stores.get(&next.code) {
                                Some(known) => assert_eq!(
                                    known, &next.entries,
                                    "one memo code must stand for one real store"
                                ),
                                None => {
                                    real_stores.insert(next.code, next.entries.clone());
                                }
                            }
                            transitions.insert((state, index), (next.code, rendered));
                            (next.code, rendered)
                        }
                    };
                    let oracle_key = [oracle[0].key(), oracle[1].key()];
                    match oracle_checks.get(&(state, index, oracle_key)) {
                        Some(after) => oracle = *after,
                        None => {
                            let expected = expected_report(launch, &mut oracle);
                            assert_eq!(
                                Expected::of(&rendered),
                                expected,
                                "states {:?} grants {:?}: the report must be exactly the required \
                                 one",
                                launch.states,
                                launch.grants
                            );
                            oracle_checks.insert((state, index, oracle_key), oracle);
                        }
                    }
                    for group in DEMO_GROUPS {
                        let slot = group as usize;
                        for (host, progress) in pairs[slot].iter_mut().enumerate() {
                            // (1) never twice without an intervening removal.
                            if rendered.shown(slot, host) && progress.shown_since_removal {
                                panic!(
                                    "shown twice: group {group:?} host {} in a launch of state \
                                     {state:?}\n{:?}",
                                    DEMO_HOSTS[host], pairs
                                );
                            }
                            // (2) nothing swallowed.
                            if launch.holds(group, host)
                                && !launch.grants[host]
                                && !progress.absorbed
                                && !rendered.shown(slot, host)
                            {
                                panic!(
                                    "swallowed: group {group:?} host {} is declared, unmet and not \
                                     absorbed but no line shows it\n{:?}\n{:?}",
                                    DEMO_HOSTS[host], rendered, pairs
                                );
                            }
                        }
                    }
                    for group in DEMO_GROUPS {
                        let slot = group as usize;
                        for (host, progress) in pairs[slot].iter_mut().enumerate() {
                            if rendered.removed[slot][host] {
                                *progress = PairProgress::default();
                            }
                            if rendered.shown(slot, host) {
                                progress.shown_since_removal = true;
                            }
                            // R25(c): absorption is credited only to a line of the
                            // pair's own group.
                            if rendered.groups_with_a_line[slot] && launch.holds(group, host) {
                                progress.absorbed = true;
                            }
                        }
                    }
                    state = next_code;
                }
            }
        }
    }
    assert_eq!(sequences, 1_000_000);
    assert_eq!(
        transitions.len(),
        25 * launches.len(),
        "every recorded state and launch pair is exercised"
    );
    eprintln!(
        "A27 enumeration: {sequences} sequences, {} transitions, in {:?}",
        transitions.len(),
        started.elapsed()
    );
}

// ---------------------------------------------------------------------------
// R20 — the doctor section
// ---------------------------------------------------------------------------

#[test]
fn doctor_section_renders_every_group_in_full() {
    let cached = CachedLabels::Present(
        [
            (key("image.base"), "deb.debian.org".to_owned()),
            (key("agent.codex"), "api.openai.com,chatgpt.com".to_owned()),
            (key("agent.pi"), String::new()),
            (key("agent.bad"), "10.0.0.1".to_owned()),
            (key("Agent.x"), "junk".to_owned()),
        ]
        .into_iter()
        .collect(),
    );
    let section = doctor_section(&cached);
    let lines: Vec<&str> = section.lines().collect();
    assert_eq!(lines[0], "==> image network requests");
    assert_eq!(lines[1], "for every launch deb.debian.org");
    assert_eq!(lines[2], "for codex api.openai.com, chatgpt.com");
    assert_eq!(lines[3], "for pi (declares no requests)");
    assert!(lines[4].starts_with(&format!(
        "ignored invalid label {REQUEST_LABEL_PREFIX}agent.bad (entry 0: "
    )));
    assert_eq!(
        lines[5],
        format!(
            "ignored 1 label under {REQUEST_LABEL_PREFIX} whose key is not image.NAME or agent.NAME"
        )
    );
    assert_eq!(
        lines[6],
        "requests never grant access; a launch reports those its grants do not cover, once per \
         image reference, then as changes"
    );
    assert_eq!(lines.len(), 7);
}

#[test]
fn doctor_section_states_that_an_excess_report_is_incomplete() {
    let mut raw: Vec<(String, String)> = (0..MAX_REQUEST_LABELS)
        .map(|index| {
            (
                key(&format!("agent.a{index:02}")),
                format!("h{index}.example"),
            )
        })
        .collect();
    raw.push((key("agent.zz"), "late.example".to_owned()));
    let section = doctor_section(&CachedLabels::Present(raw.into_iter().collect()));
    assert!(section.contains(
        "ignored 1 request label beyond the first 64 in key order; the requests above are incomplete"
    ));
    assert!(!section.contains("for zz"));
    assert_eq!(
        section
            .lines()
            .filter(|line| line.starts_with("for "))
            .count(),
        MAX_REQUEST_LABELS
    );
}

#[test]
fn doctor_section_has_a_fixed_row_for_every_unavailable_state() {
    let fixed = [
        (CachedLabels::LocalPath, "local rootfs or disk path"),
        (
            CachedLabels::NotCached,
            "not cached; doctor does not acquire images",
        ),
        (
            CachedLabels::Unreadable,
            "the cached image metadata could not be read",
        ),
        (
            CachedLabels::ApprovalUnreadable,
            "the image approval record could not be read",
        ),
        (
            CachedLabels::LocationUnknown,
            "the image cache location could not be determined",
        ),
    ];
    for (cached, expected) in fixed {
        let section = doctor_section(&cached);
        assert!(
            section.starts_with("==> image network requests\n"),
            "{section}"
        );
        assert!(section.contains(expected), "{section}");
        assert_eq!(section.lines().count(), 2, "{section}");
    }
    let none = doctor_section(&CachedLabels::Present(Default::default()));
    assert_eq!(
        none,
        "==> image network requests\nthe selected image declares no requests"
    );
}

// ---------------------------------------------------------------------------
// R23, A18 — the source tripwire
// ---------------------------------------------------------------------------

/// Tokens that construct or mutate egress authority, reach network I/O or a
/// resolver, or reach credential or provisioning code (R23).
const FORBIDDEN: [&str; 16] = [
    "std::net",
    "tokio",
    "lookup_host",
    "to_socket_addrs",
    "ToSocketAddrs",
    "TcpStream",
    "UdpSocket",
    "EgressAuthority",
    "from_cli",
    "CliEgress",
    "apply_to",
    ".policy(",
    "egress_reference",
    "credential_injection",
    "credential_resolver",
    "provision",
];

/// The same sixteen obligations, written out again: an oracle that *is* the list
/// moves with it, so deleting an entry would leave the self-test green.
const OBLIGATIONS: [&str; 16] = [
    "std::net",
    "tokio",
    "lookup_host",
    "to_socket_addrs",
    "ToSocketAddrs",
    "TcpStream",
    "UdpSocket",
    "EgressAuthority",
    "from_cli",
    "CliEgress",
    "apply_to",
    ".policy(",
    "egress_reference",
    "credential_injection",
    "credential_resolver",
    "provision",
];

/// The crate items the report module may name after `crate::` (R23's "only an
/// allow-listed set of crate modules"). An item is a path prefix: the root
/// segment, or a root plus the exact members used.
const PARENT_ITEMS: [&str; 3] = [
    "network_requests",
    "pi_credential_inspection::provider_id_is_safe_bytes",
    "boot_image::ImageLabel",
];

/// The crate items the store module may name, plus its parent through `super::`.
const STORE_ITEMS: [&str; 5] = [
    "network_requests",
    "host_paths::state_root",
    "host_paths::atomic_write",
    "host_paths::read_optional_bounded_regular_file_no_follow",
    "pi_credential_inspection::provider_id_is_safe_bytes",
];

/// Path roots that may be named wholesale: the verifier prelude and the crates
/// the report already depends on. Everything else is a violation, so a future
/// `use microsandbox::…` or `reqwest::…` is a red build rather than a review
/// miss.
const EXTERNAL_ROOTS: [&str; 5] = ["std", "vstd", "serde", "serde_json", "anyhow"];

/// `std` is *not* wholesale: only these modules, plus the one filesystem call the
/// store makes. `std::process`, `std::env`, `std::net` and `std::fs::write` are
/// therefore violations, which a bare token denylist could not guarantee.
const STD_MODULES: [&str; 5] = ["collections", "fmt", "io", "path", "slice"];
const STD_ITEMS: [&str; 1] = ["fs::symlink_metadata"];

/// Every other path root either production file names: this module's own types,
/// its parent's types and the sibling modules it reads. A new module or type has
/// to be added here deliberately, so reaching one is a visible edit.
const LOCAL_ROOTS: [&str; 39] = [
    "Self",
    "Vec",
    "String",
    "BTreeMap",
    "BTreeSet",
    "HashMap",
    "ToString",
    "ErrorKind",
    "NetworkRequests",
    "NetworkRequestsError",
    "collect",
    "Composed",
    "LabelSource",
    "CachedLabels",
    "ExcessWording",
    "ClassifiedKey",
    "RequestLabelKind",
    "RequestLabelFacts",
    "DeclaredImageRequests",
    "Groups",
    "IgnoredFacts",
    "LabelKey",
    "LabelName",
    "LabelRefusal",
    "LabelWord",
    "RequestGroup",
    "Entry",
    "Loaded",
    "PathState",
    "Disposition",
    "Saved",
    "Store",
    "baseline",
    "network_requests",
    "host_paths",
    "pi_credential_inspection",
    "boot_image",
    "fmt",
    "str",
];

/// Drop whitespace around every `::`, so `crate :: network` is `crate::network`.
fn normalize_paths(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(character) = chars.next() {
        if character == ':' && chars.peek() == Some(&':') {
            while out.ends_with(char::is_whitespace) {
                out.pop();
            }
            out.push_str("::");
            chars.next();
            while chars.peek().is_some_and(|next| next.is_whitespace()) {
                chars.next();
            }
        } else {
            out.push(character);
        }
    }
    out
}

fn is_ident(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// Every `root::rest` chain on one line as `(root, rest)`, where `rest` is the
/// remaining segments joined by `::` and is empty when the chain ends at a
/// brace, a glob or the line.
fn path_chains(line: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = line.chars().collect();
    let mut chains = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        if !is_ident(chars[at]) {
            at += 1;
            continue;
        }
        let start = at;
        while at < chars.len() && is_ident(chars[at]) {
            at += 1;
        }
        let root: String = chars[start..at].iter().collect();
        if !(at + 1 < chars.len() && chars[at] == ':' && chars[at + 1] == ':') {
            continue;
        }
        at += 2;
        let mut segments = Vec::new();
        loop {
            if at >= chars.len() || !is_ident(chars[at]) {
                break;
            }
            let segment_start = at;
            while at < chars.len() && is_ident(chars[at]) {
                at += 1;
            }
            segments.push(chars[segment_start..at].iter().collect::<String>());
            if at + 1 < chars.len() && chars[at] == ':' && chars[at + 1] == ':' {
                at += 2;
            } else {
                break;
            }
        }
        chains.push((root, segments.join("::")));
    }
    chains
}

fn first_segment(rest: &str) -> &str {
    rest.split("::").next().unwrap_or("")
}

fn item_allowed(items: &[&str], rest: &str) -> bool {
    items
        .iter()
        .any(|item| rest == *item || rest.starts_with(&format!("{item}::")))
}

/// Every forbidden token, and every path root outside the allow-lists, on a line
/// that is not a leading `//` comment.
///
/// The path rule is an **allow-list over roots**, not a longer denylist: a root
/// that is not `std`/`vstd`/`serde`/`serde_json`/`anyhow`/`crate`/`super`/`self`
/// or one of this module's own names is a violation, whatever crate it belongs
/// to. `std` is narrowed to five modules and one item, and `crate` to the items
/// the two modules may read.
///
/// The exemption is textual, so a block comment that a `//` line closes, an `as`
/// alias, a `macro_rules!` wrapper and a re-export from another module are all
/// invisible here. The data flow is A18's structural review; this is a pattern
/// check over text (ADR-0018).
fn scan(source: &str, items: &[&str], super_allowed: bool) -> Vec<String> {
    let mut violations = Vec::new();
    for (index, line) in source.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for forbidden in FORBIDDEN {
            if line.contains(forbidden) {
                violations.push(format!(
                    "line {}: production text reaches `{forbidden}`",
                    index + 1
                ));
            }
        }
        for (root, rest) in path_chains(&normalize_paths(line)) {
            let reason = match root.as_str() {
                "crate" => (!item_allowed(items, &rest)).then_some(format!(
                    "`crate::` names a module outside the allow-list: {rest}"
                )),
                "super" => {
                    if !super_allowed {
                        Some("`super::` is not allowed here".to_owned())
                    } else if first_segment(&rest) == "super" {
                        Some(format!("`super::` may not reach the crate root: {rest}"))
                    } else {
                        None
                    }
                }
                "std" => {
                    let module = first_segment(&rest);
                    let allowed = STD_MODULES.contains(&module) || item_allowed(&STD_ITEMS, &rest);
                    (!allowed).then_some(format!(
                        "`std::` names a module outside the allow-list: {rest}"
                    ))
                }
                "self" => None,
                other if EXTERNAL_ROOTS.contains(&other) || LOCAL_ROOTS.contains(&other) => None,
                other => Some(format!(
                    "path root `{other}::` is outside the allow-list: {rest}"
                )),
            };
            if let Some(reason) = reason {
                violations.push(format!("line {}: {reason}", index + 1));
            }
        }
    }
    violations
}

fn parent_violations(source: &str) -> Vec<String> {
    scan(source, &PARENT_ITEMS, false)
}

fn store_violations(source: &str) -> Vec<String> {
    scan(source, &STORE_ITEMS, true)
}

/// The report module's production text: no forbidden token, no `super::`, and no
/// path root outside the allow-lists. Both files are production by construction,
/// and each scan first asserts a marker so a wrong include cannot pass vacuously.
#[test]
fn image_request_sources_contain_no_forbidden_token() {
    let parent = include_str!("../image_requests.rs");
    assert!(
        parent.contains("fn report_before_boot("),
        "the include must be the report module"
    );
    let store = include_str!("baseline.rs");
    assert!(
        store.contains("fn save("),
        "the include must be the store module"
    );
    assert_eq!(parent_violations(parent), Vec::<String>::new());
    assert_eq!(store_violations(store), Vec::<String>::new());
}

/// The tripwire's own self-tests: each obligation is detected on its own, the
/// module and root allow-lists are enforced, and a leading `//` line is the only
/// exemption.
#[test]
fn image_request_tripwire_rejects_forbidden_edits() {
    assert_eq!(FORBIDDEN[..], OBLIGATIONS[..]);
    for forbidden in OBLIGATIONS {
        let code = format!("    let _ = {forbidden};\n");
        assert!(
            !parent_violations(&code).is_empty(),
            "`{forbidden}` was not flagged"
        );
        let comment = format!("    // the report must not reach {forbidden}\n");
        assert!(
            parent_violations(&comment).is_empty(),
            "`{forbidden}` was flagged inside a leading comment"
        );
        let trailing = format!("    let _ = 1; // {forbidden}\n");
        assert!(
            !parent_violations(&trailing).is_empty(),
            "a trailing comment is not the leading-comment exemption"
        );
    }

    // The allow-list rows. Each was a blind spot of the path denylist this
    // replaced: every one of them returned no violation before (#505 review A
    // RC1 and review B R10). A compiling line that reaches any of these must
    // redden the gate.
    let parent_blind_spots = [
        // The sandbox builder and its policy, through an external crate.
        "    let _ = microsandbox::Sandbox::builder(\"x\");\n",
        "    use microsandbox::sandbox::SandboxBuilder;\n",
        // Network I/O and a resolver.
        "    let _ = std::process::Command::new(\"curl\");\n",
        "    let _ = reqwest::get(\"http://x\");\n",
        "    let _ = hickory_resolver::Resolver::default();\n",
        // Process environment and an arbitrary host write.
        "    std::env::set_var(\"MSB_NETWORK\", \"x\");\n",
        "    let _ = std::fs::write(path, bytes);\n",
        // Whitespace inside a path defeats a `crate::` substring scan.
        "    let _ = crate :: network::Plan::default();\n",
        // A brace import of a std module is not one of the five allowed ones.
        "    use std::{process::Command, env};\n",
    ];
    for line in parent_blind_spots {
        assert!(
            !parent_violations(line).is_empty(),
            "the allow-list did not flag: {line:?}"
        );
    }
    let store_blind_spots = [
        // `super_allowed` used to permit reaching the crate root from the store.
        "    let _ = super::super::network::Plan::default();\n",
        "    use super::super::secrets::refresh;\n",
        "    use super::super::launch_target;\n",
    ];
    for line in store_blind_spots {
        assert!(
            !store_violations(line).is_empty(),
            "the store allow-list did not flag: {line:?}"
        );
    }

    // The allowed spellings stay allowed: one positive row per root the
    // production scan relies on.
    let allowed = [
        (
            "    let _ = std::collections::BTreeMap::<u8, u8>::new();\n",
            true,
        ),
        ("    let _ = std::fs::symlink_metadata(path);\n", true),
        ("    let _ = crate::host_paths::state_root();\n", true),
        ("    let _ = super::MAX_REQUEST_LABELS;\n", true),
        ("    let _ = crate::network_requests::GRANT_HINT;\n", false),
        ("    let _ = super::LabelName;\n", true),
    ];
    for (line, in_store) in allowed {
        let violations = if in_store {
            store_violations(line)
        } else {
            parent_violations(line)
        };
        assert!(
            violations.is_empty(),
            "an allowed path was flagged: {line:?} => {violations:?}"
        );
    }

    assert_eq!(
        parent_violations("    let _ = super::LabelName;\n").len(),
        1,
        "the report module may not name its parent"
    );
    assert_eq!(
        store_violations("    let _ = crate::{a, b};\n").len(),
        1,
        "a brace import of the crate root is not an allow-listed item"
    );
    assert_eq!(
        parent_violations("    // crate::network\n").len(),
        0,
        "a leading comment is the textual exemption"
    );
    assert_eq!(
        parent_violations("    let _ = crate::boot_image::ImageLabel::for_default_upgrade();\n")
            .len(),
        0
    );
    assert_eq!(
        parent_violations("    let _ = crate::boot_image::BootImage;\n").len(),
        1,
        "the allow-list names one item, not a module"
    );
}
