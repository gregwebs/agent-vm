//! The facade's two halves: what a store becomes for one project (A), and the
//! coverage query every row of ADR-0065 §4.3 is pinned against (B).
//!
//! Group B's oracle is the **runtime's own evaluator**, never this module: a
//! test that re-derived the expectation from `covers` would agree with any bug.
//! The two places exactness is claimed (address-only sets, and DNS queries) are
//! `⇔`; soundness (`recorded ⇒ admissible`) is asserted over mixed sets, and the
//! conservative negatives are fixed cases where the oracle says "allow" and this
//! query deliberately says "not recorded".

use std::{
    net::SocketAddr,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use microsandbox_network::{
    policy::{NetworkPolicy, Protocol},
    shared::{ResolvedHostnameFamily, SharedState},
};
use proptest::prelude::*;

use super::*;
use crate::refusal::{EntryKey, GuestName};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// One leaked directory, so a digest is a *real* digest of a real path without
/// every test paying for its own temporary tree.
fn scratch() -> &'static Path {
    static ROOT: OnceLock<tempfile::TempDir> = OnceLock::new();
    ROOT.get_or_init(|| tempfile::tempdir().unwrap()).path()
}

/// The identity of a project named `name`. Real bytes, real capture: the store's
/// columns are digests of paths, so a fabricated 64-hex string would test
/// nothing about identity.
fn project_id(name: &str) -> ProjectId {
    let dir = scratch().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    ProjectId::of(&ProjectDir::from_path_for_tests(&dir).unwrap())
}

fn project_path(name: &str) -> PathBuf {
    scratch().join(name).canonicalize().unwrap()
}

fn record(project: &ProjectId, text: &str, recorded_ms: i64) -> store::StoredRecord {
    store::StoredRecord {
        project: project.as_str().to_owned(),
        path: "/unused-in-group-a".to_owned(),
        destination: text.to_owned(),
        recorded_ms,
    }
}

/// A view over records with no filesystem, which is what group A is about: the
/// selection and the wording, not the read.
fn view_of(records: Vec<store::StoredRecord>, project: &ProjectId) -> ProjectView {
    from_read(
        store::Read::Current {
            records,
            mode: 0o600,
        },
        PathBuf::from("/home/a/.config/agent-vm/allowances.json"),
        project,
    )
}

fn destinations(view: &ProjectView) -> Vec<String> {
    view.allowances()
        .destinations()
        .map(ToString::to_string)
        .collect()
}

// ---------------------------------------------------------------------------
// A. The facade, pure
// ---------------------------------------------------------------------------

/// The whole expected destination set, with another project's record *absent*
/// from it rather than merely present in the file.
#[test]
fn view_selects_this_project_only() {
    let a = project_id("a");
    let b = project_id("b");
    let view = view_of(
        vec![
            record(&a, "tcp://[203.0.113.10/32]:443", 1_762_680_120_000),
            record(&b, "10.0.0.5", 1_760_000_000_000),
            record(&a, "api.example.com", 1_762_680_300_000),
        ],
        &a,
    );
    assert_eq!(
        destinations(&view),
        ["tcp://[203.0.113.10/32]:443", "api.example.com"]
    );
    assert_eq!(view.allowances().len(), 2);
    assert!(view.notice().is_none());
    assert_eq!(
        view.file(),
        Some(Path::new("/home/a/.config/agent-vm/allowances.json"))
    );
    // The other project's record is not an error: B sees only its own.
    let other = view_of(
        vec![
            record(&a, "tcp://[203.0.113.10/32]:443", 1_762_680_120_000),
            record(&b, "10.0.0.5", 1_760_000_000_000),
            record(&a, "api.example.com", 1_762_680_300_000),
        ],
        &b,
    );
    assert_eq!(destinations(&other), ["10.0.0.5/32"]);
}

/// Canonical value, not text: the same allowance written two ways is one
/// allowance, exactly as `resolve` deduplicates a launch's own entries.
#[test]
fn view_dedups_by_parsed_value() {
    let a = project_id("dedup");
    let view = view_of(
        vec![
            record(&a, "10.0.0.5", 111),
            record(&a, "10.0.0.5/32", 222),
            record(&a, "API.example.com.", 333),
            record(&a, "api.example.com", 444),
        ],
        &a,
    );
    assert_eq!(destinations(&view), ["10.0.0.5/32", "api.example.com"]);
    // The first occurrence's timestamp survives: it is when the record that is
    // in force was made.
    assert_eq!(view.allowances().entries[0].recorded_ms(), 111);
    assert!(view.notice().is_none());
}

/// A spelling this build cannot parse is named, and the rest of the file still
/// applies. Silent skipping would let a hand-edited `tool:codex` look like an
/// allowance the file does not actually grant.
#[test]
fn unusable_destinations_are_named() {
    let a = project_id("unusable");
    for spelling in [
        "tool:codex",
        "host.microsandbox.internal",
        "udp://a.example",
    ] {
        let view = view_of(vec![record(&a, spelling, 1)], &a);
        let notice = view.notice().expect("one notice");
        assert!(view.allowances().len() == 0, "{spelling}");
        assert!(notice.starts_with(&format!(
            "1 project allowance(s) in \"/home/a/.config/agent-vm/allowances.json\" not applied: \"{spelling}\" ("
        )), "{notice}");
        assert_eq!(notice.matches("project allowance(s)").count(), 1);
    }
    // A string form the grammar accepts but a *reference* form it does not: it
    // is reported, never resolved.
    let view = view_of(vec![record(&a, "set:x", 1)], &a);
    assert!(view.notice().unwrap().contains("\"set:x\" ("));
    // Three named, the fourth counted: a hand-edited file can hold thousands.
    let view = view_of(
        vec![
            record(&a, "tool:codex", 1),
            record(&a, "host.microsandbox.internal", 2),
            record(&a, "udp://a.example", 3),
            record(&a, "set:x", 4),
            record(&a, "10.0.0.5", 5),
        ],
        &a,
    );
    let notice = view.notice().unwrap();
    assert!(notice.starts_with("4 project allowance(s) in "), "{notice}");
    assert_eq!(notice.matches(" (").count(), 3, "{notice}");
    assert!(notice.ends_with(" and 1 more"), "{notice}");
    assert!(!notice.contains("set:x"), "{notice}");
    // Exactly three unusable records name all three and claim no tail: a `>=`
    // in the "more" test would print "and 0 more".
    let exactly_three = view_of(
        vec![
            record(&a, "tool:codex", 1),
            record(&a, "host.microsandbox.internal", 2),
            record(&a, "udp://a.example", 3),
        ],
        &a,
    );
    let notice = exactly_three.notice().unwrap();
    assert!(!notice.contains("more"), "{notice}");
    assert_eq!(notice.matches(" (").count(), 3, "{notice}");
    // The usable record still applies.
    assert_eq!(destinations(&view), ["10.0.0.5/32"]);
}

/// One condition, one line, and every byte of a measured path or a file-chosen
/// destination escaped. The ESC bytes are the discriminator: a terminal escape
/// from a hand-edited destination must not reach the screen.
#[test]
fn notice_wording_golden() {
    use crate::config_authority::AuthorityRefusal;
    const ESC: char = '\u{1b}';
    let file = Path::new("/home/a/allow\nances.json");
    let quoted = "\"/home/a/allow\\x0aances.json\"";
    let cases: Vec<(store::Read, String)> = vec![
        (
            store::Read::NotUsed(store::Problem::Damaged(store::Damage::Undecodable)),
            format!(
                "project allowances not applied: {quoted} could not be used (not a JSON document this build reads); this version does not repair it — move it aside to start over"
            ),
        ),
        (
            store::Read::NotUsed(store::Problem::Damaged(store::Damage::TooLarge)),
            format!(
                "project allowances not applied: {quoted} could not be used (larger than 1048576 byte(s)); this version does not repair it — move it aside to start over"
            ),
        ),
        (
            store::Read::NotUsed(store::Problem::Damaged(store::Damage::OlderVersion(0))),
            format!(
                "project allowances not applied: {quoted} could not be used (version 0, which this build cannot read); this version does not repair it — move it aside to start over"
            ),
        ),
        (
            store::Read::NotUsed(store::Problem::Damaged(store::Damage::Invalid(
                "a record's path is not absolute",
            ))),
            format!(
                "project allowances not applied: {quoted} could not be used (a record's path is not absolute); this version does not repair it — move it aside to start over"
            ),
        ),
        (
            store::Read::NotUsed(store::Problem::Unreadable(
                "reading \"/home/a/x\": permission denied".to_owned(),
            )),
            format!(
                "project allowances not applied: {quoted} could not be read (reading \"/home/a/x\": permission denied)"
            ),
        ),
        (
            store::Read::NotUsed(store::Problem::Unsettled),
            format!(
                "project allowances not applied: {quoted} changed while being read; the next launch reads it again"
            ),
        ),
        (
            store::Read::Newer {
                v: 2,
                records: Vec::new(),
            },
            format!(
                "project allowances not applied: {quoted} was written by a newer agent-vm (version 2); this version applies none of it"
            ),
        ),
    ];
    for (read, expected) in cases {
        let view = from_read(read, file.to_path_buf(), &project_id("wording"));
        assert_eq!(view.notice(), Some(expected.as_str()));
        assert_eq!(view.allowances().len(), 0);
    }
    // Every refusal the proved kernel can return, in this file's words.
    for (refusal, clause) in [
        (AuthorityRefusal::FileOwner, "is owned by another user"),
        (
            AuthorityRefusal::FileWritable,
            "is group- or other-writable",
        ),
        (AuthorityRefusal::FileLinks(2), "has 2 hard links"),
        (AuthorityRefusal::ThroughSymlink, "is a symbolic link"),
        (
            AuthorityRefusal::DirOwner,
            "is in a directory owned by another user",
        ),
        (
            AuthorityRefusal::DirWritable,
            "is in a group- or other-writable directory",
        ),
        (AuthorityRefusal::DirNotDirectory, "is not in a directory"),
    ] {
        let view = from_read(
            store::Read::NotUsed(store::Problem::Untrusted(refusal)),
            file.to_path_buf(),
            &project_id("wording-refusal"),
        );
        assert_eq!(
            view.notice(),
            Some(
                format!(
                    "project allowances not applied: {quoted} {clause}; a guest or another account may have written it, so review it before removing it"
                )
                .as_str()
            )
        );
    }
    // A destination is file-chosen text, so it is byte-escaped: every non-ASCII
    // byte spelled out, and a control byte cannot end the line.
    let project = project_id("wording-destination");
    let view = view_of(vec![record(&project, &format!("x{ESC}[31m"), 1)], &project);
    let notice = view.notice().unwrap();
    assert!(!notice.contains(ESC), "{notice}");
    assert!(notice.contains("\\x1b"), "{notice}");
    // And `$HOME` that is set but unusable is one line, not a launch error.
    let with_host_error = super::view(
        None,
        Some(anyhow::anyhow!("$HOME is set but empty")),
        &project,
    );
    assert_eq!(
        with_host_error.notice(),
        Some("project allowances not read: $HOME is set but empty")
    );
}

/// C8 (plan §8.6): a newer file's records are decoded — `doctor` counts them —
/// and never applied. The `Newer` variant *carries* the records, so this is the
/// one test that keeps "carries" from becoming "applies".
#[test]
fn newer_is_never_applied() {
    let project = project_id("newer-never");
    let file = PathBuf::from("/home/a/.config/agent-vm/allowances.json");
    let view = from_read(
        store::Read::Newer {
            v: 2,
            records: vec![
                record(&project, "10.0.0.5", 1_762_680_120_000),
                record(&project, "api.example.com", 1_762_680_120_000),
            ],
        },
        file.clone(),
        &project,
    );
    assert_eq!(view.allowances().len(), 0, "nothing from a newer file");
    assert_eq!(destinations(&view), Vec::<String>::new());
    assert_eq!(
        view.notice(),
        Some(
            format!(
                "project allowances not applied: {} was written by a newer agent-vm (version 2); this version applies none of it",
                crate::one_line::quoted_path(&file)
            )
            .as_str()
        )
    );
    assert_eq!(view.file(), Some(file.as_path()));
}

/// A record can never name a project whose path is not UTF-8, and nothing in
/// the read path converts a path to text on the way.
///
/// The identity is the digest of the path's **raw bytes**. Its `path` column is
/// a JSON string, so it is valid UTF-8, and `check_record` requires the two to
/// agree — which is why such a project gets an empty view without an error
/// rather than through a special case (ADR-0065 P2). The host cannot even
/// canonicalize such a path (macOS `realpath` answers `EILSEQ`), so a fabricated
/// `ProjectId` would test nothing about the real read path.
#[test]
fn non_utf8_project_digest_selects_nothing() {
    use sha2::{Digest as _, Sha256};
    use std::os::unix::ffi::OsStrExt as _;
    let bytes = b"/tmp/not-\xff-utf8";
    let path = Path::new(std::ffi::OsStr::from_bytes(bytes));
    // Independent oracle: the digest of exactly these bytes, with no conversion.
    let expected: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(crate::project::digest_hex_of(path), expected);
    // A lossy conversion would hash a different string, and so a different
    // project: the two digests must not agree.
    assert_ne!(
        crate::project::digest_hex_of(path),
        crate::project::digest_hex_of(Path::new(&path.to_string_lossy().into_owned()))
    );
    // No record can carry that identity, so a launch from such a project sees
    // an empty set and — because the other project's record is merely not ours —
    // no notice.
    let other = project_id("utf8-neighbour");
    let view = view_of(vec![record(&other, "10.0.0.5", 1)], &other);
    assert_eq!(destinations(&view), ["10.0.0.5/32"]);
    assert!(view.notice().is_none(), "{:?}", view.notice());
    let empty = from_read(
        store::Read::Current {
            records: Vec::new(),
            mode: 0o600,
        },
        PathBuf::from("/f"),
        &other,
    );
    assert_eq!(empty.allowances().len(), 0);
    assert!(empty.notice().is_none());
}

// ---------------------------------------------------------------------------
// B. `covers`
// ---------------------------------------------------------------------------

fn entry(
    destination: Destination,
    site: &str,
    layer: &str,
    name: Option<(&str, &str)>,
) -> RefusalEntry {
    RefusalEntry {
        id: "abcdef01".to_owned(),
        key: EntryKey {
            kind: Kind::NetworkDenial,
            destination,
        },
        layer: layer.to_owned(),
        last_site: site.to_owned(),
        last_ip: None,
        name: name.map(|(text, source)| GuestName {
            name: text.to_owned(),
            source: source.to_owned(),
            truncated: false,
        }),
        last_revision: 1,
        count: 1,
        first_ms: 0,
        last_ms: 0,
    }
}

fn address_entry(protocol: &str, ip: &str, port: Option<u16>, site: &str) -> RefusalEntry {
    entry(
        Destination::Address {
            protocol: protocol.to_owned(),
            ip: Some(ip.parse().unwrap()),
            port,
        },
        site,
        "tenant",
        None,
    )
}

fn host_entry(name: &str, port: u16, site: &str, source: &str) -> RefusalEntry {
    let mut entry = entry(
        Destination::Host {
            protocol: "tcp".to_owned(),
            name: name.to_owned(),
            port: Some(port),
        },
        site,
        "tenant",
        Some((name, source)),
    );
    entry.last_ip = Some("203.0.113.10".parse().unwrap());
    entry
}

fn dns_entry(name: &str, site: &str) -> RefusalEntry {
    entry(
        Destination::DnsName {
            name: name.to_owned(),
        },
        site,
        "tenant",
        Some((name, "dns-query")),
    )
}

/// A record set built from spellings, without a file: group B is about the
/// query, not the read.
fn set(spellings: &[&str]) -> ProjectAllowances {
    ProjectAllowances::for_tests(spellings)
}

fn covers(spellings: &[&str], entry: &RefusalEntry) -> bool {
    set(spellings).covers(entry).is_some()
}

/// ADR-0065 §4.3's *recorded* column, row for row, plus every `Kind` behind a
/// platform layer.
///
/// The rows are literals copied from the spec, not composed from the code: a
/// table that agreed with itself would accept any answer.
#[test]
fn coverage_table() {
    for (row, records, entry, expected) in [
        (
            "address/tcp, exact record",
            &["tcp://[203.0.113.10/32]:443"][..],
            address_entry("tcp", "203.0.113.10", Some(443), "tcp-syn"),
            true,
        ),
        (
            "address/tcp, udp record",
            &["udp://[203.0.113.10/32]:443"][..],
            address_entry("tcp", "203.0.113.10", Some(443), "tcp-syn"),
            false,
        ),
        (
            "address/tcp, other port",
            &["[203.0.113.10/32]:443"][..],
            address_entry("tcp", "203.0.113.10", Some(444), "tcp-syn"),
            false,
        ),
        (
            "address/icmp, port-filtered record",
            &["[203.0.113.10/32]:443"][..],
            address_entry("icmpv4", "203.0.113.10", None, "icmp"),
            false,
        ),
        (
            "address/icmp, bare record",
            &["203.0.113.10"][..],
            address_entry("icmpv4", "203.0.113.10", None, "icmp"),
            true,
        ),
        (
            "address/icmpv6, bare v6 record",
            &["2001:db8::1"][..],
            address_entry("icmpv6", "2001:db8::1", None, "icmp"),
            true,
        ),
        (
            "address/icmpv6, v4 record",
            &["203.0.113.10"][..],
            address_entry("icmpv6", "2001:db8::1", None, "icmp"),
            false,
        ),
        (
            "address/cidr, inside",
            &["203.0.113.0/31"][..],
            address_entry("tcp", "203.0.113.1", Some(443), "tcp-syn"),
            true,
        ),
        (
            "address/cidr, outside",
            &["203.0.113.0/31"][..],
            address_entry("tcp", "203.0.113.10", Some(443), "tcp-syn"),
            false,
        ),
        (
            "address, v4-mapped v6",
            &["tcp://[203.0.113.10/32]:443"][..],
            address_entry("tcp", "::ffff:203.0.113.10", Some(443), "tcp-syn"),
            true,
        ),
        (
            "address, tls site",
            &["203.0.113.10"][..],
            address_entry("tcp", "203.0.113.10", Some(443), "tls-sni"),
            false,
        ),
        (
            "host, sni",
            &["api.example.com"][..],
            host_entry("api.example.com", 443, "tls-sni", "sni"),
            true,
        ),
        (
            "host, tcp-hostname site",
            &["api.example.com"][..],
            host_entry("api.example.com", 443, "tcp-hostname", "sni"),
            true,
        ),
        (
            "host, http-host first source",
            &["api.example.com"][..],
            host_entry("api.example.com", 443, "tls-sni", "http-host"),
            false,
        ),
        (
            "host, bare name, unintercepted port",
            &["api.example.com"][..],
            host_entry("api.example.com", 8443, "tls-sni", "sni"),
            false,
        ),
        (
            "host, port from the recorded set",
            &["api.example.com", "tcp://other.example.com:8443"][..],
            host_entry("api.example.com", 8443, "tls-sni", "sni"),
            true,
        ),
        (
            "host, cidr record over the name",
            &["203.0.113.10"][..],
            host_entry("api.example.com", 443, "tls-sni", "sni"),
            false,
        ),
        (
            "host, http-authority site",
            &["tcp://api.example.com:80"][..],
            host_entry("api.example.com", 80, "http-authority", "http-host"),
            false,
        ),
        (
            "dns query",
            &["api.example.com"][..],
            dns_entry("api.example.com", "dns-query"),
            true,
        ),
        (
            "dns resolver",
            &["api.example.com"][..],
            dns_entry("api.example.com", "dns-resolver"),
            false,
        ),
    ] {
        assert_eq!(covers(records, &entry), expected, "{row}");
    }
    // Never, whatever the destination: a kind no allowance reaches, and the
    // platform floor under any kind.
    for kind in [
        Kind::NetworkDenial,
        Kind::PolicyLock,
        Kind::CredentialRefusal,
    ] {
        for layer in ["tenant", "platform"] {
            let mut entry = address_entry("tcp", "203.0.113.10", Some(443), "tcp-syn");
            entry.key.kind = kind;
            entry.layer = layer.to_owned();
            let expected = kind == Kind::NetworkDenial && layer == "tenant";
            assert_eq!(
                covers(&["tcp://[203.0.113.10/32]:443"], &entry),
                expected,
                "{kind:?}/{layer}"
            );
        }
    }
}

/// Each gate is the *only* thing deciding its row, paired with the mutant it
/// kills. Every case is otherwise satisfiable — the record matches the probe's
/// address, port and protocol — so deleting the named guard turns the row true.
#[test]
fn each_guard_decides_alone() {
    // (1) `None => rule.ports.is_empty()`: an ICMP probe has no port, so a
    // port-filtered rule cannot admit it.
    assert!(!covers(
        &["[203.0.113.10/32]:443"],
        &address_entry("icmpv4", "203.0.113.10", None, "icmp")
    ));
    // (2) the protocol filter: a udp record cannot admit a tcp flow.
    assert!(!covers(
        &["udp://[203.0.113.10/32]:443"],
        &address_entry("tcp", "203.0.113.10", Some(443), "tcp-syn")
    ));
    // (3) the port filter: a 443-only rule cannot admit 444.
    assert!(!covers(
        &["[203.0.113.10/32]:443"],
        &address_entry("tcp", "203.0.113.10", Some(444), "tcp-syn")
    ));
    // (4) CIDR membership, not its inverse: the first address is inside, the
    // second outside, one /31 apart.
    assert!(covers(
        &["203.0.113.0/31"],
        &address_entry("tcp", "203.0.113.1", Some(443), "tcp-syn")
    ));
    assert!(!covers(
        &["203.0.113.0/31"],
        &address_entry("tcp", "203.0.113.10", Some(443), "tcp-syn")
    ));
    // (5) the first name source: an HTTP `Host` is not SNI, so the name is not
    // the one TLS verified.
    assert!(!covers(
        &["api.example.com"],
        &host_entry("api.example.com", 443, "tls-sni", "http-host")
    ));
    // (6) `dns-resolver` is decided on the resolver's address, not the name.
    assert!(!covers(
        &["api.example.com"],
        &dns_entry("api.example.com", "dns-resolver")
    ));
    // (7) the ports come from the recorded set, not a fixed 443.
    assert!(covers(
        &["api.example.com", "tcp://other.example.com:8443"],
        &host_entry("api.example.com", 8443, "tls-sni", "sni")
    ));
    // (8) `to_canonical`: a v4-mapped v6 address is the v4 address for a Cidr.
    assert!(covers(
        &["tcp://[203.0.113.10/32]:443"],
        &address_entry("tcp", "::ffff:203.0.113.10", Some(443), "tcp-syn")
    ));
}

// --- the oracle -------------------------------------------------------------

/// The rules every record contributes, assembled by the launch's own producers.
fn oracle_rules(records: &[&str]) -> Vec<Rule> {
    let mut destination_rules: Vec<Rule> = Vec::new();
    let hostnames: Vec<HostnameAllowance> = records
        .iter()
        .filter_map(|text| match Allowance::parse(text).expect(text) {
            Allowance::Address(_) => None,
            Allowance::Hostname(hostname) => Some(hostname),
        })
        .collect();
    for text in records {
        if let Allowance::Address(address) = Allowance::parse(text).expect(text) {
            destination_rules.push(address.rule());
        }
    }
    if let Some(ports) = InterceptedPorts::for_hostnames(&hostnames) {
        destination_rules.extend(domain_rules(&hostnames, &ports));
    }
    destination_rules
}

fn oracle_policy(records: &[&str], configured: &[&str]) -> NetworkPolicy {
    let mut rules = oracle_rules(records);
    rules.extend(oracle_rules(configured));
    NetworkPolicy {
        default_egress: Action::Deny,
        default_ingress: Action::Allow,
        rules,
    }
}

fn allows(evaluation: microsandbox_network::policy::EgressEvaluation) -> bool {
    evaluation == microsandbox_network::policy::EgressEvaluation::Allow
}

/// What the runtime's evaluator would do with this entry under a policy holding
/// these records.
fn oracle(entry: &RefusalEntry, records: &[&str], configured: &[&str]) -> bool {
    let policy = oracle_policy(records, configured);
    let shared = SharedState::new(4);
    // The NAT64 projection needs the prefix the runtime would have installed;
    // without it the oracle and `covers` would agree for the wrong reason.
    shared.set_nat64_prefixes(vec!["64:ff9b::/96".parse().expect("prefix")]);
    match &entry.key.destination {
        Destination::Address {
            protocol,
            ip: Some(ip),
            port,
        } => {
            let protocol = wire_protocol(protocol).expect(protocol);
            match port {
                Some(port) => {
                    if let Some(binding) = cache_binding(entry) {
                        shared.cache_resolved_hostname(
                            binding.0,
                            ResolvedHostnameFamily::Ipv4,
                            [binding.1],
                            std::time::Duration::from_secs(60),
                        );
                    }
                    policy.evaluate_egress(SocketAddr::new(*ip, *port), protocol, &shared)
                        == Action::Allow
                }
                None => policy.evaluate_egress_ip(*ip, protocol, &shared) == Action::Allow,
            }
        }
        Destination::Host {
            name,
            port: Some(port),
            ..
        } => {
            // The stated precondition (ADR-0065 AC8): a DNS binding ties the
            // name to the address the guest connected to.
            let address = entry.last_ip.expect("a host entry carries its address");
            shared.cache_resolved_hostname(
                name,
                ResolvedHostnameFamily::Ipv4,
                [address],
                std::time::Duration::from_secs(60),
            );
            allows(policy.evaluate_egress_with_source(
                SocketAddr::new(address, *port),
                Protocol::Tcp,
                &shared,
                microsandbox_network::policy::HostnameSource::Sni(name),
            ))
        }
        Destination::DnsName { name } => {
            let Ok(name) = name.parse::<DomainName>() else {
                return false;
            };
            policy.evaluate_dns_query(&name, Protocol::Udp, 53) == Action::Allow
        }
        _ => panic!("the oracle needs a full destination"),
    }
}

/// The DNS cache binding an address entry's own name evidence states, when the
/// guest supplied one: the `(name, address)` pair a `CacheOnly` walk can match.
fn cache_binding(entry: &RefusalEntry) -> Option<(&str, std::net::IpAddr)> {
    let Destination::Address { ip: Some(ip), .. } = &entry.key.destination else {
        return None;
    };
    let name = entry.name.as_ref()?;
    (name.source == "dns-cache").then_some((name.name.as_str(), *ip))
}

// --- B3/B4/B5: the property tests -------------------------------------------

/// Every record spelling the generators may choose, mixable across kinds.
///
/// The first [`ADDRESS_VOCABULARY_LEN`] entries are address-only, which is what
/// `address_only_sets_are_exact` draws from.
const VOCABULARY: [&str; 21] = [
    "10.0.0.5",
    "10.0.0.5/32",
    "192.168.1.7/24",
    "192.168.1.0/24",
    "203.0.113.0/31",
    "0.0.0.0/0",
    "::/0",
    "2001:db8::/32",
    "2001:db8::1",
    "::ffff:203.0.113.10",
    "tcp://[203.0.113.10/32]:443",
    "udp://[203.0.113.10/32]:443",
    "[203.0.113.10/32]:8443",
    "tcp://[203.0.113.10/32]:1",
    "10.0.0.5/1",
    "2001:db8::/127",
    "api.example.com",
    "API.example.com.",
    "xn--bcher-kva.example",
    "tcp://api.example.com:8443",
    "tcp://xn--bcher-kva.example:9443",
];
const ADDRESS_VOCABULARY_LEN: usize = 16;

/// Address entries at the three sites a `Cidr` rule can decide, including the
/// protocol, ports and prefix lengths the first generator missed.
const ADDRESS_PROBES: [(&str, &str, Option<u16>, &str); 17] = [
    ("tcp", "203.0.113.10", Some(443), "tcp-syn"),
    ("tcp", "203.0.113.10", Some(444), "tcp-syn"),
    ("tcp", "203.0.113.10", Some(8443), "tcp-syn"),
    ("tcp", "203.0.113.10", Some(1), "tcp-syn"),
    ("tcp", "203.0.113.10", Some(442), "tcp-syn"),
    ("tcp", "203.0.113.10", Some(65535), "tcp-syn"),
    ("tcp", "203.0.113.1", Some(443), "tcp-syn"),
    ("tcp", "192.168.1.7", Some(443), "tcp-syn"),
    ("udp", "203.0.113.10", Some(443), "udp"),
    ("udp", "192.168.1.7", Some(53), "udp"),
    ("udp", "2001:db8::1", Some(53), "udp"),
    ("icmpv4", "203.0.113.10", None, "icmp"),
    ("icmpv4", "192.168.1.7", None, "icmp"),
    ("icmpv6", "2001:db8::1", None, "icmp"),
    ("icmpv6", "2001:db8::2", None, "icmp"),
    ("tcp", "::ffff:203.0.113.10", Some(443), "tcp-syn"),
    ("tcp", "2001:db8::1", Some(443), "tcp-syn"),
];

/// Host entries at both TCP sites that can decide a Domain rule. The site is
/// generated because `probe` accepts two of them, and a generator that only
/// produced `tls-sni` would leave the `tcp-hostname` arm unexercised.
const HOST_PROBES: [(&str, u16, &str); 6] = [
    ("api.example.com", 443, "tls-sni"),
    ("api.example.com", 8443, "tls-sni"),
    ("api.example.com", 80, "tls-sni"),
    ("api.example.com", 443, "tcp-hostname"),
    ("xn--bcher-kva.example", 443, "tls-sni"),
    ("other.example", 443, "tcp-hostname"),
];

const DNS_PROBES: [&str; 4] = [
    "api.example.com",
    "API.example.com",
    "xn--bcher-kva.example",
    "absent.example",
];

fn any_records() -> impl Strategy<Value = Vec<&'static str>> {
    proptest::collection::vec(proptest::sample::select(VOCABULARY.as_slice()), 0..5)
}

fn address_only_records() -> impl Strategy<Value = Vec<&'static str>> {
    proptest::collection::vec(
        proptest::sample::select(&VOCABULARY[..ADDRESS_VOCABULARY_LEN]),
        0..4,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Soundness, over mixed record sets: everything `covers` calls *recorded*
    /// the runtime also admits. The converse is deliberately not claimed for
    /// hostname-involving sets (§5.3's conservative negatives).
    #[test]
    fn recorded_implies_admissible(
        records in any_records(),
        address in proptest::sample::select(ADDRESS_PROBES.as_slice()),
        host in proptest::sample::select(HOST_PROBES.as_slice()),
        dns in proptest::sample::select(DNS_PROBES.as_slice()),
    ) {
        let address_entry = address_entry(address.0, address.1, address.2, address.3);
        let host_entry = host_entry(host.0, host.1, host.2, "sni");
        let dns_entry = dns_entry(dns, "dns-query");
        for entry in [address_entry, host_entry, dns_entry] {
            if covers(&records, &entry) {
                prop_assert!(
                    oracle(&entry, &records, &[]),
                    "{:?} is recorded under {records:?} but not admissible", entry.key.destination
                );
            }
        }
    }

    /// Exactness where it is claimed: an address-only record set against
    /// address entries at `tcp-syn`/`udp`/`icmp`, with no NAT64 projection.
    #[test]
    fn address_only_sets_are_exact(
        records in address_only_records(),
        address in proptest::sample::select(ADDRESS_PROBES.as_slice()),
    ) {
        let entry = address_entry(address.0, address.1, address.2, address.3);
        prop_assert_eq!(covers(&records, &entry), oracle(&entry, &records, &[]));
    }

    /// Exactness for a DNS query under any record set: the runtime's own pure
    /// predicate decides it, and it matches only by name.
    #[test]
    fn dns_query_is_exact(
        records in any_records(),
        dns in proptest::sample::select(DNS_PROBES.as_slice()),
    ) {
        let entry = dns_entry(dns, "dns-query");
        prop_assert_eq!(covers(&records, &entry), oracle(&entry, &records, &[]));
    }
}

/// The same two claims as the properties above, evaluated over a *whole* finite
/// slice of the space instead of 96 random draws from it.
///
/// The spellings are a closed set, so the properties' real domain is small and
/// enumerable: every ordered record tuple of length ≤ 2 over [`VOCABULARY`]
/// against every probe, plus every length-3 tuple over the address-only
/// spellings against every address probe. That is 81 208 (set, probe) pairs —
/// exhaustive where a random draw is not — and it is the only test that compares
/// `covers` with the runtime on *every* two-record interaction rather than the
/// ones 96 draws happened to hit. Soundness is asserted over all pairs;
/// exactness only where §5.3 claims it (address-only sets, address entries).
#[test]
fn every_small_record_set_agrees_with_the_runtime_where_the_table_claims_it() {
    let mut sets: Vec<Vec<&'static str>> = vec![Vec::new()];
    for a in VOCABULARY {
        sets.push(vec![a]);
        for b in VOCABULARY {
            sets.push(vec![a, b]);
        }
    }
    for a in &VOCABULARY[..ADDRESS_VOCABULARY_LEN] {
        for b in &VOCABULARY[..ADDRESS_VOCABULARY_LEN] {
            for c in &VOCABULARY[..ADDRESS_VOCABULARY_LEN] {
                sets.push(vec![a, b, c]);
            }
        }
    }
    let address_probes: Vec<RefusalEntry> = ADDRESS_PROBES
        .iter()
        .map(|probe| address_entry(probe.0, probe.1, probe.2, probe.3))
        .collect();
    let other_probes: Vec<RefusalEntry> = HOST_PROBES
        .iter()
        .map(|probe| host_entry(probe.0, probe.1, probe.2, "sni"))
        .chain(DNS_PROBES.iter().map(|name| dns_entry(name, "dns-query")))
        .collect();

    // Threads, so the exhaustive sweep costs the suite a fraction of a second:
    // the runtime evaluator builds a policy per probe.
    let failures = std::sync::Mutex::new(Vec::<String>::new());
    std::thread::scope(|scope| {
        for part in sets.chunks(sets.len().div_ceil(8)) {
            let (address_probes, other_probes, failures) =
                (&address_probes, &other_probes, &failures);
            scope.spawn(move || {
                for records in part {
                    let address_only = records
                        .iter()
                        .all(|record| VOCABULARY[..ADDRESS_VOCABULARY_LEN].contains(record));
                    for entry in address_probes {
                        let recorded = covers(records, entry);
                        let admitted = oracle(entry, records, &[]);
                        if recorded && !admitted {
                            failures.lock().unwrap().push(format!(
                                "{} is recorded under {records:?} but the runtime denies it",
                                destination_text(entry)
                            ));
                        }
                        if address_only && recorded != admitted {
                            failures.lock().unwrap().push(format!(
                                "{}: covers says {recorded}, the runtime says {admitted}, under {records:?}",
                                destination_text(entry)
                            ));
                        }
                    }
                    for entry in other_probes {
                        let recorded = covers(records, entry);
                        if recorded && !oracle(entry, records, &[]) {
                            failures.lock().unwrap().push(format!(
                                "{} is recorded under {records:?} but the runtime denies it",
                                destination_text(entry)
                            ));
                        }
                    }
                }
            });
        }
    });
    let failures = failures.into_inner().unwrap();
    assert!(
        failures.is_empty(),
        "{} disagreement(s) with the runtime, first 8: {:#?}",
        failures.len(),
        &failures[..failures.len().min(8)]
    );
}

/// A destination for a failure message, rendered the way the table in ADR-0065
/// §5.3 names it.
fn destination_text(entry: &RefusalEntry) -> String {
    format!("{:?}", entry.key.destination)
}

/// Every conservative negative of ADR-0065 §5.3, each a fixed case: what the
/// runtime admits, this query deliberately does not claim.
#[test]
fn conservative_negatives_are_intentional() {
    // (f) an Address entry admitted by a Domain rule through the DNS cache.
    let mut cached = address_entry("tcp", "203.0.113.10", Some(443), "tcp-syn");
    cached.name = Some(GuestName {
        name: "api.example.com".to_owned(),
        source: "dns-cache".to_owned(),
        truncated: false,
    });
    assert!(oracle(&cached, &["api.example.com"], &[]), "(f) oracle");
    assert!(!covers(&["api.example.com"], &cached), "(f) covers");
    // (g) a Host entry a Cidr record would admit over its `last_ip`.
    let host = host_entry("api.example.com", 443, "tls-sni", "sni");
    assert!(oracle(&host, &["203.0.113.10"], &[]), "(g) oracle");
    assert!(!covers(&["203.0.113.10"], &host), "(g) covers");
    // (h) an Address entry at a TLS site.
    let strict = address_entry("tcp", "203.0.113.10", Some(443), "tls-sni");
    assert!(oracle(&strict, &["203.0.113.10"], &[]), "(h) oracle");
    assert!(!covers(&["203.0.113.10"], &strict), "(h) covers");
    // (i) NAT64: the runtime projects the destination onto its embedded v4.
    let nat64 = address_entry("tcp", "64:ff9b::cb00:710a", Some(443), "tcp-syn");
    assert!(oracle(&nat64, &["203.0.113.10"], &[]), "(i) oracle");
    assert!(!covers(&["203.0.113.10"], &nat64), "(i) covers");
    // (j) a bare recorded hostname on a port only a *configured* entry
    // intercepts. The oracle's policy carries both authorities, which is what
    // the session would enforce.
    let widened = host_entry("api.example.com", 8443, "tls-sni", "sni");
    assert!(
        oracle(
            &widened,
            &["api.example.com"],
            &["tcp://api.example.com:8443"]
        ),
        "(j) oracle"
    );
    assert!(!covers(&["api.example.com"], &widened), "(j) covers");
    // (k) a DNS query answered by a `dns-resolver` refusal: that site decides on
    // the resolver's address.
    let resolver = dns_entry("api.example.com", "dns-resolver");
    assert!(oracle(&resolver, &["api.example.com"], &[]), "(k) oracle");
    assert!(!covers(&["api.example.com"], &resolver), "(k) covers");
    // (l) a TLS refusal whose first name source is the HTTP `Host`.
    let http_host = host_entry("api.example.com", 443, "tls-sni", "http-host");
    assert!(oracle(&http_host, &["api.example.com"], &[]), "(l) oracle");
    assert!(!covers(&["api.example.com"], &http_host), "(l) covers");
}

/// Which record the ACTION cell names: the first in file order, so the same
/// store always prints the same sentence.
#[test]
fn first_matching_record_in_file_order() {
    let entry = address_entry("tcp", "203.0.113.10", Some(443), "tcp-syn");
    for (spellings, expected) in [
        (["203.0.113.0/24", "203.0.113.10"], "203.0.113.0/24"),
        (["203.0.113.10", "203.0.113.0/24"], "203.0.113.10/32"),
    ] {
        let records = set(&spellings);
        let Some(Coverage::Recorded(record)) = records.covers(&entry) else {
            panic!("both records cover it");
        };
        assert_eq!(record.destination().to_string(), expected);
    }
}

// ---------------------------------------------------------------------------
// H. `doctor`'s section
// ---------------------------------------------------------------------------

/// A store on disk for `doctor`, with the authority directory at 0700.
fn doctor_store(root: &Path) -> (PathBuf, store::Store) {
    let dir = root.join("agent-vm");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = store::Store::at(&dir);
    (dir, store)
}

fn record_for(path: &Path, destination: &str, recorded_ms: i64) -> store::StoredRecord {
    store::StoredRecord {
        project: crate::project::digest_hex_of(path),
        path: path.display().to_string(),
        destination: destination.to_owned(),
        recorded_ms,
    }
}

/// The section for a store on disk: the test's door onto
/// [`doctor_section_from`], which is the same function `doctor` calls.
fn doctor_section_at(
    store: Option<&store::Store>,
    host_error: Option<anyhow::Error>,
    project: Option<ProjectId>,
) -> (String, Option<anyhow::Error>) {
    doctor_section_from(
        store.map(store::Store::file),
        store.map(store::Store::read),
        host_error,
        project,
    )
}

fn write_store(dir: &Path, records: Vec<store::StoredRecord>, v: u32) -> String {
    let lines: Vec<String> = records
        .iter()
        .map(|record| {
            format!(
                r#"{{"project":"{}","path":"{}","destination":"{}","recorded_ms":{}}}"#,
                record.project, record.path, record.destination, record.recorded_ms
            )
        })
        .collect();
    let body = format!(r#"{{"v":{v},"records":[{}]}}"#, lines.join(","));
    std::fs::write(dir.join(store::FILE), body.as_bytes()).unwrap();
    std::fs::set_permissions(
        dir.join(store::FILE),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    body
}

/// The section's states, in one table: the file line, the counts, the orphan
/// and unknown classifications, the mode clause, and which states make `doctor`
/// exit nonzero.
#[test]
fn allowances_section_states() {
    let own = project_id("doctor-own");
    let other = project_id("doctor-other");
    let root = tempfile::tempdir().unwrap();
    let present = root.path().join("present");
    std::fs::create_dir(&present).unwrap();
    let missing = root.path().join("gone");

    // A current file: this project, another project that still exists, one that
    // does not, and a destination this build cannot parse.
    let (dir, store) = doctor_store(root.path());
    write_store(
        &dir,
        vec![
            record_for(
                &project_path("doctor-own"),
                "tcp://[203.0.113.10/32]:443",
                1_762_680_120_000,
            ),
            record_for(&project_path("doctor-own"), "tool:codex", 1_762_680_120_000),
            record_for(&present, "10.0.0.5", 1_762_680_120_000),
            record_for(&missing, "10.0.0.6", 1_762_680_120_000),
        ],
        1,
    );
    let (section, failure) = doctor_section_at(Some(&store), None, Some(own.clone()));
    assert!(failure.is_none(), "a current store is not a failure");
    assert_eq!(
        section,
        format!(
            "==> project allowances\n\
             file: {file} (version 1, mode 0600)\n\
             this project: 2\n  \
             tcp://[203.0.113.10/32]:443  recorded 2025-11-09 09:22Z\n  \
             tool:codex  not applied: port must be a decimal number 1-65535\n\
             other projects: 2\n  \
             {present} (1 allowance(s))\n  \
             orphaned: {missing} (1 allowance(s))\n\
             orphaned: 1 project path(s) no longer exist",
            file = crate::one_line::path(&dir.join(store::FILE)),
            present = crate::one_line::path(&present),
            missing = crate::one_line::path(&missing),
        )
    );

    // One other project with two records, and one whose path is now a *file*:
    // the count is per project, and a non-directory is an orphan.
    let (dir, store) = doctor_store(&root.path().join("counting"));
    let was_file = root.path().join("was-a-file");
    std::fs::write(&was_file, b"").unwrap();
    write_store(
        &dir,
        vec![
            record_for(&present, "10.0.0.5", 0),
            record_for(&present, "10.0.0.6", 0),
            record_for(&was_file, "10.0.0.7", 0),
        ],
        1,
    );
    let (section, failure) = doctor_section_at(Some(&store), None, None);
    assert!(failure.is_none(), "{section}");
    assert!(section.contains("other projects: 2"), "{section}");
    assert!(section.contains("(2 allowance(s))"), "{section}");
    assert!(
        section.contains(&format!(
            "orphaned: {} (1 allowance(s))",
            crate::one_line::path(&was_file)
        )),
        "{section}"
    );
    assert!(
        section.contains("orphaned: 1 project path(s) no longer exist"),
        "{section}"
    );

    // A recorded path that is now a symlink: a live one still names a project
    // (followed, not called gone), a dangling one is an orphan, and a link that
    // cannot be inspected is *unknown* rather than a definite orphan.
    let (dir, store) = doctor_store(&root.path().join("links"));
    let live_target = root.path().join("live-target");
    std::fs::create_dir(&live_target).unwrap();
    let live_link = root.path().join("link-live");
    std::os::unix::fs::symlink(&live_target, &live_link).unwrap();
    let dead_link = root.path().join("link-dead");
    std::os::unix::fs::symlink(root.path().join("absent-target"), &dead_link).unwrap();
    let loop_link = root.path().join("link-loop");
    std::os::unix::fs::symlink(&loop_link, &loop_link).unwrap();
    write_store(
        &dir,
        vec![
            record_for(&live_link, "10.0.0.5", 0),
            record_for(&dead_link, "10.0.0.6", 0),
            record_for(&loop_link, "10.0.0.7", 0),
        ],
        1,
    );
    let (section, failure) = doctor_section_at(Some(&store), None, None);
    assert!(failure.is_none(), "{section}");
    assert!(
        section.contains(&format!(
            "\n  {} (1 allowance(s))",
            crate::one_line::path(&live_link)
        )),
        "a live symlink is followed, not called gone: {section}"
    );
    assert!(
        section.contains(&format!(
            "\n  orphaned: {} (1 allowance(s))",
            crate::one_line::path(&dead_link)
        )),
        "a dangling symlink is an orphan: {section}"
    );
    assert!(
        section.contains(&format!(
            "\n  unknown: {} (",
            crate::one_line::path(&loop_link)
        )),
        "an uninspectable link is unknown, not gone: {section}"
    );
    assert!(
        section.contains("orphaned: 1 project path(s) no longer exist"),
        "{section}"
    );
    assert!(
        section.contains("unknown: 1 project path(s) could not be checked"),
        "{section}"
    );

    // A newer file is counted, not applied, and does not fail the run.
    let (dir, store) = doctor_store(&root.path().join("newer"));
    write_store(
        &dir,
        vec![record_for(&present, "10.0.0.5", 1_762_680_120_000)],
        2,
    );
    let (section, failure) = doctor_section_at(Some(&store), None, Some(other.clone()));
    assert!(failure.is_none(), "a newer file is not a failure");
    assert!(
        section.contains("(written by a newer agent-vm, version 2; not applied)"),
        "{section}"
    );
    assert!(section.contains("this project: 0"), "{section}");
    assert!(section.contains("other projects: 1"), "{section}");

    // Modes: 0644 and 0400 say what agent-vm would write without claiming
    // anything about who can read them.
    for (mode, clause) in [
        (0o644, "; group- or other-readable, agent-vm writes 0600"),
        (0o400, "; agent-vm writes 0600"),
        (0o600, ""),
    ] {
        let (dir, store) = doctor_store(&root.path().join(format!("mode-{mode:o}")));
        write_store(&dir, vec![record_for(&present, "10.0.0.5", 0)], 1);
        std::fs::set_permissions(dir.join(store::FILE), std::fs::Permissions::from_mode(mode))
            .unwrap();
        let (section, _) = doctor_section_at(Some(&store), None, None);
        assert!(
            section.contains(&format!("(version 1, mode {mode:04o}{clause})")),
            "{mode:o}: {section}"
        );
    }

    // Every state that makes doctor fail: damaged, untrusted, unreadable,
    // unsettled (the retry is driven at the read level) and an unusable $HOME.
    let (dir, store) = doctor_store(&root.path().join("damaged"));
    std::fs::write(dir.join(store::FILE), b"not json").unwrap();
    let (section, failure) = doctor_section_at(Some(&store), None, None);
    assert!(
        section.contains("(not used: could not be used (not a JSON document this build reads))"),
        "{section}"
    );
    assert!(failure.is_some(), "{section}");

    let (dir, store) = doctor_store(&root.path().join("untrusted"));
    write_store(&dir, vec![record_for(&present, "10.0.0.5", 0)], 1);
    std::fs::set_permissions(
        dir.join(store::FILE),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    let (section, failure) = doctor_section_at(Some(&store), None, None);
    assert!(
        section.contains("(not used: is group- or other-writable)"),
        "{section}"
    );
    assert!(failure.is_some(), "{section}");

    let (section, failure) = doctor_section_at(None, None, None);
    assert_eq!(
        section,
        "==> project allowances\nfile: not checked ($HOME is not set)"
    );
    assert!(failure.is_none(), "an unset $HOME is not a failure");

    let (section, failure) =
        doctor_section_at(None, Some(anyhow::anyhow!("$HOME is set but empty")), None);
    assert!(
        section.contains("file: not read ($HOME is set but empty)"),
        "{section}"
    );
    assert!(failure.is_some(), "an unusable $HOME fails the run");

    // AC10's `unsettled` arm, driven through the same function with the state
    // the reader would have returned: it prints the state *and* fails the run.
    // A mutant returning `(section, None)` here would leave `doctor` exiting 0
    // on a store that was not used.
    let (section, failure) = doctor_section_from(
        Some(PathBuf::from("/home/a/.config/agent-vm/allowances.json")),
        Some(store::Read::NotUsed(store::Problem::Unsettled)),
        None,
        Some(own.clone()),
    );
    assert!(
        section.contains("(changed while being read; not used)"),
        "{section}"
    );
    assert!(failure.is_some(), "an unsettled store fails the run");
}

/// The timestamp renderer is a calendar, so it gets a table rather than one
/// date: every month, both leap years and a non-leap century, and one instant
/// before the epoch. Each row is an independently computed UTC reading, so a
/// rewritten formula fails on the row whose arithmetic it changed.
#[test]
fn recorded_at_is_a_utc_calendar() {
    for (ms, expected) in [
        (0_i64, "1970-01-01 00:00Z"),
        (-86_400_000, "1969-12-31 00:00Z"),
        (951_782_400_000, "2000-02-29 00:00Z"),
        (1_704_067_200_000, "2024-01-01 00:00Z"),
        (1_706_745_540_000, "2024-01-31 23:59Z"),
        (1_709_164_800_000, "2024-02-29 00:00Z"),
        (1_709_251_200_000, "2024-03-01 00:00Z"),
        (1_718_454_840_000, "2024-06-15 12:34Z"),
        (1_720_051_200_000, "2024-07-04 00:00Z"),
        (1_727_654_400_000, "2024-09-30 00:00Z"),
        (1_732_924_800_000, "2024-11-30 00:00Z"),
        (1_735_689_540_000, "2024-12-31 23:59Z"),
        (1_735_689_600_000, "2025-01-01 00:00Z"),
        (1_762_680_120_000, "2025-11-09 09:22Z"),
        (4_102_444_800_000, "2100-01-01 00:00Z"),
        (4_107_542_400_000, "2100-03-01 00:00Z"),
        // Pre-year-1 instants, computed by [`days_from_civil`] rather than
        // pinned: `access` reaches them from a refusal log's unrestricted
        // `last_ms` (`access --all` bypasses the time window), so the `else`
        // arm of `civil_from_days` is reachable production input, not a
        // hypothetical direct call.
        (days_from_civil(0, 2, 29) * 86_400_000, "0000-02-29 00:00Z"),
        (
            days_from_civil(-1, 12, 31) * 86_400_000,
            "-001-12-31 00:00Z",
        ),
        (days_from_civil(1, 1, 1) * 86_400_000, "0001-01-01 00:00Z"),
        // The exact value a review drove through `agent-vm access --all` (a
        // logged `last_ms`), which is the production route into the negative
        // era arm.
        (-62_162_121_600_000, "0000-02-29 00:00Z"),
    ] {
        assert_eq!(recorded_at(ms), expected, "{ms}");
    }
    // No timestamp may panic the renderer, whatever the log says: the value is
    // deserialized as an unrestricted `i64`.
    for extreme in [i64::MIN, i64::MIN + 1, i64::MAX - 1, i64::MAX] {
        assert!(!recorded_at(extreme).is_empty(), "{extreme}");
    }
}

/// Howard Hinnant's `days_from_civil`, the inverse `civil_from_days` is defined
/// by, written here so a pre-year-1 expectation is *computed*: the day count and
/// the calendar date are then checked against each other rather than a number
/// nobody can confirm.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 } as i64;
    let day_of_year = (153 * shifted_month + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The two entry points that read `$HOME`: a store is found where `$HOME` says
/// it is, and an unusable `$HOME` is the one section state that is not about a
/// file. This is the only test in the module that touches the environment, and
/// it holds the process-wide guard while it does.
#[test]
fn doctor_section_and_the_launch_view_read_the_store_under_home() {
    let mut env = crate::test_env::guard();
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let (dir, _) = doctor_store(&home.join(".config"));
    let project = project.canonicalize().unwrap();
    write_store(
        &dir,
        vec![record_for(&project, "tcp://[203.0.113.10/32]:443", 0)],
        1,
    );
    env.set_var("HOME", &home);
    let (section, failure) = doctor_section(Some(
        &crate::project::ProjectDir::from_path_for_tests(&project).unwrap(),
    ));
    assert!(failure.is_none(), "{section}");
    assert!(section.contains("(version 1, mode 0600)"), "{section}");
    assert!(section.contains("this project: 1"), "{section}");
    // The launch's view selects the same record, so the two commands cannot
    // disagree about what this project has.
    let view = for_launch(&crate::project::ProjectDir::from_path_for_tests(&project).unwrap());
    assert_eq!(view.allowances().len(), 1);
    assert!(view.notice().is_none(), "{:?}", view.notice());

    // An unusable `$HOME` is not the file's fault, and is still reported.
    env.set_var("HOME", "");
    let (section, failure) = doctor_section(None);
    assert!(
        section.contains("file: not read ($HOME is set but empty)"),
        "{section}"
    );
    assert!(failure.is_some(), "{section}");
}

/// The orphan classification's third row: a path whose *ancestor* cannot be
/// inspected is `unknown`, never counted as orphaned. The check reads the mode
/// bits, so it cannot run as root, where every path is inspectable.
#[test]
fn doctor_reports_an_uninspectable_project_as_unknown() {
    if crate::host_paths::current_euid() == 0 {
        eprintln!(
            "uninspectable-path fixture NOT RUN: running as root, so every path is inspectable"
        );
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (dir, store) = doctor_store(root.path());
    let locked = root.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::create_dir(locked.join("project")).unwrap();
    write_store(
        &dir,
        vec![record_for(&locked.join("project"), "10.0.0.5", 0)],
        1,
    );
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (section, failure) = doctor_section_at(Some(&store), None, None);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(failure.is_none(), "{section}");
    assert!(
        section.contains("unknown: 1 project path(s) could not be checked"),
        "{section}"
    );
    assert!(!section.contains("no longer exist"), "{section}");
    // An intermediate component that became a *file* answers `NotADirectory`,
    // which is the same fact as a missing path.
    let file = root.path().join("now-a-file");
    std::fs::write(&file, b"").unwrap();
    let (dir, store) = doctor_store(&root.path().join("not-a-dir"));
    write_store(
        &dir,
        vec![record_for(&file.join("project"), "10.0.0.5", 0)],
        1,
    );
    let (section, _) = doctor_section_at(Some(&store), None, None);
    assert!(
        section.contains("orphaned: 1 project path(s) no longer exist"),
        "{section}"
    );
}

// ---------------------------------------------------------------------------
// Group L: the live controller, coverage, and grantable destinations (PR 2)
// ---------------------------------------------------------------------------

use crate::allowances::apply::{
    GrantResult, GrantScope, LiveAllowances, RevokeResult, RevokeScope, SessionAllowancesSnapshot,
    UnconfirmedReason, WireAllowance,
};
use crate::refusal::feed::LiveRefusals;
use std::sync::{Arc, Mutex};

/// One project directory a live controller can own.
fn live_project(name: &str) -> ProjectDir {
    let dir = scratch().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    ProjectDir::from_path_for_tests(&dir).unwrap()
}

/// A `LivePolicyPlan` for an explicit launch authority.
fn live_plan(allow_egress: &[&str], host_proxy_used: bool) -> crate::network::LivePolicyPlan {
    crate::network::plan_for_tests(allow_egress, host_proxy_used)
        .live_policy_plan(Some(Path::new("/home/a/.config/agent-vm/allowances.json")))
}

/// Every policy handed to the runtime, with a monotonic revision.
struct Recorder {
    policies: Mutex<Vec<(NetworkPolicy, u64)>>,
    fail: std::sync::atomic::AtomicBool,
    unsupported: Mutex<bool>,
}

impl Recorder {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            policies: Mutex::new(Vec::new()),
            fail: std::sync::atomic::AtomicBool::new(false),
            unsupported: Mutex::new(false),
        })
    }

    fn calls(&self) -> usize {
        self.policies.lock().unwrap().len()
    }

    fn last(&self) -> Option<(NetworkPolicy, u64)> {
        self.policies.lock().unwrap().last().cloned()
    }

    fn updater(self: &Arc<Self>) -> crate::allowances::PolicyUpdater {
        let recorder = Arc::clone(self);
        Arc::new(move |policy: NetworkPolicy| {
            let recorder = Arc::clone(&recorder);
            Box::pin(async move {
                if *recorder.unsupported.lock().unwrap() {
                    return Err(microsandbox::MicrosandboxError::Unsupported {
                        op: microsandbox::Operation::SandboxUpdateNetworkPolicy,
                        reason: microsandbox::UnsupportedReason::NotAvailable("test".to_owned()),
                    });
                }
                if recorder.fail.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(microsandbox::MicrosandboxError::ControlStateChanged);
                }
                let mut policies = recorder.policies.lock().unwrap();
                let revision = policies.len() as u64 + 2;
                policies.push((policy, revision));
                Ok(revision)
            })
        })
    }
}

/// A controller over a temporary authority directory, with nothing adopted.
fn live(
    project: &ProjectDir,
    plan: crate::network::LivePolicyPlan,
) -> (Arc<LiveAllowances>, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    let store = crate::allowances::StoreHandle::at_for_tests(root.path());
    let controller = LiveAllowances::new(project, store, plan);
    (controller, root)
}

fn live_refusals() -> Arc<LiveRefusals> {
    LiveRefusals::new(crate::refusal::SessionRefusals::new(
        crate::refusal::SessionInfo {
            id: crate::refusal::SessionId::parse("0a1b2c3d").unwrap(),
            pid: 1,
            started_ms: 0,
            socket: true,
        },
    ))
}

/// The policy a fresh launch resolved with exactly these entries would produce.
fn fresh_policy(allow_egress: &[&str], combined: &[&str]) -> NetworkPolicy {
    let mut authority = crate::egress_policy::EgressAuthority::resolve(
        crate::egress_policy::CliEgress {
            internet: None,
            lan: None,
            host: None,
            allowances: &[],
        },
        None,
        None,
    )
    .unwrap();
    // One `set_recorded` with the whole effective set: it replaces, not appends.
    let mut effective = Vec::new();
    for text in allow_egress.iter().chain(combined.iter()) {
        effective.push(Allowance::parse(text).unwrap());
    }
    authority.set_recorded(Path::new("/live"), effective);
    authority.policy()
}

/// L1: every grantable destination round-trips through `covers`, and the names
/// this command must refuse are refused.
#[test]
fn grantable_destination_round_trips_through_covers() {
    // Address sites.
    for (protocol, site, ip, port, spelling) in [
        (
            "tcp",
            "tcp-syn",
            "203.0.113.10",
            Some(443),
            "tcp://[203.0.113.10/32]:443",
        ),
        (
            "udp",
            "udp",
            "203.0.113.10",
            Some(53),
            "udp://[203.0.113.10/32]:53",
        ),
        (
            "tcp",
            "tcp-syn",
            "203.0.113.10",
            None,
            "tcp://203.0.113.10/32",
        ),
    ] {
        let entry = address_entry(protocol, ip, port, site);
        let granted = grantable_destination(&entry).expect(spelling);
        assert_eq!(granted.to_string(), spelling);
        assert!(
            covers(&[spelling], &entry),
            "{spelling} covers the entry it came from"
        );
    }

    // A hostname through TLS/SNI.
    let sni = host_entry("api.example.com", 443, "tls-sni", "sni");
    let granted = grantable_destination(&sni).expect("a TLS hostname");
    assert_eq!(granted.to_string(), "tcp://api.example.com:443");
    assert!(covers(&["tcp://api.example.com:443"], &sni));

    // A DNS query.
    let dns = dns_entry("api.example.com", "dns-query");
    assert_eq!(
        grantable_destination(&dns).unwrap().to_string(),
        "api.example.com"
    );
    assert!(covers(&["api.example.com"], &dns));

    // Refusals this command must not turn into an allowance.
    assert!(matches!(
        grantable_destination(&host_entry("api.example.com", 80, "http-host", "http-host")),
        Err(CannotAllow::PlainHttpHostname)
    ));
    assert!(matches!(
        grantable_destination(&address_entry(
            "tcp",
            "203.0.113.10",
            Some(443),
            "dns-query"
        )),
        Err(CannotAllow::SiteNotAllowable { .. })
    ));
    let mut platform = address_entry("tcp", "203.0.113.10", Some(443), "tcp-syn");
    platform.layer = "platform".to_owned();
    assert!(matches!(
        grantable_destination(&platform),
        Err(CannotAllow::NotNetworkDenial(_))
    ));
    // A non-canonical name is refused rather than granted in a spelling the
    // recorded query could never recognise.
    let uppercase = host_entry("API.Example.COM", 443, "tls-sni", "sni");
    match grantable_destination(&uppercase) {
        Ok(allowance) => assert!(
            covers(&[&allowance.to_string()], &uppercase),
            "a grantable name must round-trip"
        ),
        Err(CannotAllow::InvalidDestination(_)) => {}
        Err(other) => panic!("unexpected refusal {other:?}"),
    }
}

/// L2: the policy handed to the runtime is the launch's one computation over
/// `session ∪ project`, byte for byte.
#[tokio::test]
async fn live_grant_rederives_through_egress_authority_policy() {
    let project = live_project("l2");
    let (controller, _root) = live(&project, live_plan(&["api.example.com"], false));
    let recorder = Recorder::new();
    assert!(!controller.attach_updater(recorder.updater()));
    let refusals = live_refusals();

    let result = controller
        .grant(
            &refusals,
            None,
            Some("tcp://[203.0.113.10/32]:443"),
            GrantScope::Session,
            1_000,
        )
        .await;
    assert!(
        matches!(result, GrantResult::Applied { revision: 2, .. }),
        "{result:?}"
    );
    let (policy, revision) = recorder.last().expect("one swap");
    assert_eq!(revision, 2);
    let expected = fresh_policy(&["api.example.com"], &["tcp://[203.0.113.10/32]:443"]);
    assert_eq!(
        format!("{policy:?}"),
        format!("{expected:?}"),
        "one computation produced this policy"
    );
}

/// L3: adding a TLS-intercepted port is refused for a session grant and deferred
/// for a project grant; nothing calls the runtime.
#[tokio::test]
async fn live_grant_refuses_or_defers_when_intercepted_ports_change() {
    let project = live_project("l3");
    let (controller, root) = live(&project, live_plan(&[], false));
    let recorder = Recorder::new();
    controller.attach_updater(recorder.updater());
    let refusals = live_refusals();

    // A launch that intercepted nothing cannot grant a hostname live.
    let result = controller
        .grant(
            &refusals,
            None,
            Some("api.example.com"),
            GrantScope::Session,
            1_000,
        )
        .await;
    assert!(
        matches!(
            result,
            GrantResult::Refused {
                reason: GrantRefusalReason::InterceptedPortsFixedAtLaunch
            }
        ),
        "{result:?}"
    );
    assert_eq!(recorder.calls(), 0, "no policy swap for a refused grant");

    // With `--project` the same grant becomes a next-launch record.
    let result = controller
        .grant(
            &refusals,
            None,
            Some("api.example.com"),
            GrantScope::Project,
            2_000,
        )
        .await;
    assert!(
        matches!(
            result,
            GrantResult::NextLaunch {
                reason: NextLaunchReason::InterceptedPortsFixedAtLaunch,
                ..
            }
        ),
        "{result:?}"
    );
    assert_eq!(recorder.calls(), 0);
    let view = ProjectView::at_dir_for_tests(root.path(), &ProjectId::of(&project));
    assert_eq!(
        view.allowances()
            .destinations()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["api.example.com".to_owned()],
        "the project record is written for the next launch"
    );
}

/// L4: scoped revoke respects the union, and revoking the last *granted*
/// hostname removes the last Domain rule within the launch's ports.
#[tokio::test]
async fn live_revoke_of_last_hostname_stops_connections_within_launch_ports_and_keeps_state_on_failure()
 {
    // Part 1: one destination in both tables collapses to one rule; a project
    // revoke leaves the session entry in force.
    let project = live_project("l4");
    let (controller, _root) = live(&project, live_plan(&["api.example.com"], false));
    let recorder = Recorder::new();
    controller.attach_updater(recorder.updater());
    let refusals = live_refusals();

    let session = controller
        .grant(
            &refusals,
            None,
            Some("api.example.com"),
            GrantScope::Session,
            1_000,
        )
        .await;
    assert!(
        matches!(session, GrantResult::Applied { .. }),
        "{session:?}"
    );
    let project_grant = controller
        .grant(
            &refusals,
            None,
            Some("api.example.com"),
            GrantScope::Project,
            2_000,
        )
        .await;
    assert!(
        matches!(project_grant, GrantResult::Applied { .. }),
        "{project_grant:?}"
    );
    assert_eq!(
        recorder.calls(),
        1,
        "the duplicate grant did not swap the policy again"
    );

    let result = controller
        .revoke(
            &Allowance::parse("api.example.com").unwrap(),
            RevokeScope::Project,
        )
        .await;
    match result {
        RevokeResult::Revoked {
            still_effective,
            revision,
            ..
        } => {
            assert!(still_effective, "the session allowance is still in force");
            // The duplicate project grant took no swap, so this revoke is the
            // session's second confirmed revision.
            assert_eq!(revision, Some(3));
        }
        other => panic!("{other:?}"),
    }

    // Part 2: a launch that fixed port 443 for TLS but granted no hostname. A
    // live grant of one hostname narrows cleanly when it is revoked again: the
    // derived policy has no Domain rule at all, and the launch's ports are kept.
    let (controller, _root) = {
        let project = live_project("l4b");
        let root = tempfile::tempdir().unwrap();
        let store = crate::allowances::StoreHandle::at_for_tests(root.path());
        let plan = crate::network::LivePolicyPlan::with_launch_ports_for_tests(
            &[],
            Some("fixed.example"),
            false,
        );
        (LiveAllowances::new(&project, store, plan), root)
    };
    let recorder = Recorder::new();
    controller.attach_updater(recorder.updater());
    let refusals = live_refusals();
    let granted = controller
        .grant(
            &refusals,
            None,
            Some("api.example.com"),
            GrantScope::Session,
            4_000,
        )
        .await;
    assert!(
        matches!(granted, GrantResult::Applied { .. }),
        "{granted:?}"
    );
    let result = controller
        .revoke(
            &Allowance::parse("api.example.com").unwrap(),
            RevokeScope::All,
        )
        .await;
    assert!(
        matches!(
            result,
            RevokeResult::Revoked {
                still_effective: false,
                ..
            }
        ),
        "{result:?}"
    );
    let (policy, _) = recorder.last().unwrap();
    let has_domain = policy.rules.iter().any(|rule| {
        matches!(
            rule.destination,
            microsandbox_network::policy::Destination::Domain(_)
        )
    });
    assert!(!has_domain, "no Domain rule remains: {policy:?}");

    // Part 3: a runtime failure keeps every entry.
    controller
        .grant(
            &refusals,
            None,
            Some("tcp://[203.0.113.10/32]:443"),
            GrantScope::Session,
            5_000,
        )
        .await;
    recorder
        .fail
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let before = controller.snapshot();
    let result = controller
        .revoke(
            &Allowance::parse("tcp://[203.0.113.10/32]:443").unwrap(),
            RevokeScope::All,
        )
        .await;
    assert!(
        matches!(
            result,
            RevokeResult::Unconfirmed {
                reason: UnconfirmedReason::RuntimeFailed { .. },
                ..
            }
        ),
        "{result:?}"
    );
    assert_eq!(controller.snapshot(), before, "memory keeps its entries");
}

/// L5: `Applied` requires a confirmed revision *after* the refusal, and the port
/// set is computed over both tables before either is searched.
#[test]
fn applied_coverage_requires_confirmed_revision_after_last_refusal() {
    let project = project_id("l5");
    let view = ProjectView::for_tests(&[], 0, None);
    let mut entry = address_entry("tcp", "203.0.113.10", Some(443), "tcp-syn");
    entry.last_revision = 1;

    let snapshot = |revision: Option<u64>| SessionAllowancesSnapshot {
        session: vec![WireAllowance {
            destination: "tcp://[203.0.113.10/32]:443".to_owned(),
            granted_ms: 5,
            revision,
            not_recorded_error: None,
        }],
        project: Vec::new(),
    };

    // A boot revision (`1`) did not apply to a refusal at revision 1.
    assert!(
        view.covers_in_session(&entry, Some(&snapshot(Some(1))))
            .is_none()
    );
    // A confirmed later revision does.
    assert!(matches!(
        view.covers_in_session(&entry, Some(&snapshot(Some(2)))),
        Some(Coverage::Applied { revision: 2, .. })
    ));
    // A refusal already at the confirmed revision is still only recorded.
    entry.last_revision = 2;
    assert!(
        view.covers_in_session(&entry, Some(&snapshot(Some(2))))
            .is_none()
    );
    // An unconfirmed entry never claims application.
    entry.last_revision = 1;
    assert!(
        view.covers_in_session(&entry, Some(&snapshot(None)))
            .is_none()
    );

    // m3: a confirmed hostname in the *session* table supplies the port set for a
    // hostname rule in the project table, so the cross-revision union is seen.
    let mut host = host_entry("api.example.com", 8443, "tls-sni", "sni");
    host.last_revision = 1;
    let cross = SessionAllowancesSnapshot {
        project: vec![WireAllowance {
            destination: "tcp://api.example.com:8443".to_owned(),
            granted_ms: 3,
            revision: Some(3),
            not_recorded_error: None,
        }],
        session: vec![WireAllowance {
            destination: "api.example.com".to_owned(),
            granted_ms: 4,
            revision: Some(2),
            not_recorded_error: None,
        }],
    };
    assert!(matches!(
        view.covers_in_session(&host, Some(&cross)),
        Some(Coverage::Applied {
            scope: AllowanceScope::Project,
            revision: 3,
            ..
        })
    ));
    let _ = project;
}

/// L6: a boot hostname skipped under a host proxy is not in the live tables, so
/// it stays recorded and never blocks a live address grant.
#[tokio::test]
async fn proxy_skipped_boot_hostname_stays_recorded_and_does_not_block_live_address_grants() {
    let project = live_project("l6");
    let mut plan = crate::network::plan_for_tests(&[], true);
    let view = ProjectView::for_tests(&["api.example.com", "tcp://[203.0.113.10/32]:443"], 7, None);
    let (adopted, notice) = plan.adopt_recorded(view.file().unwrap(), view.allowances());
    assert!(notice.is_some(), "the skipped hostname has one notice");
    assert_eq!(adopted.len(), 1, "only the address was adopted");

    let (controller, root) = live(&project, plan.live_policy_plan(view.file()));
    controller.adopt_boot_allowances(&view, &adopted, plan.live_policy_plan(view.file()));
    let snapshot = controller.snapshot();
    assert!(
        snapshot
            .project
            .iter()
            .all(|item| item.destination != "api.example.com"),
        "the proxy-skipped hostname is absent: {snapshot:?}"
    );

    // It stays `Recorded` for the row that names it…
    let host = host_entry("api.example.com", 443, "tls-sni", "sni");
    assert!(matches!(
        view.covers_in_session(&host, Some(&snapshot)),
        Some(Coverage::Recorded(_))
    ));
    // …and does not block a live address grant.
    let recorder = Recorder::new();
    controller.attach_updater(recorder.updater());
    let result = controller
        .grant(
            &live_refusals(),
            None,
            Some("tcp://[198.51.100.0/24]:443"),
            GrantScope::Session,
            1_000,
        )
        .await;
    assert!(matches!(result, GrantResult::Applied { .. }), "{result:?}");

    // B-m4: a live *hostname* grant under a host proxy is refused below
    // `derive_for`, and refuses without asking the runtime: the mapping from the
    // precondition to the reply is what a regression would get wrong (turning it
    // into a next-launch record would write a hostname the proxy cannot honour).
    let before = recorder.calls();
    let refused = controller
        .grant(
            &live_refusals(),
            None,
            Some("other.example"),
            GrantScope::Project,
            2_000,
        )
        .await;
    match refused {
        GrantResult::Refused { reason } => assert!(
            matches!(
                reason,
                crate::allowances::apply::GrantRefusalReason::HostProxyInUse
            ),
            "{reason:?}"
        ),
        other => panic!("a hostname under a host proxy must be refused: {other:?}"),
    }
    assert_eq!(recorder.calls(), before, "no swap was attempted");
    assert_eq!(
        ProjectView::at_dir_for_tests(root.path(), &crate::image_pin::ProjectId::of(&project))
            .allowances()
            .len(),
        0,
        "a refused hostname writes no record"
    );
}

/// A queued grant is promoted at `follow`, and a failed flush drops it with a
/// notice that says whether a project record carries it forward.
#[tokio::test]
async fn queued_grants_are_promoted_or_dropped_with_a_notice() {
    let project = live_project("p2");
    let (controller, root) = live(&project, live_plan(&[], false));
    let refusals = live_refusals();

    let queued = controller
        .grant(
            &refusals,
            None,
            Some("tcp://[203.0.113.10/32]:443"),
            GrantScope::Project,
            1_000,
        )
        .await;
    assert!(
        matches!(
            queued,
            GrantResult::QueuedForBoot {
                scope: GrantScope::Project,
                ..
            }
        ),
        "{queued:?}"
    );
    // The store write happened, because a queued project grant is a record.
    let view = ProjectView::at_dir_for_tests(root.path(), &ProjectId::of(&project));
    assert_eq!(view.allowances().len(), 1);

    // Success: the queued entry takes the runtime's revision.
    let recorder = Recorder::new();
    assert!(controller.attach_updater(recorder.updater()));
    assert!(controller.flush_queued().await.is_empty());
    let snapshot = controller.snapshot();
    assert_eq!(snapshot.project[0].revision, Some(2));

    // Failure: the queued entry is dropped, and the notice names the record.
    let (controller, _root) = self::live(&live_project("p2b"), live_plan(&[], false));
    let refusals = live_refusals();
    controller
        .grant(
            &refusals,
            None,
            Some("tcp://[198.51.100.0/24]:443"),
            GrantScope::Project,
            2_000,
        )
        .await;
    controller
        .grant(
            &refusals,
            None,
            Some("tcp://[203.0.113.0/24]:443"),
            GrantScope::Session,
            3_000,
        )
        .await;
    let failing = Recorder::new();
    failing
        .fail
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(controller.attach_updater(failing.updater()));
    let warnings = controller.flush_queued().await;
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(
        warnings
            .iter()
            .any(|line| line.contains("still carries it"))
    );
    assert!(
        warnings
            .iter()
            .any(|line| line.contains("no project record"))
    );
    assert!(controller.snapshot().project.is_empty());
    assert!(controller.snapshot().session.is_empty());
}

/// A-M01: the whole `NotInSession` branch, for the three states that decide
/// whether the tool may say a destination is gone.
///
/// The honesty claim lives here: `still_effective` must be a fact about the
/// *policy*, so a destination this launch's own `--allow-egress` admits is still
/// allowed even though no allowance names it (B01). A mutant that hard-codes
/// either answer dies on one of these three cases.
#[tokio::test]
async fn revoke_names_only_what_the_policy_still_allows() {
    // (a) Only the launch's own configured authority admits it.
    let (controller, _root) = live(
        &live_project("b01a"),
        live_plan(&["tcp://[203.0.113.7/32]:443"], false),
    );
    let configured = Allowance::parse("tcp://[203.0.113.7/32]:443").unwrap();
    match controller.revoke(&configured, RevokeScope::All).await {
        RevokeResult::NotInSession {
            scope,
            revision,
            still_effective,
            ..
        } => {
            assert!(
                still_effective,
                "the launch's own --allow-egress still admits it"
            );
            assert_eq!(scope, RevokeScope::All);
            assert_eq!(revision, None, "no swap happened, so there is no revision");
        }
        other => panic!("{other:?}"),
    }

    // (b) Only the other scope names it.
    let (controller, _root) = live(&live_project("b01b"), live_plan(&[], false));
    let recorder = Recorder::new();
    controller.attach_updater(recorder.updater());
    let held = controller
        .grant(
            &live_refusals(),
            None,
            Some("tcp://[198.51.100.9/32]:443"),
            GrantScope::Session,
            1_000,
        )
        .await;
    assert!(matches!(held, GrantResult::Applied { .. }), "{held:?}");
    let destination = Allowance::parse("tcp://[198.51.100.9/32]:443").unwrap();
    match controller.revoke(&destination, RevokeScope::Project).await {
        RevokeResult::NotInSession {
            scope,
            revision,
            still_effective,
            ..
        } => {
            assert!(still_effective, "the session table still holds it");
            assert_eq!(scope, RevokeScope::Project);
            assert_eq!(revision, Some(2), "the session has a confirmed revision");
        }
        other => panic!("{other:?}"),
    }

    // (c) Neither table nor the configured authority names it: nothing is in force.
    let (controller, _root) = live(&live_project("b01c"), live_plan(&[], false));
    let absent = Allowance::parse("tcp://[192.0.2.44/32]:443").unwrap();
    match controller.revoke(&absent, RevokeScope::All).await {
        RevokeResult::NotInSession {
            revision,
            still_effective,
            ..
        } => {
            assert!(!still_effective, "nothing admits it");
            assert_eq!(revision, None);
        }
        other => panic!("{other:?}"),
    }
}

/// A-m01: a revoke that never asks the runtime must not report a revision.
#[tokio::test]
async fn revoke_of_a_queued_entry_reports_no_revision() {
    let (controller, _root) = live(&live_project("m01"), live_plan(&[], false));
    let queued = controller
        .grant(
            &live_refusals(),
            None,
            Some("tcp://[203.0.113.11/32]:443"),
            GrantScope::Session,
            1_000,
        )
        .await;
    assert!(
        matches!(queued, GrantResult::QueuedForBoot { .. }),
        "{queued:?}"
    );
    let recorder = Recorder::new();
    controller.attach_updater(recorder.updater());
    // The entry is still queued: the flush has not run, so nothing is in force.
    match controller
        .revoke(
            &Allowance::parse("tcp://[203.0.113.11/32]:443").unwrap(),
            RevokeScope::All,
        )
        .await
    {
        RevokeResult::Revoked { revision, .. } => {
            assert_eq!(revision, None, "no policy change was made");
            assert_eq!(recorder.calls(), 0, "the runtime was never asked");
        }
        other => panic!("{other:?}"),
    }
    assert!(controller.snapshot().session.is_empty());
}

/// B02: a `--project` grant that lands on an entry still queued for boot records
/// the allowance before it claims one, and never claims a record it did not write.
#[tokio::test]
async fn project_grant_over_a_queued_session_entry_records_before_claiming_it() {
    let project = live_project("b02");
    let (controller, root) = live(&project, live_plan(&[], false));
    let refusals = live_refusals();
    let destination = "tcp://[203.0.113.12/32]:443";
    let queued = controller
        .grant(
            &refusals,
            None,
            Some(destination),
            GrantScope::Session,
            1_000,
        )
        .await;
    assert!(
        matches!(
            queued,
            GrantResult::QueuedForBoot {
                scope: GrantScope::Session,
                ..
            }
        ),
        "{queued:?}"
    );

    let recorded = controller
        .grant(
            &refusals,
            None,
            Some(destination),
            GrantScope::Project,
            2_000,
        )
        .await;
    assert!(
        matches!(
            recorded,
            GrantResult::QueuedForBoot {
                scope: GrantScope::Project,
                ..
            }
        ),
        "the reply the CLI renders as `recorded project allowance`: {recorded:?}"
    );
    // The claim is true: the record exists, and the entry moved to the table the
    // flush is about to promote.
    let view = ProjectView::at_dir_for_tests(root.path(), &ProjectId::of(&project));
    assert_eq!(view.allowances().len(), 1, "the record the reply promised");
    let snapshot = controller.snapshot();
    assert!(snapshot.session.is_empty(), "{snapshot:?}");
    assert_eq!(snapshot.project.len(), 1, "{snapshot:?}");

    // A store that cannot be written refuses instead, and moves nothing.
    let (blocked, blocked_root) = live(&live_project("b02b"), live_plan(&[], false));
    blocked
        .grant(
            &refusals,
            None,
            Some(destination),
            GrantScope::Session,
            1_000,
        )
        .await;
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(blocked_root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    match blocked
        .grant(
            &refusals,
            None,
            Some(destination),
            GrantScope::Project,
            2_000,
        )
        .await
    {
        GrantResult::Refused { reason } => assert!(
            matches!(
                reason,
                crate::allowances::apply::GrantRefusalReason::Store { .. }
            ),
            "{reason:?}"
        ),
        other => panic!("a store it could not write was claimed: {other:?}"),
    }
    let snapshot = blocked.snapshot();
    assert_eq!(snapshot.session.len(), 1, "the session entry is untouched");
    assert!(
        snapshot.project.is_empty(),
        "nothing was claimed as a record"
    );
}

/// B03: while the boot queue is pending, a grant is queued instead of swapped,
/// so no policy carries an entry the flush has not confirmed — and a failed flush
/// leaves memory matching the runtime, with the accepted policy restored.
#[tokio::test]
async fn a_grant_while_the_boot_queue_is_pending_makes_no_swap() {
    let (controller, _root) = live(&live_project("b03"), live_plan(&[], false));
    let refusals = live_refusals();
    controller
        .grant(
            &refusals,
            None,
            Some("tcp://[203.0.113.13/32]:443"),
            GrantScope::Session,
            1_000,
        )
        .await;
    let recorder = Recorder::new();
    assert!(controller.attach_updater(recorder.updater()));
    let second = controller
        .grant(
            &refusals,
            None,
            Some("tcp://[198.51.100.13/32]:443"),
            GrantScope::Session,
            2_000,
        )
        .await;
    assert!(
        matches!(second, GrantResult::QueuedForBoot { .. }),
        "a swap here would carry the first, unconfirmed entry: {second:?}"
    );
    assert_eq!(
        recorder.calls(),
        0,
        "nothing was sent while the queue is pending"
    );

    // The flush is the only writer of that policy, and its failure drops both
    // queued entries: after it, memory names nothing the runtime did not receive.
    recorder
        .fail
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let warnings = controller.flush_queued().await;
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(
        controller.snapshot().session.is_empty(),
        "{:?}",
        controller.snapshot()
    );
    assert!(controller.snapshot().project.is_empty());

    // The restored policy is usable: a later grant derives from it, not from a
    // plan that still carried the dropped entries.
    recorder
        .fail
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let third = controller
        .grant(
            &refusals,
            None,
            Some("tcp://[192.0.2.13/32]:443"),
            GrantScope::Session,
            3_000,
        )
        .await;
    assert!(matches!(third, GrantResult::Applied { .. }), "{third:?}");
    let (policy, _revision) = recorder.last().unwrap();
    assert_eq!(
        format!("{policy:?}"),
        format!("{:?}", fresh_policy(&[], &["tcp://[192.0.2.13/32]:443"]))
    );
}

/// A-M02: a failed record on an already-session-granted destination keeps the
/// demotion on the entry, so every later render still says no record carries it.
#[tokio::test]
async fn project_grant_over_a_session_entry_keeps_the_demotion_on_the_entry() {
    let project = live_project("m02");
    let (controller, root) = live(&project, live_plan(&[], false));
    let refusals = live_refusals();
    let destination = "tcp://[203.0.113.14/32]:443";
    let recorder = Recorder::new();
    controller.attach_updater(recorder.updater());
    let first = controller
        .grant(
            &refusals,
            None,
            Some(destination),
            GrantScope::Session,
            1_000,
        )
        .await;
    assert!(matches!(first, GrantResult::Applied { .. }), "{first:?}");

    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let failed = controller
        .grant(
            &refusals,
            None,
            Some(destination),
            GrantScope::Project,
            2_000,
        )
        .await;
    assert!(
        matches!(failed, GrantResult::AppliedNotRecorded { .. }),
        "{failed:?}"
    );
    let snapshot = controller.snapshot();
    assert_eq!(snapshot.session.len(), 1, "{snapshot:?}");
    assert!(
        snapshot.session[0].not_recorded_error.is_some(),
        "the demotion must survive the reply: {snapshot:?}"
    );
    assert!(snapshot.project.is_empty(), "{snapshot:?}");
}

/// B-S4: the adoption-window re-derivation plan §8.5 P2 Part A asks for.
///
/// A grant that arrives between `for_launch` and `adopt_boot_allowances` is queued
/// on the pre-adoption plan; adoption must re-derive it over the post-adoption one
/// (`configured ∪ adopted ∪ queued`), promote an adopted record to `rev 1`, and
/// hand the runtime a policy containing all three.
#[tokio::test]
async fn adopt_boot_allowances_rederives_a_queued_grant_over_the_post_adoption_plan() {
    let project = live_project("s4");
    let mut launch = crate::network::plan_for_tests(&["api.example.com"], false);
    let view = ProjectView::for_tests(&["adopted.example"], 1_000, None);
    let file = Path::new("/home/a/.config/agent-vm/allowances.json");
    let (adopted, notice) = launch.adopt_recorded(file, view.allowances());
    assert!(notice.is_none(), "{notice:?}");
    assert_eq!(adopted.len(), 1);

    let (controller, _root) = live(&project, launch.live_policy_plan(Some(file)));
    let refusals = live_refusals();
    // Queued before adoption, on the configured-only plan.
    let queued = controller
        .grant(
            &refusals,
            None,
            Some("tcp://[203.0.113.15/32]:443"),
            GrantScope::Session,
            2_000,
        )
        .await;
    assert!(
        matches!(queued, GrantResult::QueuedForBoot { .. }),
        "{queued:?}"
    );

    let warnings =
        controller.adopt_boot_allowances(&view, &adopted, launch.live_policy_plan(Some(file)));
    assert!(warnings.is_empty(), "{warnings:?}");
    let snapshot = controller.snapshot();
    assert_eq!(
        snapshot.project.len(),
        1,
        "the adopted record: {snapshot:?}"
    );
    assert_eq!(
        snapshot.project[0].revision,
        Some(1),
        "boot adoption is rev 1"
    );
    assert_eq!(
        snapshot.session.len(),
        1,
        "the queued grant survives: {snapshot:?}"
    );
    assert_eq!(
        snapshot.session[0].revision, None,
        "still queued: {snapshot:?}"
    );

    let recorder = Recorder::new();
    controller.attach_updater(recorder.updater());
    assert!(controller.flush_queued().await.is_empty());
    let snapshot = controller.snapshot();
    assert_eq!(snapshot.session[0].revision, Some(2), "{snapshot:?}");
    assert_eq!(snapshot.project[0].revision, Some(1), "{snapshot:?}");
    // The policy the runtime received carries configured ∪ adopted ∪ queued.
    let (policy, _) = recorder.last().unwrap();
    assert_eq!(
        format!("{policy:?}"),
        format!(
            "{:?}",
            fresh_policy(
                &["api.example.com"],
                &["adopted.example", "tcp://[203.0.113.15/32]:443"]
            )
        )
    );
}

/// A-m08: the live tables are bounded, and a grant past the bound is refused with
/// a reason rather than dropped.
#[tokio::test]
async fn live_tables_are_bounded_and_refused_with_a_reason() {
    let (controller, _root) = live(&live_project("m08"), live_plan(&[], false));
    let refusals = live_refusals();
    let recorder = Recorder::new();
    controller.attach_updater(recorder.updater());
    for index in 0..256u32 {
        let destination = format!("tcp://[10.{}.{}.1/32]:443", index / 256, index % 256);
        let result = controller
            .grant(
                &refusals,
                None,
                Some(&destination),
                GrantScope::Session,
                1_000,
            )
            .await;
        assert!(
            matches!(result, GrantResult::Applied { .. }),
            "{index}: {result:?}"
        );
    }
    let refused = controller
        .grant(
            &refusals,
            None,
            Some("tcp://[192.0.2.99/32]:443"),
            GrantScope::Session,
            1_000,
        )
        .await;
    match refused {
        GrantResult::Refused { reason } => assert!(
            matches!(
                reason,
                crate::allowances::apply::GrantRefusalReason::Full { limit: 256 }
            ),
            "{reason:?}"
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(recorder.calls(), 256, "the refused grant swapped nothing");
}
