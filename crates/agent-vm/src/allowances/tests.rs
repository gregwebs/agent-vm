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
const VOCABULARY: [&str; 18] = [
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
    "api.example.com",
    "API.example.com.",
    "xn--bcher-kva.example",
    "tcp://api.example.com:8443",
];

/// Address entries at the three sites a `Cidr` rule can decide.
const ADDRESS_PROBES: [(&str, &str, Option<u16>, &str); 12] = [
    ("tcp", "203.0.113.10", Some(443), "tcp-syn"),
    ("tcp", "203.0.113.10", Some(444), "tcp-syn"),
    ("tcp", "203.0.113.10", Some(8443), "tcp-syn"),
    ("tcp", "203.0.113.10", Some(1), "tcp-syn"),
    ("tcp", "203.0.113.1", Some(443), "tcp-syn"),
    ("tcp", "192.168.1.7", Some(443), "tcp-syn"),
    ("udp", "203.0.113.10", Some(443), "udp"),
    ("udp", "192.168.1.7", Some(53), "udp"),
    ("icmpv4", "203.0.113.10", None, "icmp"),
    ("icmpv4", "192.168.1.7", None, "icmp"),
    ("tcp", "::ffff:203.0.113.10", Some(443), "tcp-syn"),
    ("tcp", "2001:db8::1", Some(443), "tcp-syn"),
];

const HOST_PROBES: [(&str, u16); 5] = [
    ("api.example.com", 443),
    ("api.example.com", 8443),
    ("api.example.com", 80),
    ("xn--bcher-kva.example", 443),
    ("other.example", 443),
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
    proptest::collection::vec(proptest::sample::select(&VOCABULARY[..14]), 0..4)
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
        let host_entry = host_entry(host.0, host.1, "tls-sni", "sni");
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
