//! The coalescing table, the ID derivation and the counters.
//!
//! The toy run here is §5's table, record for record, with the golden IDs
//! computed from the documented derivation. It is the one test a reader should
//! be able to follow without opening any other file.

use super::*;
use microsandbox::logs::{LogSource, NetworkSuppressed};
use microsandbox_types::Protocol;

/// The `NetworkLogRecord` envelope's timestamp type.
type At = chrono::DateTime<chrono::Utc>;

const SID: &str = "3f9a12c4";
/// 2025-10-09T09:33:20Z. Every record below is a whole second after it.
const BASE_MS: i64 = 1_760_000_000_000;

/// The golden IDs from §5, computed by hand from the documented derivation.
const E1: &str = "46d712fd";
const E2: &str = "71aca03c";
const E3: &str = "88f5da9d";
const E4: &str = "a00b2078";
const E5: &str = "310ba275";

fn at(offset_secs: i64) -> At {
    At::from_timestamp_millis(BASE_MS + offset_secs * 1000).unwrap()
}

fn session() -> SessionRefusals {
    SessionRefusals::new(SessionInfo {
        id: SessionId::parse(SID).unwrap(),
        pid: 4242,
        started_ms: BASE_MS,
        socket: true,
    })
}

#[allow(clippy::too_many_arguments)]
fn refusal(
    offset_secs: i64,
    site: RefusalSite,
    layer: RefusalLayer,
    protocol: Protocol,
    ip: &str,
    port: Option<u16>,
    name: Option<&str>,
    source: NameSource,
    revision: u64,
) -> NetworkLogRecord {
    NetworkLogRecord {
        v: 1,
        t: at(offset_secs),
        s: LogSource::Network,
        event: NetworkLogEvent::Refusal(NetworkRefusal {
            site,
            layer,
            protocol,
            dst_ip: ip.parse().ok(),
            dst_port: port,
            name: name.map(str::to_owned),
            name_source: source,
            revision,
        }),
    }
}

fn suppressed(offset_secs: i64, count: u64) -> NetworkLogRecord {
    NetworkLogRecord {
        v: 1,
        t: at(offset_secs),
        s: LogSource::Network,
        event: NetworkLogEvent::Suppressed(NetworkSuppressed {
            site: RefusalSite::Udp,
            count,
        }),
    }
}

/// §5's eight records, in order.
fn toy_records() -> Vec<NetworkLogRecord> {
    vec![
        // 1: tcp-syn tenant tcp 203.0.113.10:443, api.example.com (dns-cache)
        refusal(
            1,
            RefusalSite::TcpSyn,
            RefusalLayer::Tenant,
            Protocol::Tcp,
            "203.0.113.10",
            Some(443),
            Some("api.example.com"),
            NameSource::DnsCache,
            2,
        ),
        // 2: the same destination, one second later.
        refusal(
            2,
            RefusalSite::TcpSyn,
            RefusalLayer::Tenant,
            Protocol::Tcp,
            "203.0.113.10",
            Some(443),
            Some("api.example.com"),
            NameSource::DnsCache,
            2,
        ),
        // 3: dns-query tenant udp 100.96.0.1:53, blocked.example
        refusal(
            3,
            RefusalSite::DnsQuery,
            RefusalLayer::Tenant,
            Protocol::Udp,
            "100.96.0.1",
            Some(53),
            Some("blocked.example"),
            NameSource::DnsQuery,
            2,
        ),
        // 4: tls-sni tcp 198.51.100.7:443, cdn.example (sni)
        refusal(
            4,
            RefusalSite::TlsSni,
            RefusalLayer::Tenant,
            Protocol::Tcp,
            "198.51.100.7",
            Some(443),
            Some("cdn.example"),
            NameSource::Sni,
            2,
        ),
        // 5: the same *name* in another case, from another address.
        refusal(
            5,
            RefusalSite::TlsSni,
            RefusalLayer::Tenant,
            Protocol::Tcp,
            "198.51.100.8",
            Some(443),
            Some("CDN.example"),
            NameSource::Sni,
            2,
        ),
        // 6: icmp platform 10.0.0.7 — the platform floor, not a denial.
        refusal(
            6,
            RefusalSite::Icmp,
            RefusalLayer::Platform,
            Protocol::Icmpv4,
            "10.0.0.7",
            None,
            None,
            NameSource::Absent,
            1,
        ),
        // 7: one suppressed report, never an entry.
        suppressed(7, 4744),
        // 8: udp tenant 203.0.113.10:443 — E1's address and port, another protocol.
        refusal(
            8,
            RefusalSite::Udp,
            RefusalLayer::Tenant,
            Protocol::Udp,
            "203.0.113.10",
            Some(443),
            None,
            NameSource::Absent,
            2,
        ),
    ]
}

fn ingest_all(session: &mut SessionRefusals, records: &[NetworkLogRecord]) -> Vec<Update> {
    records
        .iter()
        .filter_map(|record| session.ingest(record))
        .collect()
}

#[test]
fn toy_records_coalesce_into_the_documented_entries() {
    let mut session = session();
    let updates = ingest_all(&mut session, &toy_records());
    // Eight records, eight changes: every one of them moved something.
    assert_eq!(updates.len(), 8);
    let snapshot = session.snapshot();
    assert_eq!(
        snapshot
            .entries
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>(),
        [E1, E2, E3, E4, E5]
    );

    let by_id = |id: &str| {
        snapshot
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("{id} is an entry"))
    };

    // E1: address-shaped, coalesced twice, last seen at its second record.
    let e1 = by_id(E1);
    assert_eq!(e1.count, 2);
    assert_eq!(e1.first_ms, BASE_MS + 1000);
    assert_eq!(e1.last_ms, BASE_MS + 2000);
    assert_eq!(
        e1.key.destination,
        Destination::Address {
            protocol: "tcp".into(),
            ip: Some("203.0.113.10".parse().unwrap()),
            port: Some(443),
        }
    );
    // The DNS-cache name is evidence, not a destination.
    assert_eq!(e1.name.as_ref().unwrap().name, "api.example.com");
    assert_eq!(e1.name.as_ref().unwrap().source, "dns-cache");
    assert_eq!(e1.key.kind, Kind::NetworkDenial);

    // E2: the name the guest asked for is the destination.
    let e2 = by_id(E2);
    assert_eq!(
        e2.key.destination,
        Destination::DnsName {
            name: "blocked.example".into()
        }
    );
    assert_eq!(e2.name.as_ref().unwrap().source, "dns-query");

    // E3: two spellings of one name, from two addresses; the address is evidence.
    let e3 = by_id(E3);
    assert_eq!(
        e3.key.destination,
        Destination::Host {
            protocol: "tcp".into(),
            name: "cdn.example".into(),
            port: Some(443),
        }
    );
    assert_eq!(e3.count, 2);
    assert_eq!(e3.last_ip, Some("198.51.100.8".parse().unwrap()));
    // The first spelling is what the entry was created with; a later record's
    // case does not rewrite the name a reader may already have copied.
    assert_eq!(e3.name.as_ref().unwrap().name, "cdn.example");

    // E4: the platform layer is a policy lock whatever the site says.
    let e4 = by_id(E4);
    assert_eq!(e4.key.kind, Kind::PolicyLock);
    assert_eq!(e4.reason(), "can't be allowed: platform policy");

    // E5: E1's address and port but another protocol is another destination.
    let e5 = by_id(E5);
    assert_ne!(e5.id, E1);
    assert_eq!(e5.key.kind, Kind::NetworkDenial);

    // The suppressed report is a session counter, never an entry.
    assert_eq!(snapshot.suppressed, 4744);
    assert_eq!(snapshot.entries.len(), 5);
    assert_eq!(snapshot.lost, 0);
    assert!(!snapshot.gap);
    // Every record bumped the revision.
    assert_eq!(snapshot.rev, 8);
}

#[test]
fn key_bytes_and_id_golden_vectors() {
    let cases: [(&str, EntryKey); 3] = [
        (
            "network-denial\naddress\ntcp\n203.0.113.10\n443\n",
            EntryKey {
                kind: Kind::NetworkDenial,
                destination: Destination::Address {
                    protocol: "tcp".into(),
                    ip: Some("203.0.113.10".parse().unwrap()),
                    port: Some(443),
                },
            },
        ),
        (
            "network-denial\nhost\ntcp\n\n443\ncdn.example",
            EntryKey {
                kind: Kind::NetworkDenial,
                destination: Destination::Host {
                    protocol: "tcp".into(),
                    name: "cdn.example".into(),
                    port: Some(443),
                },
            },
        ),
        (
            "network-denial\ndns-name\n\n\n\nblocked.example",
            EntryKey {
                kind: Kind::NetworkDenial,
                destination: Destination::DnsName {
                    name: "blocked.example".into(),
                },
            },
        ),
    ];
    for (expected, key) in cases {
        assert_eq!(String::from_utf8(key_bytes(&key)).unwrap(), expected);
        // An absent field is the empty string, so the field count is constant.
        assert_eq!(expected.split('\n').count(), 6);
        assert_eq!(refusal_id(SID, &key, 0).len(), 8);
        // `n` is part of the derivation, so a collision has a second answer.
        assert_ne!(refusal_id(SID, &key, 0), refusal_id(SID, &key, 1));
        // The session is, too: the same destination in two sessions differs.
        assert_ne!(refusal_id(SID, &key, 0), refusal_id("00000000", &key, 0));
    }
    // The five toy entries, as published in §5.
    let mut session = session();
    ingest_all(&mut session, &toy_records());
    let ids: Vec<String> = session
        .snapshot()
        .entries
        .iter()
        .map(|entry| entry.id.clone())
        .collect();
    assert_eq!(ids, [E1, E2, E3, E4, E5]);
}

#[test]
fn ids_are_assigned_once_and_unique_within_a_session() {
    let mut session = session();
    let mut record = toy_records().remove(0);
    // The same destination twice: one entry, one ID, two counts.
    session.ingest(&record);
    let first = session.snapshot().entries[0].id.clone();
    session.ingest(&record);
    assert_eq!(session.snapshot().entries.len(), 1);
    assert_eq!(session.snapshot().entries[0].id, first);
    assert_eq!(session.snapshot().entries[0].count, 2);

    // Every entry the toy run keeps has an ID nothing else in it uses.
    let mut all = self::session();
    ingest_all(&mut all, &toy_records());
    let ids: Vec<String> = all.snapshot().ids().map(str::to_owned).collect();
    let unique: std::collections::BTreeSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len());

    // A later destination gets an ID of its own, and the entries before it keep
    // theirs: an ID is assigned once and never recomputed.
    record = toy_records().remove(2);
    let before = all.snapshot().rev;
    all.ingest(&record);
    assert!(all.snapshot().rev > before);
    let after: Vec<String> = all.snapshot().ids().map(str::to_owned).collect();
    assert_eq!(&after[..ids.len()], ids.as_slice());
    assert_eq!(
        ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        ids.len()
    );
}

#[test]
fn names_coalesce_case_insensitively() {
    let mut session = session();
    for (offset, name) in [(1, "CDN.example"), (2, "cdn.EXAMPLE"), (3, "cdn.example")] {
        session.ingest(&refusal(
            offset,
            RefusalSite::TlsSni,
            RefusalLayer::Tenant,
            Protocol::Tcp,
            "198.51.100.7",
            Some(443),
            Some(name),
            NameSource::Sni,
            1,
        ));
    }
    let snapshot = session.snapshot();
    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.entries[0].count, 3);
    // The key is the lowercased name; the displayed name is what arrived first.
    assert_eq!(
        snapshot.entries[0].key.destination,
        Destination::Host {
            protocol: "tcp".into(),
            name: "cdn.example".into(),
            port: Some(443),
        }
    );
    assert_eq!(
        snapshot.entries[0].name.as_ref().unwrap().name,
        "CDN.example"
    );
}

#[test]
fn suppressed_adds_to_the_session_never_an_entry() {
    let mut session = session();
    let update = session.ingest(&suppressed(1, 10)).expect("a change");
    assert_eq!(update.suppressed, 10);
    assert!(update.entry.is_none());
    let update = session.ingest(&suppressed(2, 5)).expect("a change");
    assert_eq!(update.suppressed, 15);
    assert!(session.snapshot().entries.is_empty());
}

#[test]
fn a_new_destination_past_512_is_counted_lost() {
    let mut session = session();
    for host in 0..(MAX_ENTRIES_PER_SESSION as u16 + 3) {
        session.ingest(&refusal(
            1,
            RefusalSite::TcpSyn,
            RefusalLayer::Tenant,
            Protocol::Tcp,
            &format!("10.0.0.{}", host / 256 + 1),
            Some(host + 1),
            None,
            NameSource::Absent,
            1,
        ));
    }
    let snapshot = session.snapshot();
    assert_eq!(snapshot.entries.len(), MAX_ENTRIES_PER_SESSION);
    assert_eq!(snapshot.lost, 3);
    // A destination that is already kept still coalesces past the cap: the
    // budget is on distinct destinations, not on records.
    let update = session
        .ingest(&refusal(
            2,
            RefusalSite::TcpSyn,
            RefusalLayer::Tenant,
            Protocol::Tcp,
            "10.0.0.1",
            Some(1),
            None,
            NameSource::Absent,
            1,
        ))
        .expect("a change");
    assert_eq!(update.lost, 3);
    assert!(update.entry.is_some());
}

#[test]
fn counters_saturate() {
    let mut session = session();
    let mut update = session.ingest(&suppressed(1, u64::MAX)).unwrap();
    assert_eq!(update.suppressed, u64::MAX);
    update = session.ingest(&suppressed(2, 1)).unwrap();
    assert_eq!(update.suppressed, u64::MAX);
    let snapshot = session.snapshot();
    assert_eq!(snapshot.rev, 2);
}

#[test]
fn every_refusal_site_has_a_kind() {
    // `RefusalSite::ALL` is exhaustive by construction (its `index` match has no
    // wildcard), so iterating it covers every site this build can name.
    for site in RefusalSite::ALL {
        let kind = classify(site, RefusalLayer::Tenant);
        assert!(
            [
                Kind::NetworkDenial,
                Kind::PolicyLock,
                Kind::CredentialRefusal
            ]
            .contains(&kind),
            "{site:?}"
        );
        // The platform floor outranks any site.
        assert_eq!(classify(site, RefusalLayer::Platform), Kind::PolicyLock);
    }
    // The documented split, site by site.
    for site in [
        RefusalSite::TcpSyn,
        RefusalSite::TcpHostname,
        RefusalSite::TlsSni,
        RefusalSite::Udp,
        RefusalSite::Icmp,
        RefusalSite::DnsQuery,
        RefusalSite::DnsResolver,
        RefusalSite::HttpAuthority,
    ] {
        assert_eq!(classify(site, RefusalLayer::Tenant), Kind::NetworkDenial);
    }
    assert_eq!(
        classify(RefusalSite::SecretViolation, RefusalLayer::Tenant),
        Kind::CredentialRefusal
    );
    for site in [
        RefusalSite::UdpQuic,
        RefusalSite::TcpDot,
        RefusalSite::DnsRebind,
    ] {
        assert_eq!(classify(site, RefusalLayer::Tenant), Kind::PolicyLock);
    }
}

#[test]
fn platform_layer_is_always_a_policy_lock() {
    let mut session = session();
    session.ingest(&refusal(
        1,
        RefusalSite::TcpSyn,
        RefusalLayer::Platform,
        Protocol::Tcp,
        "203.0.113.10",
        Some(443),
        None,
        NameSource::Absent,
        1,
    ));
    let entry = &session.snapshot().entries[0];
    assert_eq!(entry.key.kind, Kind::PolicyLock);
    assert_eq!(entry.layer, "platform");
    assert_eq!(entry.reason(), "can't be allowed: platform policy");
}

#[test]
fn the_reason_column_names_the_lock_that_holds() {
    let mut session = session();
    ingest_all(&mut session, &toy_records());
    let reasons: Vec<String> = session
        .snapshot()
        .entries
        .iter()
        .map(RefusalEntry::reason)
        .collect();
    assert_eq!(
        reasons[0],
        "no grant in this version; relaunch with --allow-egress"
    );
    assert_eq!(reasons[3], "can't be allowed: platform policy");

    // A tenant-layer built-in rule names itself, because "no grant" would be a
    // promise this version cannot keep.
    let mut locked = self::session();
    locked.ingest(&refusal(
        1,
        RefusalSite::UdpQuic,
        RefusalLayer::Tenant,
        Protocol::Udp,
        "203.0.113.10",
        Some(443),
        None,
        NameSource::Absent,
        1,
    ));
    assert_eq!(
        locked.snapshot().entries[0].reason(),
        "can't be allowed: built-in rule udp-quic"
    );
}

#[test]
fn records_before_the_session_started_are_ignored() {
    let mut session = session();
    let mut record = toy_records().remove(0);
    record.t = At::from_timestamp_millis(BASE_MS - 1).unwrap();
    assert!(session.ingest(&record).is_none());
    assert!(session.snapshot().entries.is_empty());
    assert_eq!(session.snapshot().rev, 0);
}

#[test]
fn an_overlong_name_is_truncated_and_says_so() {
    let long = "a".repeat(MAX_NAME_BYTES + 10);
    let mut session = session();
    session.ingest(&refusal(
        1,
        RefusalSite::TlsSni,
        RefusalLayer::Tenant,
        Protocol::Tcp,
        "198.51.100.7",
        Some(443),
        Some(&long),
        NameSource::Sni,
        1,
    ));
    let name = session.snapshot().entries[0].name.clone().unwrap();
    assert_eq!(name.name.len(), MAX_NAME_BYTES);
    assert!(name.truncated);
}

#[test]
fn a_mark_gap_is_one_change_and_never_an_entry() {
    let mut session = session();
    let update = session.mark_gap().expect("the first gap is a change");
    assert!(update.gap);
    assert!(update.entry.is_none());
    assert!(session.mark_gap().is_none());
    assert_eq!(session.snapshot().rev, 1);
    assert!(session.snapshot().entries.is_empty());
}

#[test]
fn an_entry_serializes_within_two_kibibytes() {
    let mut session = session();
    session.ingest(&refusal(
        1,
        RefusalSite::TlsSni,
        RefusalLayer::Tenant,
        Protocol::Tcp,
        "2001:db8::1",
        Some(65535),
        Some(&"z".repeat(MAX_NAME_BYTES)),
        NameSource::HttpHost,
        u64::MAX,
    ));
    let entry = &session.snapshot().entries[0];
    let encoded = serde_json::to_vec(entry).unwrap();
    assert!(encoded.len() <= 2048, "{} bytes", encoded.len());
}

#[test]
fn a_snapshot_round_trips_through_the_wire_and_back_in() {
    let mut session = session();
    ingest_all(&mut session, &toy_records());
    let snapshot = session.snapshot();
    let encoded = serde_json::to_vec(&snapshot).unwrap();
    let decoded: SessionSnapshot = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, snapshot);
    // Resuming from it rebuilds the index, so the next record coalesces.
    let mut resumed = SessionRefusals::resume(decoded);
    let before = resumed.snapshot().entries.len();
    assert!(resumed.ingest(&toy_records()[0]).is_some());
    assert_eq!(resumed.snapshot().entries.len(), before);
    assert_eq!(resumed.snapshot().entries[0].count, 3);
}

#[test]
fn session_ids_are_eight_lowercase_hex_and_parse_strictly() {
    for _ in 0..64 {
        let id = SessionId::generate();
        assert_eq!(id.as_str().len(), 8);
        assert!(id.as_str().bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(id.as_str(), id.as_str().to_lowercase());
        assert_eq!(SessionId::parse(id.as_str()), Some(id));
    }
    for rejected in ["", "1234567", "123456789", "3F9A12C4", "3f9a12cg", "../x"] {
        assert_eq!(SessionId::parse(rejected), None, "{rejected}");
    }
    // The strictness survives a round trip through a document: a value read from
    // a log is validated on the way in, because `access` prints it.
    let id = SessionId::generate();
    let round_tripped: SessionId =
        serde_json::from_str(&serde_json::to_string(&id).unwrap()).unwrap();
    assert_eq!(round_tripped, id);
    for rejected in ["\"3F9A12C4\"", "\"3f9a12cg\"", "\"\\u001b[31mabcdef0\""] {
        assert!(
            serde_json::from_str::<SessionId>(rejected).is_err(),
            "{rejected} decoded"
        );
    }
}

proptest::proptest! {
    /// The count and the last-seen of an entry are properties of the *set* of
    /// records, not of the order they were read in: a re-read after a rotation
    /// must land on the same totals.
    #[test]
    fn entry_counts_are_independent_of_record_order(
        ports in proptest::collection::vec(1u16..8, 1..12),
        reverse in proptest::bool::ANY,
    ) {
        let records: Vec<NetworkLogRecord> = ports
            .iter()
            .enumerate()
            .map(|(index, port)| refusal(
                index as i64 + 1,
                RefusalSite::TcpSyn,
                RefusalLayer::Tenant,
                Protocol::Tcp,
                "203.0.113.10",
                Some(*port),
                None,
                NameSource::Absent,
                1,
            ))
            .collect();
        let mut forward = session();
        ingest_all(&mut forward, &records);
        let mut ordered: Vec<NetworkLogRecord> = records.clone();
        if reverse {
            ordered.reverse();
        }
        let mut backward = session();
        ingest_all(&mut backward, &ordered);
        let summarize = |session: &SessionRefusals| {
            let mut rows: Vec<(String, u64)> = session
                .snapshot()
                .entries
                .iter()
                .map(|entry| (format!("{:?}", entry.key), entry.count))
                .collect();
            rows.sort();
            rows
        };
        proptest::prop_assert_eq!(summarize(&forward), summarize(&backward));
        proptest::prop_assert_eq!(
            forward.snapshot().entries.len(),
            backward.snapshot().entries.len()
        );
        let total: u64 = forward.snapshot().entries.iter().map(|e| e.count).sum();
        proptest::prop_assert_eq!(total, records.len() as u64);
    }
}
