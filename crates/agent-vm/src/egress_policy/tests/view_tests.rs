//! View tests for `effective_rows` / `live_rows` / `dns_authorization`, a
//! submodule of `egress_policy::tests` so the shared helpers (`resolve_saved`,
//! `resolve_saved_with_tools`, `empty_cli`, `reference_tools`, `authority`,
//! `grants`, `REFERENCE_USER_FILE`, `RECORD_FILE`) are in scope.

use super::*;

// -- #631: the effective-egress rows ------------------------------------

use crate::effective_egress::{EgressRow, LiveEntry, LiveScope, RowDestination, RowStatus};

/// One row, spelled the way the table prints it.
fn cells_of(row: &EgressRow) -> (String, String, String, String, String) {
    (
        row.destination.cell(),
        row.ports.cell(),
        row.via.clone().unwrap_or_else(|| "-".to_owned()),
        row.source.cell().to_owned(),
        row.status.cell(),
    )
}

fn table_of(rows: &[EgressRow]) -> Vec<(String, String, String, String, String)> {
    rows.iter().map(cells_of).collect()
}

fn live_entry(text: &str, scope: LiveScope, status: RowStatus) -> LiveEntry {
    LiveEntry {
        allowance: Allowance::parse(text).unwrap(),
        scope,
        status,
    }
}

/// AC1: the ticket's own table, in its own order, with its own cells.
#[test]
fn effective_rows_match_the_ticket_table() {
    let namespace = crate::egress_reference::test_support::user_namespace(
        std::path::Path::new(REFERENCE_USER_FILE),
        &[],
        Some(
            "anthropic = [\"api.anthropic.com\", \"platform.claude.com\"]\n\
             rust = [\"crates.io\"]\n",
        ),
    );
    let authority = resolve_saved_with_tools(
        Default::default(),
        &["set:anthropic", "set:rust", "api.github.com"],
        CliEgress {
            internet: Some(true),
            ..empty_cli()
        },
        &namespace,
    );
    let live = [live_entry(
        "tcp://[203.0.113.10/32]:443",
        LiveScope::Session,
        RowStatus::AppliedAt { revision: 2 },
    )];
    // As the launcher does: the recorded tier is exactly the live entries.
    let mut authority = authority;
    authority.set_recorded(
        std::path::Path::new(RECORD_FILE),
        vec![Allowance::parse("tcp://[203.0.113.10/32]:443").unwrap()],
    );
    let rows = authority.effective_rows(&live, RowStatus::Applied);
    let cell = |destination: &str, ports: &str, via: &str, source: &str, status: &str| {
        (
            destination.to_owned(),
            ports.to_owned(),
            via.to_owned(),
            source.to_owned(),
            status.to_owned(),
        )
    };
    assert_eq!(
        table_of(&rows),
        vec![
            cell(
                "api.anthropic.com",
                "443",
                "set:anthropic",
                "persisted grant",
                "applied"
            ),
            cell(
                "platform.claude.com",
                "443",
                "set:anthropic",
                "persisted grant",
                "applied"
            ),
            cell("crates.io", "443", "set:rust", "persisted grant", "applied"),
            cell("api.github.com", "443", "-", "persisted grant", "applied"),
            cell(
                "203.0.113.10/32",
                "tcp:443",
                "-",
                "session allowance",
                "applied (rev 2)"
            ),
            cell(
                "internet (public)",
                "all",
                "-",
                "--allow-internet-egress",
                "applied"
            ),
        ]
    );
    assert_eq!(
        authority.dns_authorization(),
        crate::effective_egress::DnsAuthorization::AnyName {
            via: vec!["--allow-internet-egress".to_owned()],
        }
    );
}

/// A row's PORTS are its own grants' ports, never the domain's merged rule.
#[test]
fn a_rows_ports_are_its_own_grants() {
    let authority = resolve_saved(
        Default::default(),
        &["a.example"],
        CliEgress {
            allowances: &["tcp://a.example:8443".into()],
            ..empty_cli()
        },
    );
    assert_eq!(
        table_of(&authority.effective_rows(&[], RowStatus::Applied)),
        vec![
            (
                "a.example".to_owned(),
                "443, 8443".to_owned(),
                "-".to_owned(),
                "persisted grant".to_owned(),
                "applied".to_owned()
            ),
            (
                "a.example".to_owned(),
                "8443".to_owned(),
                "-".to_owned(),
                "--allow-egress".to_owned(),
                "applied".to_owned()
            ),
        ]
    );
    // A reference row lists only what its own expansion grants.
    let tools = reference_tools(&[("x", &["a.example:8443"])]);
    let authority = resolve_saved_with_tools(
        Default::default(),
        &["a.example"],
        CliEgress {
            allowances: &["tool:x".into()],
            ..empty_cli()
        },
        &tools,
    );
    // Reference rows come before bare ones, whatever tier granted them.
    assert_eq!(
        table_of(&authority.effective_rows(&[], RowStatus::Applied)),
        vec![
            (
                "a.example".to_owned(),
                "8443".to_owned(),
                "tool:x".to_owned(),
                "--allow-egress".to_owned(),
                "applied".to_owned()
            ),
            (
                "a.example".to_owned(),
                "443, 8443".to_owned(),
                "-".to_owned(),
                "persisted grant".to_owned(),
                "applied".to_owned()
            ),
        ]
    );
}

/// Review finding 2: live rows group by (scope, state), never picking a
/// "first" entry, and merge only within a group.
#[test]
fn live_rows_split_by_confirmation_state() {
    let authority = resolve_saved(Default::default(), &["tcp://a.example:443"], empty_cli());
    let live = [
        live_entry(
            "tcp://a.example:443",
            LiveScope::Session,
            RowStatus::AppliedAt { revision: 2 },
        ),
        live_entry(
            "tcp://a.example:8443",
            LiveScope::Session,
            RowStatus::AppliedAt { revision: 3 },
        ),
    ];
    assert_eq!(
        table_of(&authority.live_rows(&live)),
        vec![
            (
                "a.example".to_owned(),
                "443".to_owned(),
                "-".to_owned(),
                "session allowance".to_owned(),
                "applied (rev 2)".to_owned()
            ),
            (
                "a.example".to_owned(),
                "8443".to_owned(),
                "-".to_owned(),
                "session allowance".to_owned(),
                "applied (rev 3)".to_owned()
            ),
        ]
    );
    // One project entry applied at boot and one queued: two rows.
    let live = [
        live_entry(
            "tcp://b.example:443",
            LiveScope::Project,
            RowStatus::Applied,
        ),
        live_entry(
            "tcp://b.example:8443",
            LiveScope::Project,
            RowStatus::Queued,
        ),
    ];
    let authority = resolve_saved(
        Default::default(),
        &["tcp://b.example:443", "tcp://b.example:8443"],
        empty_cli(),
    );
    assert_eq!(
        table_of(&authority.live_rows(&live)),
        vec![
            (
                "b.example".to_owned(),
                "443".to_owned(),
                "-".to_owned(),
                "project allowance".to_owned(),
                "applied".to_owned()
            ),
            (
                "b.example".to_owned(),
                "8443".to_owned(),
                "-".to_owned(),
                "project allowance".to_owned(),
                "queued".to_owned()
            ),
        ]
    );
    // Two entries sharing scope and state are one row with the port union.
    let live = [
        live_entry(
            "tcp://c.example:443",
            LiveScope::Session,
            RowStatus::Applied,
        ),
        live_entry(
            "tcp://c.example:8443",
            LiveScope::Session,
            RowStatus::Applied,
        ),
    ];
    let authority = resolve_saved(
        Default::default(),
        &["tcp://c.example:443", "tcp://c.example:8443"],
        empty_cli(),
    );
    assert_eq!(
        table_of(&authority.live_rows(&live)),
        vec![(
            "c.example".to_owned(),
            "443, 8443".to_owned(),
            "-".to_owned(),
            "session allowance".to_owned(),
            "applied".to_owned()
        )]
    );
}

/// AC1's structural claim: the table and the launch's own notices attribute
/// every hostname to the same tier and reference.
#[test]
fn rows_and_notice_agree_on_every_source() {
    let namespace = crate::egress_reference::test_support::user_namespace(
        std::path::Path::new(REFERENCE_USER_FILE),
        &[
            ("codex", &["api.openai.com"]),
            ("fetcher", &["git.example:8443"]),
        ],
        Some("agents = [\"tool:codex\"]\n"),
    );
    let mut authority = resolve_saved_with_tools(
        Default::default(),
        &["tool:codex", "api.github.com", "set:agents"],
        CliEgress {
            allowances: &["tool:fetcher".into(), "cli.example".into()],
            ..empty_cli()
        },
        &namespace,
    );
    authority.set_recorded(
        std::path::Path::new(RECORD_FILE),
        vec![Allowance::parse("recorded.example").unwrap()],
    );

    // As the launcher does: the recorded tier is exactly the live entries.
    let live = [live_entry(
        "recorded.example",
        LiveScope::Project,
        RowStatus::Applied,
    )];
    type Key = (String, Option<String>, &'static str);
    let from_rows: std::collections::BTreeSet<Key> = authority
        .effective_rows(&live, RowStatus::Applied)
        .iter()
        .filter_map(|row| {
            let RowDestination::Hostname { name } = &row.destination else {
                return None;
            };
            let tier = match row.source {
                crate::effective_egress::RowSource::PersistedGrant => "user",
                crate::effective_egress::RowSource::AllowEgress => "cli",
                // A recorded name is its own tier and names no reference.
                _ => return None,
            };
            Some((name.clone(), row.via.clone(), tier))
        })
        .collect();
    let mut from_notice: std::collections::BTreeSet<Key> = std::collections::BTreeSet::new();
    for attribution in authority.hostname_attributions() {
        for (tier, origin) in [("user", &attribution.user), ("cli", &attribution.cli)] {
            for reference in &origin.via {
                from_notice.insert((
                    attribution.name.as_str().to_owned(),
                    Some(reference.to_string()),
                    tier,
                ));
            }
            if origin.direct {
                from_notice.insert((attribution.name.as_str().to_owned(), None, tier));
            }
        }
    }
    assert_eq!(from_rows, from_notice);
}

#[test]
fn a_destination_granted_twice_has_two_rows() {
    let authority = resolve_saved(Default::default(), &["api.example.com"], empty_cli());
    let live = [live_entry(
        "tcp://api.example.com:443",
        LiveScope::Session,
        RowStatus::AppliedAt { revision: 2 },
    )];
    assert_eq!(
        table_of(&authority.effective_rows(&live, RowStatus::Applied)),
        vec![
            (
                "api.example.com".to_owned(),
                "443".to_owned(),
                "-".to_owned(),
                "persisted grant".to_owned(),
                "applied".to_owned()
            ),
            (
                "api.example.com".to_owned(),
                "443".to_owned(),
                "-".to_owned(),
                "session allowance".to_owned(),
                "applied (rev 2)".to_owned()
            ),
        ]
    );
}

#[test]
fn groups_rows_follow_their_origin() {
    let flag = resolve_saved(
        Default::default(),
        &[],
        CliEgress {
            internet: Some(true),
            host: Some(true),
            ..empty_cli()
        },
    );
    assert_eq!(
        table_of(&flag.effective_rows(&[], RowStatus::Applied)),
        vec![
            (
                "internet (public)".to_owned(),
                "all".to_owned(),
                "-".to_owned(),
                "--allow-internet-egress".to_owned(),
                "applied".to_owned()
            ),
            (
                "host (loopback)".to_owned(),
                "all".to_owned(),
                "-".to_owned(),
                "--allow-host".to_owned(),
                "applied".to_owned()
            ),
        ]
    );
    let persisted = resolve_saved(
        crate::user_network::SavedGroups {
            lan: Some(true),
            ..Default::default()
        },
        &[],
        empty_cli(),
    );
    assert_eq!(
        table_of(&persisted.effective_rows(&[], RowStatus::Applied)),
        vec![(
            "lan (private)".to_owned(),
            "all".to_owned(),
            "-".to_owned(),
            "persisted grant".to_owned(),
            "applied".to_owned()
        )]
    );
    // The launch's own --allow-* says the flag, even with a user table.
    let override_flag = resolve_saved(
        crate::user_network::SavedGroups {
            internet: Some(true),
            ..Default::default()
        },
        &[],
        CliEgress {
            internet: Some(true),
            ..empty_cli()
        },
    );
    assert_eq!(
        table_of(&override_flag.effective_rows(&[], RowStatus::Applied)),
        vec![(
            "internet (public)".to_owned(),
            "all".to_owned(),
            "-".to_owned(),
            "--allow-internet-egress".to_owned(),
            "applied".to_owned()
        )]
    );
    // A disabled group gets no row at all.
    let disabled = resolve_saved(
        crate::user_network::SavedGroups {
            internet: Some(false),
            ..Default::default()
        },
        &[],
        empty_cli(),
    );
    assert!(disabled.effective_rows(&[], RowStatus::Applied).is_empty());
}

#[test]
fn address_ports_cells() {
    let authority = resolve_saved(
        Default::default(),
        &[],
        CliEgress {
            allowances: &[
                "10.0.0.1".into(),
                "tcp://10.0.0.2".into(),
                "10.0.0.3:443".into(),
                "udp://10.0.0.4:53".into(),
            ],
            ..empty_cli()
        },
    );
    let ports: Vec<String> = authority
        .effective_rows(&[], RowStatus::Applied)
        .iter()
        .map(|row| row.ports.cell())
        .collect();
    assert_eq!(ports, vec!["all", "tcp:all", "tcp/udp:443", "udp:53"]);
}

/// The DNS line and the launch's DNS notice reach the same decision.
#[test]
fn dns_authorization_matches_the_notice() {
    use crate::effective_egress::DnsAuthorization;
    for bits in 0..8u8 {
        for entries in [&[][..], &["api.example.com"][..]] {
            let authority = authority(grants(bits), entries);
            let mut out = Vec::new();
            authority.write_notices(&mut out).unwrap();
            let text = String::from_utf8(out).unwrap();
            assert_eq!(
                matches!(
                    authority.dns_authorization(),
                    DnsAuthorization::AnyName { .. }
                ),
                text.contains("arbitrary-name DNS queries authorized"),
                "{bits} {entries:?}: {text}"
            );
        }
        for user in [None, Some(true)] {
            let saved = crate::user_network::SavedGroups {
                internet: user,
                lan: None,
                host: user,
            };
            let authority = resolve_saved(saved, &["api.example.com"], empty_cli());
            let mut out = Vec::new();
            authority.write_notices(&mut out).unwrap();
            let text = String::from_utf8(out).unwrap();
            assert_eq!(
                matches!(
                    authority.dns_authorization(),
                    DnsAuthorization::AnyName { .. }
                ),
                text.contains("arbitrary-name DNS queries authorized"),
                "{bits} {user:?}: {text}"
            );
        }
    }
    // A hostname-only launch authorizes exactly the allowed names…
    assert_eq!(
        resolve_saved(Default::default(), &["api.example.com"], empty_cli()).dns_authorization(),
        DnsAuthorization::AllowedHostnamesOnly
    );
    // …and nothing at all is denied.
    assert_eq!(
        resolve_saved(Default::default(), &[], empty_cli()).dns_authorization(),
        DnsAuthorization::Denied
    );
}

#[test]
fn nothing_allowed_has_no_rows() {
    let authority = resolve_saved(Default::default(), &[], empty_cli());
    assert!(authority.effective_rows(&[], RowStatus::Applied).is_empty());
    assert!(authority.live_rows(&[]).is_empty());
}
