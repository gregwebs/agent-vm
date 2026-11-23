//! Attribution of this launch's effective destinations: which tier granted
//! what, and how. The launch notice and `agent-vm access egress` both derive
//! from `ResolvedAllowances::hostname_grants` — the table from each grant, the
//! notice from their union — so their sources cannot disagree (#631 AC1).

use std::collections::BTreeSet;

use crate::egress_hostname::InterceptedPorts;
use crate::egress_reference::{EgressReference, EntryOrigin, ResolvedAllowances};
use microsandbox_network::policy::{Destination, DomainName};

use super::{Allowance, EgressAllowance, EgressAuthority, GrantSource, Transport};
use crate::effective_egress::{
    DnsAuthorization, EgressGroup, EgressRow, LiveEntry, LiveScope, RowDestination, RowPorts,
    RowSource, RowStatus, WireTransport,
};

/// One hostname rule and how each tier reached it: `hostname_origin`, the union
/// of that tier's grants for the name.
#[derive(Debug)]
pub(super) struct HostnameAttribution<'a> {
    pub(super) name: DomainName,
    /// The rule's merged ports, exactly as `domain_rules` emits them.
    pub(super) ports: Vec<u16>,
    pub(super) user: EntryOrigin<'a>,
    pub(super) cli: EntryOrigin<'a>,
    /// The project record (recorded tier) names this domain.
    pub(super) recorded: bool,
    /// The launched authorized tool whose own `network_requests` name this
    /// domain (#735), if any.
    pub(super) tool: Option<&'a str>,
}

/// The position of `reference` in the user's written order; a reference the
/// order does not hold is a bug, so it sorts last in release.
pub(super) fn written_index(order: &[&EgressReference], reference: &EgressReference) -> usize {
    order
        .iter()
        .position(|candidate| *candidate == reference)
        .unwrap_or_else(|| {
            debug_assert!(
                false,
                "every reference a view names is in reference_order()"
            );
            usize::MAX
        })
}

impl EgressAuthority {
    /// Every hostname rule in policy order. Empty when no hostname is in force.
    pub(super) fn hostname_attributions(&self) -> Vec<HostnameAttribution<'_>> {
        // A recorded hostname is matched by its Domain, not by its spelling, so
        // a configured `api.example.com` and a recorded
        // `tcp://api.example.com:8443` share one rule and one tag (ADR-0065 D4).
        let recorded: Option<Vec<DomainName>> = self.recorded_entries().map(|recorded| {
            recorded
                .destinations
                .iter()
                .filter_map(|allowance| match allowance {
                    Allowance::Hostname(hostname) => Some(hostname.domain().clone()),
                    Allowance::Address(_) => None,
                })
                .collect()
        });
        let Some(ports) = self.intercepted_ports() else {
            return Vec::new();
        };
        crate::egress_hostname::domain_rules(&self.effective.hostnames, &ports)
            .into_iter()
            .filter_map(|rule| {
                let Destination::Domain(name) = rule.destination else {
                    return None;
                };
                Some(HostnameAttribution {
                    user: self
                        .provenance
                        .as_ref()
                        .map_or_else(EntryOrigin::default, |p| {
                            p.user_entries.hostname_origin(&name)
                        }),
                    cli: self.cli.hostname_origin(&name),
                    recorded: recorded
                        .as_ref()
                        .is_some_and(|recorded| recorded.contains(&name)),
                    tool: self
                        .tool_grants()
                        .filter(|tool| !tool.ports_for(&name, &ports).is_empty())
                        .map(|tool| tool.name()),
                    ports: rule.ports.iter().map(|port| port.start).collect(),
                    name,
                })
            })
            .collect()
    }

    /// Every reference in the order the user wrote it: the user file's in
    /// first-use order, then the CLI's that the file did not already name.
    pub(super) fn reference_order(&self) -> Vec<&EgressReference> {
        let mut order: Vec<&EgressReference> = Vec::new();
        for reference in self
            .provenance
            .iter()
            .flat_map(|p| p.user_entries.references())
            .chain(self.cli.references())
        {
            if !order.contains(&reference) {
                order.push(reference);
            }
        }
        order
    }

    /// The grants that authorize arbitrary-name DNS, in the notice's own words.
    pub(super) fn dns_grant_labels(&self) -> Vec<String> {
        let mut labels = Vec::new();
        for (enabled, origin, setting, flag) in [
            (
                self.groups.internet,
                self.provenance.as_ref().map(|p| p.internet),
                "allow_internet_egress",
                "--allow-internet-egress",
            ),
            (
                self.groups.host,
                self.provenance.as_ref().map(|p| p.host),
                "allow_host",
                "--allow-host",
            ),
        ] {
            if !enabled {
                continue;
            }
            labels.push(match origin {
                Some(origin) if origin.resolved.source == GrantSource::UserConfig => {
                    format!("persisted grant {setting}")
                }
                _ => flag.to_owned(),
            });
        }
        labels
    }

    /// Whether arbitrary-name DNS is authorized, and by what.
    pub(crate) fn dns_authorization(&self) -> DnsAuthorization {
        let labels = self.dns_grant_labels();
        if !labels.is_empty() {
            DnsAuthorization::AnyName { via: labels }
        } else if self.has_hostnames() {
            DnsAuthorization::AllowedHostnamesOnly
        } else {
            DnsAuthorization::Denied
        }
    }

    /// Every attribution of every effective destination, in the #631 row order.
    /// `configured` is the status configured and group rows carry; `live` must be
    /// exactly the live entries this authority's recorded tier holds.
    ///
    /// A launch has no live entries and does not use this view: the launch's
    /// notices say what was asked for, and only [`crate::allowances::LiveAllowances`]
    /// can tell a session allowance from a project one.
    pub(crate) fn effective_rows(
        &self,
        live: &[LiveEntry],
        configured: RowStatus,
    ) -> Vec<EgressRow> {
        let order = self.reference_order();
        let ports = self.intercepted_ports();
        let mut rows = Vec::new();

        // Hostnames: reference rows first, in written order, then bare names in
        // policy order with each name's live rows after its own configured ones.
        let mut referenced: Vec<((usize, usize, Tier), EgressRow)> = Vec::new();
        let mut bare: Vec<EgressRow> = Vec::new();
        if let Some(ports) = &ports {
            for (index, attribution) in self.hostname_attributions().into_iter().enumerate() {
                let mut explained = false;
                for (tier, grants, source) in [
                    (
                        Tier::User,
                        self.provenance.as_ref().map(|p| &p.user_entries),
                        RowSource::PersistedGrant,
                    ),
                    (Tier::Cli, Some(&self.cli), RowSource::AllowEgress),
                ] {
                    let Some(grants) = grants else {
                        continue;
                    };
                    explained |= tier_hostname_rows(
                        &attribution.name,
                        grants,
                        source,
                        index,
                        tier,
                        &order,
                        ports,
                        configured,
                        &mut referenced,
                        &mut bare,
                    );
                }
                // #735: an authorized tool's own requests are its own row, with
                // the tool as the `VIA` cell, so `access egress` explains every
                // effective hostname (the `debug_assert` below).
                if let Some(tool) = attribution.tool
                    && let Some(grants) = self.tool_grants()
                {
                    let tool_ports = grants.ports_for(&attribution.name, ports);
                    if !tool_ports.is_empty() {
                        explained = true;
                        bare.push(EgressRow {
                            destination: RowDestination::Hostname {
                                name: attribution.name.as_str().to_owned(),
                            },
                            ports: RowPorts::Tls { ports: tool_ports },
                            via: Some(tool.to_owned()),
                            source: RowSource::AuthorizedTool,
                            status: configured,
                        });
                    }
                }
                let live_rows = live_hostname_rows(&attribution.name, live, ports);
                explained |= !live_rows.is_empty();
                bare.extend(live_rows);
                debug_assert!(
                    explained,
                    "an effective destination no tier and no live entry explains"
                );
            }
        }
        referenced.sort_by_key(|(key, _)| *key);
        rows.extend(referenced.into_iter().map(|(_, row)| row));
        rows.extend(bare);

        // Addresses: per destination, each tier's direct grant then its
        // references in first-use order, then the live rows.
        for address in &self.effective.addresses {
            let allowance = Allowance::Address(*address);
            let destination = address_destination(address);
            let ports = address_ports(address);
            for (origin, source) in [
                (
                    self.provenance
                        .as_ref()
                        .map_or_else(EntryOrigin::default, |p| {
                            p.user_entries.entry_origin(&allowance)
                        }),
                    RowSource::PersistedGrant,
                ),
                (self.cli.entry_origin(&allowance), RowSource::AllowEgress),
            ] {
                if origin.direct {
                    rows.push(EgressRow {
                        destination: destination.clone(),
                        ports: ports.clone(),
                        via: None,
                        source,
                        status: configured,
                    });
                }
                for reference in origin.via {
                    rows.push(EgressRow {
                        destination: destination.clone(),
                        ports: ports.clone(),
                        via: Some(reference.to_string()),
                        source,
                        status: configured,
                    });
                }
            }
            rows.extend(live_address_rows(&allowance, live));
        }

        // Groups: never granted by a live entry, so this section is configured
        // authority only.
        for (enabled, group, origin, flag) in [
            (
                self.groups.internet,
                EgressGroup::Internet,
                self.provenance.as_ref().map(|p| p.internet),
                RowSource::AllowInternetEgress,
            ),
            (
                self.groups.lan,
                EgressGroup::Lan,
                self.provenance.as_ref().map(|p| p.lan),
                RowSource::AllowLan,
            ),
            (
                self.groups.host,
                EgressGroup::Host,
                self.provenance.as_ref().map(|p| p.host),
                RowSource::AllowHost,
            ),
        ] {
            if !enabled {
                continue;
            }
            rows.push(EgressRow {
                destination: RowDestination::Group { group },
                ports: RowPorts::All,
                via: None,
                source: match origin {
                    Some(origin) if origin.resolved.source == GrantSource::UserConfig => {
                        RowSource::PersistedGrant
                    }
                    _ => flag,
                },
                status: configured,
            });
        }
        rows
    }

    /// Rows for `live` alone — no configured or group rows — with each row's
    /// ports read against this authority's intercepted ports. The launcher uses
    /// it for queued entries, read from the pending plan that contains them.
    pub(crate) fn live_rows(&self, live: &[LiveEntry]) -> Vec<EgressRow> {
        let ports = self.intercepted_ports();
        // A live hostname is always in the plan it is read against, so this is a
        // caller bug rather than an empty answer.
        debug_assert!(
            ports.is_some()
                || live
                    .iter()
                    .all(|entry| matches!(entry.allowance, Allowance::Address(_))),
            "a live hostname is not effective in the plan it is read against"
        );
        let mut rows = Vec::new();
        let mut names: Vec<&DomainName> = Vec::new();
        for name in live.iter().filter_map(|entry| match &entry.allowance {
            Allowance::Hostname(hostname) => Some(hostname.domain()),
            Allowance::Address(_) => None,
        }) {
            if names.contains(&name) {
                continue;
            }
            names.push(name);
            if let Some(ports) = &ports {
                rows.extend(live_hostname_rows(name, live, ports));
            }
        }
        let mut addresses: Vec<&Allowance> = Vec::new();
        for entry in live {
            if matches!(entry.allowance, Allowance::Hostname(_))
                || addresses.contains(&&entry.allowance)
            {
                continue;
            }
            addresses.push(&entry.allowance);
            rows.extend(live_address_rows(&entry.allowance, live));
        }
        rows
    }
}

/// Which tier granted a hostname row. User-file rows sort before CLI rows for
/// the same reference and domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Tier {
    User,
    Cli,
}

/// One tier's rows for one hostname: a row per reference it reached the name
/// through, then a row for a direct grant. Returns whether it explained the
/// hostname at all.
#[allow(clippy::too_many_arguments)]
fn tier_hostname_rows(
    name: &DomainName,
    grants: &ResolvedAllowances,
    source: RowSource,
    domain_index: usize,
    tier: Tier,
    order: &[&EgressReference],
    ports: &InterceptedPorts,
    status: RowStatus,
    referenced: &mut Vec<((usize, usize, Tier), EgressRow)>,
    bare: &mut Vec<EgressRow>,
) -> bool {
    let grants = grants.hostname_grants(name);
    let mut references: Vec<&EgressReference> = Vec::new();
    for (_, origin) in &grants {
        for reference in &origin.via {
            if !references.contains(reference) {
                references.push(reference);
            }
        }
    }
    references.sort_by_key(|reference| written_index(order, reference));
    let explained = !references.is_empty();
    for reference in references {
        let granted: BTreeSet<u16> = grants
            .iter()
            .filter(|(_, origin)| origin.via.contains(&reference))
            .flat_map(|(allowance, _)| allowance.effective_ports(ports))
            .collect();
        referenced.push((
            (written_index(order, reference), domain_index, tier),
            EgressRow {
                destination: RowDestination::Hostname {
                    name: name.as_str().to_owned(),
                },
                ports: RowPorts::Tls {
                    ports: granted.into_iter().collect(),
                },
                via: Some(reference.to_string()),
                source,
                status,
            },
        ));
    }
    let direct: BTreeSet<u16> = grants
        .iter()
        .filter(|(_, origin)| origin.direct)
        .flat_map(|(allowance, _)| allowance.effective_ports(ports))
        .collect();
    let has_direct = !direct.is_empty();
    if has_direct {
        bare.push(EgressRow {
            destination: RowDestination::Hostname {
                name: name.as_str().to_owned(),
            },
            ports: RowPorts::Tls {
                ports: direct.into_iter().collect(),
            },
            via: None,
            source,
            status,
        });
    }
    explained || has_direct
}

/// One scope's confirmation state, the key a live row groups by: two entries in
/// one scope with different states are two rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LiveKey {
    scope: LiveScope,
    status: RowStatus,
}

impl LiveKey {
    /// Session before project; `applied`, then `applied (rev N)` ascending, then
    /// `queued`.
    fn order(self) -> (u8, u8, u64) {
        let scope = match self.scope {
            LiveScope::Session => 0,
            LiveScope::Project => 1,
        };
        let status = match self.status {
            RowStatus::Applied => (0, 0),
            RowStatus::AppliedAt { revision } => (1, revision),
            RowStatus::Queued => (2, 0),
        };
        (scope, status.0, status.1)
    }
}

fn live_hostname_rows(
    name: &DomainName,
    live: &[LiveEntry],
    ports: &InterceptedPorts,
) -> Vec<EgressRow> {
    let mut groups: Vec<(LiveKey, BTreeSet<u16>)> = Vec::new();
    for entry in live {
        let Allowance::Hostname(hostname) = &entry.allowance else {
            continue;
        };
        if hostname.domain() != name {
            continue;
        }
        push_ports(
            &mut groups,
            LiveKey {
                scope: entry.scope,
                status: entry.status,
            },
            hostname.effective_ports(ports),
        );
    }
    groups.sort_by_key(|(key, _)| key.order());
    groups
        .into_iter()
        .map(|(key, granted)| EgressRow {
            destination: RowDestination::Hostname {
                name: name.as_str().to_owned(),
            },
            ports: RowPorts::Tls {
                ports: granted.into_iter().collect(),
            },
            via: None,
            source: key.scope.source(),
            status: key.status,
        })
        .collect()
}

fn live_address_rows(allowance: &Allowance, live: &[LiveEntry]) -> Vec<EgressRow> {
    let Allowance::Address(address) = allowance else {
        return Vec::new();
    };
    let mut keys: Vec<LiveKey> = Vec::new();
    for entry in live {
        if &entry.allowance != allowance {
            continue;
        }
        let key = LiveKey {
            scope: entry.scope,
            status: entry.status,
        };
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys.sort_by_key(|key| key.order());
    keys.into_iter()
        .map(|key| EgressRow {
            destination: address_destination(address),
            ports: address_ports(address),
            via: None,
            source: key.scope.source(),
            status: key.status,
        })
        .collect()
}

/// An address row's DESTINATION cell, as `ipnetwork` prints the network.
fn address_destination(address: &EgressAllowance) -> RowDestination {
    RowDestination::Address {
        network: address.network.to_string(),
    }
}

/// An address row's PORTS cell: no transport and no port is `all`, and each
/// missing half is spelled out rather than implied.
fn address_ports(address: &EgressAllowance) -> RowPorts {
    RowPorts::Address {
        transport: address.transport.map(|transport| match transport {
            Transport::Tcp => WireTransport::Tcp,
            Transport::Udp => WireTransport::Udp,
        }),
        port: address.port.map(std::num::NonZeroU16::get),
    }
}

fn push_ports(groups: &mut Vec<(LiveKey, BTreeSet<u16>)>, key: LiveKey, ports: Vec<u16>) {
    match groups.iter_mut().find(|(seen, _)| *seen == key) {
        Some((_, granted)) => granted.extend(ports),
        None => {
            groups.push((key, ports.into_iter().collect()));
        }
    }
}
