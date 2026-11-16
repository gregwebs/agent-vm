//! One session's effective egress (CONTEXT.md § Egress authority), as the
//! launcher answers it over the control socket and `agent-vm access egress`
//! prints it.
//!
//! Typed rather than pre-rendered text: the launcher owns the facts and the CLI
//! owns the layout, and a row the CLI cannot decode is a session it reports as
//! not available rather than a cell it prints wrong. Every `String` here came
//! over a socket, so a renderer escapes it.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EffectiveEgress {
    /// `None` until the runtime is attached: nothing is in force yet.
    pub(crate) policy_revision: Option<u64>,
    pub(crate) rows: Vec<EgressRow>,
    pub(crate) dns: DnsAuthorization,
    pub(crate) narrowing: EgressNarrowing,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EgressRow {
    pub(crate) destination: RowDestination,
    pub(crate) ports: RowPorts,
    /// The egress reference as written (`set:NAME`, `tool:NAME`), `None` when
    /// granted directly.
    pub(crate) via: Option<String>,
    pub(crate) source: RowSource,
    pub(crate) status: RowStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum RowDestination {
    Hostname { name: String },
    Address { network: String },
    Group { group: EgressGroup },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EgressGroup {
    Internet,
    Lan,
    Host,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WireTransport {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum RowPorts {
    /// A hostname rule's effective TLS ports.
    Tls { ports: Vec<u16> },
    Address {
        transport: Option<WireTransport>,
        port: Option<u16>,
    },
    /// A destination group: every port.
    All,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RowSource {
    PersistedGrant,
    AllowEgress,
    AllowInternetEgress,
    AllowLan,
    AllowHost,
    ProjectAllowance,
    SessionAllowance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum RowStatus {
    Applied,
    /// Confirmed by a live swap at this revision (always ≥ 2).
    AppliedAt {
        revision: u64,
    },
    Queued,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum DnsAuthorization {
    Denied,
    AllowedHostnamesOnly,
    /// The notice's own source labels (`--allow-internet-egress`,
    /// `persisted grant allow_host`, …).
    AnyName {
        via: Vec<String>,
    },
}

/// What narrows this session's egress without adding to it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EgressNarrowing {
    pub(crate) credential_rules: bool,
    pub(crate) github_repos: Vec<String>,
}

/// One live allowance the session holds, as the view needs it. Built only by
/// `LiveAllowances::effective_egress`; `scope` cannot name a configured tier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LiveEntry {
    pub(crate) allowance: crate::egress_policy::Allowance,
    pub(crate) scope: LiveScope,
    pub(crate) status: RowStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LiveScope {
    Session,
    Project,
}

impl LiveScope {
    pub(crate) fn source(self) -> RowSource {
        match self {
            Self::Session => RowSource::SessionAllowance,
            Self::Project => RowSource::ProjectAllowance,
        }
    }
}

/// The table's three sections, in print order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RowSection {
    Hostnames,
    Addresses,
    Groups,
}

impl RowDestination {
    pub(crate) fn section(&self) -> RowSection {
        match self {
            Self::Hostname { .. } => RowSection::Hostnames,
            Self::Address { .. } => RowSection::Addresses,
            Self::Group { .. } => RowSection::Groups,
        }
    }

    pub(crate) fn cell(&self) -> String {
        match self {
            Self::Hostname { name } => name.clone(),
            Self::Address { network } => network.clone(),
            Self::Group { group } => match group {
                EgressGroup::Internet => "internet (public)".to_owned(),
                EgressGroup::Lan => "lan (private)".to_owned(),
                EgressGroup::Host => "host (loopback)".to_owned(),
            },
        }
    }
}

impl RowPorts {
    pub(crate) fn cell(&self) -> String {
        match self {
            Self::Tls { ports } => ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            Self::All => "all".to_owned(),
            Self::Address { transport, port } => match (transport, port) {
                (None, None) => "all".to_owned(),
                (Some(transport), None) => format!("{}:all", transport.cell()),
                (None, Some(port)) => format!("tcp/udp:{port}"),
                (Some(transport), Some(port)) => format!("{}:{port}", transport.cell()),
            },
        }
    }
}

impl WireTransport {
    fn cell(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl RowSource {
    pub(crate) fn cell(self) -> &'static str {
        match self {
            Self::PersistedGrant => "persisted grant",
            Self::AllowEgress => "--allow-egress",
            Self::AllowInternetEgress => "--allow-internet-egress",
            Self::AllowLan => "--allow-lan",
            Self::AllowHost => "--allow-host",
            Self::ProjectAllowance => "project allowance",
            Self::SessionAllowance => "session allowance",
        }
    }
}

impl RowStatus {
    pub(crate) fn cell(self) -> String {
        match self {
            Self::Applied => "applied".to_owned(),
            Self::AppliedAt { revision } => format!("applied (rev {revision})"),
            Self::Queued => "queued".to_owned(),
        }
    }
}

impl DnsAuthorization {
    /// Takes the escape function because the labels are wire strings; each is
    /// escaped before it is joined.
    pub(crate) fn line(&self, escape: impl Fn(&str) -> String) -> String {
        match self {
            Self::Denied => "DNS: denied".to_owned(),
            Self::AllowedHostnamesOnly => "DNS: allowed hostnames only".to_owned(),
            Self::AnyName { via } => format!(
                "DNS: any name, via {}",
                via.iter()
                    .map(|label| escape(label))
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
        }
    }
}

impl EgressNarrowing {
    /// `Narrowed by:`'s parts, escaped before joining; empty when nothing
    /// narrows.
    pub(crate) fn parts(&self, escape: impl Fn(&str) -> String) -> Vec<String> {
        let mut parts = Vec::new();
        if self.credential_rules {
            parts.push("credential rules".to_owned());
        }
        if !self.github_repos.is_empty() {
            parts.push(format!(
                "GitHub repos {}",
                self.github_repos
                    .iter()
                    .map(|repo| escape(repo))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        parts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The launcher and the CLI are separate builds, so the shape they exchange
    /// is a contract: this pins it literally rather than restating the derives.
    #[test]
    fn wire_shape_is_pinned() {
        let pinned = serde_json::json!({
            "policy_revision": 2,
            "rows": [
                {"destination": {"kind": "hostname", "name": "api.example.com"},
                 "ports": {"kind": "tls", "ports": [443]},
                 "via": "set:ai",
                 "source": "persisted-grant",
                 "status": {"kind": "applied"}},
                {"destination": {"kind": "address", "network": "203.0.113.10/32"},
                 "ports": {"kind": "address", "transport": "tcp", "port": 443},
                 "via": null,
                 "source": "session-allowance",
                 "status": {"kind": "applied-at", "revision": 2}},
                {"destination": {"kind": "group", "group": "internet"},
                 "ports": {"kind": "all"},
                 "via": null,
                 "source": "allow-internet-egress",
                 "status": {"kind": "applied"}}
            ],
            "dns": {"kind": "any-name", "via": ["--allow-internet-egress"]},
            "narrowing": {"credential_rules": true, "github_repos": ["gregwebs/agent-vm"]}
        });
        let answer = EffectiveEgress {
            policy_revision: Some(2),
            rows: vec![
                EgressRow {
                    destination: RowDestination::Hostname {
                        name: "api.example.com".to_owned(),
                    },
                    ports: RowPorts::Tls { ports: vec![443] },
                    via: Some("set:ai".to_owned()),
                    source: RowSource::PersistedGrant,
                    status: RowStatus::Applied,
                },
                EgressRow {
                    destination: RowDestination::Address {
                        network: "203.0.113.10/32".to_owned(),
                    },
                    ports: RowPorts::Address {
                        transport: Some(WireTransport::Tcp),
                        port: Some(443),
                    },
                    via: None,
                    source: RowSource::SessionAllowance,
                    status: RowStatus::AppliedAt { revision: 2 },
                },
                EgressRow {
                    destination: RowDestination::Group {
                        group: EgressGroup::Internet,
                    },
                    ports: RowPorts::All,
                    via: None,
                    source: RowSource::AllowInternetEgress,
                    status: RowStatus::Applied,
                },
            ],
            dns: DnsAuthorization::AnyName {
                via: vec!["--allow-internet-egress".to_owned()],
            },
            narrowing: EgressNarrowing {
                credential_rules: true,
                github_repos: vec!["gregwebs/agent-vm".to_owned()],
            },
        };
        assert_eq!(serde_json::to_value(&answer).unwrap(), pinned);
        assert_eq!(
            serde_json::from_value::<EffectiveEgress>(pinned).unwrap(),
            answer
        );
    }

    #[test]
    fn cells_match_the_spec_table() {
        let destination = |destination: RowDestination| destination.cell();
        assert_eq!(
            destination(RowDestination::Hostname {
                name: "api.example.com".to_owned()
            }),
            "api.example.com"
        );
        assert_eq!(
            destination(RowDestination::Address {
                network: "203.0.113.10/32".to_owned()
            }),
            "203.0.113.10/32"
        );
        assert_eq!(
            destination(RowDestination::Group {
                group: EgressGroup::Internet
            }),
            "internet (public)"
        );
        assert_eq!(
            destination(RowDestination::Group {
                group: EgressGroup::Lan
            }),
            "lan (private)"
        );
        assert_eq!(
            destination(RowDestination::Group {
                group: EgressGroup::Host
            }),
            "host (loopback)"
        );

        assert_eq!(
            RowPorts::Tls {
                ports: vec![443, 8443]
            }
            .cell(),
            "443, 8443"
        );
        assert_eq!(
            RowPorts::Address {
                transport: None,
                port: None
            }
            .cell(),
            "all"
        );
        assert_eq!(
            RowPorts::Address {
                transport: Some(WireTransport::Tcp),
                port: None
            }
            .cell(),
            "tcp:all"
        );
        assert_eq!(
            RowPorts::Address {
                transport: Some(WireTransport::Udp),
                port: None
            }
            .cell(),
            "udp:all"
        );
        assert_eq!(
            RowPorts::Address {
                transport: None,
                port: Some(443)
            }
            .cell(),
            "tcp/udp:443"
        );
        assert_eq!(
            RowPorts::Address {
                transport: Some(WireTransport::Tcp),
                port: Some(443)
            }
            .cell(),
            "tcp:443"
        );
        assert_eq!(
            RowPorts::Address {
                transport: Some(WireTransport::Udp),
                port: Some(53)
            }
            .cell(),
            "udp:53"
        );
        assert_eq!(RowPorts::All.cell(), "all");

        for (source, cell) in [
            (RowSource::PersistedGrant, "persisted grant"),
            (RowSource::AllowEgress, "--allow-egress"),
            (RowSource::AllowInternetEgress, "--allow-internet-egress"),
            (RowSource::AllowLan, "--allow-lan"),
            (RowSource::AllowHost, "--allow-host"),
            (RowSource::ProjectAllowance, "project allowance"),
            (RowSource::SessionAllowance, "session allowance"),
        ] {
            assert_eq!(source.cell(), cell);
        }

        assert_eq!(RowStatus::Applied.cell(), "applied");
        assert_eq!(
            RowStatus::AppliedAt { revision: 2 }.cell(),
            "applied (rev 2)"
        );
        assert_eq!(RowStatus::Queued.cell(), "queued");

        assert_eq!(DnsAuthorization::Denied.line(str::to_owned), "DNS: denied");
        assert_eq!(
            DnsAuthorization::AllowedHostnamesOnly.line(str::to_owned),
            "DNS: allowed hostnames only"
        );
        assert_eq!(
            DnsAuthorization::AnyName {
                via: vec![
                    "--allow-host".to_owned(),
                    "persisted grant allow_host".to_owned()
                ]
            }
            .line(str::to_owned),
            "DNS: any name, via --allow-host and persisted grant allow_host"
        );

        assert!(EgressNarrowing::default().parts(str::to_owned).is_empty());
        assert_eq!(
            EgressNarrowing {
                credential_rules: true,
                github_repos: vec!["gregwebs/agent-vm".to_owned()],
            }
            .parts(str::to_owned),
            vec![
                "credential rules".to_owned(),
                "GitHub repos gregwebs/agent-vm".to_owned()
            ]
        );
    }

    #[test]
    fn sections_sort_hostnames_then_addresses_then_groups() {
        let hostname = RowDestination::Hostname {
            name: "a.example".to_owned(),
        };
        let address = RowDestination::Address {
            network: "10.0.0.1/32".to_owned(),
        };
        let group = RowDestination::Group {
            group: EgressGroup::Lan,
        };
        let mut rows = [group.clone(), address.clone(), hostname.clone()];
        rows.sort_by_key(RowDestination::section);
        assert_eq!(rows, [hostname, address, group]);
        assert!(RowSection::Hostnames < RowSection::Addresses);
        assert!(RowSection::Addresses < RowSection::Groups);
    }
}
