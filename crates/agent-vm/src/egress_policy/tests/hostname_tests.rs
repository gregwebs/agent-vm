//! Hostname allowance/authority unit tests, a submodule of
//! `egress_policy::tests` so the shared helpers (`grants`, `corpus`,
//! `allowed_oracle`, `authority`) are in scope.

use super::*;

const SEVEN: [&str; 7] = [
    "api.deepseek.com",
    "api.anthropic.com",
    "platform.claude.com",
    "api.openai.com",
    "auth.openai.com",
    "chatgpt.com",
    "models.opencode.ai",
];

#[test]
fn hostname_acceptance_and_display_table() {
    for (input, display) in [
        ("API.Example.COM.", "api.example.com"),
        ("Build", "build"),
        ("tcp://h.example:8443", "tcp://h.example:8443"),
        ("TCP://h.example:8443", "tcp://h.example:8443"),
        ("h.example:8443", "tcp://h.example:8443"),
        ("h.example:443", "tcp://h.example:443"),
        ("tcp://h.example", "h.example"),
        ("h.example:80", "tcp://h.example:80"),
    ] {
        let a = Allowance::parse(input).unwrap();
        assert_eq!(a.to_string(), display);
        assert_eq!(Allowance::parse(display).unwrap(), a);
    }
}
fn hostname_auth(bits: u8, specs: &[&str]) -> EgressAuthority {
    let raw: Vec<_> = specs.iter().map(|s| (*s).to_owned()).collect();
    let g = grants(bits);
    EgressAuthority::from_cli(CliEgress {
        internet: Some(g.internet),
        lan: Some(g.lan),
        host: Some(g.host),
        allowances: &raw,
    })
    .unwrap()
}
// This checks serialized input eligibility, not the vendored crate-private evaluator.
// The witness is RFC1918 and outside the configured gateway addresses: only
// Private can match it among the documented disjoint destination groups.
fn private_answer_eligibility(
    policy: &microsandbox::NetworkPolicy,
    protocol: Protocol,
) -> Option<Action> {
    use microsandbox_network::policy::{DestinationGroup, Direction, Rule};
    let serialized = serde_json::to_value(policy).unwrap();
    let rules: Vec<Rule> = serde_json::from_value(serialized["rules"].clone()).unwrap();
    let witness = Ipv4Addr::new(10, 0, 0, 5);
    rules
        .iter()
        .any(|rule| {
            let matches_address = match &rule.destination {
                Destination::Cidr(ipnetwork::IpNetwork::V4(network)) => {
                    let mask = if network.prefix() == 0 {
                        0
                    } else {
                        u32::MAX << (32 - network.prefix())
                    };
                    u32::from(witness) & mask == u32::from(network.ip()) & mask
                }
                Destination::Group(group) => *group == DestinationGroup::Private,
                _ => false,
            };
            matches!(rule.direction, Direction::Egress | Direction::Any)
                && rule.action == Action::Allow
                && matches_address
                && rule.ports.is_empty()
                && (rule.protocols.is_empty() || rule.protocols.contains(&protocol))
        })
        .then_some(Action::Allow)
}
#[test]
fn hostname_dns_and_private_answer_table() {
    use microsandbox_network::shared::{ResolvedHostnameFamily, SharedState};
    let shared = SharedState::new(4);
    shared.set_gateway_ips(
        Some("100.64.0.1".parse().unwrap()),
        Some("fd00::1".parse().unwrap()),
    );
    for (specs, bits, expected) in [
        (vec!["build"], 0, [None, None]),
        (
            vec!["build", "udp://10.0.0.0/8"],
            0,
            [None, Some(Action::Allow)],
        ),
        (vec!["build", "udp://[10.0.0.0/8]:18080"], 0, [None, None]),
        (vec!["build"], 2, [Some(Action::Allow), Some(Action::Allow)]),
    ] {
        let policy = hostname_auth(bits, &specs).policy();
        for (protocol, eligible) in [Protocol::Tcp, Protocol::Udp].into_iter().zip(expected) {
            assert_eq!(
                policy.evaluate_dns_query(&"build".parse().unwrap(), protocol, 53),
                Action::Allow
            );
            assert_eq!(
                policy.evaluate_dns_query(&"build.corp.example".parse().unwrap(), protocol, 53),
                Action::Deny
            );
            assert_eq!(private_answer_eligibility(&policy, protocol), eligible);
        }
    }
    let domain_only = hostname_auth(0, &["build"]).policy();
    shared.cache_resolved_hostname(
        "build",
        ResolvedHostnameFamily::Ipv4,
        ["10.0.0.5".parse().unwrap()],
        std::time::Duration::from_secs(60),
    );
    // C3: the Domain rule carries `protocols = [Tcp]`, so even with the cache
    // binding present a UDP flow to the name is denied while TCP is allowed.
    for (protocol, expected) in [
        (
            Protocol::Tcp,
            microsandbox_network::policy::EgressEvaluation::Allow,
        ),
        (
            Protocol::Udp,
            microsandbox_network::policy::EgressEvaluation::Deny,
        ),
    ] {
        assert_eq!(
            domain_only.evaluate_egress_with_source(
                SocketAddr::new("10.0.0.5".parse().unwrap(), 443),
                protocol,
                &shared,
                microsandbox_network::policy::HostnameSource::Sni("build")
            ),
            expected
        );
        assert_eq!(private_answer_eligibility(&domain_only, protocol), None);
    }
    let policy = hostname_auth(4, &["build"]).policy();
    assert_eq!(
        policy.evaluate_dns_query(&"other.example".parse().unwrap(), Protocol::Udp, 53),
        Action::Allow
    );
}
#[test]
fn hostname_notices_show_effective_ports_and_dns_scope() {
    let mut output = Vec::new();
    hostname_auth(0, &["api.example.com", "tcp://git.example.com:8443"])
        .write_notices(&mut output)
        .unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "==> Egress policy: allowing TLS to api.example.com on ports 443, 8443\n==> Egress policy: allowing TLS to git.example.com on ports 8443\n==> Egress policy: hostname allowances are TLS-only (SNI and DNS verified; no plain HTTP)\n==> TLS interception: ports 443, 8443 — global to every destination (TLS ClientHello with SNI required, UDP dropped, sandbox CA must be trusted). A tcp://HOST:PORT entry widens every bare hostname to PORT.\n==> Egress DNS: only allowed hostnames resolve (others NXDOMAIN when forwarder is available; private answers need --allow-lan or a port-less numeric allowance)\n"
    );
    // Mixed launch: a numeric grant, a group grant, a duplicate hostname
    // (dropped), and a later `tcp://HOST:PORT` that must widen every bare
    // hostname (including one written first) and make its port TLS-only
    // globally. `tcp://plain.example:80` exercises the port-80 caveat.
    let mut output = Vec::new();
    hostname_auth(
        2,
        &[
            "10.0.0.5",
            "b.example.com",
            "api.example.com",
            "b.example.com",
            "tcp://plain.example:80",
            "b.example.com",
        ],
    )
    .write_notices(&mut output)
    .unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "==> Egress policy: allowing 10.0.0.5/32\n\
==> Egress policy: --allow-lan enabled (Private RFC1918 + 100.64/10 + fc00::/7 reachable; does not itself enable DNS)\n\
==> Egress policy: allowing TLS to b.example.com, api.example.com on ports 80, 443\n\
==> Egress policy: allowing TLS to plain.example on ports 80\n\
==> Egress policy: hostname allowances are TLS-only (SNI and DNS verified; no plain HTTP)\n\
==> TLS interception: ports 80, 443 — global to every destination (TLS ClientHello with SNI required, UDP dropped, sandbox CA must be trusted). A tcp://HOST:PORT entry widens every bare hostname to PORT.\n\
==> Egress DNS: only allowed hostnames resolve (others NXDOMAIN when forwarder is available; private answers need --allow-lan or a port-less numeric allowance)\n"
    );
}

// The literal names and lines operators see for the provider set the compact
// form exists for: one grant line, one security clause.
#[test]
fn seven_bare_hostnames_share_one_grant_line_and_one_explanation() {
    let grant = format!(
        "==> Egress policy: allowing TLS to {} on ports 443",
        SEVEN.join(", ")
    );
    let tail = format!(
        "{SHARED_TLS_ONLY}\n==> TLS interception: ports 443 — global to every destination (TLS ClientHello with SNI required, UDP dropped, sandbox CA must be trusted). A tcp://HOST:PORT entry widens every bare hostname to PORT.\n==> Egress DNS: only allowed hostnames resolve (others NXDOMAIN when forwarder is available; private answers need --allow-lan or a port-less numeric allowance)\n"
    );
    let mut output = Vec::new();
    resolve_saved(Default::default(), &SEVEN, empty_cli())
        .write_notices(&mut output)
        .unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        format!(
            "==> Egress authority: persisted grants from \"/home/a/.config/agent-vm/config.toml\" [network] merged with this launch's flags (flags override persisted booleans and add allowances; nothing is saved)\n{grant} (persisted grants)\n{tail}"
        )
    );
    // Without a user table no source suffix appears at all.
    let mut output = Vec::new();
    hostname_auth(0, &SEVEN).write_notices(&mut output).unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        format!("{grant}\n{tail}")
    );
}

#[test]
fn every_name_of_a_large_group_is_printed_once_without_truncation() {
    let names: Vec<String> = (0..9).map(|i| format!("h{i}.example")).collect();
    let specs: Vec<&str> = names.iter().map(String::as_str).collect();
    let mut output = Vec::new();
    hostname_auth(0, &specs).write_notices(&mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(text.starts_with(&format!(
        "==> Egress policy: allowing TLS to {} on ports 443\n",
        names.join(", ")
    )));
    assert_eq!(text.matches("on ports").count(), 1, "{text}");
    assert_eq!(text.matches(SHARED_TLS_ONLY).count(), 1, "{text}");
}

// A writer that fails after a bounded prefix must surface the error from the
// later line, not lose it.
struct FailAfter {
    written: Vec<u8>,
    remaining: usize,
}
impl std::io::Write for FailAfter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::other("writer closed"));
        }
        let taken = buf.len().min(self.remaining);
        self.written.extend_from_slice(&buf[..taken]);
        self.remaining -= taken;
        Ok(taken)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn hostname_notice_write_error_after_the_grant_line_is_returned() {
    const GRANT: &str = "==> Egress policy: allowing TLS to api.example.com on ports 443\n";
    let mut writer = FailAfter {
        written: Vec::new(),
        remaining: GRANT.len(),
    };
    let error = hostname_auth(0, &["api.example.com"])
        .write_notices(&mut writer)
        .unwrap_err();
    assert_eq!(error.to_string(), "writer closed");
    assert_eq!(String::from_utf8(writer.written).unwrap(), GRANT);
}
proptest! {
    #[test]
    fn hostname_rule_shape(bits in 0u8..8, port in (1u16..=65535).prop_filter("not DNS", |p| !matches!(p,53|853))) {
        let explicit = format!("tcp://git.example:{port}");
        let auth = hostname_auth(bits, &["api.example", &explicit, "tcp://api.example:443", "api.example", "10.1.2.3"]);
        let policy = auth.policy();
        let g = grants(bits);
        prop_assert_eq!(policy.rules.len(), 1 + 2 * usize::from(g.internet) + usize::from(g.lan) + usize::from(g.host) + 2);
        let ports = auth.intercepted_ports().unwrap().to_vec();
        let mut seen_domain = false;
        for rule in &policy.rules {
            prop_assert_eq!(rule.action, Action::Allow);
            if let Destination::Domain(name) = &rule.destination {
                seen_domain = true;
                prop_assert_eq!(&rule.protocols, &vec![Protocol::Tcp]);
                prop_assert!(!rule.ports.is_empty());
                for range in &rule.ports {
                    prop_assert_eq!(range.start,range.end);
                    prop_assert!(ports.contains(&range.start));
                    prop_assert!(!matches!(range.start, 53|853));
                }
                if name.as_str() == "api.example" {
                    prop_assert_eq!(rule.ports.iter().map(|p| p.start).collect::<Vec<_>>(), ports.clone());
                }
            } else { prop_assert!(!seen_domain); }
        }
        prop_assert_eq!(policy.rules.iter().filter(|r| matches!(r.destination, Destination::Group(microsandbox_network::policy::DestinationGroup::Host)) && r.ports.iter().any(|p| p.start == 53)).count(), usize::from(g.internet));
    }
}
#[test]
fn hostname_runtime_differential_with_dns_cache() {
    use microsandbox_network::{
        policy::{EgressEvaluation, HostnameSource},
        shared::{ResolvedHostnameFamily, SharedState},
    };
    use std::time::Duration;
    for bits in 0..8 {
        for numeric in [false, true] {
            let mut specs = vec!["a.example", "tcp://b.example:8443"];
            if numeric {
                specs.push("tcp://10.1.2.3:8443");
            }
            let auth = hostname_auth(bits, &specs);
            let policy = auth.policy();
            for (ip, label) in corpus() {
                for binding in [false, true] {
                    let shared = SharedState::new(4);
                    shared.set_gateway_ips(
                        Some("100.64.0.1".parse().unwrap()),
                        Some("fd00::1".parse().unwrap()),
                    );
                    for name in ["a.example", "b.example", "unlisted.example"] {
                        let family = if ip.is_ipv4() {
                            ResolvedHostnameFamily::Ipv4
                        } else {
                            ResolvedHostnameFamily::Ipv6
                        };
                        if binding {
                            shared.cache_resolved_hostname(
                                name,
                                family,
                                [ip],
                                Duration::from_secs(60),
                            );
                        }
                    }
                    for protocol in [Protocol::Tcp, Protocol::Udp] {
                        for port in [22, 53, 80, 443, 8443] {
                            for name in ["a.example", "b.example", "unlisted.example"] {
                                let base = allowed_oracle(&auth, ip, label, protocol, Some(port));
                                let domain = protocol == Protocol::Tcp
                                    && binding
                                    && ((name == "a.example" && [443, 8443].contains(&port))
                                        || (name == "b.example" && port == 8443));
                                let expected = if base || domain {
                                    EgressEvaluation::Allow
                                } else {
                                    EgressEvaluation::Deny
                                };
                                assert_eq!(
                                    policy.evaluate_egress_with_source(
                                        SocketAddr::new(ip, port),
                                        protocol,
                                        &shared,
                                        HostnameSource::Sni(name)
                                    ),
                                    expected,
                                    "{ip}:{port} {name} {protocol:?} binding={binding}"
                                );
                            }
                            if ![443, 8443].contains(&port) {
                                assert_eq!(
                                    policy.evaluate_egress_with_source(
                                        SocketAddr::new(ip, port),
                                        protocol,
                                        &shared,
                                        HostnameSource::CacheOnly
                                    ),
                                    if allowed_oracle(&auth, ip, label, protocol, Some(port)) {
                                        EgressEvaluation::Allow
                                    } else {
                                        EgressEvaluation::Deny
                                    }
                                );
                            }
                            let base = allowed_oracle(&auth, ip, label, protocol, Some(port));
                            let domain =
                                protocol == Protocol::Tcp && binding && [443, 8443].contains(&port);
                            assert_eq!(
                                policy.evaluate_egress_with_source(
                                    SocketAddr::new(ip, port),
                                    protocol,
                                    &shared,
                                    HostnameSource::Deferred
                                ),
                                if base {
                                    EgressEvaluation::Allow
                                } else if domain {
                                    EgressEvaluation::DeferUntilHostname
                                } else {
                                    EgressEvaluation::Deny
                                }
                            );
                        }
                    }
                    for protocol in [Protocol::Icmpv4, Protocol::Icmpv6] {
                        assert_eq!(
                            policy.evaluate_egress_ip(ip, protocol, &shared),
                            if allowed_oracle(&auth, ip, label, protocol, None) {
                                Action::Allow
                            } else {
                                Action::Deny
                            }
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn network_request_coverage_table() {
    use crate::network_requests::NetworkRequests;
    let requests = NetworkRequests::parse(
        &[
            "api.example.com",
            "tcp://api.example.com:8443",
            "tcp://api.example.com:9443",
            "other.example",
        ]
        .map(str::to_owned),
    )
    .unwrap();
    for (bits, specs, expected) in [
        (0, vec![], [false, false, false, false]),
        (1, vec![], [true, true, true, true]),
        (2, vec![], [false, false, false, false]),
        (4, vec![], [false, false, false, false]),
        (6, vec![], [false, false, false, false]),
        (0, vec!["0.0.0.0/0"], [false, false, false, false]),
        (
            0,
            vec!["tcp://[93.184.216.0/24]:443"],
            [false, false, false, false],
        ),
        (0, vec!["api.example.com"], [true, false, false, false]),
        (
            0,
            vec!["tcp://api.example.com:8443"],
            [false, true, false, false],
        ),
        (
            0,
            vec!["tcp://api.example.com:8443", "tcp://api.example.com:9443"],
            [false, true, true, false],
        ),
        (
            0,
            vec!["api.example.com", "tcp://x.example:8443"],
            [true, true, false, false],
        ),
        (0, vec!["API.Example.com."], [true, false, false, false]),
    ] {
        let auth = hostname_auth(bits, &specs);
        let actual: Vec<_> = requests
            .iter()
            .map(|r| auth.covers_tls(r.name(), r.port()))
            .collect();
        assert_eq!(actual, expected, "{bits}: {specs:?}");
    }
}
#[test]
fn network_request_coverage_matches_policy_rules() {
    use crate::network_requests::NetworkRequests;
    use microsandbox_network::policy::{DestinationGroup, Direction};
    const COVERAGE_SPECS: &[&[&str]] = &[
        &[],
        &["api.example.com"],
        &["tcp://api.example.com:8443"],
        &["tcp://api.example.com:8443", "tcp://api.example.com:9443"],
        &["api.example.com", "tcp://x.example:8443"],
        &["API.Example.com.", "api.example.com:443"],
        &["10.1.2.3", "0.0.0.0/0", "tcp://[93.184.216.0/24]:443"],
        &["api.example.com", "10.0.0.0/8"],
    ];
    let requests = NetworkRequests::parse(
        &[
            "api.example.com",
            "api.example.com:8443",
            "api.example.com:9443",
            "api.example.com:22",
            "x.example",
            "x.example:8443",
            "other.example",
        ]
        .map(str::to_owned),
    )
    .unwrap();
    for bits in 0..8 {
        for specs in COVERAGE_SPECS {
            let auth = hostname_auth(bits, specs);
            for request in requests.iter() {
                let oracle = auth.policy().rules.iter().any(|rule| {
                    rule.action == Action::Allow
                        && matches!(rule.direction, Direction::Egress | Direction::Any)
                        && (rule.protocols.is_empty() || rule.protocols.contains(&Protocol::Tcp))
                        && (rule.ports.is_empty()
                            || rule.ports.iter().any(|p| {
                                p.start <= request.port().get() && request.port().get() <= p.end
                            }))
                        && match &rule.destination {
                            Destination::Group(DestinationGroup::Public) => true,
                            Destination::Domain(d) => d.as_str() == request.name().as_str(),
                            _ => false,
                        }
                });
                assert_eq!(
                    auth.covers_tls(request.name(), request.port()),
                    oracle,
                    "{bits} {specs:?} {request}"
                );
            }
        }
    }
}
