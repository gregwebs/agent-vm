//! Launch egress authority: CLI grants never inherit the SDK's public default.
//! Numeric allowances are address-wide, not hostname isolation.

use crate::egress_grammar::{AllowanceError, SchemeSel, split_scheme, split_target};
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum GrantSource { Default, UserConfig, Cli }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedGrant { pub enabled: bool, pub source: GrantSource }

/// A `--allow-*` flag's explicit value, or `None` when the flag was absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CliGrant(pub Option<bool>);
/// The saved `[network]` value for one group, or `None` when it is unset.
/// No `Structural`: nothing compares these by value, and `ResolvedGrant`
/// beside them omits it too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavedGrant(pub Option<bool>);

/// An explicit flag (true or false) beats the saved setting; nothing beats default-deny but an explicit true.
///
/// The two sources have distinct types so a call site that swaps them -- the
/// "saved beats CLI" defect -- cannot compile.
pub fn resolve_grant(cli: CliGrant, saved: SavedGrant) -> (r: ResolvedGrant)
    ensures
        r.enabled == match cli.0 { Some(c) => c, None => match saved.0 { Some(u) => u, None => false } },
        (r.source == GrantSource::Cli) == cli.0.is_some(),
        (r.source == GrantSource::UserConfig) == (cli.0.is_none() && saved.0.is_some()),
        (r.source == GrantSource::Default) == (cli.0.is_none() && saved.0.is_none()),
{
    match cli.0 {
        Some(c) => ResolvedGrant { enabled: c, source: GrantSource::Cli },
        None => match saved.0 {
            Some(u) => ResolvedGrant { enabled: u, source: GrantSource::UserConfig },
            None => ResolvedGrant { enabled: false, source: GrantSource::Default },
        },
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GroupGrants { pub internet: bool, pub lan: bool, pub host: bool }
#[derive(Debug, PartialEq, Eq)]
pub struct GroupRules { pub gateway_dns: bool, pub public: bool, pub private: bool, pub host: bool }

pub fn group_rules(grants: GroupGrants) -> (rules: GroupRules)
    ensures
        rules.public == grants.internet,
        rules.gateway_dns == grants.internet,
        rules.private == grants.lan,
        rules.host == grants.host,
{
    GroupRules { gateway_dns: grants.internet, public: grants.internet, private: grants.lan, host: grants.host }
}

} // verus!

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Transport {
    Tcp,
    Udp,
}
impl Transport {
    fn protocol(self) -> microsandbox_network::policy::Protocol {
        use microsandbox_network::policy::Protocol;
        match self {
            Self::Tcp => Protocol::Tcp,
            Self::Udp => Protocol::Udp,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct EgressAllowance {
    network: ipnetwork::IpNetwork,
    transport: Option<Transport>,
    port: Option<std::num::NonZeroU16>,
}

fn address_network(text: &str) -> Result<ipnetwork::IpNetwork, AllowanceError> {
    let parsed = if text.contains('/') {
        text.parse::<ipnetwork::IpNetwork>().map_err(|_| ())
    } else {
        text.parse::<std::net::IpAddr>()
            .map(ipnetwork::IpNetwork::from)
            .map_err(|_| ())
    };
    parsed.map_err(|()| AllowanceError::MalformedAddress)
}
use crate::egress_hostname::{
    CanonicalHostname, HostnameAllowance, InterceptedPorts, domain_rules,
};
/// Borrowed verified user authority; resolution assembles it without filesystem reads.
pub(crate) struct UserEgress<'a> {
    pub(crate) file: &'a std::path::Path,
    pub(crate) internet: Option<bool>,
    pub(crate) lan: Option<bool>,
    pub(crate) host: Option<bool>,
    pub(crate) allowances: &'a [Allowance],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Allowance {
    Address(EgressAllowance),
    Hostname(HostnameAllowance),
}
impl Allowance {
    pub(crate) fn parse(text: &str) -> Result<Self, AllowanceError> {
        if text.is_empty() {
            return Err(AllowanceError::Empty);
        }
        let (scheme, start) = split_scheme(text.as_bytes())?;
        let target = &text[start..];
        let layout = split_target(target.as_bytes(), address_network(target).is_ok())?;
        let slice = &target[layout.addr_start..layout.addr_end];
        match address_network(slice) {
            Ok(_) => EgressAllowance::parse(text).map(Self::Address),
            Err(_) => {
                HostnameAllowance::from_target(scheme, layout.addr_start == 1, slice, layout.port)
                    .map(Self::Hostname)
            }
        }
    }
}
impl std::fmt::Display for Allowance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Address(a) => a.fmt(f),
            Self::Hostname(h) => h.fmt(f),
        }
    }
}
impl EgressAllowance {
    pub(crate) fn parse(text: &str) -> Result<Self, AllowanceError> {
        if text.is_empty() {
            return Err(AllowanceError::Empty);
        }
        let (scheme, start) = split_scheme(text.as_bytes())?;
        let target = &text[start..];
        let whole_address = address_network(target).is_ok();
        let layout = split_target(target.as_bytes(), whole_address)?;
        // Verified offsets are anchored by ASCII delimiters, hence UTF-8 boundaries.
        let mut network = address_network(&target[layout.addr_start..layout.addr_end])?;
        if let ipnetwork::IpNetwork::V6(v6) = network
            && v6.prefix() >= 96
            && let Some(v4) = v6.ip().to_ipv4_mapped()
        {
            network = ipnetwork::IpNetwork::new(v4.into(), v6.prefix() - 96)
                .map_err(|_| AllowanceError::MalformedAddress)?;
        }
        network = ipnetwork::IpNetwork::new(network.network(), network.prefix())
            .map_err(|_| AllowanceError::MalformedAddress)?;
        Ok(Self {
            network,
            transport: match scheme {
                SchemeSel::Any => None,
                SchemeSel::Tcp => Some(Transport::Tcp),
                SchemeSel::Udp => Some(Transport::Udp),
            },
            port: trusted_port(layout.port)?,
        })
    }
    fn rule(&self) -> microsandbox_network::policy::Rule {
        use microsandbox_network::policy::{Action, Destination, Direction, PortRange, Rule};
        Rule {
            direction: Direction::Egress,
            destination: Destination::Cidr(self.network),
            protocols: self
                .transport
                .map(Transport::protocol)
                .into_iter()
                .collect(),
            ports: self
                .port
                .map(|p| PortRange::single(p.get()))
                .into_iter()
                .collect(),
            action: Action::Allow,
        }
    }
}
// A broken kernel must not turn a scoped port into an all-ports grant.
fn trusted_port(port: Option<u16>) -> Result<Option<std::num::NonZeroU16>, AllowanceError> {
    port.map(|p| std::num::NonZeroU16::new(p).ok_or(AllowanceError::MalformedPort))
        .transpose()
}

impl std::fmt::Display for EgressAllowance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(t) = self.transport {
            f.write_str(match t {
                Transport::Tcp => "tcp://",
                Transport::Udp => "udp://",
            })?;
        }
        match self.port {
            Some(p) => write!(f, "[{}]:{p}", self.network),
            None => write!(f, "{}", self.network),
        }
    }
}
pub(crate) struct CliEgress<'a> {
    pub(crate) internet: Option<bool>,
    pub(crate) lan: Option<bool>,
    pub(crate) host: Option<bool>,
    pub(crate) allowances: &'a [String],
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct EntrySources {
    user: bool,
    cli: bool,
}
impl EntrySources {
    fn tag(self) -> &'static str {
        match (self.user, self.cli) {
            (true, true) => "persisted grants and --allow-egress",
            (true, false) => "persisted grants",
            _ => "--allow-egress",
        }
    }
}
#[derive(Clone, Copy, Debug)]
struct GroupOrigin {
    resolved: ResolvedGrant,
    saved: Option<bool>,
}
#[derive(Debug)]
struct Provenance {
    file: std::path::PathBuf,
    internet: GroupOrigin,
    lan: GroupOrigin,
    host: GroupOrigin,
    // Membership by canonical value, never index-aligned with effective lists.
    user_entries: Vec<Allowance>,
    cli_entries: Vec<Allowance>,
}
impl Provenance {
    fn sources(&self, entry: &Allowance) -> EntrySources {
        EntrySources {
            user: self.user_entries.contains(entry),
            cli: self.cli_entries.contains(entry),
        }
    }
    fn hostname_sources(&self, name: &microsandbox_network::policy::DomainName) -> EntrySources {
        let contains = |entries: &[Allowance]| {
            entries
                .iter()
                .any(|entry| matches!(entry, Allowance::Hostname(h) if h.domain() == name))
        };
        EntrySources {
            user: contains(&self.user_entries),
            cli: contains(&self.cli_entries),
        }
    }
}

/// Which sources carry the launch's hostname authority (ADR-0037 C8 refusal).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostnameAuthority<'a> {
    /// Only the launch flags (`--allow-egress`).
    Cli,
    /// Only the saved user-tier `[network]` table, whose file this is.
    Saved(&'a std::path::Path),
    /// Both the saved table and this launch's flags.
    SavedAndCli(&'a std::path::Path),
}

#[derive(Debug)]
pub(crate) struct EgressAuthority {
    groups: GroupGrants,
    allowances: Vec<EgressAllowance>,
    hostnames: Vec<HostnameAllowance>,
    provenance: Option<Provenance>,
}
impl EgressAuthority {
    #[cfg(test)]
    pub(crate) fn from_cli(input: CliEgress<'_>) -> anyhow::Result<Self> {
        Self::resolve(input, None)
    }
    pub(crate) fn resolve(
        cli: CliEgress<'_>,
        user: Option<UserEgress<'_>>,
    ) -> anyhow::Result<Self> {
        let internet = resolve_grant(
            CliGrant(cli.internet),
            SavedGrant(user.as_ref().and_then(|u| u.internet)),
        );
        let lan = resolve_grant(
            CliGrant(cli.lan),
            SavedGrant(user.as_ref().and_then(|u| u.lan)),
        );
        let host = resolve_grant(
            CliGrant(cli.host),
            SavedGrant(user.as_ref().and_then(|u| u.host)),
        );
        let mut cli_entries = Vec::new();
        for (i, text) in cli.allowances.iter().enumerate() {
            let entry = Allowance::parse(text)
                .map_err(|e| anyhow::anyhow!("--allow-egress #{}: {e}", i + 1))?;
            if !cli_entries.contains(&entry) {
                cli_entries.push(entry);
            }
        }
        let user_entries = user
            .as_ref()
            .map_or_else(Vec::new, |u| u.allowances.to_vec());
        let mut allowances = Vec::new();
        let mut hostnames = Vec::new();
        for entry in user_entries.iter().chain(&cli_entries) {
            match entry {
                Allowance::Address(a) if !allowances.contains(a) => allowances.push(*a),
                Allowance::Hostname(h) if !hostnames.contains(h) => hostnames.push(h.clone()),
                _ => {}
            }
        }
        let provenance = user.map(|u| Provenance {
            file: u.file.to_owned(),
            internet: GroupOrigin {
                resolved: internet,
                saved: u.internet,
            },
            lan: GroupOrigin {
                resolved: lan,
                saved: u.lan,
            },
            host: GroupOrigin {
                resolved: host,
                saved: u.host,
            },
            user_entries,
            cli_entries,
        });
        Ok(Self {
            groups: GroupGrants {
                internet: internet.enabled,
                lan: lan.enabled,
                host: host.enabled,
            },
            allowances,
            hostnames,
            provenance,
        })
    }
    /// Where the launch's hostname authority comes from, for the ambient-proxy
    /// refusal. `Some` iff some hostname allowance exists.
    pub(crate) fn hostname_authority(&self) -> Option<HostnameAuthority<'_>> {
        if self.hostnames.is_empty() {
            return None;
        }
        let Some(provenance) = self.provenance.as_ref() else {
            return Some(HostnameAuthority::Cli);
        };
        let hostname =
            |entries: &[Allowance]| entries.iter().any(|a| matches!(a, Allowance::Hostname(_)));
        Some(
            match (
                hostname(&provenance.user_entries),
                hostname(&provenance.cli_entries),
            ) {
                (true, true) => HostnameAuthority::SavedAndCli(&provenance.file),
                (true, false) => HostnameAuthority::Saved(&provenance.file),
                (false, _) => HostnameAuthority::Cli,
            },
        )
    }
    #[cfg(test)]
    fn sourced_entries(&self) -> Vec<(String, EntrySources)> {
        self.allowances
            .iter()
            .cloned()
            .map(Allowance::Address)
            .chain(self.hostnames.iter().cloned().map(Allowance::Hostname))
            .map(|a| {
                (
                    a.to_string(),
                    self.provenance.as_ref().map_or(
                        EntrySources {
                            user: false,
                            cli: true,
                        },
                        |p| p.sources(&a),
                    ),
                )
            })
            .collect()
    }
    pub(crate) fn has_hostnames(&self) -> bool {
        !self.hostnames.is_empty()
    }
    pub(crate) fn intercepted_ports(&self) -> Option<InterceptedPorts> {
        InterceptedPorts::for_hostnames(&self.hostnames)
    }
    /// Lookup-free report query; reads authority without granting or resolving.
    pub(crate) fn covers_tls(&self, name: &CanonicalHostname, port: std::num::NonZeroU16) -> bool {
        let public = group_rules(self.groups).public;
        public
            || self.intercepted_ports().is_some_and(|ports| {
                self.hostnames
                    .iter()
                    .any(|h| h.grants_tls(name, port, &ports))
            })
    }
    pub(crate) fn policy(&self) -> microsandbox::NetworkPolicy {
        use microsandbox_network::policy::{Action, Destination, DestinationGroup, Rule};
        let emitted = group_rules(self.groups);
        let mut rules: Vec<Rule> = self.allowances.iter().map(EgressAllowance::rule).collect();
        if emitted.gateway_dns {
            rules.push(Rule::allow_dns());
        }
        for (enabled, group) in [
            (emitted.public, DestinationGroup::Public),
            (emitted.private, DestinationGroup::Private),
            (emitted.host, DestinationGroup::Host),
        ] {
            if enabled {
                rules.push(Rule::allow_egress(Destination::Group(group)));
            }
        }
        if let Some(ports) = self.intercepted_ports() {
            rules.extend(domain_rules(&self.hostnames, &ports));
        }
        // from_profiles opens DNS for LAN alone; none() also denies ingress.
        microsandbox::NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules,
        }
    }
    pub(crate) fn write_notices(&self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        if let Some(p) = &self.provenance {
            writeln!(
                output,
                "==> Egress authority: persisted grants from \"{}\" [network] merged with this launch's flags (flags override persisted booleans and add allowances; nothing is saved)",
                crate::one_line::path(&p.file)
            )?;
        }
        if self.allowances.is_empty()
            && !self.has_hostnames()
            && !self.groups.internet
            && !self.groups.lan
            && !self.groups.host
        {
            writeln!(
                output,
                "==> Egress policy: all guest egress denied (opt in with --allow-internet-egress, --allow-egress, --allow-lan or --allow-host)"
            )?;
        }
        for allowance in &self.allowances {
            if let Some(p) = &self.provenance {
                writeln!(
                    output,
                    "==> Egress policy: allowing {allowance} ({})",
                    p.sources(&Allowance::Address(*allowance)).tag()
                )?;
            } else {
                writeln!(output, "==> Egress policy: allowing {allowance}")?;
            }
        }
        for (enabled, origin, setting, flag, detail) in [
            (
                self.groups.internet,
                self.provenance.as_ref().map(|p| p.internet),
                "allow_internet_egress",
                "--allow-internet-egress",
                "public internet; does not itself grant LAN or host",
            ),
            (
                self.groups.lan,
                self.provenance.as_ref().map(|p| p.lan),
                "allow_lan",
                "--allow-lan",
                "Private RFC1918 + 100.64/10 + fc00::/7 reachable; does not itself enable DNS",
            ),
            (
                self.groups.host,
                self.provenance.as_ref().map(|p| p.host),
                "allow_host",
                "--allow-host",
                "host.microsandbox.internal → host 127.0.0.1 reachable; includes the host DNS resolver",
            ),
        ] {
            if enabled {
                if origin.is_some_and(|o| o.resolved.source == GrantSource::UserConfig) {
                    writeln!(
                        output,
                        "==> Egress policy: persisted grant {setting} = true ({detail})"
                    )?;
                } else {
                    writeln!(output, "==> Egress policy: {flag} enabled ({detail})")?;
                }
            } else if origin
                .is_some_and(|o| o.resolved.source == GrantSource::Cli && o.saved == Some(true))
            {
                writeln!(
                    output,
                    "==> Egress policy: {flag}=false overrides persisted grant {setting} = true"
                )?;
            }
        }
        if let Some(ports) = self.intercepted_ports() {
            // Display only: names sharing a complete effective port vector and
            // hostname sources share one line, so the TLS-only clause is stated
            // once instead of once per name. Rules stay per name (`policy`).
            struct HostnameNoticeGroup {
                ports: Vec<u16>,
                sources: Option<EntrySources>,
                names: Vec<String>,
            }
            let mut groups: Vec<HostnameNoticeGroup> = Vec::new();
            for rule in domain_rules(&self.hostnames, &ports) {
                let microsandbox_network::policy::Destination::Domain(name) = rule.destination
                else {
                    continue;
                };
                let effective: Vec<u16> = rule.ports.iter().map(|p| p.start).collect();
                let sources = self.provenance.as_ref().map(|p| p.hostname_sources(&name));
                // First-seen lookup in a Vec keeps group and name order the
                // rule traversal order; hashing would reorder display.
                match groups
                    .iter_mut()
                    .find(|group| group.ports == effective && group.sources == sources)
                {
                    Some(group) => group.names.push(name.as_str().to_owned()),
                    None => groups.push(HostnameNoticeGroup {
                        ports: effective,
                        sources,
                        names: vec![name.as_str().to_owned()],
                    }),
                }
            }
            for group in &groups {
                let names = group.names.join(", ");
                let effective = group
                    .ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                match group.sources {
                    Some(sources) => writeln!(
                        output,
                        "==> Egress policy: allowing TLS to {names} on ports {effective} ({})",
                        sources.tag()
                    )?,
                    None => writeln!(
                        output,
                        "==> Egress policy: allowing TLS to {names} on ports {effective}"
                    )?,
                }
            }
            if !groups.is_empty() {
                writeln!(
                    output,
                    "==> Egress policy: hostname allowances are TLS-only (SNI and DNS verified; no plain HTTP)"
                )?;
            }
            let effective = ports
                .to_vec()
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(
                output,
                "==> TLS interception: ports {effective} — global to every destination (TLS ClientHello with SNI required, UDP dropped, sandbox CA must be trusted). A tcp://HOST:PORT entry widens every bare hostname to PORT."
            )?;
        }
        let source = if let Some(p) = &self.provenance {
            let label = |origin: GroupOrigin, setting: &str, flag: &str| {
                if origin.resolved.source == GrantSource::UserConfig {
                    format!("persisted grant {setting}")
                } else {
                    flag.to_owned()
                }
            };
            let mut sources = Vec::new();
            if self.groups.internet {
                sources.push(label(
                    p.internet,
                    "allow_internet_egress",
                    "--allow-internet-egress",
                ));
            }
            if self.groups.host {
                sources.push(label(p.host, "allow_host", "--allow-host"));
            }
            if sources.is_empty() {
                None
            } else {
                Some(sources.join(" and "))
            }
        } else {
            match (self.groups.internet, self.groups.host) {
                (true, true) => Some("both".to_owned()),
                (true, false) => Some("--allow-internet-egress".to_owned()),
                (false, true) => Some("--allow-host".to_owned()),
                (false, false) => None,
            }
        };
        if let Some(source) = source {
            writeln!(
                output,
                "==> Egress DNS: arbitrary-name DNS queries authorized via {source} (resolver/rebind/platform constraints still apply)"
            )
        } else if self.has_hostnames() {
            writeln!(
                output,
                "==> Egress DNS: only allowed hostnames resolve (others NXDOMAIN when forwarder is available; private answers need --allow-lan or a port-less numeric allowance)"
            )
        } else {
            writeln!(
                output,
                "==> Egress DNS: queries denied (NXDOMAIN when forwarder is available; use IP or hostname allowances)"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress_grammar::{LayoutError, TargetLayout, port_from_decimal_bytes};
    use proptest::prelude::*;

    fn resolve_saved(
        groups: crate::user_network::SavedGroups,
        entries: &[&str],
        cli: CliEgress<'_>,
    ) -> EgressAuthority {
        let user = crate::user_network::UserNetwork::for_test(
            "/home/a/.config/agent-vm/config.toml",
            groups,
            entries,
        );
        EgressAuthority::resolve(cli, Some(user.egress())).unwrap()
    }
    fn empty_cli() -> CliEgress<'static> {
        CliEgress {
            internet: None,
            lan: None,
            host: None,
            allowances: &[],
        }
    }
    // Printed once per launch, after every hostname grant line: the clause is
    // about hostname allowances, not about numeric or group grants.
    const SHARED_TLS_ONLY: &str =
        "==> Egress policy: hostname allowances are TLS-only (SNI and DNS verified; no plain HTTP)";
    // Independent: the expected source and permission are enumerated, not derived by resolve.
    #[test]
    fn resolve_grant_matches_the_nine_row_table() {
        use GrantSource::*;
        for (cli, user, enabled, source) in [
            (None, None, false, Default),
            (None, Some(false), false, UserConfig),
            (None, Some(true), true, UserConfig),
            (Some(false), None, false, Cli),
            (Some(false), Some(false), false, Cli),
            (Some(false), Some(true), false, Cli),
            (Some(true), None, true, Cli),
            (Some(true), Some(false), true, Cli),
            (Some(true), Some(true), true, Cli),
        ] {
            assert_eq!(
                resolve_grant(CliGrant(cli), SavedGrant(user)),
                ResolvedGrant { enabled, source }
            );
        }
    }
    proptest! {
        #[test]
        fn resolve_grant_matches_option_precedence(cli in any::<Option<bool>>(), user in any::<Option<bool>>()) {
            prop_assert_eq!(resolve_grant(CliGrant(cli), SavedGrant(user)).enabled, cli.or(user).unwrap_or(false));
        }
    }

    // Independent rule/source oracle: literal SDK wire objects, no rule constructors.
    #[test]
    fn resolve_emits_enumerated_rules_and_sources() {
        use crate::user_network::SavedGroups;
        use serde_json::json;
        let private = json!([{"direction":"egress","destination":{"group":"private"},"protocols":[],"ports":[],"action":"allow"}]);
        let lan = SavedGroups {
            lan: Some(true),
            ..Default::default()
        };
        let cases = [
            (resolve_saved(lan, &[], empty_cli()), private, None, vec![]),
            (
                resolve_saved(
                    lan,
                    &[],
                    CliEgress {
                        lan: Some(false),
                        ..empty_cli()
                    },
                ),
                json!([]),
                None,
                vec![],
            ),
            (
                resolve_saved(
                    Default::default(),
                    &["10.0.0.5"],
                    CliEgress {
                        allowances: &["10.0.0.5/32".into(), "192.168.1.0/24".into()],
                        ..empty_cli()
                    },
                ),
                json!([
                    {"direction":"egress","destination":{"cidr":"10.0.0.5/32"},"protocols":[],"ports":[],"action":"allow"},
                    {"direction":"egress","destination":{"cidr":"192.168.1.0/24"},"protocols":[],"ports":[],"action":"allow"}
                ]),
                None,
                vec![
                    (
                        "10.0.0.5/32",
                        EntrySources {
                            user: true,
                            cli: true,
                        },
                    ),
                    (
                        "192.168.1.0/24",
                        EntrySources {
                            user: false,
                            cli: true,
                        },
                    ),
                ],
            ),
            (
                resolve_saved(
                    SavedGroups {
                        internet: Some(true),
                        ..Default::default()
                    },
                    &[],
                    empty_cli(),
                ),
                json!([
                    {"direction":"egress","destination":{"group":"host"},"protocols":["udp","tcp"],"ports":[{"start":53,"end":53}],"action":"allow"},
                    {"direction":"egress","destination":{"group":"public"},"protocols":[],"ports":[],"action":"allow"}
                ]),
                None,
                vec![],
            ),
            (
                resolve_saved(
                    Default::default(),
                    &["api.example.com"],
                    CliEgress {
                        allowances: &["tcp://api.example.com:8443".into()],
                        ..empty_cli()
                    },
                ),
                json!([{"direction":"egress","destination":{"domain":"api.example.com"},"protocols":["tcp"],"ports":[{"start":443,"end":443},{"start":8443,"end":8443}],"action":"allow"}]),
                Some(vec![443, 8443]),
                vec![
                    (
                        "api.example.com",
                        EntrySources {
                            user: true,
                            cli: false,
                        },
                    ),
                    (
                        "tcp://api.example.com:8443",
                        EntrySources {
                            user: false,
                            cli: true,
                        },
                    ),
                ],
            ),
            (
                resolve_saved(Default::default(), &[], empty_cli()),
                json!([]),
                None,
                vec![],
            ),
        ];
        for (authority, rules, ports, entries) in cases {
            assert_eq!(
                serde_json::to_value(authority.policy()).unwrap()["rules"],
                rules
            );
            assert_eq!(authority.intercepted_ports().map(|p| p.to_vec()), ports);
            assert_eq!(
                authority.sourced_entries(),
                entries
                    .into_iter()
                    .map(|(s, sources)| (s.to_owned(), sources))
                    .collect::<Vec<_>>()
            );
            assert!(authority.provenance.is_some());
        }
        let h = resolve_saved(
            Default::default(),
            &["api.example.com"],
            CliEgress {
                allowances: &["tcp://api.example.com:8443".into()],
                ..empty_cli()
            },
        );
        assert_eq!(
            h.provenance
                .as_ref()
                .unwrap()
                .hostname_sources(h.hostnames[0].domain()),
            EntrySources {
                user: true,
                cli: true
            }
        );
        let internet = resolve_saved(
            SavedGroups {
                internet: Some(true),
                ..Default::default()
            },
            &[],
            empty_cli(),
        );
        assert_eq!(
            internet.provenance.unwrap().internet.resolved.source,
            GrantSource::UserConfig
        );
    }

    #[test]
    fn resolution_union_is_canonical_deduped_and_user_first() {
        let authority = resolve_saved(
            Default::default(),
            &["10.0.0.5", "api.example.com"],
            CliEgress {
                allowances: &["10.0.0.5/32".into(), "192.168.1.0/24".into()],
                ..empty_cli()
            },
        );
        assert_eq!(
            authority.sourced_entries(),
            vec![
                (
                    "10.0.0.5/32".into(),
                    EntrySources {
                        user: true,
                        cli: true
                    }
                ),
                (
                    "192.168.1.0/24".into(),
                    EntrySources {
                        user: false,
                        cli: true
                    }
                ),
                (
                    "api.example.com".into(),
                    EntrySources {
                        user: true,
                        cli: false
                    }
                ),
            ]
        );
    }
    proptest! {
        // Independent canonical classes, not Allowance::parse as the expectation.
        #[test]
        fn canonical_union_matches_vocabulary_membership(user_bits in any::<u8>(), cli_bits in any::<u8>()) {
            let vocabulary = [
                ("10.0.0.5", "10.0.0.5/32"), ("10.0.0.5/32", "10.0.0.5/32"),
                ("API.example.com.", "api.example.com"), ("api.example.com", "api.example.com"),
                ("192.168.1.7/24", "192.168.1.0/24"), ("192.168.1.0/24", "192.168.1.0/24"),
            ];
            let user: Vec<_> = vocabulary.iter().enumerate().filter(|(i, _)| user_bits & (1 << i) != 0).map(|(_, (text, _))| *text).collect();
            let cli: Vec<String> = vocabulary.iter().enumerate().filter(|(i, _)| cli_bits & (1 << i) != 0).map(|(_, (text, _))| (*text).into()).collect();
            let expected_membership = |bits: u8, canonical: &str| vocabulary.iter().enumerate().any(|(i, (_, c))| bits & (1 << i) != 0 && *c == canonical);
            let authority = resolve_saved(Default::default(), &user, CliEgress { allowances: &cli, ..empty_cli() });
            let actual = authority.sourced_entries();
            let expected: std::collections::BTreeSet<_> = vocabulary.iter().enumerate().filter(|(i, _)| (user_bits | cli_bits) & (1 << i) != 0).map(|(_, (_, c))| *c).collect();
            prop_assert_eq!(actual.len(), expected.len());
            prop_assert_eq!(actual.iter().map(|(c, _)| c.as_str()).collect::<std::collections::BTreeSet<_>>(), expected);
            for (canonical, sources) in actual {
                prop_assert_eq!(sources, EntrySources { user: expected_membership(user_bits, &canonical), cli: expected_membership(cli_bits, &canonical) });
            }
        }
        // Metamorphic: both sides resolve; independent rule oracles above establish correctness.
        #[test]
        fn user_tier_is_metamorphic_to_equivalent_flags(
            saved in any::<[Option<bool>; 3]>(), flags in any::<[Option<bool>; 3]>(), hostname in any::<bool>(),
        ) {
            let user_entries = if hostname { vec!["10.0.0.5", "api.example.com"] } else { vec!["10.0.0.5"] };
            let cli_entries = vec!["10.0.0.5/32".into(), "192.168.1.0/24".into()];
            let resolved = resolve_saved(crate::user_network::SavedGroups { internet: saved[0], lan: saved[1], host: saved[2] }, &user_entries,
                CliEgress { internet: flags[0], lan: flags[1], host: flags[2], allowances: &cli_entries });
            let mut union: Vec<String> = user_entries.iter().map(|s| (*s).into()).collect();
            union.extend(cli_entries);
            let equivalent = EgressAuthority::from_cli(CliEgress {
                internet: Some(flags[0].or(saved[0]).unwrap_or(false)), lan: Some(flags[1].or(saved[1]).unwrap_or(false)), host: Some(flags[2].or(saved[2]).unwrap_or(false)), allowances: &union,
            }).unwrap();
            prop_assert_eq!(serde_json::to_value(resolved.policy()).unwrap(), serde_json::to_value(equivalent.policy()).unwrap());
        }
    }
    #[test]
    fn notices_with_user_table_show_provenance() {
        use crate::user_network::SavedGroups;
        const HEADER: &str = "==> Egress authority: persisted grants from \"/home/a/.config/agent-vm/config.toml\" [network] merged with this launch's flags (flags override persisted booleans and add allowances; nothing is saved)\n";
        const TLS: &str = "==> TLS interception: ports 443 — global to every destination (TLS ClientHello with SNI required, UDP dropped, sandbox CA must be trusted). A tcp://HOST:PORT entry widens every bare hostname to PORT.\n";
        let saved = SavedGroups {
            lan: Some(true),
            ..Default::default()
        };
        for row in 1..=3 {
            let cli_entries = ["10.0.0.5/32".into(), "192.168.1.0/24".into()];
            let cli = match row {
                2 => CliEgress {
                    lan: Some(false),
                    ..empty_cli()
                },
                3 => CliEgress {
                    internet: Some(true),
                    allowances: &cli_entries,
                    ..empty_cli()
                },
                _ => empty_cli(),
            };
            let authority = resolve_saved(saved, &["10.0.0.5", "api.example.com"], cli);
            let mut out = Vec::new();
            authority.write_notices(&mut out).unwrap();
            let mut expected = HEADER.to_owned();
            if row == 3 {
                expected.push_str("==> Egress policy: allowing 10.0.0.5/32 (persisted grants and --allow-egress)\n==> Egress policy: allowing 192.168.1.0/24 (--allow-egress)\n==> Egress policy: --allow-internet-egress enabled (public internet; does not itself grant LAN or host)\n");
            } else {
                expected.push_str("==> Egress policy: allowing 10.0.0.5/32 (persisted grants)\n");
            }
            if row == 2 {
                expected.push_str("==> Egress policy: --allow-lan=false overrides persisted grant allow_lan = true\n");
            } else {
                expected.push_str("==> Egress policy: persisted grant allow_lan = true (Private RFC1918 + 100.64/10 + fc00::/7 reachable; does not itself enable DNS)\n");
            }
            expected.push_str("==> Egress policy: allowing TLS to api.example.com on ports 443 (persisted grants)\n");
            expected.push_str(SHARED_TLS_ONLY);
            expected.push('\n');
            expected.push_str(TLS);
            expected.push_str(if row == 3 { "==> Egress DNS: arbitrary-name DNS queries authorized via --allow-internet-egress (resolver/rebind/platform constraints still apply)\n" }
                else { "==> Egress DNS: only allowed hostnames resolve (others NXDOMAIN when forwarder is available; private answers need --allow-lan or a port-less numeric allowance)\n" });
            assert_eq!(String::from_utf8(out).unwrap(), expected);
        }
        let mixed = resolve_saved(
            SavedGroups {
                host: Some(true),
                ..Default::default()
            },
            &[],
            CliEgress {
                internet: Some(true),
                ..empty_cli()
            },
        );
        let mut out = Vec::new();
        mixed.write_notices(&mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!(
                "{HEADER}==> Egress policy: --allow-internet-egress enabled (public internet; does not itself grant LAN or host)\n==> Egress policy: persisted grant allow_host = true (host.microsandbox.internal → host 127.0.0.1 reachable; includes the host DNS resolver)\n==> Egress DNS: arbitrary-name DNS queries authorized via --allow-internet-egress and persisted grant allow_host (resolver/rebind/platform constraints still apply)\n"
            )
        );
        let split = resolve_saved(
            Default::default(),
            &["api.example.com"],
            CliEgress {
                allowances: &["tcp://api.example.com:8443".into()],
                ..empty_cli()
            },
        );
        let mut out = Vec::new();
        split.write_notices(&mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!(
                "{HEADER}==> Egress policy: allowing TLS to api.example.com on ports 443, 8443 (persisted grants and --allow-egress)\n{SHARED_TLS_ONLY}\n==> TLS interception: ports 443, 8443 — global to every destination (TLS ClientHello with SNI required, UDP dropped, sandbox CA must be trusted). A tcp://HOST:PORT entry widens every bare hostname to PORT.\n==> Egress DNS: only allowed hostnames resolve (others NXDOMAIN when forwarder is available; private answers need --allow-lan or a port-less numeric allowance)\n"
            )
        );
    }

    /// The header names the config file the grants came from — a measured path,
    /// so a non-ASCII `$HOME` reads as itself there, and a control byte is still
    /// escaped rather than ending the line (issue #422).
    #[test]
    fn the_provenance_header_prints_a_non_ascii_config_path_as_itself() {
        use crate::user_network::{SavedGroups, UserNetwork};
        for (file, expected) in [
            (
                "/home/дом/.config/agent-vm/config.toml",
                "/home/дом/.config/agent-vm/config.toml",
            ),
            ("/home/a/bad\nconfig.toml", "/home/a/bad\\x0aconfig.toml"),
        ] {
            let user = UserNetwork::for_test(
                file,
                SavedGroups {
                    lan: Some(true),
                    ..Default::default()
                },
                &["10.0.0.5"],
            );
            let authority = EgressAuthority::resolve(empty_cli(), Some(user.egress())).unwrap();
            let mut out = Vec::new();
            authority.write_notices(&mut out).unwrap();
            let text = String::from_utf8(out).unwrap();
            let header = text.lines().next().unwrap_or_default();
            assert_eq!(
                header,
                format!(
                    "==> Egress authority: persisted grants from \"{expected}\" [network] merged with this launch's flags (flags override persisted booleans and add allowances; nothing is saved)"
                )
            );
            assert!(!header.contains("\\xd0"), "byte-escaped: {header}");
        }
    }

    // Grouping is display-only: a name shares a line only with names whose
    // complete effective port vector and hostname sources are identical.
    #[test]
    fn hostname_notices_group_by_effective_ports_and_sources() {
        use crate::user_network::SavedGroups;
        const HEADER: &str = "==> Egress authority: persisted grants from \"/home/a/.config/agent-vm/config.toml\" [network] merged with this launch's flags (flags override persisted booleans and add allowances; nothing is saved)\n";
        for (saved, cli, ports, hostnames) in [
            (
                &[
                    "b.example.com",
                    "tcp://p.example:8443",
                    "a.example.com",
                    "both.example.com",
                ][..],
                &["both.example.com", "c.example.com"][..],
                "443, 8443",
                "==> Egress policy: allowing TLS to b.example.com, a.example.com on ports 443, 8443 (persisted grants)\n==> Egress policy: allowing TLS to p.example on ports 8443 (persisted grants)\n==> Egress policy: allowing TLS to both.example.com on ports 443, 8443 (persisted grants and --allow-egress)\n==> Egress policy: allowing TLS to c.example.com on ports 443, 8443 (--allow-egress)\n",
            ),
            (
                &["tcp://n.example:8443", "tcp://m.example:9443"][..],
                &[][..],
                "443, 8443, 9443",
                "==> Egress policy: allowing TLS to n.example on ports 8443 (persisted grants)\n==> Egress policy: allowing TLS to m.example on ports 9443 (persisted grants)\n",
            ),
            (
                &["api.example.com"][..],
                &["tcp://api.example.com:443"][..],
                "443",
                "==> Egress policy: allowing TLS to api.example.com on ports 443 (persisted grants and --allow-egress)\n",
            ),
            (
                &[][..],
                &["api.example.com"][..],
                "443",
                "==> Egress policy: allowing TLS to api.example.com on ports 443 (--allow-egress)\n",
            ),
            (
                &[
                    "API.Example.COM.",
                    "api.example.com",
                    "tcp://API.example.com:8443",
                ][..],
                &[][..],
                "443, 8443",
                "==> Egress policy: allowing TLS to api.example.com on ports 443, 8443 (persisted grants)\n",
            ),
        ] {
            let cli: Vec<String> = cli.iter().map(|entry| (*entry).to_owned()).collect();
            let authority = resolve_saved(
                SavedGroups::default(),
                saved,
                CliEgress {
                    allowances: &cli,
                    ..empty_cli()
                },
            );
            let mut out = Vec::new();
            authority.write_notices(&mut out).unwrap();
            assert_eq!(
                String::from_utf8(out).unwrap(),
                format!(
                    "{HEADER}{hostnames}{SHARED_TLS_ONLY}\n==> TLS interception: ports {ports} — global to every destination (TLS ClientHello with SNI required, UDP dropped, sandbox CA must be trusted). A tcp://HOST:PORT entry widens every bare hostname to PORT.\n==> Egress DNS: only allowed hostnames resolve (others NXDOMAIN when forwarder is available; private answers need --allow-lan or a port-less numeric allowance)\n"
                )
            );
        }
    }

    #[test]
    fn trusted_port_rejects_zero_instead_of_granting_all_ports() {
        assert_eq!(trusted_port(Some(0)), Err(AllowanceError::MalformedPort));
        assert_eq!(trusted_port(None), Ok(None));
        assert_eq!(trusted_port(Some(22)).unwrap().unwrap().get(), 22);
    }

    fn port_oracle(s: &str) -> Option<u16> {
        if s.is_empty() || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse::<u32>()
            .ok()
            .filter(|p| (1..=65535).contains(p))
            .map(|p| p as u16)
    }

    #[test]
    fn port_kernel_matches_canonical_decimal_table() {
        for s in [
            "", "0", "00", "022", "+22", "-1", "1", "9", "10", "65535", "65536", "99999", "100000",
            "6553a",
        ] {
            assert_eq!(port_from_decimal_bytes(s.as_bytes()), port_oracle(s), "{s}");
        }
    }

    #[test]
    fn group_rules_match_independent_table() {
        let cases = [
            ((false, false, false), (false, false, false, false)),
            ((true, false, false), (true, true, false, false)),
            ((false, true, false), (false, false, true, false)),
            ((false, false, true), (false, false, false, true)),
            ((true, true, false), (true, true, true, false)),
            ((true, false, true), (true, true, false, true)),
            ((false, true, true), (false, false, true, true)),
            ((true, true, true), (true, true, true, true)),
        ];
        for ((internet, lan, host), (gateway_dns, public, private, expected_host)) in cases {
            assert_eq!(
                group_rules(GroupGrants {
                    internet,
                    lan,
                    host
                }),
                GroupRules {
                    gateway_dns,
                    public,
                    private,
                    host: expected_host
                }
            );
        }
    }

    mod hostname_tests;
    proptest! {
        #[test]
        fn port_kernel_matches_decimal_oracle(s in "[0-9+\\- a]{0,7}") {
            prop_assert_eq!(port_from_decimal_bytes(s.as_bytes()), port_oracle(&s));
        }
    }
    use microsandbox_network::policy::{Action, Destination, Direction, Protocol};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn authority(groups: GroupGrants, allowances: &[&str]) -> EgressAuthority {
        let raw: Vec<_> = allowances.iter().map(|s| (*s).to_owned()).collect();
        EgressAuthority::from_cli(CliEgress {
            internet: Some(groups.internet),
            lan: Some(groups.lan),
            host: Some(groups.host),
            allowances: &raw,
        })
        .unwrap()
    }
    #[test]
    fn grammar_accept_table() {
        for (input, display, transport, port) in [
            ("10.0.0.5", "10.0.0.5/32", None, None),
            ("10.0.0.5/24", "10.0.0.0/24", None, None),
            (
                "TCP://1.1.1.1",
                "tcp://1.1.1.1/32",
                Some(Transport::Tcp),
                None,
            ),
            (
                "udp://1.1.1.1",
                "udp://1.1.1.1/32",
                Some(Transport::Udp),
                None,
            ),
            (
                "udp://[fd00::/64]:123",
                "udp://[fd00::/64]:123",
                Some(Transport::Udp),
                Some(123),
            ),
            ("10.0.0.5:22", "[10.0.0.5/32]:22", None, Some(22)),
            (
                "tcp://[192.168.10.0/24]:22",
                "tcp://[192.168.10.0/24]:22",
                Some(Transport::Tcp),
                Some(22),
            ),
            ("::ffff:10.0.0.5", "10.0.0.5/32", None, None),
            ("::ffff:10.0.0.5/120", "10.0.0.0/24", None, None),
            ("::ffff:0:0/96", "0.0.0.0/0", None, None),
            ("[1.2.3.4]", "1.2.3.4/32", None, None),
            ("[10.0.0.0/24]:22", "[10.0.0.0/24]:22", None, Some(22)),
            (
                "TCP://[fd00::1]:80",
                "tcp://[fd00::1/128]:80",
                Some(Transport::Tcp),
                Some(80),
            ),
            ("[fd00::1]:80", "[fd00::1/128]:80", None, Some(80)),
            ("0.0.0.0", "0.0.0.0/32", None, None),
            ("0.0.0.0/0", "0.0.0.0/0", None, None),
            ("::", "::/128", None, None),
            ("fd00::1:80", "fd00::1:80/128", None, None),
            ("1.2.3.4:1", "[1.2.3.4/32]:1", None, Some(1)),
            ("1.2.3.4:65535", "[1.2.3.4/32]:65535", None, Some(65535)),
            ("1.2.3.4/32", "1.2.3.4/32", None, None),
            ("fd00::/128", "fd00::/128", None, None),
        ] {
            let parsed = EgressAllowance::parse(input).unwrap();
            assert_eq!(parsed.to_string(), display, "{input}");
            assert_eq!(parsed.transport, transport);
            assert_eq!(parsed.port.map(|p| p.get()), port);
            let rule = parsed.rule();
            assert_eq!(
                rule.protocols,
                transport
                    .map(Transport::protocol)
                    .into_iter()
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                rule.ports,
                port.map(microsandbox_network::policy::PortRange::single)
                    .into_iter()
                    .collect::<Vec<_>>()
            );
        }
    }
    #[test]
    fn grammar_error_precedence_table() {
        use AllowanceError::*;
        let rows: &[(AllowanceError, &[&str])] = &[
            (Empty, &[""]),
            (
                UnsupportedScheme,
                &[
                    "https://1.1.1.1",
                    "https://example.com",
                    "icmp://1.1.1.1",
                    "://1.1.1.1",
                    "tcp://udp://1.1.1.1",
                ],
            ),
            (
                MalformedAddress,
                &[
                    "[::1",
                    "[]",
                    "[]:80",
                    "[[::1]]",
                    "[::1]]",
                    "[::1]:80]",
                    "[::1]x",
                    "[::1]/64",
                    "1.2.3.4]",
                    "a[b",
                    "x[::1]",
                    "tcp://",
                    "1.2.3",
                    "10.0.0.0/33",
                    "fd00::/129",
                    "a b",
                    "1.2.3.4/x",
                    "\x1b[2J",
                    "user@1.2.3.4",
                    "1.2.3.4/path?q",
                    "fe80::1%en0",
                    ":22",
                ],
            ),
            (PortNeedsBrackets, &["10.0.0.0/24:22", "10.0.0.0/24:0"]),
            (
                MalformedPort,
                &[
                    "1.2.3.4:0",
                    "1.2.3.4:65536",
                    "1.2.3.4:022",
                    "1.2.3.4:+22",
                    "1.2.3.4:",
                    "[::1]:",
                    "[::1]:x",
                    "[::1]:0",
                    "1.2.3:0",
                    "tcp:/1.1.1.1",
                    ":0",
                ],
            ),
            (UdpHostname, &["udp://h.example", "udp://h.example:53"]),
            (HostnameDnsPort, &["h.example:53", "tcp://h.example:853"]),
            (HostAlias, &["host.microsandbox.internal."]),
            (
                MalformedAddress,
                &[
                    "[h.example]:443",
                    "*.h.example",
                    ".h.example",
                    "user@h.example",
                    "h.example/p",
                    "h.example?q",
                    "bücher.example",
                    "h.example..",
                    "1234",
                    "127.1",
                    "0x7f.1",
                ],
            ),
            (
                MalformedPort,
                &[
                    "h.example:0",
                    "h.example:022",
                    "h.example:65536",
                    "tcp://h.example:65536",
                ],
            ),
        ];
        for (error, inputs) in rows {
            for input in *inputs {
                assert_eq!(Allowance::parse(input), Err(*error), "{input}");
            }
        }
    }
    #[test]
    fn layout_kernel_exact_offsets_table() {
        for (input, scheme, offset) in [
            ("", SchemeSel::Any, 0),
            ("1.1.1.1", SchemeSel::Any, 0),
            ("tcp://x", SchemeSel::Tcp, 6),
            ("TCP://x", SchemeSel::Tcp, 6),
            ("tCp://x", SchemeSel::Tcp, 6),
            ("udp://x", SchemeSel::Udp, 6),
            ("tcp:/x", SchemeSel::Any, 0),
        ] {
            assert_eq!(split_scheme(input.as_bytes()), Ok((scheme, offset)));
        }
        for input in ["https://x", "://x", "tcp://udp://x", "x://y", "x://1.2.3.4"] {
            assert_eq!(
                split_scheme(input.as_bytes()),
                Err(LayoutError::UnsupportedScheme)
            );
        }
        for (input, whole, start, end, port) in [
            ("[::1]:22", false, 1, 4, Some(22)),
            ("1.2.3.4:22", false, 0, 7, Some(22)),
            ("fd00::1:80", true, 0, 10, None),
            ("fd00::1:80", false, 0, 10, None),
            ("1.2.3.4", true, 0, 7, None),
            ("x1.2.3.4", false, 0, 8, None),
            ("[1.2.3.4]", false, 1, 8, None),
        ] {
            assert_eq!(
                split_target(input.as_bytes(), whole),
                Ok(TargetLayout {
                    addr_start: start,
                    addr_end: end,
                    port
                })
            );
        }
        for (input, error) in [
            ("[::1]x", LayoutError::MalformedAddress),
            ("[::1", LayoutError::MalformedAddress),
            ("[]", LayoutError::MalformedAddress),
            ("[]:80", LayoutError::MalformedAddress),
            ("[[::1]]", LayoutError::MalformedAddress),
            ("[::1]]", LayoutError::MalformedAddress),
            ("[::1]:80]", LayoutError::MalformedAddress),
            ("[::1]/64", LayoutError::MalformedAddress),
            ("1.2.3.4]", LayoutError::MalformedAddress),
            ("a[b", LayoutError::MalformedAddress),
            ("x[::1]", LayoutError::MalformedAddress),
            ("10.0.0.0/24:22", LayoutError::PortNeedsBrackets),
            ("[::1]:", LayoutError::MalformedPort),
            ("[::1]:x", LayoutError::MalformedPort),
            ("[::1]:0", LayoutError::MalformedPort),
            ("", LayoutError::MalformedAddress),
            (":22", LayoutError::MalformedAddress),
            (":0", LayoutError::MalformedPort),
            ("10.0.0.0/24:0", LayoutError::PortNeedsBrackets),
        ] {
            assert_eq!(split_target(input.as_bytes(), false), Err(error));
        }
    }
    #[test]
    fn dedupe_is_canonical_and_first_occurrence_ordered() {
        let auth = authority(
            GroupGrants::default(),
            &[
                "10.0.0.5",
                "10.0.0.5/32",
                "::ffff:10.0.0.5",
                "tcp://10.0.0.5",
                "10.0.0.5/24",
            ],
        );
        assert_eq!(
            auth.allowances
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.0.0.5/32", "tcp://10.0.0.5/32", "10.0.0.0/24"]
        );
    }
    #[test]
    fn error_index_never_echoes_input() {
        let raw = ["1.1.1.1".to_owned(), "udp://example.com".to_owned()];
        let error = EgressAuthority::from_cli(CliEgress {
            internet: None,
            lan: None,
            host: None,
            allowances: &raw,
        })
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            format!("--allow-egress #2: {}", AllowanceError::UdpHostname)
        );
        assert!(!error.contains("example"));
    }
    #[test]
    fn dns_table_and_rebind_rule_shape() {
        for bits in 0..8 {
            let groups = grants(bits);
            for allowances in [&[][..], &["1.1.1.1"][..], &["tcp://[10.0.0.0/8]:53"][..]] {
                let policy = authority(groups, allowances).policy();
                for name in ["example.com", "host.microsandbox.internal"] {
                    for proto in [Protocol::Tcp, Protocol::Udp] {
                        assert_eq!(
                            policy.evaluate_dns_query(&name.parse().unwrap(), proto, 53),
                            if groups.internet || groups.host {
                                Action::Allow
                            } else {
                                Action::Deny
                            }
                        );
                    }
                }
            }
        }
        for (input, transport, port) in [
            ("10.0.0.0/8", None, None),
            ("tcp://10.0.0.0/8", Some(Transport::Tcp), None),
            ("udp://10.0.0.0/8", Some(Transport::Udp), None),
            ("[10.0.0.0/8]:443", None, Some(443)),
            ("tcp://[10.0.0.0/8]:443", Some(Transport::Tcp), Some(443)),
            ("udp://[10.0.0.0/8]:443", Some(Transport::Udp), Some(443)),
        ] {
            let rule = EgressAllowance::parse(input).unwrap().rule();
            assert_eq!(
                serde_json::to_value(&rule.destination).unwrap(),
                serde_json::to_value(Destination::Cidr("10.0.0.0/8".parse().unwrap())).unwrap()
            );
            assert_eq!(
                rule.protocols,
                transport
                    .map(Transport::protocol)
                    .into_iter()
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                rule.ports,
                port.map(microsandbox_network::policy::PortRange::single)
                    .into_iter()
                    .collect::<Vec<_>>()
            );
        }
    }
    fn grants(bits: u8) -> GroupGrants {
        GroupGrants {
            internet: bits & 1 != 0,
            lan: bits & 2 != 0,
            host: bits & 4 != 0,
        }
    }
    // Independent arithmetic model: never calls the production canonicalizer.
    fn model_canon(ip: IpAddr, prefix: u8) -> ipnetwork::IpNetwork {
        let (ip, prefix) = match ip {
            IpAddr::V6(v6) if u128::from(v6) >> 32 == 0xffff && prefix >= 96 => (
                IpAddr::V4(Ipv4Addr::from(u128::from(v6) as u32)),
                prefix - 96,
            ),
            _ => (ip, prefix),
        };
        let network = match ip {
            IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(
                u32::from(v4)
                    & if prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - prefix)
                    },
            )),
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(
                u128::from(v6)
                    & if prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - prefix)
                    },
            )),
        };
        ipnetwork::IpNetwork::new(network, prefix).unwrap()
    }
    fn address_strategy() -> impl Strategy<Value = (IpAddr, u8)> {
        prop_oneof![
            3 => (any::<u32>(),prop::sample::select(vec![96u8,120,128])).prop_map(|(v,p)| (IpAddr::V6(Ipv6Addr::from((0xffffu128 << 32) | v as u128)),p)),
            2 => prop::sample::select(vec![(IpAddr::V4(Ipv4Addr::UNSPECIFIED),0),(IpAddr::V6(Ipv6Addr::UNSPECIFIED),0),(IpAddr::V4(Ipv4Addr::UNSPECIFIED),32),(IpAddr::V6(Ipv6Addr::UNSPECIFIED),128)]),
            3 => (any::<u32>(),0u8..=32).prop_map(|(v,p)| (IpAddr::V4(Ipv4Addr::from(v)),p)),
            2 => (any::<u128>(),0u8..=128).prop_map(|(v,p)| (IpAddr::V6(Ipv6Addr::from(v)),p)),
        ]
    }
    fn transport_strategy() -> impl Strategy<Value = Option<Transport>> {
        prop::sample::select(vec![None, Some(Transport::Tcp), Some(Transport::Udp)])
    }
    fn render_input(
        ip: IpAddr,
        prefix: u8,
        transport: Option<Transport>,
        port: Option<u16>,
    ) -> String {
        let scheme = match transport {
            None => "",
            Some(Transport::Tcp) => "tcp://",
            Some(Transport::Udp) => "udp://",
        };
        match port {
            None => format!("{scheme}{ip}/{prefix}"),
            Some(p) => format!("{scheme}[{ip}/{prefix}]:{p}"),
        }
    }
    // Labels are hand-specified, including specials and Host-over-Private gateways.
    fn corpus() -> Vec<(IpAddr, &'static str)> {
        [
            ("8.8.8.8", "public"),
            ("1.1.1.1", "public"),
            ("2001:4860:4860::8888", "public"),
            ("::ffff:8.8.4.4", "public"),
            ("10.1.2.3", "private"),
            ("172.16.5.4", "private"),
            ("192.168.1.10", "private"),
            ("100.64.0.9", "private"),
            ("fd00::5", "private"),
            ("::ffff:10.1.2.3", "private"),
            ("100.64.0.1", "host"),
            ("fd00::1", "host"),
            ("127.0.0.1", "other"),
            ("::1", "other"),
            ("::ffff:127.0.0.1", "other"),
            ("169.254.1.1", "other"),
            ("fe80::1", "other"),
            ("169.254.169.254", "other"),
            ("::ffff:169.254.169.254", "other"),
            ("224.0.0.251", "other"),
            ("ff02::1", "other"),
            ("0.0.0.0", "other"),
            ("::", "other"),
        ]
        .into_iter()
        .map(|(ip, label)| (ip.parse().unwrap(), label))
        .collect()
    }
    fn allowed_oracle(
        auth: &EgressAuthority,
        ip: IpAddr,
        label: &str,
        protocol: Protocol,
        port: Option<u16>,
    ) -> bool {
        let ip = match ip {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        auth.allowances.iter().any(|a| {
            a.network.contains(ip)
                && a.transport.is_none_or(|t| t.protocol() == protocol)
                && a.port.is_none_or(|p| port == Some(p.get()))
        }) || (auth.groups.internet && label == "public")
            || (auth.groups.internet
                && label == "host"
                && port == Some(53)
                && matches!(protocol, Protocol::Tcp | Protocol::Udp))
            || (auth.groups.lan && label == "private")
            || (auth.groups.host && label == "host")
    }
    fn differential(auth: &EgressAuthority) -> usize {
        let shared = microsandbox_network::shared::SharedState::new(4);
        shared.set_gateway_ips(
            Some("100.64.0.1".parse().unwrap()),
            Some("fd00::1".parse().unwrap()),
        );
        let policy = auth.policy();
        let mut positives = 0;
        for (ip, label) in corpus() {
            for protocol in [Protocol::Tcp, Protocol::Udp] {
                for port in [22, 53, 80, 443, 8080] {
                    let expected = allowed_oracle(auth, ip, label, protocol, Some(port));
                    positives += usize::from(expected);
                    assert_eq!(
                        policy.evaluate_egress(SocketAddr::new(ip, port), protocol, &shared),
                        if expected {
                            Action::Allow
                        } else {
                            Action::Deny
                        },
                        "{ip}:{port} {protocol:?}"
                    );
                }
            }
            for protocol in [Protocol::Icmpv4, Protocol::Icmpv6] {
                let expected = allowed_oracle(auth, ip, label, protocol, None);
                assert_eq!(
                    policy.evaluate_egress_ip(ip, protocol, &shared),
                    if expected {
                        Action::Allow
                    } else {
                        Action::Deny
                    },
                    "{ip} {protocol:?}"
                );
            }
        }
        positives
    }
    #[test]
    fn runtime_differential_positive_controls() {
        let mut positives = 0;
        for bits in 0..8 {
            positives += differential(&authority(
                grants(bits),
                &["10.0.0.5", "10.0.0.5:22", "tcp://10.0.0.5"],
            ));
        }
        assert!(positives >= 200);
    }
    #[test]
    fn notices_all_combinations() {
        for bits in 0..8 {
            let g = grants(bits);
            let mut output = Vec::new();
            authority(g, &["10.0.0.5"])
                .write_notices(&mut output)
                .unwrap();
            let mut expected = "==> Egress policy: allowing 10.0.0.5/32\n".to_owned();
            if g.internet {
                expected.push_str("==> Egress policy: --allow-internet-egress enabled (public internet; does not itself grant LAN or host)\n");
            }
            if g.lan {
                expected.push_str("==> Egress policy: --allow-lan enabled (Private RFC1918 + 100.64/10 + fc00::/7 reachable; does not itself enable DNS)\n");
            }
            if g.host {
                expected.push_str("==> Egress policy: --allow-host enabled (host.microsandbox.internal → host 127.0.0.1 reachable; includes the host DNS resolver)\n");
            }
            let source = match bits & 5 {
                1 => Some("--allow-internet-egress"),
                4 => Some("--allow-host"),
                5 => Some("both"),
                _ => None,
            };
            if let Some(source) = source {
                expected.push_str(&format!("==> Egress DNS: arbitrary-name DNS queries authorized via {source} (resolver/rebind/platform constraints still apply)\n"));
            } else {
                expected.push_str("==> Egress DNS: queries denied (NXDOMAIN when forwarder is available; use IP or hostname allowances)\n");
            }
            assert_eq!(String::from_utf8(output).unwrap(), expected);
        }
    }
    proptest! {
        #[test]
        fn rejected_errors_are_fixed_text(s in any::<String>()) {
            if let Err(e) = Allowance::parse(&s) {
                prop_assert!(AllowanceError::ALL.map(|e| e.to_string()).contains(&e.to_string()));
            }
        }
        #[test]
        fn canonical_round_trip_matches_independent_masks((ip,prefix) in address_strategy(),transport in transport_strategy(),port in prop::option::of(1u16..=65535)) {
            let model = EgressAllowance { network:model_canon(ip,prefix),transport,port:port.and_then(std::num::NonZeroU16::new) };
            prop_assert_eq!(EgressAllowance::parse(&render_input(ip,prefix,transport,port)),Ok(model));
            prop_assert_eq!(EgressAllowance::parse(&model.to_string()),Ok(model));
        }
        #[test]
        fn grammar_shaped_display_is_a_fixed_point(s in "[a-zA-Z0-9:/\\[\\].+ -]{0,90}") {
            if let Ok(a) = Allowance::parse(&s) {
                let displayed = a.to_string();
                let reparsed = Allowance::parse(&displayed);
                prop_assert_eq!(&reparsed, &Ok(a));
                prop_assert_eq!(reparsed.unwrap().to_string(), displayed);
            }
        }
        #[test]
        fn rule_shape_and_runtime_differential(bits in 0u8..8, specs in prop::collection::vec((prop::sample::select(corpus()),0u8..=32,transport_strategy(),prop::option::of(prop::sample::select(vec![22u16,53,80,443,8080]))),0..5)) {
            let raw: Vec<_> = specs.into_iter().map(|((ip,_),prefix,t,p)| render_input(ip,prefix,t,p)).collect();
            let g = grants(bits);
            let auth = EgressAuthority::from_cli(CliEgress { internet:Some(g.internet),lan:Some(g.lan),host:Some(g.host),allowances:&raw }).unwrap();
            let policy = auth.policy();
            prop_assert_eq!(policy.default_egress,Action::Deny);
            prop_assert_eq!(policy.default_ingress,Action::Allow);
            prop_assert!(!policy.has_domain_rules());
            prop_assert_eq!(policy.rules.len(),auth.allowances.len()+2*usize::from(g.internet)+usize::from(g.lan)+usize::from(g.host));
            prop_assert!(policy.rules.iter().all(|r| r.direction == Direction::Egress && r.action == Action::Allow));
            differential(&auth);
        }
        #[test]
        fn narrowing_input_never_loses_filters((ip,prefix) in address_strategy(),transport in transport_strategy(),port in prop::option::of(1u16..=65535), bare_host_port in any::<bool>()) {
            let input = if bare_host_port && ip.is_ipv4() && port.is_some() {
                let scheme = match transport { None => "", Some(Transport::Tcp) => "tcp://", Some(Transport::Udp) => "udp://" };
                format!("{scheme}{ip}:{}", port.unwrap())
            } else { render_input(ip,prefix,transport,port) };
            for mutated in [input.clone(),input.replace("tcp://","TCP://").replace("udp://","uDp://"),input.replace('[',"[["),input.replace("]:","]::")] {
                if let Ok(a) = EgressAllowance::parse(&mutated) {
                    if let Some(t) = transport { prop_assert_eq!(a.rule().protocols,vec![t.protocol()]); }
                    if let Some(p) = port { prop_assert_eq!(a.rule().ports,vec![microsandbox_network::policy::PortRange::single(p)]); }
                }
            }
        }
    }
}
