//! Launch networking configuration, validation, and lifecycle reporting.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use microsandbox::{Sandbox, sandbox::SandboxBuilder};

/// Networking options flattened into the launch command.
#[derive(ClapArgs)]
#[group(id = "network")]
pub(crate) struct Args {
    /// Publish a guest TCP port to the host, docker-style (repeatable).
    ///
    /// Format `[HOST_BIND:]HOST_PORT:GUEST_PORT`. HOST_BIND defaults to
    /// `127.0.0.1` — pass `0.0.0.0:HOST_PORT:GUEST_PORT` to expose on
    /// every host interface.
    ///
    /// The guest service must listen on `0.0.0.0` (or the assigned
    /// guest IP from `MSB_NET_IPV4`); a bare `127.0.0.1` bind inside
    /// the guest is not reachable because the smoltcp dial target is
    /// the guest's assigned VLAN address, not loopback.
    #[arg(
        long = "publish",
        short = 'p',
        value_name = "[BIND:]HOST_PORT:GUEST_PORT",
        help_heading = "Mounts & ports"
    )]
    pub(crate) publish: Vec<String>,

    /// Auto-forward every guest listener onto the host (Lima-style).
    ///
    /// The runtime polls `/proc/net/tcp{,6}` inside the guest every ~2s
    /// and mirrors each detected wildcard (`0.0.0.0`/`[::]`) OR
    /// loopback (`127.0.0.1`/`[::1]`) TCP LISTEN socket onto a
    /// host listener at `127.0.0.1:<same port>` (or an ephemeral
    /// host port if the preferred one is taken). Loopback-only
    /// guest services are reachable via an in-guest agentd
    /// forwarder (`eth0_ip:port → 127.0.0.1:port`) — so anything
    /// listening inside the guest, whether on the wildcard
    /// interface or just loopback, becomes reachable on host
    /// `127.0.0.1`. agent-vm prints each new mapping to stderr as
    /// the runtime emits `PortEvent`s. Off by default.
    ///
    /// Security note: with this flag, every TCP service that
    /// becomes reachable inside the guest is also reachable from
    /// other processes on the host's loopback. If you don't want
    /// that, omit `--auto-publish` and use `--publish` to expose
    /// only the specific ports you mean to share.
    #[arg(
        long = "auto-publish",
        default_value_t = false,
        help_heading = "Mounts & ports"
    )]
    pub(crate) auto_publish: bool,

    /// Allow guest egress to one IP or CIDR (repeatable).
    ///
    /// Examples: `--allow-egress 10.100.1.75` (single host),
    /// `--allow-egress 10.100.1.0/24` (CIDR),
    /// `--allow-egress fd00::1/128` (IPv6).
    ///
    /// The default policy (`NetworkPolicy::from_profiles([Public])`)
    /// only allows DNS and the `Public` destination group, so RFC1918
    /// (10/8, 172.16/12, 192.168/16, 100.64/10), loopback, link-
    /// local, and metadata addresses are all denied with
    /// ECONNREFUSED. Use this flag to reach a specific dev box on
    /// the same LAN as the host. Use `--allow-lan` instead if you
    /// want to open the entire Private group at once.
    #[arg(
        long = "allow-egress",
        value_name = "IP|CIDR",
        help_heading = "Network egress"
    )]
    pub(crate) allow_egress: Vec<String>,

    /// Allow guest egress to the whole private LAN.
    ///
    /// Switches the egress policy from `from_profiles([Public])` to
    /// `from_profiles([Public, Private])` — adds the entire
    /// `DestinationGroup::Private` (10/8, 172.16/12, 192.168/16,
    /// 100.64/10, fc00::/7) to the allow list. Coarser than
    /// `--allow-egress <CIDR>`; useful for "trust everything on my
    /// LAN". Loopback, link-local, and metadata are still denied.
    ///
    /// Security note: a compromised in-guest process gets full
    /// access to every device on your LAN with this flag. Prefer
    /// `--allow-egress <CIDR>` for production-ish uses.
    #[arg(
        long = "allow-lan",
        default_value_t = false,
        help_heading = "Network egress"
    )]
    pub(crate) allow_lan: bool,

    /// Allow the guest to reach the host's 127.0.0.1 services.
    ///
    /// The smoltcp stack rewrites the per-sandbox gateway IP
    /// (resolves as `host.microsandbox.internal` inside the guest)
    /// to host's loopback, so e.g. a dev server bound to
    /// `127.0.0.1:8080` on the host becomes reachable from the guest
    /// at `host.microsandbox.internal:8080`. Adds the
    /// `DestinationGroup::Host` (the gateway IP only) to the allow
    /// list; loopback, link-local, metadata, and the wider LAN
    /// remain denied.
    ///
    /// Security note: anything bound to the host's loopback —
    /// including admin UIs, dev DBs, the Docker socket if it's
    /// listening on a TCP port — becomes reachable from a possibly-
    /// compromised in-guest process. Use only when you actually need
    /// it.
    #[arg(
        long = "allow-host",
        default_value_t = false,
        help_heading = "Network egress"
    )]
    pub(crate) allow_host: bool,
}

/// Validated networking intent for one sandbox launch.
#[derive(Debug)]
pub(crate) struct Plan {
    publish_ports: Vec<PublishPort>,
    egress_policy: Option<microsandbox::NetworkPolicy>,
    auto_publish: bool,
    allow_lan: bool,
    allow_host: bool,
    proxy_notice: Option<ProxyNotice>,
}

#[derive(Debug)]
struct ProxyNotice {
    variable: &'static str,
    value: ProxyDisplay,
}

/// A proxy value that is safe to retain and render in user-visible output.
///
/// The process environment is untrusted input here: malformed values could
/// hide userinfo after a fake path separator, and control bytes would affect
/// terminal output. We retain only a validated authority with its userinfo
/// removed; everything else becomes a fixed placeholder.
#[derive(Debug)]
struct ProxyDisplay(String);

impl std::fmt::Display for ProxyDisplay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl ProxyDisplay {
    const MALFORMED: &'static str = "<redacted malformed proxy value>";

    fn parse(raw: &str) -> Self {
        if raw.chars().any(char::is_control) {
            return Self(Self::MALFORMED.into());
        }
        let (scheme_prefix, remainder) = match raw.split_once("://") {
            Some((scheme, remainder)) if valid_proxy_scheme(scheme) => {
                (format!("{scheme}://"), remainder)
            }
            Some(_) => return Self(Self::MALFORMED.into()),
            // The connector accepts a missing scheme as HTTP-compatible.
            None => (String::new(), raw),
        };
        let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        let (authority, tail) = remainder.split_at(authority_end);
        let authority = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host)
            .trim();
        if !valid_proxy_authority(authority) {
            return Self(Self::MALFORMED.into());
        }
        Self(format!("{scheme_prefix}{authority}{tail}"))
    }
}

fn valid_proxy_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic())
        && chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
}

/// Mirrors the connector's accepted host/port grammar without retaining
/// userinfo. Keeping these accepted forms aligned makes the diagnostic useful
/// for a proxy that the runtime can actually select.
fn valid_proxy_authority(authority: &str) -> bool {
    if authority.is_empty() {
        return false;
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((address, suffix)) = bracketed.split_once(']') else {
            return false;
        };
        return address.parse::<std::net::Ipv6Addr>().is_ok() && valid_proxy_port(suffix, true);
    }
    if authority.matches(':').count() > 1 {
        return authority.parse::<std::net::Ipv6Addr>().is_ok();
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            valid_proxy_host(host) && valid_proxy_port(port, false)
        }
        Some(_) => false,
        None => valid_proxy_host(authority),
    }
}

fn valid_proxy_host(host: &str) -> bool {
    !host
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn valid_proxy_port(value: &str, bracketed: bool) -> bool {
    let value = if bracketed {
        if value.is_empty() {
            return true;
        }
        let Some(value) = value.strip_prefix(':').filter(|value| !value.is_empty()) else {
            return false;
        };
        value
    } else {
        value
    };
    value.parse::<u16>().is_ok_and(|port| port != 0)
}

impl Plan {
    /// Parses CLI networking input and observes proxy environment variables.
    ///
    /// Proxy lookup is ambient because the vendored netstack uses the process
    /// environment too; only a trimmed, credential-free rendering is retained.
    pub(crate) fn from_args(args: Args) -> Result<Self> {
        Self::from_args_with_proxy_lookup(args, |variable| std::env::var(variable).ok())
    }

    fn from_args_with_proxy_lookup(
        args: Args,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        let publish_ports = parse_publish_args(&args.publish).context("parsing --publish")?;
        let allow_egress_cidrs =
            parse_allow_egress(&args.allow_egress).context("parsing --allow-egress")?;
        let egress_policy =
            build_egress_policy(args.allow_lan, args.allow_host, &allow_egress_cidrs);
        let proxy_notice = active_guest_proxy_var_from(lookup)
            .map(|(variable, value)| ProxyNotice { variable, value });
        Ok(Self {
            publish_ports,
            egress_policy,
            auto_publish: args.auto_publish,
            allow_lan: args.allow_lan,
            allow_host: args.allow_host,
            proxy_notice,
        })
    }

    pub(crate) fn emit_launch_notices(&self) -> std::io::Result<()> {
        self.emit_launch_notices_to(&mut std::io::stderr().lock())
    }

    fn emit_launch_notices_to(&self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        for port in &self.publish_ports {
            writeln!(
                output,
                "==> Publishing host {}:{}/{} → guest :{}",
                port.host_bind,
                port.host_port,
                port.protocol.name(),
                port.guest_port,
            )?;
        }
        if let Some(policy) = &self.egress_policy {
            for rule in &policy.rules {
                if let microsandbox_network::policy::Destination::Cidr(cidr) = rule.destination {
                    writeln!(output, "==> Egress policy: allowing {cidr}")?;
                }
            }
        }
        if self.allow_lan {
            writeln!(
                output,
                "==> Egress policy: --allow-lan enabled (Private RFC1918 + 100.64/10 + fc00::/7 reachable)"
            )?;
        }
        if self.allow_host {
            writeln!(
                output,
                "==> Egress policy: --allow-host enabled (host.microsandbox.internal → host 127.0.0.1 reachable)"
            )?;
        }
        if let Some(proxy) = &self.proxy_notice {
            writeln!(
                output,
                "==> Guest egress proxy: {}={} (used when it parses as an http:// proxy; NO_PROXY honored, otherwise egress goes direct)",
                proxy.variable, proxy.value
            )?;
        }
        Ok(())
    }

    pub(crate) fn apply_to(&self, builder: SandboxBuilder) -> SandboxBuilder {
        if self.egress_policy.is_none() && self.publish_ports.is_empty() && !self.auto_publish {
            return builder;
        }
        let policy = self.egress_policy.clone();
        let publish_ports = self.publish_ports.clone();
        let auto_publish = self.auto_publish;
        let enable_tls = !publish_ports.is_empty();
        builder.network(move |mut network| {
            if let Some(policy) = policy {
                network = network.policy(policy);
            }
            // TlsBuilder defaults to enabled, so only opt in for explicit ports.
            if enable_tls {
                network = network.tls(|tls| tls);
            }
            for port in &publish_ports {
                network = match port.protocol {
                    PublishProto::Tcp => {
                        network.port_bind(port.host_bind, port.host_port, port.guest_port)
                    }
                    PublishProto::Udp => {
                        network.port_udp_bind(port.host_bind, port.host_port, port.guest_port)
                    }
                };
            }
            if auto_publish {
                network = network.auto_publish();
            }
            network
        })
    }

    pub(crate) fn start_event_reporting(&self, sandbox: &Sandbox) -> std::io::Result<()> {
        let sandbox = sandbox.clone();
        self.start_event_reporting_with(
            move || async move { sandbox.port_events().await },
            StderrWriter,
            |reporter| {
                // Detaching is intentional: reporting follows the sandbox lifetime,
                // rather than the initial attach/exec request.
                std::mem::drop(tokio::spawn(reporter));
            },
        )
    }

    fn start_event_reporting_with<Subscribe, Events, Spawn>(
        &self,
        subscribe: Subscribe,
        mut output: impl std::io::Write + Send + 'static,
        spawn: Spawn,
    ) -> std::io::Result<()>
    where
        Subscribe: FnOnce() -> Events + Send + 'static,
        Events: std::future::Future<
                Output = tokio::sync::mpsc::UnboundedReceiver<
                    microsandbox::protocol::network::PortEvent,
                >,
            > + Send
            + 'static,
        Spawn: FnOnce(std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>),
    {
        if !self.auto_publish {
            return Ok(());
        }
        writeln!(
            output,
            "==> auto-publish: watching guest LISTEN sockets via /proc/net/tcp{{,6}}"
        )?;
        spawn(Box::pin(async move {
            // This must remain the sole subscription: a second subscriber replaces it.
            let events = subscribe().await;
            if let Err(error) = report_port_events(events, &mut output).await {
                // The detached reporter cannot return to launch. Its explicit terminal
                // policy is to report the output failure and stop this reporter.
                tracing::error!(%error, "auto-publish event reporting stopped after terminal output failure");
            }
        }));
        Ok(())
    }
}

struct StderrWriter;

impl std::io::Write for StderrWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        std::io::stderr().write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

async fn report_port_events(
    mut events: tokio::sync::mpsc::UnboundedReceiver<microsandbox::protocol::network::PortEvent>,
    output: &mut impl std::io::Write,
) -> std::io::Result<()> {
    use microsandbox::protocol::network::PortEvent;

    while let Some(event) = events.recv().await {
        match event {
            PortEvent::Added {
                host_bind,
                host_port,
                guest_port,
            } => writeln!(
                output,
                "==> auto-published guest :{guest_port} -> host {host_bind}:{host_port}"
            )?,
            PortEvent::Removed { guest_port, .. } => {
                writeln!(output, "==> auto-publish removed :{guest_port}")?
            }
        }
    }
    Ok(())
}

/// One `--publish [HOST_BIND:]HOST_PORT:GUEST_PORT[/proto]` entry, parsed.
#[derive(Clone, Debug)]
struct PublishPort {
    host_bind: std::net::IpAddr,
    host_port: u16,
    guest_port: u16,
    protocol: PublishProto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishProto {
    Tcp,

    #[allow(dead_code)]
    Udp,
}

impl PublishProto {
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Parse `--publish` entries. Accepts docker-style:
///   `HOST_PORT:GUEST_PORT`                 → 127.0.0.1 bind, TCP
///   `HOST_IP:HOST_PORT:GUEST_PORT`         → explicit IPv4 bind
///   `[HOST_IP6]:HOST_PORT:GUEST_PORT`      → explicit IPv6 bind (bracket form)
///   any of the above + `/tcp` (UDP rejected — not implemented)
///
/// The connection enters the smoltcp in-process stack as a dial to
/// the guest's assigned MSB_NET_IPV4 (or v6) on `GUEST_PORT`, so the
/// in-guest service has to listen on `0.0.0.0`/`::` (or that exact
/// guest IP) — a bare `127.0.0.1` bind inside the guest is not
/// reachable from the publisher.
///
/// `/udp` is parsed but REJECTED with a clear error: the underlying
/// `PortPublisher::spawn_listener_one` short-circuits non-TCP ports
/// silently, so silently accepting `/udp` would leave the user with
/// a "published" port that has no listener. When UDP support lands
/// upstream, drop the rejection here.
fn parse_publish_args(raw: &[String]) -> Result<Vec<PublishPort>> {
    use std::net::IpAddr;
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let (body, proto) = match entry.rsplit_once('/') {
            Some((b, p)) if matches!(p, "tcp" | "udp" | "TCP" | "UDP") => {
                (b, p.to_ascii_lowercase())
            }
            _ => (entry.as_str(), "tcp".to_string()),
        };
        if proto == "udp" {
            anyhow::bail!(
                "--publish {entry:?}: UDP is not yet supported by the underlying smoltcp \
                 PortPublisher; remove `/udp` to publish a TCP port instead"
            );
        }
        let protocol = PublishProto::Tcp;

        // Split off an IPv6 bracketed prefix first (docker convention)
        // so `[::1]:8080:80` doesn't trip the generic colon split.
        let (host_bind, rest) = if let Some(after_bracket) = body.strip_prefix('[') {
            let (v6_str, after) = after_bracket.split_once("]:").ok_or_else(|| {
                anyhow::anyhow!(
                    "--publish {entry:?}: bracketed IPv6 must be `[ADDR]:HOST_PORT:GUEST_PORT`"
                )
            })?;
            let addr = v6_str.parse::<std::net::Ipv6Addr>().with_context(|| {
                format!("--publish {entry:?}: HOST_BIND {v6_str:?} is not an IPv6")
            })?;
            (Some(IpAddr::V6(addr)), after)
        } else {
            (None, body)
        };

        let parts: Vec<&str> = rest.split(':').collect();
        let (host_bind, host_port, guest_port) = match (host_bind, parts.as_slice()) {
            (Some(bind), [h, g]) => (
                bind,
                parse_port(entry, "HOST_PORT", h)?,
                parse_port(entry, "GUEST_PORT", g)?,
            ),
            (None, [h, g]) => (
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                parse_port(entry, "HOST_PORT", h)?,
                parse_port(entry, "GUEST_PORT", g)?,
            ),
            (None, [ip, h, g]) => (
                ip.parse::<IpAddr>().with_context(|| {
                    format!("--publish {entry:?}: HOST_BIND {ip:?} is not an IP")
                })?,
                parse_port(entry, "HOST_PORT", h)?,
                parse_port(entry, "GUEST_PORT", g)?,
            ),
            _ => anyhow::bail!(
                "--publish {entry:?} must be [HOST_BIND:]HOST_PORT:GUEST_PORT or \
                 [IPv6_BIND]:HOST_PORT:GUEST_PORT"
            ),
        };
        if host_port == 0 || guest_port == 0 {
            anyhow::bail!("--publish {entry:?}: port 0 is not allowed");
        }
        out.push(PublishPort {
            host_bind,
            host_port,
            guest_port,
            protocol,
        });
    }
    Ok(out)
}

fn parse_port(entry: &str, field: &str, s: &str) -> Result<u16> {
    s.parse::<u16>()
        .with_context(|| format!("--publish {entry:?}: {field} {s:?} is not a u16"))
}

/// Parse `--allow-egress` entries. Each entry is an IP literal or
/// a CIDR (e.g. `10.100.1.75` or `10.100.1.0/24`). A bare IP is
/// expanded to a /32 (v4) or /128 (v6) CIDR — that matches the
/// shape the policy builder's `Destination::Cidr` expects.
fn parse_allow_egress(raw: &[String]) -> Result<Vec<ipnetwork::IpNetwork>> {
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        // Try CIDR first (foo/N); fall back to bare IP.
        let cidr = if entry.contains('/') {
            entry
                .parse::<ipnetwork::IpNetwork>()
                .with_context(|| format!("--allow-egress {entry:?}: not a valid CIDR"))?
        } else {
            let ip: std::net::IpAddr = entry
                .parse()
                .with_context(|| format!("--allow-egress {entry:?}: not an IP address or CIDR"))?;
            // /32 for v4, /128 for v6 — single-host rule.
            ipnetwork::IpNetwork::from(ip)
        };
        out.push(cidr);
    }
    Ok(out)
}

/// Egress policy for the requested overrides, or `None` when none were
/// requested — leaves the SDK default `NetworkPolicy::from_profiles([Public])`
/// untouched rather than installing an equivalent-but-distinct policy, so a
/// plain launch's egress behavior can never silently drift from the SDK
/// default as that default evolves.
///
/// `--allow-lan` adds `NetworkProfile::Private`, `--allow-host` adds
/// `NetworkProfile::Host`, and each `--allow-egress` CIDR becomes a
/// `Rule::allow_egress(Destination::Cidr(..))` prepended ahead of the
/// profile-derived rules. `Public` is always retained.
fn build_egress_policy(
    allow_lan: bool,
    allow_host: bool,
    allow_egress_cidrs: &[ipnetwork::IpNetwork],
) -> Option<microsandbox::NetworkPolicy> {
    if !allow_lan && !allow_host && allow_egress_cidrs.is_empty() {
        return None;
    }
    use microsandbox::NetworkProfile;
    use microsandbox_network::policy::{Destination, Rule};

    let mut profiles = vec![NetworkProfile::Public];
    if allow_lan {
        profiles.push(NetworkProfile::Private);
    }
    if allow_host {
        profiles.push(NetworkProfile::Host);
    }
    let mut policy = microsandbox::NetworkPolicy::from_profiles(profiles);

    // Prepend the explicit CIDR allows ahead of the profile-derived group
    // rules. NOTE: with every rule here an `allow` under the policy's
    // `default_egress == Deny`, allow-list ORDER is functionally inert today
    // (the first matching allow wins, and every candidate rule allows) — this
    // is kept only so a future `deny` rule inserted here would take
    // precedence over the group rules, not because correctness needs it now.
    let mut cidr_rules: Vec<Rule> = allow_egress_cidrs
        .iter()
        .map(|net| Rule::allow_egress(Destination::Cidr(*net)))
        .collect();
    cidr_rules.append(&mut policy.rules);
    policy.rules = cidr_rules;
    Some(policy)
}

/// Pure proxy lookup, taking a function instead of reading the real process
/// environment so tests don't need unsafe
/// `std::env::set_var`/`remove_var` mutation under `cargo test`'s parallel
/// threads.
fn active_guest_proxy_var_from(
    lookup: impl Fn(&str) -> Option<String>,
) -> Option<(&'static str, ProxyDisplay)> {
    for (upper, lower) in [
        ("HTTPS_PROXY", "https_proxy"),
        ("HTTP_PROXY", "http_proxy"),
        ("ALL_PROXY", "all_proxy"),
    ] {
        // Lowercase first, matching the netstack's own preference — the
        // banner must name the variable the netstack will actually use.
        for var in [lower, upper] {
            if let Some(value) = lookup(var) {
                let value = value.trim();
                if !value.is_empty() {
                    return Some((var, ProxyDisplay::parse(value)));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    fn args() -> Args {
        Args {
            publish: Vec::new(),
            auto_publish: false,
            allow_egress: Vec::new(),
            allow_lan: false,
            allow_host: false,
        }
    }

    fn plan(input: Args) -> Plan {
        Plan::from_args_with_proxy_lookup(input, |_| None).expect("valid networking plan")
    }

    fn test_builder(name: &str) -> SandboxBuilder {
        Sandbox::builder(name).image("example.invalid/network-test:latest")
    }

    async fn configured_network(input: Args, name: &str) -> serde_json::Value {
        let config = plan(input)
            .apply_to(test_builder(name))
            .build()
            .await
            .expect("network config");
        serde_json::to_value(config.spec.network).expect("network serializes")
    }

    fn notice_output(input: Args, proxy: impl Fn(&str) -> Option<String>) -> String {
        let plan = Plan::from_args_with_proxy_lookup(input, proxy).expect("valid networking plan");
        let mut output = Vec::new();
        plan.emit_launch_notices_to(&mut output)
            .expect("notice output");
        String::from_utf8(output).expect("UTF-8 notices")
    }

    fn policy_groups(network: &serde_json::Value) -> Vec<String> {
        network["policy"]["rules"]
            .as_array()
            .expect("policy rules")
            .iter()
            .filter(|rule| rule["ports"] == serde_json::json!([]))
            .filter_map(|rule| rule["destination"]["group"].as_str())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn plan_rejects_publish_grammar_with_exact_errors() {
        for (value, expected) in [
            (
                "53:53/udp",
                "parsing --publish: --publish \"53:53/udp\": UDP is not yet supported by the underlying smoltcp PortPublisher; remove `/udp` to publish a TCP port instead",
            ),
            (
                "80",
                "parsing --publish: --publish \"80\" must be [HOST_BIND:]HOST_PORT:GUEST_PORT or [IPv6_BIND]:HOST_PORT:GUEST_PORT",
            ),
            (
                "a:b",
                "parsing --publish: --publish \"a:b\": HOST_PORT \"a\" is not a u16: invalid digit found in string",
            ),
            (
                "0:80",
                "parsing --publish: --publish \"0:80\": port 0 is not allowed",
            ),
            (
                "80:0",
                "parsing --publish: --publish \"80:0\": port 0 is not allowed",
            ),
            (
                "999999:80",
                "parsing --publish: --publish \"999999:80\": HOST_PORT \"999999\" is not a u16: number too large to fit in target type",
            ),
            (
                "[::1:8080:80",
                "parsing --publish: --publish \"[::1:8080:80\": bracketed IPv6 must be `[ADDR]:HOST_PORT:GUEST_PORT`",
            ),
        ] {
            let error = Plan::from_args_with_proxy_lookup(
                Args {
                    publish: vec![value.into()],
                    ..args()
                },
                |_| None,
            )
            .expect_err("invalid publish input is rejected");
            assert_eq!(format!("{error:#}"), expected, "{value}");
        }
    }

    #[test]
    fn plan_retains_allow_egress_parse_context() {
        let error = Plan::from_args_with_proxy_lookup(
            Args {
                allow_egress: vec!["not-an-ip".into()],
                ..args()
            },
            |_| None,
        )
        .expect_err("invalid CIDR is rejected");
        assert!(format!("{error:#}").starts_with("parsing --allow-egress:"));
    }

    #[tokio::test]
    async fn default_plan_leaves_builder_network_config_unchanged() {
        let baseline = test_builder("network-default")
            .build()
            .await
            .expect("baseline config");
        let applied = plan(args())
            .apply_to(test_builder("network-default"))
            .build()
            .await
            .expect("applied config");
        assert_eq!(
            serde_json::to_value(applied.spec.network).expect("serializable config"),
            serde_json::to_value(baseline.spec.network).expect("serializable config")
        );
    }

    #[tokio::test]
    async fn plan_applies_publish_bindings_and_tls_to_structured_config() {
        let mut input = args();
        input.publish = vec![
            "8080:3000".into(),
            "0.0.0.0:8081:3001/tcp".into(),
            "[::1]:8082:3002".into(),
            "[::]:8083:3003/TCP".into(),
        ];
        let network = configured_network(input, "network-publish").await;
        assert_eq!(network["tls"]["enabled"], true);
        assert_eq!(
            network["ports"],
            serde_json::json!([
                {"host_port": 8080, "guest_port": 3000, "protocol": "tcp", "host_bind": "127.0.0.1"},
                {"host_port": 8081, "guest_port": 3001, "protocol": "tcp", "host_bind": "0.0.0.0"},
                {"host_port": 8082, "guest_port": 3002, "protocol": "tcp", "host_bind": "::1"},
                {"host_port": 8083, "guest_port": 3003, "protocol": "tcp", "host_bind": "::"},
            ])
        );
    }

    #[tokio::test]
    async fn plan_egress_overrides_preserve_policy_defaults_dns_groups_and_cidr_order() {
        let mut input = args();
        input.publish.push("8080:3000".into());
        input.allow_egress = vec!["10.0.0.5".into(), "fd00::1".into()];
        input.allow_lan = true;
        input.allow_host = true;
        let network = configured_network(input, "network-policy").await;
        let policy = &network["policy"];
        assert_eq!(policy["default_egress"], "deny");
        assert_eq!(policy["default_ingress"], "allow");
        assert_eq!(
            policy["rules"][0]["destination"]["cidr"],
            serde_json::json!("10.0.0.5/32")
        );
        assert_eq!(
            policy["rules"][1]["destination"]["cidr"],
            serde_json::json!("fd00::1/128")
        );
        let groups = policy_groups(&network);
        assert_eq!(groups, ["public", "private", "host"]);
        assert_eq!(
            policy["rules"][2],
            serde_json::json!({
                "direction": "egress",
                "destination": {"group": "host"},
                "protocols": ["udp", "tcp"],
                "ports": [{"start": 53, "end": 53}],
                "action": "allow",
            })
        );
        assert_eq!(network["tls"]["enabled"], true);
        assert_eq!(network["ports"][0]["host_port"], 8080);
        assert_eq!(network["ports"][0]["guest_port"], 3000);
    }

    #[tokio::test]
    async fn plan_preserves_explicit_ipv4_and_ipv6_egress_cidrs_in_config() {
        let network = configured_network(
            Args {
                allow_egress: vec!["10.20.30.0/24".into(), "2001:db8:1234::/48".into()],
                ..args()
            },
            "network-explicit-cidrs",
        )
        .await;
        let rules = network["policy"]["rules"].as_array().expect("policy rules");
        assert_eq!(
            rules[0]["destination"]["cidr"],
            serde_json::json!("10.20.30.0/24")
        );
        assert_eq!(
            rules[1]["destination"]["cidr"],
            serde_json::json!("2001:db8:1234::/48")
        );
    }

    #[tokio::test]
    async fn each_egress_override_changes_only_its_requested_group() {
        for (name, input, expected_groups) in [
            (
                "cidr",
                Args {
                    publish: vec!["8080:3000".into()],
                    allow_egress: vec!["10.0.0.5".into()],
                    ..args()
                },
                vec!["public"],
            ),
            (
                "lan",
                Args {
                    publish: vec!["8080:3000".into()],
                    allow_lan: true,
                    ..args()
                },
                vec!["public", "private"],
            ),
            (
                "host",
                Args {
                    publish: vec!["8080:3000".into()],
                    allow_host: true,
                    ..args()
                },
                vec!["public", "host"],
            ),
        ] {
            let network = configured_network(input, &format!("network-{name}")).await;
            assert_eq!(policy_groups(&network), expected_groups, "{name}");
            assert_eq!(network["policy"]["default_ingress"], "allow", "{name}");
            assert_eq!(network["tls"]["enabled"], true, "{name}");
            assert_eq!(
                network["ports"],
                serde_json::json!([
                    {"host_port": 8080, "guest_port": 3000, "protocol": "tcp", "host_bind": "127.0.0.1"},
                ]),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn only_explicit_publish_enables_tls_and_auto_publish_is_configured() {
        for (name, input) in [
            (
                "egress",
                Args {
                    allow_egress: vec!["10.0.0.5".into()],
                    ..args()
                },
            ),
            (
                "auto-publish",
                Args {
                    auto_publish: true,
                    ..args()
                },
            ),
        ] {
            let network = configured_network(input, &format!("network-tls-{name}")).await;
            assert_eq!(
                network["tls"]["enabled"], false,
                "{name} must not enable TLS"
            );
        }
        let network = configured_network(
            Args {
                auto_publish: true,
                ..args()
            },
            "network-auto-publish",
        )
        .await;
        assert_eq!(network["auto_publish"]["poll_interval_ms"], 2000);
        assert_eq!(network["auto_publish"]["host_bind"], "127.0.0.1");
    }

    #[test]
    fn plan_notices_preserve_order_and_proxy_precedence_without_secrets() {
        let mut input = args();
        input.publish.push("8080:3000".into());
        input.allow_egress.push("10.0.0.5".into());
        input.allow_lan = true;
        input.allow_host = true;
        let output = notice_output(input, |variable| match variable {
            "https_proxy" => Some(" http://alice:hunter2@proxy.example:3128/path@kept ".into()),
            _ => None,
        });
        assert_eq!(
            output,
            "==> Publishing host 127.0.0.1:8080/tcp → guest :3000\n\
==> Egress policy: allowing 10.0.0.5/32\n\
==> Egress policy: --allow-lan enabled (Private RFC1918 + 100.64/10 + fc00::/7 reachable)\n\
==> Egress policy: --allow-host enabled (host.microsandbox.internal → host 127.0.0.1 reachable)\n\
==> Guest egress proxy: https_proxy=http://proxy.example:3128/path@kept (used when it parses as an http:// proxy; NO_PROXY honored, otherwise egress goes direct)\n"
        );
        assert!(!output.contains("alice"));
        assert!(!output.contains("hunter2"));
    }

    struct ProxyNoticeCase {
        name: &'static str,
        values: &'static [(&'static str, &'static str)],
        selected: &'static str,
    }

    #[test]
    fn plan_proxy_notices_cover_blank_precedence_ipv6_and_unsupported_schemes() {
        let cases = [
            ProxyNoticeCase {
                name: "absent",
                values: &[],
                selected: "",
            },
            ProxyNoticeCase {
                name: "blank",
                values: &[("https_proxy", " \t ")],
                selected: "",
            },
            ProxyNoticeCase {
                name: "uppercase",
                values: &[("HTTPS_PROXY", "http://upper.example:3128")],
                selected: "HTTPS_PROXY=http://upper.example:3128",
            },
            ProxyNoticeCase {
                name: "lowercase",
                values: &[
                    ("https_proxy", "http://lower.example:3128"),
                    ("HTTPS_PROXY", "http://upper.example:3128"),
                ],
                selected: "https_proxy=http://lower.example:3128",
            },
            ProxyNoticeCase {
                name: "http lowercase wins",
                values: &[
                    ("HTTPS_PROXY", " "),
                    ("http_proxy", "http://lower-http.example:3128"),
                    ("HTTP_PROXY", "http://upper-http.example:3128"),
                ],
                selected: "http_proxy=http://lower-http.example:3128",
            },
            ProxyNoticeCase {
                name: "unsupported higher class still wins",
                values: &[
                    ("HTTPS_PROXY", "socks5://higher.example:1080"),
                    ("http_proxy", "http://lower.example:3128"),
                ],
                selected: "HTTPS_PROXY=socks5://higher.example:1080",
            },
            ProxyNoticeCase {
                name: "all lowercase wins",
                values: &[
                    ("HTTP_PROXY", "\n"),
                    ("all_proxy", "socks5://lower-all.example:1080"),
                    ("ALL_PROXY", "socks5://upper-all.example:1080"),
                ],
                selected: "all_proxy=socks5://lower-all.example:1080",
            },
            ProxyNoticeCase {
                name: "bracketed ipv6",
                values: &[("https_proxy", "http://u:p@[::1]:3128/a@b?x=@")],
                selected: "https_proxy=http://[::1]:3128/a@b?x=@",
            },
            ProxyNoticeCase {
                name: "schemeless runtime-compatible proxy",
                values: &[("https_proxy", "alice:hunter2@proxy.example:3128")],
                selected: "https_proxy=proxy.example:3128",
            },
            ProxyNoticeCase {
                name: "unbracketed IPv6 runtime-compatible proxy",
                values: &[("https_proxy", "http://u:p@2001:db8::1")],
                selected: "https_proxy=http://2001:db8::1",
            },
        ];
        for case in cases {
            let output = notice_output(args(), |variable| {
                case.values
                    .iter()
                    .find_map(|(name, value)| (*name == variable).then(|| (*value).into()))
            });
            if case.selected.is_empty() {
                assert!(output.is_empty(), "{}", case.name);
            } else {
                assert!(output.contains(case.selected), "{}: {output}", case.name);
                assert!(
                    output.contains("used when it parses as an http:// proxy"),
                    "{}",
                    case.name
                );
                for secret in ["u:p", "alice", "hunter2"] {
                    assert!(!output.contains(secret), "{}: {output}", case.name);
                }
            }
        }
    }

    #[test]
    fn plan_notice_prefers_http_class_over_all_with_lowercase_precedence() {
        let output = notice_output(args(), |variable| match variable {
            "HTTPS_PROXY" => Some(" \t ".into()),
            "http_proxy" => Some("http://lower-http.example:3128".into()),
            "HTTP_PROXY" => Some("http://upper-http.example:3128".into()),
            "all_proxy" => Some("http://lower-all.example:3128".into()),
            "ALL_PROXY" => Some("http://upper-all.example:3128".into()),
            _ => None,
        });
        assert_eq!(
            output,
            "==> Guest egress proxy: http_proxy=http://lower-http.example:3128 (used when it parses as an http:// proxy; NO_PROXY honored, otherwise egress goes direct)\n"
        );
        for ignored in [
            "upper-http.example",
            "lower-all.example",
            "upper-all.example",
        ] {
            assert!(
                !output.contains(ignored),
                "unexpected proxy notice: {output}"
            );
        }
    }

    #[test]
    fn malformed_proxy_notice_never_echoes_credentials_or_control_characters() {
        let output = notice_output(args(), |variable| {
            (variable == "https_proxy")
                .then(|| "http:////alice:hunter2@proxy.example:3128\u{1b}[2J".into())
        });
        assert!(output.contains("redacted malformed proxy value"));
        for secret_or_control in ["alice", "hunter2", "\u{1b}"] {
            assert!(
                !output.contains(secret_or_control),
                "unsafe output: {output}"
            );
        }
        let plan = Plan::from_args_with_proxy_lookup(args(), |variable| {
            (variable == "https_proxy").then(|| "http:////alice:hunter2@proxy.example:3128".into())
        })
        .expect("valid plan");
        let debug = format!("{plan:?}");
        assert!(!debug.contains("alice"));
        assert!(!debug.contains("hunter2"));
    }

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("writer lock").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn plan_event_reporting_uses_one_subscription_and_reports_lifecycle() {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let subscriptions = Arc::new(AtomicUsize::new(0));
        let output = Arc::new(Mutex::new(Vec::new()));
        let (finished_sender, finished_receiver) = tokio::sync::oneshot::channel();
        let plan = plan(Args {
            auto_publish: true,
            ..args()
        });
        let subscription_count = subscriptions.clone();
        plan.start_event_reporting_with(
            move || {
                subscription_count.fetch_add(1, Ordering::SeqCst);
                async move { receiver }
            },
            SharedWriter(output.clone()),
            move |reporter| {
                tokio::spawn(async move {
                    reporter.await;
                    finished_sender
                        .send(())
                        .expect("test observes reporter completion");
                });
            },
        )
        .expect("reporting starts");
        sender
            .send(microsandbox::protocol::network::PortEvent::Added {
                host_bind: "127.0.0.1".parse().expect("IP"),
                host_port: 8080,
                guest_port: 3000,
            })
            .expect("receiver remains open");
        sender
            .send(microsandbox::protocol::network::PortEvent::Removed {
                host_bind: "127.0.0.1".parse().expect("IP"),
                host_port: 8080,
                guest_port: 3000,
            })
            .expect("receiver remains open");
        drop(sender);
        finished_receiver
            .await
            .expect("reporter ends on channel close");
        assert_eq!(subscriptions.load(Ordering::SeqCst), 1);
        assert_eq!(
            String::from_utf8(output.lock().expect("writer lock").clone()).expect("UTF-8"),
            "==> auto-publish: watching guest LISTEN sockets via /proc/net/tcp{,6}\n\
==> auto-published guest :3000 -> host 127.0.0.1:8080\n\
==> auto-publish removed :3000\n"
        );
    }

    #[test]
    fn disabled_event_reporting_does_not_subscribe_or_write() {
        let (_, receiver) = tokio::sync::mpsc::unbounded_channel();
        let subscriptions = Arc::new(AtomicUsize::new(0));
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscription_count = subscriptions.clone();
        plan(args())
            .start_event_reporting_with(
                move || {
                    subscription_count.fetch_add(1, Ordering::SeqCst);
                    async move { receiver }
                },
                SharedWriter(output.clone()),
                |_| panic!("disabled plan must not spawn a reporter"),
            )
            .expect("disabled reporting is a no-op");
        assert_eq!(subscriptions.load(Ordering::SeqCst), 0);
        assert!(output.lock().expect("writer lock").is_empty());
    }

    struct FailingWriter;

    impl std::io::Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("broken output"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn user_visible_output_errors_are_propagated_before_reporting_starts() {
        let plan = plan(Args {
            publish: vec!["8080:3000".into()],
            auto_publish: true,
            ..args()
        });
        assert!(plan.emit_launch_notices_to(&mut FailingWriter).is_err());
        let (_, receiver) = tokio::sync::mpsc::unbounded_channel();
        assert!(
            plan.start_event_reporting_with(
                move || async move { receiver },
                FailingWriter,
                |_| panic!("failed output must not spawn a reporter"),
            )
            .is_err()
        );
    }
}
