//! Launch networking configuration, validation, and lifecycle reporting.

use crate::network_requests::{NetworkRequest, NetworkRequests, RequestReport, RequestTier};
use std::path::Path;

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

    /// Allow one IP/CIDR or TLS hostname, optionally transport/port-scoped (repeatable).
    ///
    /// Numeric grants are address-wide. Hostname grants are TLS-only, SNI- and DNS-verified,
    /// and refused with a host HTTP proxy. Bare hostnames use intercepted ports (443 by default).
    /// Use brackets for a port on an IPv6 address or CIDR.
    /// `tool:NAME` grants a user-config tool's own `network_requests`, each as
    /// `tcp://HOST:PORT`; `set:NAME` grants a user-config `[egress_sets]` entry's
    /// compiled closure.
    #[arg(
        long = "allow-egress",
        value_name = "[tcp://|udp://]IP|CIDR[:PORT] | [tcp://]HOST[:PORT]",
        help_heading = "Network egress"
    )]
    pub(crate) allow_egress: Vec<String>,

    /// Allow public internet egress and DNS. Guest egress is denied by default.
    #[arg(long = "allow-internet-egress", num_args = 0..=1, require_equals = true, default_missing_value = "true", value_name = "BOOL", value_parser = clap::value_parser!(bool), help_heading = "Network egress")]
    pub(crate) allow_internet_egress: Option<bool>,

    /// Allow Private RFC1918, 100.64/10 and fc00::/7. Does not itself grant internet or DNS.
    ///
    /// Risk: a compromised guest gets access to every device on your LAN.
    #[arg(long = "allow-lan", num_args = 0..=1, require_equals = true, default_missing_value = "true", value_name = "BOOL", value_parser = clap::value_parser!(bool), help_heading = "Network egress")]
    pub(crate) allow_lan: Option<bool>,

    /// Allow host loopback services through host.microsandbox.internal, including the host DNS resolver. Does not itself grant internet.
    ///
    /// Risk: host loopback services, including admin UIs, dev databases and the Docker socket, become reachable.
    #[arg(long = "allow-host", num_args = 0..=1, require_equals = true, default_missing_value = "true", value_name = "BOOL", value_parser = clap::value_parser!(bool), help_heading = "Network egress")]
    pub(crate) allow_host: Option<bool>,
}

/// Validated networking intent for one sandbox launch.
#[derive(Debug)]
pub(crate) struct Plan {
    publish_ports: Vec<PublishPort>,
    egress: crate::egress_policy::EgressAuthority,
    auto_publish: bool,
    /// Enable the runtime's own ambient-proxy discovery for this sandbox.
    ///
    /// The fork this build used to vendor applied `HTTPS_PROXY`/`HTTP_PROXY`/
    /// `ALL_PROXY` automatically. The merged runtime made that opt-in
    /// (`NetworkSpec::proxy_from_env`, upstream #1952), so the launch has to
    /// ask for it explicitly to keep the notice above truthful.
    proxy_from_env: bool,
    proxy_not_applied_reason: &'static str,
    proxy_notice: Option<ProxyNotice>,
    /// Whether a host HTTP proxy connector is in use for this launch, whatever
    /// `AGENT_VM_PROXY_FROM_ENV` says.
    ///
    /// The plan already refuses a *configured* hostname for exactly this reason:
    /// the runtime resolves the name on the host, so the sandbox never sees an
    /// SNI it could verify. A *recorded* hostname must not refuse the launch
    /// (ADR-0065 P6), so it is skipped instead — under the same predicate, so
    /// the two cannot disagree about when a name is unrepresentable.
    host_proxy_used: bool,
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
    pub(crate) fn from_args(
        args: Args,
        user: Option<&crate::user_network::UserNetwork>,
        user_tools: Option<&crate::egress_reference::EgressNamespace>,
    ) -> Result<Self> {
        Self::from_args_with_proxy_lookup(args, user, user_tools, |variable| {
            std::env::var(variable).ok()
        })
    }

    fn from_args_with_proxy_lookup(
        args: Args,
        user: Option<&crate::user_network::UserNetwork>,
        user_tools: Option<&crate::egress_reference::EgressNamespace>,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        let publish_ports = parse_publish_args(&args.publish).context("parsing --publish")?;
        let egress = crate::egress_policy::EgressAuthority::resolve(
            crate::egress_policy::CliEgress {
                internet: args.allow_internet_egress,
                lan: args.allow_lan,
                host: args.allow_host,
                allowances: &args.allow_egress,
            },
            user.map(crate::user_network::UserNetwork::egress),
            user_tools,
        )?;
        let disabled = lookup("AGENT_VM_PROXY_FROM_ENV").is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off"
            )
        });
        let observation = observe_host_proxy(lookup);
        if egress.has_hostnames() && observation.connector_used {
            // The parenthetical names *which* hostnames are in play, and, when an
            // egress reference granted any of them, names the reference: removing
            // an entry from `[network]` also removes its expansion (ADR-0059 R19).
            // With no reference the three sentences are the pre-#506 bytes.
            use crate::egress_policy::HostnameAuthority;
            let suffix = match egress.hostname_authority() {
                Some(HostnameAuthority::Cli { references }) if references.is_empty() => {
                    String::new()
                }
                Some(HostnameAuthority::Cli { references }) => format!(
                    " (hostnames from --allow-egress{} apply to this launch; stop passing them)",
                    including_via(&references)
                ),
                Some(HostnameAuthority::Saved { file, references }) => format!(
                    " (persisted hostname grants from \"{}\" [network]{} apply to every launch; remove them there)",
                    crate::one_line::path(file),
                    including_via(&references)
                ),
                Some(HostnameAuthority::SavedAndCli {
                    file,
                    saved_references,
                    cli_references,
                }) => format!(
                    " (hostnames from --allow-egress{} apply to this launch; persisted hostname grants from \"{}\" [network]{} apply to every launch; remove the persisted ones there and stop passing --allow-egress)",
                    including_via(&cli_references),
                    crate::one_line::path(file),
                    including_via(&saved_references)
                ),
                None => String::new(),
            };
            anyhow::bail!("{HOSTNAME_PROXY_REFUSAL}{suffix}");
        }
        let proxy_from_env = observation.connector_used && !disabled;
        let proxy_not_applied_reason = if disabled {
            "AGENT_VM_PROXY_FROM_ENV is off"
        } else if observation.no_proxy_wildcard {
            "NO_PROXY is a wildcard"
        } else {
            "not a usable http:// proxy"
        };
        let proxy_notice = observation.notice;
        Ok(Self {
            publish_ports,
            egress,
            auto_publish: args.auto_publish,
            proxy_from_env,
            proxy_not_applied_reason,
            proxy_notice,
            host_proxy_used: observation.connector_used,
        })
    }

    /// Adopt this project's recorded allowances into the one policy computation
    /// (ADR-0065 P6). Never fails.
    ///
    /// Returns the records that actually joined the authority and, when one could
    /// not, the one notice. A record is skipped only when a hostname meets a host
    /// HTTP proxy: the runtime resolves those names on the host, so the sandbox
    /// never sees an SNI it could intercept.
    ///
    /// The returned set is what the live controller adopts, rather than the whole
    /// store: seeding memory with a record the launch skipped would let a
    /// proxy-skipped hostname look applied and block a live address grant (B1).
    pub(crate) fn adopt_recorded(
        &mut self,
        file: &Path,
        recorded: &crate::allowances::ProjectAllowances,
    ) -> (Vec<crate::allowances::ProjectAllowance>, Option<String>) {
        let mut adopted = Vec::with_capacity(recorded.len());
        let mut skipped = 0usize;
        for allowance in recorded.entries() {
            if self.host_proxy_used
                && matches!(
                    allowance.destination(),
                    crate::egress_policy::Allowance::Hostname(_)
                )
            {
                skipped += 1;
                continue;
            }
            adopted.push(allowance.clone());
        }
        // Called whenever the store held anything, including when every record was
        // skipped: `set_recorded` is what makes the file the record's provenance, and
        // a skipped record must still leave the authority's own grants untouched.
        if recorded.len() > 0 {
            self.egress.set_recorded(
                file,
                adopted.iter().map(|a| a.destination().clone()).collect(),
            );
        }
        let notice = (skipped > 0).then(|| {
            format!(
                "{skipped} project hostname allowance(s) not applied: a host HTTP proxy resolves those names from the host, so the sandbox cannot intercept them; remove the proxy to apply them"
            )
        });
        (adopted, notice)
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
        self.egress.write_notices(output)?;
        if let Some(proxy) = &self.proxy_notice {
            if self.proxy_from_env {
                writeln!(
                    output,
                    "==> Guest egress proxy: {}={} (applied; CONNECT names the destination IP address rather than the hostname; non-DNS UDP is dropped while the proxy is selected; NO_PROXY honored)",
                    proxy.variable, proxy.value
                )?;
            } else {
                writeln!(
                    output,
                    "==> Guest egress proxy: {}={} (found but not applied to this sandbox: {})",
                    proxy.variable, proxy.value, self.proxy_not_applied_reason
                )?;
            }
        }
        Ok(())
    }

    /// Reads the authority being applied; requests cannot change it.
    pub(crate) fn covers(&self, request: &NetworkRequest) -> bool {
        self.egress.covers_tls(request.name(), request.port())
    }

    /// Reads the authority being applied; requests cannot change it.
    pub(crate) fn request_report<'a>(
        &self,
        requests: &'a NetworkRequests,
        tier: RequestTier,
    ) -> RequestReport<'a> {
        RequestReport::compose(requests, tier, |request| self.covers(request))
    }

    pub(crate) fn apply_to(&self, builder: SandboxBuilder) -> SandboxBuilder {
        let policy = self.egress.policy();
        let publish_ports = self.publish_ports.clone();
        let auto_publish = self.auto_publish;
        let proxy_from_env = self.proxy_from_env;
        let hostname_ports = self.egress.intercepted_ports().map(|ports| ports.to_vec());
        let enable_tls = !publish_ports.is_empty() || hostname_ports.is_some();
        let builder = builder.network(move |mut network| {
            network = network.policy(policy);
            if enable_tls {
                // The hostname set includes 443, so replacing the default loses nothing.
                // The later credential overlay unions its own ports (ADR-0037).
                network = network.tls(|tls| match &hostname_ports {
                    Some(ports) => tls.intercepted_ports(ports.clone()),
                    None => tls,
                });
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
        });
        // Keep discovery aligned with the applied/not-applied launch notice.
        // An explicit `.proxy()` still wins, and `NO_PROXY` is read at network
        // startup by the runtime, exactly as the notice says.
        builder.proxy_from_env(proxy_from_env)
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

const HOSTNAME_PROXY_REFUSAL: &str = "hostname allowances cannot be enforced through the host HTTP proxy (HTTPS_PROXY/HTTP_PROXY/ALL_PROXY): the proxy resolves the name, so the address scope is not checked; unset the proxy, use an IP/CIDR allowance, or use --allow-internet-egress";

/// The reference clause of a proxy refusal, or nothing when the tier named no
/// reference — which is what keeps the pre-#506 sentences byte-identical.
fn including_via(references: &[&crate::egress_reference::EgressReference]) -> String {
    if references.is_empty() {
        String::new()
    } else {
        format!(
            ", including via {},",
            crate::egress_reference::render_list(references)
        )
    }
}
struct HostProxyObservation {
    notice: Option<ProxyNotice>,
    connector_used: bool,
    no_proxy_wildcard: bool,
}
/// Pure proxy lookup, taking a function instead of reading the real process
/// environment so tests don't need unsafe
/// `std::env::set_var`/`remove_var` mutation under `cargo test`'s parallel
/// threads.
///
/// Mirrors `HostHttpProxyConnector::from_values`. Both the notice and the
/// refusal use this observation; a notice's first value alone misses
/// cross-variable fallback.
fn observe_host_proxy(lookup: impl Fn(&str) -> Option<String>) -> HostProxyObservation {
    let mut notice = None;
    let mut usable = false;
    for (upper, lower) in [
        ("HTTPS_PROXY", "https_proxy"),
        ("HTTP_PROXY", "http_proxy"),
        ("ALL_PROXY", "all_proxy"),
    ] {
        let chosen = [lower, upper].into_iter().find_map(|var| {
            lookup(var)
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .map(|s| (var, s))
        });
        if let Some((variable, value)) = chosen {
            usable |= connector_would_select(&value);
            if notice.is_none() {
                notice = Some(ProxyNotice {
                    variable,
                    value: ProxyDisplay::parse(&value),
                });
            }
        }
    }
    let no_proxy = ["no_proxy", "NO_PROXY"].into_iter().find_map(|var| {
        lookup(var)
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    });
    let wildcard = no_proxy.is_some_and(|s| {
        s.split(|c: char| c == ',' || c.is_ascii_whitespace())
            .any(|s| s == "*")
    });
    HostProxyObservation {
        notice,
        connector_used: usable && !wildcard,
        no_proxy_wildcard: wildcard,
    }
}
fn connector_would_select(value: &str) -> bool {
    let authority = match value.trim().split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => rest,
        Some(_) => return false,
        None => value.trim(),
    }
    .split(['/', '?', '#'])
    .next()
    .unwrap_or("");
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
        .trim();
    valid_proxy_authority(host_port)
}

/// The provenance label of a plan captured before the store was read.
const PRE_ADOPTION_FILE: &str = "<pre-adoption>";

/// A plan for a live-allowance test: an explicit authority and an explicit
/// host-proxy flag, with no environment lookup, so a developer's proxy settings
/// cannot change what the test measures.
#[cfg(test)]
pub(crate) fn plan_for_tests(allow_egress: &[&str], host_proxy_used: bool) -> Plan {
    let mut plan = Plan::from_args_with_proxy_lookup(
        Args {
            publish: Vec::new(),
            auto_publish: false,
            allow_egress: allow_egress.iter().map(|text| (*text).to_owned()).collect(),
            allow_internet_egress: None,
            allow_lan: None,
            allow_host: None,
        },
        None,
        None,
        |_| None,
    )
    .expect("valid test plan");
    plan.host_proxy_used = host_proxy_used;
    plan
}

/// Why a live policy swap is refused rather than applied (ADR-0065 Constraint 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LivePolicyPrecondition {
    /// A hostname was included while a host HTTP proxy is in use. The runtime
    /// resolves those names on the host, so the sandbox never intercepts them.
    HostProxyInUse,
    /// The candidate set would add a TLS-intercepted port the launch did not fix.
    /// `NetworkPolicy` is replaceable live; `tls.intercepted_ports` is not.
    InterceptedPortsFixedAtLaunch,
}

impl LivePolicyPrecondition {
    /// The precondition in the user's words.
    ///
    /// A `Debug` rendering is not a sentence: it names an enum variant rather than
    /// what went wrong, and it is not the one-line escaped text a terminal needs
    /// (R12). One clause per variant, so a new precondition cannot be rendered by
    /// accident.
    pub(crate) fn clause(self) -> &'static str {
        match self {
            Self::HostProxyInUse => {
                "a host HTTP proxy is in use, so a hostname cannot be enforced in this session"
            }
            Self::InterceptedPortsFixedAtLaunch => {
                "the change needs a TLS-intercepted port this launch did not fix"
            }
        }
    }
}

/// Everything one live policy computation needs, captured at launch.
///
/// This is the only place the live allowance writer meets the one policy
/// computation (D7): `allowances/` never names `EgressAuthority`, and
/// `egress_policy.rs` never names an allowance type. The clone of the base
/// authority keeps `configured` fixed, so every derivation starts from this
/// launch's own grants and adds exactly the set it is handed.
#[derive(Clone, Debug)]
pub(crate) struct LivePolicyPlan {
    egress: crate::egress_policy::EgressAuthority,
    /// Captured once, at launch, and carried unchanged through every derivation.
    /// A live swap may narrow within it but never add to it.
    launch_intercepted_ports: Option<crate::egress_hostname::InterceptedPorts>,
    host_proxy_used: bool,
    allowances_file: std::path::PathBuf,
}

impl Plan {
    /// Capture this launch's live policy inputs. There is deliberately no
    /// production `default_deny()`: every caller passes the plan its launch
    /// resolved, so a test cannot accidentally get a silent empty authority.
    pub(crate) fn live_policy_plan(&self, allowances_file: Option<&Path>) -> LivePolicyPlan {
        LivePolicyPlan {
            egress: self.egress.clone(),
            launch_intercepted_ports: self.egress.intercepted_ports(),
            host_proxy_used: self.host_proxy_used,
            // Before the store is read there is no file, and naming a relative
            // `allowances.json` would read as one: it is only ever a provenance
            // label, and adoption replaces it with the real path.
            allowances_file: allowances_file
                .map(Path::to_owned)
                .unwrap_or_else(|| std::path::PathBuf::from(PRE_ADOPTION_FILE)),
        }
    }
}

impl LivePolicyPlan {
    /// The policy this plan derives with no live additions: the launch's own
    /// authority, and after boot adoption `configured ∪ adopted`.
    pub(crate) fn policy(&self) -> microsandbox::NetworkPolicy {
        self.egress.policy()
    }

    /// Whether the launch's own configured authority names this allowance. A live
    /// revoke cannot remove it, so a caller must not claim the destination stopped
    /// working when this is true.
    pub(crate) fn is_configured(&self, allowance: &crate::egress_policy::Allowance) -> bool {
        self.egress.configured_contains(allowance)
    }

    /// Derive the policy for one combined allowance set and the plan that
    /// produced it.
    ///
    /// The candidate is built by the launch's own one computation —
    /// `EgressAuthority::set_recorded` then `EgressAuthority::policy()` — so no
    /// second copy of rule assembly exists (R3). `launch_intercepted_ports` is
    /// carried through unchanged, so a later derivation still measures against
    /// what the netstack fixed at boot.
    pub(crate) fn derive_for(
        &self,
        combined: Vec<crate::egress_policy::Allowance>,
    ) -> Result<(Self, microsandbox::NetworkPolicy), LivePolicyPrecondition> {
        if self.host_proxy_used
            && combined
                .iter()
                .any(|a| matches!(a, crate::egress_policy::Allowance::Hostname(_)))
        {
            return Err(LivePolicyPrecondition::HostProxyInUse);
        }
        let mut candidate = self.egress.clone();
        candidate.set_recorded(&self.allowances_file, combined);
        if !crate::egress_hostname::InterceptedPorts::is_subset(
            candidate.intercepted_ports().as_ref(),
            self.launch_intercepted_ports.as_ref(),
        ) {
            return Err(LivePolicyPrecondition::InterceptedPortsFixedAtLaunch);
        }
        let derived_policy = candidate.policy();
        Ok((
            Self {
                egress: candidate,
                launch_intercepted_ports: self.launch_intercepted_ports.clone(),
                host_proxy_used: self.host_proxy_used,
                allowances_file: self.allowances_file.clone(),
            },
            derived_policy,
        ))
    }
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
            allow_internet_egress: None,
            allow_lan: None,
            allow_host: None,
        }
    }

    mod hostname_tests;

    /// The live derivation is the launch's own one computation: the policy it
    /// derives equals a fresh launch resolved with exactly those entries.
    #[tokio::test]
    async fn live_policy_plan_derives_through_the_launch_computation() {
        let plan = plan(args());
        let live = plan.live_policy_plan(Some(Path::new(ALLOWANCE_FILE)));
        let (derived, policy) = live
            .derive_for(vec![
                crate::egress_policy::Allowance::parse("tcp://[203.0.113.10/32]:443").unwrap(),
            ])
            .expect("an address derives");
        // The same one computation, spelled directly.
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
        authority.set_recorded(
            Path::new(ALLOWANCE_FILE),
            vec![crate::egress_policy::Allowance::parse("tcp://[203.0.113.10/32]:443").unwrap()],
        );
        assert_eq!(format!("{policy:?}"), format!("{:?}", authority.policy()));
        // A second derivation still measures against the launch's own ports.
        let (again, _) = derived
            .derive_for(vec![
                crate::egress_policy::Allowance::parse("tcp://[198.51.100.0/24]:8443").unwrap(),
            ])
            .expect("a port-8443 address is not intercepted");
        assert!(again.launch_intercepted_ports.is_none());
    }

    /// Adding a TLS-intercepted port the launch did not fix is refused, and
    /// removing the last hostname narrows: the launch's set stays.
    #[test]
    fn live_policy_plan_narrows_but_never_adds_intercepted_ports() {
        // A launch with no hostnames intercepted no port, so any hostname adds one.
        let plain = plan(args()).live_policy_plan(Some(Path::new(ALLOWANCE_FILE)));
        assert_eq!(
            plain
                .derive_for(vec![
                    crate::egress_policy::Allowance::parse("api.example.com").unwrap()
                ])
                .unwrap_err(),
            LivePolicyPrecondition::InterceptedPortsFixedAtLaunch
        );

        // A launch that started with a hostname may keep or remove it, but a new
        // port (8443) is outside its set.
        let with_hostname = plan(Args {
            allow_egress: vec!["api.example.com".to_owned()],
            ..args()
        })
        .live_policy_plan(Some(Path::new(ALLOWANCE_FILE)));
        let (narrowed, _) = with_hostname.derive_for(Vec::new()).unwrap();
        assert!(
            narrowed.launch_intercepted_ports.is_some(),
            "the launch's ports are carried, not recomputed"
        );
        assert_eq!(
            with_hostname
                .derive_for(vec![
                    crate::egress_policy::Allowance::parse("tcp://other.example:8443").unwrap()
                ])
                .unwrap_err(),
            LivePolicyPrecondition::InterceptedPortsFixedAtLaunch
        );
    }

    /// Under a host proxy no hostname derives at all, and an address still does.
    #[test]
    fn live_policy_plan_refuses_a_hostname_under_a_host_proxy() {
        let proxied = Plan::from_args_with_proxy_lookup(args(), None, None, |variable| {
            (variable == "HTTPS_PROXY").then(|| "http://127.0.0.1:9".into())
        })
        .unwrap()
        .live_policy_plan(Some(Path::new(ALLOWANCE_FILE)));
        assert_eq!(
            proxied
                .derive_for(vec![
                    crate::egress_policy::Allowance::parse("api.example.com").unwrap()
                ])
                .unwrap_err(),
            LivePolicyPrecondition::HostProxyInUse
        );
        assert!(
            proxied
                .derive_for(vec![
                    crate::egress_policy::Allowance::parse("tcp://[203.0.113.10/32]:443").unwrap()
                ])
                .is_ok()
        );
    }

    fn plan(input: Args) -> Plan {
        Plan::from_args_with_proxy_lookup(input, None, None, |_| None)
            .expect("valid networking plan")
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

    #[tokio::test]
    async fn user_grants_reach_the_applied_policy() {
        let user = crate::user_network::UserNetwork::for_test(
            "user.toml",
            crate::user_network::SavedGroups {
                lan: Some(true),
                ..Default::default()
            },
            &["10.0.0.5"],
        );
        let plan = Plan::from_args_with_proxy_lookup(args(), Some(&user), None, |_| None).unwrap();
        let config = plan
            .apply_to(test_builder("saved-grants"))
            .build()
            .await
            .unwrap();
        let network = serde_json::to_value(config.spec.network).unwrap();
        assert_eq!(
            network["policy"]["rules"],
            serde_json::json!([
                {"direction":"egress","destination":{"cidr":"10.0.0.5/32"},"protocols":[],"ports":[],"action":"allow"},
                {"direction":"egress","destination":{"group":"private"},"protocols":[],"ports":[],"action":"allow"}
            ])
        );
    }

    #[test]
    fn a_usable_host_proxy_opts_into_runtime_discovery() {
        // Discovery stays on by default; only explicit false-like values opt out.
        for opt_out in [
            None,
            Some("1"),
            Some("true"),
            Some(""),
            Some("other"),
            Some("0"),
            Some(" FaLsE "),
            Some(" OFF "),
        ] {
            let plan = Plan::from_args_with_proxy_lookup(args(), None, None, |v| match v {
                "HTTPS_PROXY" => Some("http://127.0.0.1:9".into()),
                "AGENT_VM_PROXY_FROM_ENV" => opt_out.map(str::to_owned),
                _ => None,
            })
            .unwrap();
            let disabled = matches!(opt_out, Some("0" | " FaLsE " | " OFF "));
            assert_eq!(plan.proxy_from_env, !disabled, "{opt_out:?}");
            let mut output = Vec::new();
            plan.emit_launch_notices_to(&mut output).unwrap();
            let output = String::from_utf8(output).unwrap();
            assert_eq!(
                output
                    .lines()
                    .filter(|line| line.starts_with("==> Guest egress proxy:"))
                    .count(),
                1
            );
            if disabled {
                assert!(output.contains(
                    "found but not applied to this sandbox: AGENT_VM_PROXY_FROM_ENV is off"
                ));
                let mut input = args();
                input.allow_egress.push("api.example.com".into());
                let error = Plan::from_args_with_proxy_lookup(input, None, None, |v| match v {
                    "HTTPS_PROXY" => Some("http://127.0.0.1:9".into()),
                    "AGENT_VM_PROXY_FROM_ENV" => opt_out.map(str::to_owned),
                    _ => None,
                })
                .unwrap_err();
                assert_eq!(error.to_string(), HOSTNAME_PROXY_REFUSAL);
            } else {
                assert!(output.contains(
                    "applied; CONNECT names the destination IP address rather than the hostname"
                ));
                assert!(output.contains("non-DNS UDP is dropped while the proxy is selected"));
                assert!(output.contains("NO_PROXY honored"));
            }
        }

        // A wildcard NO_PROXY disables the connector.
        let plan = Plan::from_args_with_proxy_lookup(args(), None, None, |v| match v {
            "HTTPS_PROXY" => Some("http://127.0.0.1:9".into()),
            "NO_PROXY" => Some("*".into()),
            _ => None,
        })
        .unwrap();
        assert!(!plan.proxy_from_env);
        let mut output = Vec::new();
        plan.emit_launch_notices_to(&mut output).unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("found but not applied to this sandbox: NO_PROXY is a wildcard")
        );

        // An unsupported scheme is never selected by the connector either.
        let plan = Plan::from_args_with_proxy_lookup(args(), None, None, |v| {
            (v == "HTTPS_PROXY").then(|| "socks5://127.0.0.1:1080".into())
        })
        .unwrap();
        assert!(!plan.proxy_from_env);
        let mut output = Vec::new();
        plan.emit_launch_notices_to(&mut output).unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("found but not applied to this sandbox: not a usable http:// proxy")
        );
    }

    // -----------------------------------------------------------------------
    // E1–E3: the recorded set reaches one policy computation (ADR-0065 P6)
    // -----------------------------------------------------------------------

    const ALLOWANCE_FILE: &str = "/home/a/.config/agent-vm/allowances.json";

    /// [`configured_network`] for a plan that already has its recorded set.
    async fn recorded_network(plan: &Plan, name: &str) -> serde_json::Value {
        let config = plan
            .apply_to(test_builder(name))
            .build()
            .await
            .expect("network config");
        serde_json::to_value(config.spec.network).expect("network serializes")
    }

    fn notices_of(plan: &Plan) -> String {
        let mut output = Vec::new();
        plan.emit_launch_notices_to(&mut output).unwrap();
        String::from_utf8(output).unwrap()
    }

    /// AC1: one recorded address is a rule in the config this launch applies,
    /// and the notices name it as the project's own.
    #[tokio::test]
    async fn recorded_address_reaches_the_applied_policy() {
        let mut plan = plan(args());
        let (adopted, notice) = plan.adopt_recorded(
            Path::new(ALLOWANCE_FILE),
            &crate::allowances::ProjectAllowances::for_tests(&["tcp://[203.0.113.10/32]:443"]),
        );
        assert_eq!(notice, None, "an address record is never skipped");
        assert_eq!(
            adopted.len(),
            1,
            "the adopted set is what the launch applied"
        );
        let network = recorded_network(&plan, "recorded-address").await;
        assert_eq!(
            network["policy"]["rules"],
            serde_json::json!([
                {"direction":"egress","destination":{"cidr":"203.0.113.10/32"},"protocols":["tcp"],"ports":[{"start":443,"end":443}],"action":"allow"}
            ])
        );
        // An address record intercepts nothing: TLS stays off.
        assert_eq!(network["tls"]["enabled"], false);
        let notices = notices_of(&plan);
        assert!(
            notices.contains(&format!(
                "==> Egress authority: 1 project allowance(s) from \"{ALLOWANCE_FILE}\""
            )),
            "{notices}"
        );
        assert!(
            notices.contains(
                "==> Egress policy: allowing tcp://[203.0.113.10/32]:443 (project allowance)"
            ),
            "{notices}"
        );
    }

    /// AC6: with a host HTTP proxy in use, recorded hostnames are skipped with
    /// one warning; recorded addresses still apply and the launch is not
    /// refused. A configured hostname in the same launch *is* refused, so this
    /// is not the refusal path with the wrong message.
    #[tokio::test]
    async fn recorded_hostnames_are_skipped_with_a_host_proxy() {
        let mut plan = Plan::from_args_with_proxy_lookup(args(), None, None, |variable| {
            (variable == "HTTPS_PROXY").then(|| "http://127.0.0.1:9".into())
        })
        .unwrap();
        let notice = plan
            .adopt_recorded(
                Path::new(ALLOWANCE_FILE),
                &crate::allowances::ProjectAllowances::for_tests(&[
                    "tcp://[203.0.113.10/32]:443",
                    "api.example.com",
                ]),
            )
            .1
            .expect("one notice for the skipped hostname");
        assert!(
            notice.starts_with("1 project hostname allowance(s) not applied: "),
            "{notice}"
        );
        assert!(notice.contains("host HTTP proxy"), "{notice}");
        let network = recorded_network(&plan, "recorded-proxy").await;
        let rules = network["policy"]["rules"].as_array().unwrap();
        assert!(
            rules
                .iter()
                .any(|rule| rule["destination"]["cidr"] == "203.0.113.10/32"),
            "{rules:?}"
        );
        assert!(
            !rules
                .iter()
                .any(|rule| rule["destination"]["domain"].is_string()),
            "a skipped hostname installs no Domain rule: {rules:?}"
        );
        assert_eq!(network["tls"]["enabled"], false);
        let notices = notices_of(&plan);
        assert!(
            notices.contains(
                "==> Egress policy: allowing tcp://[203.0.113.10/32]:443 (project allowance)"
            ),
            "{notices}"
        );
        assert!(!notices.contains("allowing TLS to"), "{notices}");
    }

    /// AC2: a launch whose *only* hostname is a recorded one still installs the
    /// whole interception apparatus — Domain rule, TLS on, port 443, and
    /// request coverage — and says where it came from.
    #[tokio::test]
    async fn record_only_hostname_installs_interception() {
        let mut plan = plan(args());
        assert_eq!(
            plan.adopt_recorded(
                Path::new(ALLOWANCE_FILE),
                &crate::allowances::ProjectAllowances::for_tests(&["api.example.com"])
            )
            .1,
            None
        );
        let network = recorded_network(&plan, "recorded-hostname").await;
        assert_eq!(
            network["policy"]["rules"],
            serde_json::json!([
                {"direction":"egress","destination":{"domain":"api.example.com"},"protocols":["tcp"],"ports":[{"start":443,"end":443}],"action":"allow"}
            ])
        );
        assert_eq!(network["tls"]["enabled"], true);
        assert_eq!(
            network["tls"]["intercepted_ports"],
            serde_json::json!([443])
        );
        let requests =
            crate::network_requests::NetworkRequests::parse(&["api.example.com:443".to_owned()])
                .unwrap();
        assert!(requests.iter().all(|request| plan.covers(request)));
        let notices = notices_of(&plan);
        assert!(
            notices.contains(
                "==> Egress policy: allowing TLS to api.example.com on ports 443 (project allowance)"
            ),
            "{notices}"
        );
    }

    /// R3's TLS enablement, through the *applied* plan rather than the
    /// authority's own accessor: `Plan::apply_to` is what decides `tls.enabled`,
    /// and it derives it from the intercepted ports. A merge that reached the
    /// policy but not the applied TLS decision would pass every other test.
    #[tokio::test]
    async fn recorded_merge_equals_cli_append_on_the_applied_tls_decision() {
        const RECORDED: [&str; 4] = [
            "api.example.com",
            "tcp://api.example.com:8443",
            "other.example",
            "10.0.0.5",
        ];
        for bits in 0..1u8 << RECORDED.len() {
            let recorded: Vec<&str> = RECORDED
                .iter()
                .enumerate()
                .filter(|(index, _)| bits & (1 << index) != 0)
                .map(|(_, spelling)| *spelling)
                .collect();
            let mut merged = plan(args());
            assert_eq!(
                merged
                    .adopt_recorded(
                        Path::new(ALLOWANCE_FILE),
                        &crate::allowances::ProjectAllowances::for_tests(&recorded)
                    )
                    .1,
                None,
                "{recorded:?}"
            );
            let applied = recorded_network(&merged, &format!("merged-{bits}")).await;
            let equivalent = plan(Args {
                allow_egress: recorded.iter().map(|text| (*text).to_owned()).collect(),
                ..args()
            });
            let expected = recorded_network(&equivalent, &format!("equivalent-{bits}")).await;
            assert_eq!(
                applied["tls"]["enabled"], expected["tls"]["enabled"],
                "{recorded:?}"
            );
            assert_eq!(
                applied["tls"]["intercepted_ports"], expected["tls"]["intercepted_ports"],
                "{recorded:?}"
            );
            assert_eq!(applied["policy"], expected["policy"], "{recorded:?}");
        }
    }

    #[test]
    fn user_hostname_with_host_proxy_is_refused() {
        let user = crate::user_network::UserNetwork::for_test(
            "user\n.toml",
            Default::default(),
            &["api.example.com"],
        );
        let error = Plan::from_args_with_proxy_lookup(args(), Some(&user), None, |v| {
            (v == "HTTPS_PROXY").then(|| "http://127.0.0.1:9".into())
        })
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            format!(
                "{HOSTNAME_PROXY_REFUSAL} (persisted hostname grants from \"user\\x0a.toml\" [network] apply to every launch; remove them there)"
            )
        );
        let numeric = crate::user_network::UserNetwork::for_test(
            "user.toml",
            Default::default(),
            &["10.0.0.5"],
        );
        assert!(
            Plan::from_args_with_proxy_lookup(args(), Some(&numeric), None, |v| (v
                == "HTTPS_PROXY")
                .then(|| "http://127.0.0.1:9".into()),)
            .is_ok()
        );
    }

    /// The file this refusal names is a *measured* config location, so a
    /// non-ASCII `$HOME` must read as itself. Parameterized over both arms —
    /// `Saved` and `SavedAndCli` are separate call sites, and reverting either one
    /// on its own leaves the other's test passing. The control-byte pin above
    /// still holds, because one-line escaping keeps `\xNN` for control bytes.
    #[test]
    fn user_hostname_refusal_prints_a_non_ascii_config_path_as_itself() {
        let file = "/home/дом/.config/agent-vm/config.toml";
        let proxy = |v: &str| (v == "HTTPS_PROXY").then(|| "http://127.0.0.1:9".into());
        let saved_only = crate::user_network::UserNetwork::for_test(
            file,
            Default::default(),
            &["api.example.com"],
        );
        let mut saved_and_cli_args = args();
        saved_and_cli_args.allow_egress = vec!["cli.example.com".into()];
        let saved_and_cli = crate::user_network::UserNetwork::for_test(
            file,
            Default::default(),
            &["api.example.com"],
        );
        for (input, user, clause) in [
            (args(), &saved_only, "remove them there)"),
            (
                saved_and_cli_args,
                &saved_and_cli,
                "stop passing --allow-egress)",
            ),
        ] {
            let error = Plan::from_args_with_proxy_lookup(input, Some(user), None, proxy)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&format!("from \"{file}\" [network]")),
                "{error}"
            );
            assert!(error.ends_with(clause), "{error}");
            assert!(!error.contains("\\xd0"), "byte-escaped: {error}");
        }
    }

    #[test]
    fn host_proxy_refusal_blames_every_hostname_source() {
        let proxy = |v: &str| (v == "HTTPS_PROXY").then(|| "http://127.0.0.1:9".into());
        let mut cli_only = args();
        cli_only.allow_egress = vec!["cli.example.com".into()];
        assert_eq!(
            Plan::from_args_with_proxy_lookup(cli_only, None, None, proxy,)
                .unwrap_err()
                .to_string(),
            HOSTNAME_PROXY_REFUSAL
        );
        let user = crate::user_network::UserNetwork::for_test(
            "user.toml",
            Default::default(),
            &["saved.example.com"],
        );
        let mut both = args();
        both.allow_egress = vec!["cli.example.com".into()];
        let error = Plan::from_args_with_proxy_lookup(both, Some(&user), None, proxy)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            format!(
                "{HOSTNAME_PROXY_REFUSAL} (hostnames from --allow-egress apply to this launch; persisted hostname grants from \"user.toml\" [network] apply to every launch; remove the persisted ones there and stop passing --allow-egress)"
            )
        );
    }

    fn notice_output(input: Args, proxy: impl Fn(&str) -> Option<String>) -> String {
        let plan = Plan::from_args_with_proxy_lookup(input, None, None, proxy)
            .expect("valid networking plan");
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
                None,
                None,
                |_| None,
            )
            .expect_err("invalid publish input is rejected");
            assert_eq!(format!("{error:#}"), expected, "{value}");
        }
    }

    #[test]
    fn plan_reports_the_allow_egress_error_without_repeating_the_flag() {
        let error = Plan::from_args_with_proxy_lookup(
            Args {
                allow_egress: vec!["udp://not-an-ip.example".into()],
                ..args()
            },
            None,
            None,
            |_| None,
        )
        .expect_err("invalid CIDR is rejected");
        // The `AllowanceError` display already names `--allow-egress #1`, so a
        // `parsing --allow-egress` context would repeat the flag.
        assert_eq!(
            format!("{error:#}"),
            format!(
                "--allow-egress #1: {}",
                crate::egress_grammar::AllowanceError::UdpHostname
            )
        );
        assert!(!format!("{error:#}").contains("not-an-ip"));
    }

    #[tokio::test]
    async fn default_plan_denies_all_egress_and_preserves_non_policy_network_config() {
        let baseline = test_builder("network-default")
            .build()
            .await
            .expect("baseline config");
        let applied = plan(args())
            .apply_to(test_builder("network-default"))
            .build()
            .await
            .expect("applied config");
        let mut applied = serde_json::to_value(applied.spec.network).unwrap();
        // Materialize dependency defaults independently of the builder closure.
        // Normalize only the expected wire representation: normalizing applied
        // JSON could hide an added unknown key or another closure mutation.
        let dense: microsandbox_network::config::NetworkConfig =
            serde_json::from_value(serde_json::to_value(baseline.spec.network).unwrap()).unwrap();
        assert!(dense.strict);
        assert!(dense.dns.rebind_protection);
        assert!(dense.dns.nameservers.is_empty());
        assert_eq!(dense.dns.query_timeout_ms, 5000);
        assert!(!dense.tls.enabled);
        assert!(dense.secrets.secrets.is_empty());
        assert!(dense.secrets.header_credentials.is_empty());
        assert_eq!(dense.tls.intercepted_ports, [443]);
        assert!(dense.max_tcp_connections.is_none());
        assert!(dense.max_udp_connections.is_none());
        assert!(dense.rate_limiter.is_none());
        let wire: microsandbox::sandbox::NetworkSpec =
            serde_json::from_value(serde_json::to_value(dense).unwrap()).unwrap();
        let mut baseline = serde_json::to_value(wire).unwrap();
        assert_eq!(baseline["secrets"]["secrets"], serde_json::json!([]));
        assert_eq!(baseline["intercept"]["rules"], serde_json::json!([]));
        assert_eq!(baseline["intercept"]["hook"], serde_json::Value::Null);
        assert_eq!(baseline["intercept"]["max_request_bytes"], 65536);
        assert_eq!(
            applied["policy"],
            serde_json::json!({"default_egress":"deny","default_ingress":"allow","rules":[]})
        );
        applied.as_object_mut().unwrap().remove("policy");
        baseline.as_object_mut().unwrap().remove("policy");
        assert_eq!(applied, baseline);
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
    async fn group_flags_and_allowances_emit_the_documented_rule_list() {
        let mut input = args();
        input.publish.push("8080:3000".into());
        input.allow_egress = vec![
            "10.0.0.5".into(),
            "fd00::1".into(),
            "api.example.com".into(),
            "tcp://git.example.com:8443".into(),
        ];
        input.allow_lan = Some(true);
        input.allow_host = Some(true);
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
        assert_eq!(policy_groups(&network), ["private", "host"]);
        assert_eq!(policy["rules"].as_array().unwrap().len(), 6);
        assert_eq!(
            policy["rules"][2],
            serde_json::json!({"direction":"egress","destination":{"group":"private"},"protocols":[],"ports":[],"action":"allow"})
        );
        assert_eq!(
            policy["rules"][3],
            serde_json::json!({"direction":"egress","destination":{"group":"host"},"protocols":[],"ports":[],"action":"allow"})
        );
        let internet = configured_network(
            Args {
                allow_internet_egress: Some(true),
                allow_lan: Some(true),
                allow_host: Some(true),
                allow_egress: vec![
                    "10.0.0.5".into(),
                    "fd00::1".into(),
                    "api.example.com".into(),
                    "tcp://git.example.com:8443".into(),
                ],
                ..args()
            },
            "network-policy-internet",
        )
        .await;
        assert_eq!(policy_groups(&internet), ["public", "private", "host"]);
        assert_eq!(internet["policy"]["rules"].as_array().unwrap().len(), 8);
        assert_eq!(
            internet["policy"]["rules"][2],
            serde_json::json!({"direction":"egress","destination":{"group":"host"},"protocols":["udp","tcp"],"ports":[{"start":53,"end":53}],"action":"allow"})
        );
        for (configured, domain_start) in [(&network, 4usize), (&internet, 6usize)] {
            assert_eq!(
                configured["tls"]["intercepted_ports"],
                serde_json::json!([443, 8443])
            );
            assert_eq!(
                configured["policy"]["rules"][domain_start],
                serde_json::json!({"direction":"egress","destination":{"domain":"api.example.com"},"protocols":["tcp"],"ports":[{"start":443,"end":443},{"start":8443,"end":8443}],"action":"allow"})
            );
            assert_eq!(
                configured["policy"]["rules"][domain_start + 1],
                serde_json::json!({"direction":"egress","destination":{"domain":"git.example.com"},"protocols":["tcp"],"ports":[{"start":8443,"end":8443}],"action":"allow"})
            );
        }
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
        assert_eq!(rules.len(), 2);
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
                vec![],
            ),
            (
                "hostname",
                Args {
                    publish: vec!["8080:3000".into()],
                    allow_egress: vec!["build".into()],
                    ..args()
                },
                vec![],
            ),
            (
                "lan",
                Args {
                    publish: vec!["8080:3000".into()],
                    allow_lan: Some(true),
                    ..args()
                },
                vec!["private"],
            ),
            (
                "host",
                Args {
                    publish: vec!["8080:3000".into()],
                    allow_host: Some(true),
                    ..args()
                },
                vec!["host"],
            ),
            (
                "internet",
                Args {
                    publish: vec!["8080:3000".into()],
                    allow_internet_egress: Some(true),
                    ..args()
                },
                vec!["public"],
            ),
        ] {
            let network = configured_network(input, &format!("network-{name}")).await;
            assert_eq!(policy_groups(&network), expected_groups, "{name}");
            assert_eq!(network["policy"]["default_ingress"], "allow", "{name}");
            assert_eq!(
                network["tls"]["intercepted_ports"],
                serde_json::json!([443]),
                "{name}"
            );
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
    async fn tls_is_enabled_only_by_publish_or_hostname_allowances() {
        for (name, input) in [
            ("default", args()),
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
            let published = configured_network(
                Args {
                    publish: vec!["8080:3000".into()],
                    ..args()
                },
                "publish-default-ports",
            )
            .await;
            assert_eq!(published["tls"]["enabled"], true);
            assert_eq!(
                published["tls"]["intercepted_ports"],
                serde_json::json!([443])
            );
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
        input.allow_lan = Some(true);
        input.allow_host = Some(true);
        let output = notice_output(input, |variable| match variable {
            "https_proxy" => Some(" http://alice:hunter2@proxy.example:3128/path@kept ".into()),
            _ => None,
        });
        assert_eq!(
            output,
            "==> Publishing host 127.0.0.1:8080/tcp → guest :3000\n\
==> Egress policy: allowing 10.0.0.5/32\n\
==> Egress policy: --allow-lan enabled (Private RFC1918 + 100.64/10 + fc00::/7 reachable; does not itself enable DNS)\n\
==> Egress policy: --allow-host enabled (host.microsandbox.internal → host 127.0.0.1 reachable; includes the host DNS resolver)\n\
==> Egress DNS: arbitrary-name DNS queries authorized via --allow-host (resolver/rebind/platform constraints still apply)\n\
==> Guest egress proxy: https_proxy=http://proxy.example:3128/path@kept (applied; CONNECT names the destination IP address rather than the hostname; non-DNS UDP is dropped while the proxy is selected; NO_PROXY honored)\n"
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
                assert!(!output.contains("Guest egress proxy"), "{}", case.name);
            } else {
                assert!(output.contains(case.selected), "{}: {output}", case.name);
                assert!(
                    output.contains(if case.name == "all lowercase wins" {
                        "found but not applied to this sandbox: not a usable http:// proxy"
                    } else {
                        "applied; CONNECT names the destination IP address"
                    }),
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
            "==> Egress policy: all guest egress denied (opt in with --allow-internet-egress, --allow-egress, --allow-lan or --allow-host)\n\
==> Egress DNS: queries denied (NXDOMAIN when forwarder is available; use IP or hostname allowances)\n\
==> Guest egress proxy: http_proxy=http://lower-http.example:3128 (applied; CONNECT names the destination IP address rather than the hostname; non-DNS UDP is dropped while the proxy is selected; NO_PROXY honored)\n"
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
        let plan = Plan::from_args_with_proxy_lookup(args(), None, None, |variable| {
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
    #[tokio::test]
    async fn plan_parses_internet_flag_and_false_overrides() {
        let baseline = configured_network(args(), "network-flags").await;
        let disabled = configured_network(
            Args {
                allow_internet_egress: Some(false),
                allow_lan: Some(false),
                allow_host: Some(false),
                ..args()
            },
            "network-flags",
        )
        .await;
        assert_eq!(baseline, disabled);
    }

    /// The sandbox name and derived socket paths the boot-free harness contract
    /// (`script/test/egress-default-deny-contract.sh`) pins. The Python cleanup
    /// code recomputes these paths; this test keeps the Runtime's derivation
    /// authoritative so the mirror cannot silently drift.
    #[test]
    fn harness_owned_socket_paths_match_runtime_derivation() {
        use sha2::{Digest, Sha256};
        let name = "agent-vm-0123456789ab-4242";
        let run_dir = std::path::Path::new("/tmp/av302-msb-home/run");
        let digest = Sha256::digest(name.as_bytes());
        let hex = |bytes: usize| -> String {
            digest[..bytes].iter().map(|b| format!("{b:02x}")).collect()
        };
        let canonical = run_dir.join("sandboxes").join(hex(12));
        let legacy = run_dir.join("agent").join(format!("{}.sock", hex(16)));
        let paths = microsandbox_runtime::ipc::RuntimeSocketPaths::new(run_dir, name);
        assert_eq!(paths.canonical_dir, canonical);
        assert_eq!(paths.agent, canonical.join("agent.sock"));
        assert_eq!(paths.control, canonical.join("control.sock"));
        assert_eq!(paths.legacy_agent, legacy);
        assert_eq!(paths.legacy_control, legacy.with_extension("control.sock"));
    }

    /// A24: with a persisted reference the refusal names it; without one the
    /// three pre-#506 sentences are byte-identical.
    ///
    /// Every expectation here is a **complete literal**, independent of
    /// [`HOSTNAME_PROXY_REFUSAL`]: an expectation built from the production
    /// constant moves with it, so mutating the base sentence would leave the
    /// test green. Three new sentences, and the three old ones beside them.
    #[test]
    fn hostname_proxy_refusal_names_references() {
        const CLI_ONLY: &str = "hostname allowances cannot be enforced through the host HTTP proxy (HTTPS_PROXY/HTTP_PROXY/ALL_PROXY): the proxy resolves the name, so the address scope is not checked; unset the proxy, use an IP/CIDR allowance, or use --allow-internet-egress (hostnames from --allow-egress, including via tool:codex, apply to this launch; stop passing them)";
        const CLI_ONLY_NO_REFERENCE: &str = "hostname allowances cannot be enforced through the host HTTP proxy (HTTPS_PROXY/HTTP_PROXY/ALL_PROXY): the proxy resolves the name, so the address scope is not checked; unset the proxy, use an IP/CIDR allowance, or use --allow-internet-egress";
        const PERSISTED_ONLY: &str = "hostname allowances cannot be enforced through the host HTTP proxy (HTTPS_PROXY/HTTP_PROXY/ALL_PROXY): the proxy resolves the name, so the address scope is not checked; unset the proxy, use an IP/CIDR allowance, or use --allow-internet-egress (persisted hostname grants from \"/home/u/.config/agent-vm/config.toml\" [network], including via tool:codex, apply to every launch; remove them there)";
        const PERSISTED_ONLY_NO_REFERENCE: &str = "hostname allowances cannot be enforced through the host HTTP proxy (HTTPS_PROXY/HTTP_PROXY/ALL_PROXY): the proxy resolves the name, so the address scope is not checked; unset the proxy, use an IP/CIDR allowance, or use --allow-internet-egress (persisted hostname grants from \"/home/u/.config/agent-vm/config.toml\" [network] apply to every launch; remove them there)";
        const BOTH: &str = "hostname allowances cannot be enforced through the host HTTP proxy (HTTPS_PROXY/HTTP_PROXY/ALL_PROXY): the proxy resolves the name, so the address scope is not checked; unset the proxy, use an IP/CIDR allowance, or use --allow-internet-egress (hostnames from --allow-egress, including via tool:codex, apply to this launch; persisted hostname grants from \"/home/u/.config/agent-vm/config.toml\" [network], including via tool:codex, apply to every launch; remove the persisted ones there and stop passing --allow-egress)";
        const BOTH_NO_REFERENCE: &str = "hostname allowances cannot be enforced through the host HTTP proxy (HTTPS_PROXY/HTTP_PROXY/ALL_PROXY): the proxy resolves the name, so the address scope is not checked; unset the proxy, use an IP/CIDR allowance, or use --allow-internet-egress (hostnames from --allow-egress apply to this launch; persisted hostname grants from \"/home/u/.config/agent-vm/config.toml\" [network] apply to every launch; remove the persisted ones there and stop passing --allow-egress)";
        let proxy = |v: &str| (v == "HTTPS_PROXY").then(|| "http://127.0.0.1:9".into());
        let tools = crate::egress_reference::test_support::user_tools(
            std::path::Path::new("/home/u/.config/agent-vm/config.toml"),
            &[("codex", &["api.openai.com"])],
        );
        let user = crate::user_network::UserNetwork::for_test_with_tools(
            "/home/u/.config/agent-vm/config.toml",
            Default::default(),
            &["tool:codex"],
            &tools,
        );
        let error = Plan::from_args_with_proxy_lookup(args(), Some(&user), Some(&tools), proxy)
            .unwrap_err()
            .to_string();
        assert_eq!(error, PERSISTED_ONLY);

        // The literal-only sentence is unchanged, byte for byte.
        let literal = crate::user_network::UserNetwork::for_test(
            "/home/u/.config/agent-vm/config.toml",
            Default::default(),
            &["api.example.com"],
        );
        let error = Plan::from_args_with_proxy_lookup(args(), Some(&literal), None, proxy)
            .unwrap_err()
            .to_string();
        assert_eq!(error, PERSISTED_ONLY_NO_REFERENCE);

        // A CLI reference, alone and alongside the persisted one.
        let mut reference = args();
        reference.allow_egress = vec!["tool:codex".into()];
        let error = Plan::from_args_with_proxy_lookup(reference, None, Some(&tools), proxy)
            .unwrap_err()
            .to_string();
        assert_eq!(error, CLI_ONLY);

        let mut both = args();
        both.allow_egress = vec!["tool:codex".into()];
        let error = Plan::from_args_with_proxy_lookup(both, Some(&user), Some(&tools), proxy)
            .unwrap_err()
            .to_string();
        assert_eq!(error, BOTH);

        // #511 A34: a *set* reference names itself in the same two slots, and
        // the tool sentence above stays byte-identical.
        const PERSISTED_SET: &str = "hostname allowances cannot be enforced through the host HTTP proxy (HTTPS_PROXY/HTTP_PROXY/ALL_PROXY): the proxy resolves the name, so the address scope is not checked; unset the proxy, use an IP/CIDR allowance, or use --allow-internet-egress (persisted hostname grants from \"/home/u/.config/agent-vm/config.toml\" [network], including via set:corp, apply to every launch; remove them there)";
        let sets = crate::egress_reference::test_support::user_namespace(
            std::path::Path::new("/home/u/.config/agent-vm/config.toml"),
            &[],
            Some("corp = [\"git.corp.example\"]\n"),
        );
        let user = crate::user_network::UserNetwork::for_test_with_tools(
            "/home/u/.config/agent-vm/config.toml",
            Default::default(),
            &["set:corp"],
            &sets,
        );
        let error = Plan::from_args_with_proxy_lookup(args(), Some(&user), Some(&sets), proxy)
            .unwrap_err()
            .to_string();
        assert_eq!(error, PERSISTED_SET);

        // The three pre-#506 sentences, also pinned independently.
        let mut cli_literal = args();
        cli_literal.allow_egress = vec!["cli.example.com".into()];
        let error = Plan::from_args_with_proxy_lookup(cli_literal, None, None, proxy)
            .unwrap_err()
            .to_string();
        assert_eq!(error, CLI_ONLY_NO_REFERENCE);
        let mut both_literal = args();
        both_literal.allow_egress = vec!["cli.example.com".into()];
        let error = Plan::from_args_with_proxy_lookup(both_literal, Some(&literal), None, proxy)
            .unwrap_err()
            .to_string();
        assert_eq!(error, BOTH_NO_REFERENCE);
    }

    /// R26, corrected for sets: the refusal names a reference only when that
    /// reference's **own expansion** grants a hostname.
    ///
    /// A set of addresses, an empty set, or a set that repeats a literal's
    /// hostname is not a source of hostname authority, so naming it would send
    /// the reader to delete a line whose removal changes nothing. Every
    /// expectation is a complete literal sentence, not a substring, so a suffix
    /// that quietly disappeared would fail here.
    #[test]
    fn hostname_proxy_refusal_names_only_references_that_grant_hostnames() {
        const REFUSAL: &str = concat!(
            "hostname allowances cannot be enforced through the host HTTP proxy ",
            "(HTTPS_PROXY/HTTP_PROXY/ALL_PROXY): the proxy resolves the name, so the address ",
            "scope is not checked; unset the proxy, use an IP/CIDR allowance, or use ",
            "--allow-internet-egress"
        );
        const SAVED_HEAD: &str =
            " (persisted hostname grants from \"/home/u/.config/agent-vm/config.toml\" [network]";
        const SAVED_TAIL: &str = " apply to every launch; remove them there)";
        const CLI_HEAD: &str = " (hostnames from --allow-egress";
        const BOTH_MIDDLE: &str = " apply to this launch; persisted hostname grants from \"/home/u/.config/agent-vm/config.toml\" [network]";
        const BOTH_TAIL: &str = " apply to every launch; remove the persisted ones there and stop passing --allow-egress)";
        let proxy = |v: &str| (v == "HTTPS_PROXY").then(|| "http://127.0.0.1:9".into());
        let file = std::path::Path::new("/home/u/.config/agent-vm/config.toml");
        // One namespace holds every case: a set of addresses, an empty set and a
        // set that does grant a hostname.
        let sets = crate::egress_reference::test_support::user_namespace(
            file,
            &[],
            Some("num = [\"10.0.0.1\"]\nempty = []\ncorp = [\"git.corp.example\"]\n"),
        );
        let saved = |entries: &[&str]| {
            crate::user_network::UserNetwork::for_test_with_tools(
                file,
                Default::default(),
                entries,
                &sets,
            )
        };
        let refusal = |plan: Result<Plan>| plan.unwrap_err().to_string();

        // Persisted tier: an address set and an empty set are silent; the set
        // that grants a hostname is named. The literal is what makes the
        // sentence appear at all.
        for entries in [
            &["set:num", "api.example.com"][..],
            &["set:empty", "api.example.com"][..],
        ] {
            assert_eq!(
                refusal(Plan::from_args_with_proxy_lookup(
                    args(),
                    Some(&saved(entries)),
                    Some(&sets),
                    proxy
                )),
                format!("{REFUSAL}{SAVED_HEAD}{SAVED_TAIL}"),
                "{entries:?}"
            );
        }
        assert_eq!(
            refusal(Plan::from_args_with_proxy_lookup(
                args(),
                Some(&saved(&[
                    "set:num",
                    "set:empty",
                    "set:corp",
                    "api.example.com"
                ])),
                Some(&sets),
                proxy
            )),
            format!("{REFUSAL}{SAVED_HEAD}, including via set:corp,{SAVED_TAIL}")
        );

        // CLI tier: the same three shapes, through `--allow-egress`. With no
        // hostname-granting reference the bare sentence is the pre-#506 one.
        let cli = |entries: &[&str]| Args {
            allow_egress: entries.iter().map(|e| (*e).to_owned()).collect(),
            ..args()
        };
        for entries in [
            &["set:num", "api.example.com"][..],
            &["set:empty", "api.example.com"][..],
        ] {
            assert_eq!(
                refusal(Plan::from_args_with_proxy_lookup(
                    cli(entries),
                    None,
                    Some(&sets),
                    proxy
                )),
                REFUSAL,
                "{entries:?}"
            );
        }
        assert_eq!(
            refusal(Plan::from_args_with_proxy_lookup(
                cli(&["set:corp"]),
                None,
                Some(&sets),
                proxy
            )),
            format!(
                "{REFUSAL}{CLI_HEAD}, including via set:corp, apply to this launch; stop passing them)"
            )
        );

        // Mixed tiers, one each way: the address-only CLI set is silent while
        // the persisted hostname set is named, and vice versa.
        assert_eq!(
            refusal(Plan::from_args_with_proxy_lookup(
                cli(&["set:num", "cli.example.com"]),
                Some(&saved(&["set:corp"])),
                Some(&sets),
                proxy
            )),
            format!("{REFUSAL}{CLI_HEAD}{BOTH_MIDDLE}, including via set:corp,{BOTH_TAIL}")
        );
        assert_eq!(
            refusal(Plan::from_args_with_proxy_lookup(
                cli(&["set:corp", "cli.example.com"]),
                Some(&saved(&["set:num", "api.example.com"])),
                Some(&sets),
                proxy
            )),
            format!("{REFUSAL}{CLI_HEAD}, including via set:corp,{BOTH_MIDDLE}{BOTH_TAIL}")
        );
    }

    /// A14 (CLI half) and A20: the CLI's own `#N` rendering of a *resolution*
    /// error, for a tool that declares no requests, and of UNKNOWN — each with a
    /// sentinel inside the name, so a message that echoed it would fail here.
    /// The text is pinned as an independent literal, not as the production
    /// constant.
    #[test]
    fn cli_reference_resolution_errors_keep_their_position_and_echo_nothing() {
        const SENTINEL: &str = "sk-live-SENTINEL-506";
        let tools = crate::egress_reference::test_support::user_tools(
            std::path::Path::new("/home/u/.config/agent-vm/config.toml"),
            &[("no-requests", &[]), ("has-requests", &["a.example"])],
        );
        for (entry, expected) in [
            (
                "tool:no-requests",
                "--allow-egress #2: an egress reference must name a tool that declares network_requests; this tool declares none, so the reference would grant nothing",
            ),
            (
                "tool:sk-live-SENTINEL-506",
                "--allow-egress #2: an egress reference must name a tool declared in the user config's own [[tools]]; built-in and project tools are never used (`agent-vm tools print` prints the shipped tools to copy there)",
            ),
        ] {
            let mut input = args();
            input.allow_egress = vec!["api.example.com".into(), entry.into()];
            let error = Plan::from_args_with_proxy_lookup(input, None, Some(&tools), |_| None)
                .unwrap_err()
                .to_string();
            assert_eq!(error, expected);
            assert!(!error.contains(SENTINEL), "the name was echoed: {error}");
            assert!(
                !error.contains("no-requests"),
                "the name was echoed: {error}"
            );
        }
        // The same rows reached through a real namespace confirm the tool that
        // *does* have requests is not the one refused.
        let mut input = args();
        input.allow_egress = vec!["tool:has-requests".into()];
        Plan::from_args_with_proxy_lookup(input, None, Some(&tools), |_| None)
            .expect("a tool with requests resolves on the flag");
    }

    /// A19, CLI half: entry-syntax errors precede resolution errors, and within
    /// each class the first failing entry wins. `#2` is reported even though `#1`
    /// is also wrong.
    #[test]
    fn cli_entry_syntax_errors_precede_resolution_errors() {
        let tools = crate::egress_reference::test_support::user_tools(
            std::path::Path::new("/home/u/.config/agent-vm/config.toml"),
            &[],
        );
        let mut input = args();
        input.allow_egress = vec!["tool:nope".into(), "udp://h.example".into()];
        let error = Plan::from_args_with_proxy_lookup(input, None, Some(&tools), |_| None)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            format!(
                "--allow-egress #2: {}",
                crate::egress_grammar::AllowanceError::UdpHostname
            )
        );
        // And the resolution error keeps its own one-based position.
        let mut input = args();
        input.allow_egress = vec!["api.example.com".into(), "tool:nope".into()];
        let error = Plan::from_args_with_proxy_lookup(input, None, Some(&tools), |_| None)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "--allow-egress #2: an egress reference must name a tool declared in the user config's own [[tools]]; built-in and project tools are never used (`agent-vm tools print` prints the shipped tools to copy there)"
        );
    }
}
