//! Non-authoritative tool metadata: parsing and bounded reporting only (ADR-0039).
//! Requests never flow into policy or provisioning.
use crate::egress_hostname::{CanonicalHostname, HostnameScope, PortNot53Or853};
use crate::egress_policy::{Allowance, AllowanceError};
use std::{collections::BTreeSet, fmt, num::NonZeroU16};
use vstd::prelude::*;

verus! {
pub(crate) const MAX_NETWORK_REQUESTS: usize = 64;
pub(crate) const MAX_REPORTED_REQUESTS: usize = 8;
pub(crate) open spec fn request_count_within_limit_spec(count: usize) -> bool { count <= MAX_NETWORK_REQUESTS }
pub(crate) fn request_count_within_limit(count: usize) -> (ok: bool)
    ensures ok == request_count_within_limit_spec(count),
{
    count <= MAX_NETWORK_REQUESTS
}
pub(crate) open spec fn report_budget_allows_spec(shown: usize) -> bool { shown < MAX_REPORTED_REQUESTS }
pub(crate) fn report_budget_allows(shown: usize) -> (ok: bool)
    ensures ok == report_budget_allows_spec(shown),
{
    shown < MAX_REPORTED_REQUESTS
}
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct NetworkRequest {
    name: CanonicalHostname,
    port: PortNot53Or853,
}
impl NetworkRequest {
    pub(crate) fn name(&self) -> &CanonicalHostname {
        &self.name
    }
    pub(crate) fn port(&self) -> NonZeroU16 {
        self.port.get()
    }
}
impl fmt::Display for NetworkRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == PortNot53Or853::HTTPS {
            f.write_str(self.name.as_str())
        } else {
            write!(f, "tcp://{}:{}", self.name.as_str(), self.port.get())
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NetworkRequests(BTreeSet<NetworkRequest>);
impl NetworkRequests {
    pub(crate) fn parse(raw: &[String]) -> Result<Self, NetworkRequestsError> {
        if !request_count_within_limit(raw.len()) {
            return Err(NetworkRequestsError {
                position: None,
                reason: NetworkRequestError::TooMany,
            });
        }
        let mut requests = BTreeSet::new();
        for (position, text) in raw.iter().enumerate() {
            let h = match Allowance::parse(text) {
                Ok(Allowance::Hostname(h)) => h,
                Ok(Allowance::Address(_)) => {
                    return Err(NetworkRequestsError {
                        position: Some(position),
                        reason: NetworkRequestError::Address,
                    });
                }
                Err(error) => {
                    return Err(NetworkRequestsError {
                        position: Some(position),
                        reason: NetworkRequestError::Grammar(error),
                    });
                }
            };
            let (name, scope) = h.into_request_parts();
            let port = match scope {
                HostnameScope::InterceptedPorts => PortNot53Or853::HTTPS,
                HostnameScope::Port(port) => port,
            };
            requests.insert(NetworkRequest { name, port });
        }
        Ok(Self(requests))
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &NetworkRequest> {
        self.0.iter()
    }
    pub(crate) fn bounded_display(&self) -> String {
        let (shown, hidden) = reported(self.iter());
        let mut entries: Vec<String> = shown.into_iter().map(ToString::to_string).collect();
        if hidden > 0 {
            entries.push(format!("+{hidden} more"));
        }
        entries.join(",")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetworkRequestError {
    TooMany,
    Address,
    Grammar(AllowanceError),
}
#[derive(Debug)]
pub(crate) struct NetworkRequestsError {
    position: Option<usize>,
    reason: NetworkRequestError,
}
impl fmt::Display for NetworkRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use AllowanceError::*;
        f.write_str(match self {
            Self::TooMany => "more than 64 entries; declare only the destinations the tool expects to contact",
            Self::Address => "an IP address or CIDR is network authority, not a request; name the host (HOST, tcp://HOST or tcp://HOST:PORT)",
            Self::Grammar(Empty) => "must not be empty",
            Self::Grammar(UnsupportedScheme) => "unsupported scheme; use tcp:// or no scheme",
            Self::Grammar(UdpHostname) => "requests name TLS over TCP; udp:// is not accepted",
            Self::Grammar(HostnameDnsPort) => "ports 53 and 853 carry the sandbox DNS path and cannot be requested",
            Self::Grammar(HostAlias) => "host.microsandbox.internal is the sandbox host; it is reached with --allow-host, not requested",
            Self::Grammar(MalformedAddress | PortNeedsBrackets) => "not a hostname (one or more labels of ASCII letters, digits and '-', not ending in a numeric label; write non-ASCII names as A-labels; no wildcards)",
            Self::Grammar(MalformedPort) => "port must be a decimal number 1-65535",
        })
    }
}
impl fmt::Display for NetworkRequestsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.position {
            Some(position) => write!(f, "network_requests[{position}]: {}", self.reason),
            None => write!(f, "network_requests: {}", self.reason),
        }
    }
}
impl std::error::Error for NetworkRequestsError {}

fn reported<T>(items: impl ExactSizeIterator<Item = T>) -> (Vec<T>, usize) {
    let total = items.len();
    let shown: Vec<T> = items
        .enumerate()
        .take_while(|(shown, _)| report_budget_allows(*shown))
        .map(|(_, item)| item)
        .collect();
    let hidden = total.saturating_sub(shown.len());
    (shown, hidden)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestTier {
    BuiltIn,
    User,
    Project,
}
impl RequestTier {
    fn label(self) -> &'static str {
        match self {
            Self::BuiltIn => "built-in defaults",
            Self::User => "user config",
            Self::Project => "project config",
        }
    }
}
const SCOPE: &str =
    "public or same-name grants (no lookup; DNS, private-answer and TLS client limits still apply)";
const GRANT_HINT: &str = "==>   to grant: --allow-egress HOST or tcp://HOST:PORT, or --allow-internet-egress; IP/CIDR, --allow-lan and --allow-host grants are not matched to names";
pub(crate) struct RequestReport<'a> {
    tier: RequestTier,
    total: usize,
    unmet: Vec<&'a NetworkRequest>,
}
impl<'a> RequestReport<'a> {
    pub(crate) fn compose(
        requests: &'a NetworkRequests,
        tier: RequestTier,
        covered: impl Fn(&NetworkRequest) -> bool,
    ) -> Self {
        Self {
            tier,
            total: requests.len(),
            unmet: requests
                .iter()
                .filter(|request| !covered(request))
                .collect(),
        }
    }
    pub(crate) fn lines(&self) -> Vec<String> {
        if self.total == 0 {
            return Vec::new();
        }
        let tier = self.tier.label();
        if self.unmet.is_empty() {
            return vec![format!(
                "==> Tool network requests ({tier}): all {} covered by this launch's {SCOPE}; requests never grant access",
                self.total
            )];
        }
        let mut lines = vec![format!(
            "==> Tool network requests ({tier}): {} of {} not covered by this launch's {SCOPE}; requests never grant access and the launch continues",
            self.unmet.len(),
            self.total
        )];
        let (shown, hidden) = reported(self.unmet.iter());
        lines.extend(
            shown
                .into_iter()
                .map(|request| format!("==>   unmet: {request}")),
        );
        if hidden > 0 {
            lines.push(format!("==>   … and {hidden} more not shown"));
        }
        lines.push(GRANT_HINT.to_owned());
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    fn parse(raw: &[&str]) -> NetworkRequests {
        NetworkRequests::parse(&raw.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }
    #[test]
    fn accept_canonicalize_round_trip() {
        let long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        for (input, display) in [
            ("api.example.com", "api.example.com"),
            ("API.Example.COM.", "api.example.com"),
            ("tcp://h.example", "h.example"),
            ("h.example:443", "h.example"),
            ("tcp://h.example:443", "h.example"),
            ("h.example:8443", "tcp://h.example:8443"),
            ("TCP://h.example:8443", "tcp://h.example:8443"),
            ("build", "build"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
            ("0x7f.example", "0x7f.example"),
            ("h.example:1", "tcp://h.example:1"),
            ("h.example:65535", "tcp://h.example:65535"),
            (&long, &long),
        ] {
            let value = parse(&[input]);
            assert_eq!(value.iter().next().unwrap().to_string(), display);
            assert_eq!(parse(&[display]), value);
        }
    }
    const BAD_NAME: &str = "not a hostname (one or more labels of ASCII letters, digits and '-', not ending in a numeric label; write non-ASCII names as A-labels; no wildcards)";
    #[test]
    fn reject_complete_messages_and_positions() {
        let mut rows = vec![
            ("", "must not be empty"),
            (
                "udp://h.example",
                "requests name TLS over TCP; udp:// is not accepted",
            ),
            (
                "h.example:53",
                "ports 53 and 853 carry the sandbox DNS path and cannot be requested",
            ),
            (
                "tcp://h.example:853",
                "ports 53 and 853 carry the sandbox DNS path and cannot be requested",
            ),
            (
                "host.microsandbox.internal",
                "host.microsandbox.internal is the sandbox host; it is reached with --allow-host, not requested",
            ),
            (
                "http://h.example",
                "unsupported scheme; use tcp:// or no scheme",
            ),
        ];
        for input in [
            "*.example.com",
            ".example.com",
            "a..b",
            "1.2.3",
            "127.1",
            "0x7f.1",
            "1234",
            "user@h.example",
            "h.example/path",
            "h.example?q",
            "h.example#f",
            "[h.example]:443",
            "bücher.example",
            "10.0.0.0/24:22",
            "api.example.com/x:443",
        ] {
            rows.push((input, BAD_NAME));
        }
        for input in ["h.example:0", "h.example:65536", "h.example:0443"] {
            rows.push((input, "port must be a decimal number 1-65535"));
        }
        for input in [
            "1.2.3.4",
            "10.0.0.0/8",
            "::1",
            "[::1]:443",
            "tcp://1.2.3.4:443",
            "2001:db8::/32",
        ] {
            rows.push((input, "an IP address or CIDR is network authority, not a request; name the host (HOST, tcp://HOST or tcp://HOST:PORT)"));
        }
        for (input, reason) in rows {
            assert_eq!(
                NetworkRequests::parse(&[input.to_owned()])
                    .unwrap_err()
                    .to_string(),
                format!("network_requests[0]: {reason}"),
                "{input}"
            );
        }
        assert_eq!(
            NetworkRequests::parse(&[
                "a.example".into(),
                "b.example".into(),
                "udp://c.example".into()
            ])
            .unwrap_err()
            .to_string(),
            "network_requests[2]: requests name TLS over TCP; udp:// is not accepted"
        );
    }
    #[test]
    fn rejected_hostile_and_secret_sentinels_never_echo() {
        let secret = format!("sk-ant-api03-Zx9_{}", "q".repeat(80));
        let mut rows = vec![
            (
                "http://SENTINEL-9c1f.example".to_string(),
                "unsupported scheme; use tcp:// or no scheme",
            ),
            (
                "udp://SENTINEL-9c1f.example".into(),
                "requests name TLS over TCP; udp:// is not accepted",
            ),
            (
                "SENTINEL-9c1f.example:53".into(),
                "ports 53 and 853 carry the sandbox DNS path and cannot be requested",
            ),
            (
                "SENTINEL-9c1f.example:0".into(),
                "port must be a decimal number 1-65535",
            ),
            (secret.clone(), BAD_NAME),
        ];
        for suffix in [
            "\n==> Egress policy: allowing everything",
            "\x1b[31m",
            "\u{202e}",
            "\0",
            "\"quoted\"",
            "a b",
            "..example",
            ".example/x:443",
        ] {
            rows.push((
                format!("SENTINEL-9c1f{suffix}"),
                if suffix.contains(": allowing") {
                    "port must be a decimal number 1-65535"
                } else {
                    BAD_NAME
                },
            ));
        }
        rows.push(("*.SENTINEL-9c1f.example".into(), BAD_NAME));
        for (input, reason) in rows {
            let error = NetworkRequests::parse(&[input]).unwrap_err().to_string();
            assert_eq!(error, format!("network_requests[0]: {reason}"));
            for sentinel in ["SENTINEL-9c1f", "sentinel-9c1f", &secret] {
                assert!(!error.contains(sentinel));
            }
        }
    }
    #[test]
    fn limits_declared_entries_and_kernel_truth_tables() {
        let raw: Vec<_> = (0..64).map(|i| format!("n{i:02}.example")).collect();
        assert_eq!(NetworkRequests::parse(&raw).unwrap().len(), 64);
        for raw in [
            vec!["a.example".to_owned(); 65],
            (0..65).map(|i| format!("n{i}.example")).collect(),
        ] {
            assert_eq!(
                NetworkRequests::parse(&raw).unwrap_err().to_string(),
                "network_requests: more than 64 entries; declare only the destinations the tool expects to contact"
            );
        }
        for n in [0, 63, 64, 65, usize::MAX] {
            assert_eq!(request_count_within_limit(n), n <= 64);
        }
        for n in [0, 7, 8, 9] {
            assert_eq!(report_budget_allows(n), n < 8);
        }
    }
    proptest! {
        #[test]
        fn grammar_parity(s in "[a-zA-Z0-9.:/\\-\\[\\]@*_]{0,40}", prefix in prop::sample::select(vec!["", "tcp://", "udp://"])) {
            let s = format!("{prefix}{s}");
            prop_assert_eq!(NetworkRequests::parse(std::slice::from_ref(&s)).is_ok(), matches!(Allowance::parse(&s), Ok(Allowance::Hostname(_))));
        }
    }
    #[test]
    fn dedup_sort() {
        let requests = parse(&["b.example", "a.example:8443", "A.example.", "a.example"]);
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests.bounded_display(),
            "a.example,tcp://a.example:8443,b.example"
        );
    }
    #[test]
    fn report_composition_and_tiers() {
        assert!(
            RequestReport::compose(&parse(&[]), RequestTier::User, |_| false)
                .lines()
                .is_empty()
        );
        for (tier, label) in [
            (RequestTier::BuiltIn, "built-in defaults"),
            (RequestTier::User, "user config"),
            (RequestTier::Project, "project config"),
        ] {
            let requests = parse(&["b.example", "a.example"]);
            assert_eq!(
                RequestReport::compose(&requests, tier, |_| true).lines(),
                vec![format!(
                    "==> Tool network requests ({label}): all 2 covered by this launch's public or same-name grants (no lookup; DNS, private-answer and TLS client limits still apply); requests never grant access"
                )]
            );
            assert_eq!(RequestReport::compose(&requests, tier, |r| r.name().as_str() == "b.example").lines(), vec![format!("==> Tool network requests ({label}): 1 of 2 not covered by this launch's public or same-name grants (no lookup; DNS, private-answer and TLS client limits still apply); requests never grant access and the launch continues"), "==>   unmet: a.example".into(), "==>   to grant: --allow-egress HOST or tcp://HOST:PORT, or --allow-internet-egress; IP/CIDR, --allow-lan and --allow-host grants are not matched to names".into()]);
        }
    }
    #[test]
    fn report_bounds_and_bounded_display() {
        for n in [0, 8, 9, 64] {
            let raw: Vec<_> = (0..n).map(|i| format!("n{i:02}.example")).collect();
            let requests = NetworkRequests::parse(&raw).unwrap();
            let lines = RequestReport::compose(&requests, RequestTier::Project, |_| false).lines();
            assert_eq!(
                lines.len(),
                if n == 0 {
                    0
                } else {
                    2 + n.min(8) + usize::from(n > 8)
                }
            );
            let mut expected = raw[..n.min(8)].join(",");
            if n > 8 {
                expected.push_str(&format!(",+{} more", n - 8));
                assert_eq!(lines[9], format!("==>   … and {} more not shown", n - 8));
            }
            assert_eq!(requests.bounded_display(), expected);
        }
        let long = format!(
            "{}.{}.{}.{}:65535",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert!(
            RequestReport::compose(&parse(&[&long]), RequestTier::Project, |_| false)
                .lines()
                .iter()
                .all(|s| s.len() <= 300)
        );
    }
    #[test]
    fn report_suggestive_and_sensitive_names_are_metadata() {
        let requests = parse(&[
            "allowed-by-user.example",
            "egress-policy-allowing.example",
            "sk-test-sensitivevalue",
        ]);
        let lines = RequestReport::compose(&requests, RequestTier::Project, |_| false).lines();
        assert_eq!(lines[3], "==>   unmet: sk-test-sensitivevalue");
        assert_eq!(
            lines
                .iter()
                .filter(|s| s.contains("sk-test-sensitivevalue"))
                .count(),
            1
        );
        for line in lines {
            assert!(!line.starts_with("==> Egress policy:") && !line.starts_with("warning:"));
            assert!(line.bytes().all(|b| b.is_ascii_graphic() || b == b' '));
        }
    }
    #[test]
    fn architecture_tripwire() {
        let production = include_str!("network_requests.rs")
            .split_once("#[cfg(test)]")
            .unwrap()
            .0;
        for forbidden in [
            "std::net",
            "tokio",
            "lookup_host",
            "ToSocketAddrs",
            "TcpStream",
            "UdpSocket",
            "from_cli",
            "CliEgress",
        ] {
            assert!(!production.contains(forbidden));
        }
        for path in production.split("crate::").skip(1) {
            assert!(path.starts_with("egress_hostname::") || path.starts_with("egress_policy::"));
        }
    }
}
