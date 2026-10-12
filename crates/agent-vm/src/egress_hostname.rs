//! Hostname acceptance is separate from credential-origin authority.
use crate::dns_name::ldh_host_bytes;
use crate::egress_policy::SchemeSel;
use vstd::prelude::*;

verus! {
pub(crate) open spec fn is_hex_lower(b: u8) -> bool {
    (b'0' <= b && b <= b'9') || (b'a' <= b && b <= b'f')
}
pub(crate) open spec fn last_dot(s: Seq<u8>, k: int) -> bool {
    0 <= k < s.len() && s[k] == 0x2e
        && forall|j: int| k < j < s.len() ==> #[trigger] s[j] != 0x2e
}
pub(crate) open spec fn no_dot(s: Seq<u8>) -> bool {
    forall|j: int| 0 <= j < s.len() ==> #[trigger] s[j] != 0x2e
}
pub(crate) open spec fn numeric_label(l: Seq<u8>) -> bool {
    (l.len() >= 1 && forall|i: int| 0 <= i < l.len() ==> b'0' <= #[trigger] l[i] <= b'9')
    || (l.len() >= 2 && l[0] == 0x30 && l[1] == 0x78
        && forall|i: int| 2 <= i < l.len() ==> is_hex_lower(#[trigger] l[i]))
}
pub(crate) open spec fn final_label_numeric(s: Seq<u8>) -> bool {
    (no_dot(s) && numeric_label(s))
    || exists|k: int| last_dot(s, k) && numeric_label(s.subrange(k + 1, s.len() as int))
}
pub(crate) open spec fn egress_hostname_spec(s: Seq<u8>) -> bool {
    crate::dns_name::ldh_host_spec(s) && !final_label_numeric(s)
}
proof fn lemma_last_dot_unique(s: Seq<u8>, k1: int, k2: int)
    requires last_dot(s, k1), last_dot(s, k2),
    ensures k1 == k2,
{
    if k1 < k2 { assert(s[k2] != 0x2e); }
    if k2 < k1 { assert(s[k1] != 0x2e); }
}
fn last_dot_index(bytes: &[u8]) -> (r: Option<usize>)
    ensures match r {
        Some(k) => last_dot(bytes@, k as int),
        None => no_dot(bytes@),
    },
{
    let mut i = bytes.len();
    while i > 0
        invariant i <= bytes.len(),
            forall|j: int| i <= j < bytes.len() ==> #[trigger] bytes@[j] != 0x2e,
        decreases i,
    {
        i -= 1;
        if bytes[i] == b'.' { return Some(i); }
    }
    None
}
// Keep length comparisons parallel to the byte-sequence specification.
#[allow(clippy::manual_range_contains, clippy::len_zero)]
fn numeric_label_bytes(bytes: &[u8]) -> (ok: bool)
    ensures ok == numeric_label(bytes@),
{
    let hex = bytes.len() >= 2 && bytes[0] == b'0' && bytes[1] == b'x';
    let start = if hex { 2usize } else { 0usize };
    if !hex && bytes.len() == 0 { return false; }
    let mut i = start;
    while i < bytes.len()
        invariant
            i <= bytes.len(), start <= i,
            hex == (bytes.len() >= 2 && bytes@[0] == b'0' && bytes@[1] == b'x'),
            start == (if hex { 2usize } else { 0usize }),
            !hex ==> bytes.len() > 0,
            forall|j: int| start <= j < i ==> (if hex { is_hex_lower(bytes@[j]) }
                else { b'0' <= bytes@[j] <= b'9' }),
        decreases bytes.len() - i,
    {
        let b = bytes[i];
        let digit = b'0' <= b && b <= b'9';
        let allowed = if hex { digit || (b'a' <= b && b <= b'f') } else { digit };
        if !allowed {
            assert(!numeric_label(bytes@));
            return false;
        }
        i += 1;
    }
    true
}
pub(crate) fn egress_hostname_bytes(bytes: &[u8]) -> (ok: bool)
    ensures ok == egress_hostname_spec(bytes@),
{
    if !ldh_host_bytes(bytes) { return false; }
    let k = last_dot_index(bytes);
    match k {
        None => {
            proof {
                assert(!exists|j: int| last_dot(bytes@, j));
            }
            !numeric_label_bytes(bytes)
        },
        Some(k) => {
            let label = &bytes[k + 1..];
            let numeric = numeric_label_bytes(label);
            proof {
                assert(label@ == bytes@.subrange(k as int + 1, bytes@.len() as int));
                assert(!no_dot(bytes@));
                assert forall|j: int| last_dot(bytes@, j) implies j == k by {
                    lemma_last_dot_unique(bytes@, j, k as int);
                }
            }
            !numeric
        },
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub(crate) enum HostnameScopeSel { Intercepted, Port(u16) }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub(crate) enum HostnameScopeError { Udp, Bracketed, DnsPort }
pub(crate) open spec fn dns_port(p: u16) -> bool { p == 53 || p == 853 }
pub(crate) fn hostname_scope(scheme: SchemeSel, bracketed: bool, port: Option<u16>)
    -> (r: Result<HostnameScopeSel, HostnameScopeError>)
    ensures
        scheme == SchemeSel::Udp ==> r == Err::<HostnameScopeSel, _>(HostnameScopeError::Udp),
        scheme != SchemeSel::Udp && bracketed ==> r == Err::<HostnameScopeSel, _>(HostnameScopeError::Bracketed),
        scheme != SchemeSel::Udp && !bracketed ==> match port {
            None => r == Ok::<_, HostnameScopeError>(HostnameScopeSel::Intercepted),
            Some(p) => if dns_port(p) { r == Err::<HostnameScopeSel, _>(HostnameScopeError::DnsPort) }
                else { r == Ok::<_, HostnameScopeError>(HostnameScopeSel::Port(p)) },
        },
{
    if scheme == SchemeSel::Udp { return Err(HostnameScopeError::Udp); }
    if bracketed { return Err(HostnameScopeError::Bracketed); }
    match port {
        None => Ok(HostnameScopeSel::Intercepted),
        Some(p) => if p == 53 || p == 853 { Err(HostnameScopeError::DnsPort) }
            else { Ok(HostnameScopeSel::Port(p)) },
    }
}
}

use crate::egress_policy::AllowanceError;
use microsandbox_network::policy::{
    Action, Destination, Direction, DomainName, PortRange, Protocol, Rule,
};
use std::{collections::BTreeSet, num::NonZeroU16};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CanonicalHostname(String);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PortNot53Or853(NonZeroU16);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum HostnameScope {
    InterceptedPorts,
    Port(PortNot53Or853),
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct HostnameAllowance {
    name: CanonicalHostname,
    scope: HostnameScope,
    // Retain the fallibly parsed SDK value: rule assembly must not reparse or panic.
    domain: DomainName,
}
#[derive(Debug)]
pub(crate) struct InterceptedPorts(BTreeSet<NonZeroU16>);
impl InterceptedPorts {
    pub(crate) fn for_hostnames(hostnames: &[HostnameAllowance]) -> Option<Self> {
        if hostnames.is_empty() {
            return None;
        }
        let mut ports = BTreeSet::from([NonZeroU16::new(443)?]);
        for hostname in hostnames {
            if let HostnameScope::Port(port) = hostname.scope {
                ports.insert(port.0);
            }
        }
        Some(Self(ports))
    }
    pub(crate) fn to_vec(&self) -> Vec<u16> {
        self.0.iter().map(|p| p.get()).collect()
    }
}
impl CanonicalHostname {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}
impl PortNot53Or853 {
    // Evaluated at compile time, so this cannot panic during launch.
    pub(crate) const HTTPS: Self = Self(NonZeroU16::new(443).unwrap());
    pub(crate) fn get(self) -> NonZeroU16 {
        self.0
    }
}
impl HostnameAllowance {
    // Keep the SDK DomainName here: requests carry no rule-ready domain.
    pub(crate) fn into_request_parts(self) -> (CanonicalHostname, HostnameScope) {
        (self.name, self.scope)
    }
    pub(crate) fn grants_tls(
        &self,
        name: &CanonicalHostname,
        port: NonZeroU16,
        ports: &InterceptedPorts,
    ) -> bool {
        &self.name == name && self.effective_ports(ports).contains(&port.get())
    }

    pub(crate) fn from_target(
        scheme: SchemeSel,
        bracketed: bool,
        host: &str,
        port: Option<u16>,
    ) -> Result<Self, AllowanceError> {
        if !host.is_ascii() || host.ends_with("..") {
            return Err(AllowanceError::MalformedAddress);
        }
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        if !egress_hostname_bytes(host.as_bytes()) {
            return Err(AllowanceError::MalformedAddress);
        }
        let scope = match hostname_scope(scheme, bracketed, port).map_err(|error| match error {
            HostnameScopeError::Udp => AllowanceError::UdpHostname,
            HostnameScopeError::Bracketed => AllowanceError::MalformedAddress,
            HostnameScopeError::DnsPort => AllowanceError::HostnameDnsPort,
        })? {
            HostnameScopeSel::Intercepted => HostnameScope::InterceptedPorts,
            HostnameScopeSel::Port(p) => HostnameScope::Port(PortNot53Or853(
                NonZeroU16::new(p).ok_or(AllowanceError::MalformedPort)?,
            )),
        };
        if host == "host.microsandbox.internal" {
            return Err(AllowanceError::HostAlias);
        }
        let domain = host.parse().map_err(|_| AllowanceError::MalformedAddress)?;
        Ok(Self {
            name: CanonicalHostname(host),
            scope,
            domain,
        })
    }
    pub(crate) fn effective_ports(&self, ports: &InterceptedPorts) -> Vec<u16> {
        match self.scope {
            HostnameScope::InterceptedPorts => ports.to_vec(),
            HostnameScope::Port(p) => vec![p.0.get()],
        }
    }
}
impl std::fmt::Display for HostnameAllowance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.scope {
            HostnameScope::InterceptedPorts => f.write_str(&self.name.0),
            HostnameScope::Port(p) => write!(f, "tcp://{}:{}", self.name.0, p.0),
        }
    }
}
pub(crate) fn domain_rules(hostnames: &[HostnameAllowance], ports: &InterceptedPorts) -> Vec<Rule> {
    let mut rules: Vec<Rule> = Vec::new();
    for hostname in hostnames {
        let effective = hostname.effective_ports(ports);
        if let Some(rule) = rules.iter_mut().find(|rule| matches!(&rule.destination, Destination::Domain(name) if name == &hostname.domain)) {
            let mut merged: BTreeSet<u16> = rule.ports.iter().map(|p| p.start).collect();
            merged.extend(effective);
            rule.ports = merged.into_iter().map(PortRange::single).collect();
        } else {
            rules.push(Rule {
                direction: Direction::Egress,
                destination: Destination::Domain(hostname.domain.clone()),
                protocols: vec![Protocol::Tcp],
                ports: effective.into_iter().map(PortRange::single).collect(),
                action: Action::Allow,
            });
        }
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    fn oracle(s: &str) -> bool {
        if s.is_empty() || s.len() > 253 {
            return false;
        }
        let labels: Vec<_> = s.split('.').collect();
        if labels.iter().any(|l| {
            l.is_empty()
                || l.len() > 63
                || l.starts_with('-')
                || l.ends_with('-')
                || !l
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        }) {
            return false;
        }
        let last = labels.last().unwrap();
        !(last.bytes().all(|b| b.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .is_some_and(|s| s.bytes().all(|b| b.is_ascii_hexdigit())))
    }
    #[test]
    fn hostname_kernel_oracle_table() {
        for s in [
            "api.example.com",
            "a.b",
            "xn--bcher-kva.example",
            "localhost",
            "build",
            "a",
            "ex.0xg1",
            "ex.123a",
            "0x7f.example",
        ] {
            assert!(oracle(s));
            assert!(egress_hostname_bytes(s.as_bytes()), "{s}");
        }
        for s in [
            "1234", "0x7f", "0x", "1.2.3", "127.1", "0x7f.1", "ex.0x", "-a.b", "a-.b", "a..b",
            "a_b.c", "",
        ] {
            assert!(!oracle(s));
            assert!(!egress_hostname_bytes(s.as_bytes()), "{s}");
        }
        for s in [
            "a".repeat(63),
            "a".repeat(64),
            format!(
                "{}.{}.{}.{}",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(61)
            ),
            format!(
                "{}.{}.{}.{}",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(62)
            ),
        ] {
            assert_eq!(egress_hostname_bytes(s.as_bytes()), oracle(&s));
        }
    }
    #[test]
    fn hostname_scope_truth_table() {
        for scheme in [SchemeSel::Any, SchemeSel::Tcp, SchemeSel::Udp] {
            for bracketed in [false, true] {
                for port in [None, Some(1), Some(53), Some(443), Some(853), Some(65535)] {
                    let expected = if scheme == SchemeSel::Udp {
                        Err(HostnameScopeError::Udp)
                    } else if bracketed {
                        Err(HostnameScopeError::Bracketed)
                    } else if matches!(port, Some(53 | 853)) {
                        Err(HostnameScopeError::DnsPort)
                    } else {
                        Ok(port.map_or(HostnameScopeSel::Intercepted, HostnameScopeSel::Port))
                    };
                    assert_eq!(hostname_scope(scheme, bracketed, port), expected);
                }
            }
        }
    }
    proptest! {
        #[test]
        fn hostname_kernel_matches_oracle(s in "[a-z0-9.\\-x]{0,70}") {
            prop_assert_eq!(egress_hostname_bytes(s.as_bytes()), oracle(&s));
        }
    }
}
