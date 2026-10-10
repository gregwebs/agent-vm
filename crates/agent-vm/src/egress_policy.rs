//! Launch egress authority: CLI grants never inherit the SDK's public default.
//! Numeric allowances are address-wide, not hostname isolation.

// The verified byte kernels use raw delimiter comparisons and length tests so
// their executable code stays aligned with the proofs. Keep the two lint
// allowances on those functions, not the trusted adapter or tests.

use vstd::prelude::*;

verus! {
pub open spec fn is_ascii_digit(b: u8) -> bool { 0x30 <= b && b <= 0x39 }
pub open spec fn decimal_value(s: Seq<u8>) -> nat decreases s.len() {
    if s.len() == 0 { 0 } else { decimal_value(s.drop_last()) * 10 + (s.last() - 0x30) as nat }
}
pub open spec fn port_text_ok(s: Seq<u8>) -> bool {
    1 <= s.len() <= 5 && s[0] != 0x30
        && (forall|i: int| 0 <= i < s.len() ==> is_ascii_digit(s[i]))
        && decimal_value(s) <= 65535
}

proof fn decimal_append(s: Seq<u8>, b: u8)
    ensures decimal_value(s.push(b)) == decimal_value(s) * 10 + (b - 0x30) as nat,
{
    assert(s.push(b).drop_last() =~= s);
}

/// Canonical decimal only: std parsing also accepts signs and leading zeros.
#[allow(clippy::len_zero, clippy::manual_range_contains)]
pub fn port_from_decimal_bytes(bytes: &[u8]) -> (port: Option<u16>)
    ensures
        port.is_some() == port_text_ok(bytes@),
        port.is_some() ==> port.unwrap() as nat == decimal_value(bytes@) && port.unwrap() >= 1,
{
    if bytes.len() == 0 || bytes.len() > 5 { return None; }
    if bytes[0] == 0x30 { return None; }
    let mut i = 0usize;
    let mut value = 0u32;
    while i < bytes.len()
        invariant
            1 <= bytes.len() <= 5,
            bytes[0] != 0x30,
            i <= bytes.len(),
            value == decimal_value(bytes@.subrange(0, i as int)),
            value < 100000,
            i == 0 ==> value == 0,
            i > 0 ==> value >= 1,
            i == 1 ==> value < 10,
            i == 2 ==> value < 100,
            i == 3 ==> value < 1000,
            i == 4 ==> value < 10000,
            forall|j: int| 0 <= j < i ==> is_ascii_digit(bytes@[j]),
        decreases bytes.len() - i,
    {
        let b = bytes[i];
        if b < 0x30 || b > 0x39 { return None; }
        proof {
            let prefix = bytes@.subrange(0, i as int);
            decimal_append(prefix, b);
            assert(bytes@.subrange(0, i as int + 1) =~= prefix.push(b));
        }
        value = value * 10 + (b - 0x30) as u32;
        i += 1;
    }
    proof { assert(bytes@.subrange(0, bytes@.len() as int) =~= bytes@); }
    if value > 65535 { return None; }
    Some(value as u16)
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum SchemeSel { Any, Tcp, Udp }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum LayoutError { UnsupportedScheme, MalformedAddress, PortNeedsBrackets, MalformedPort }
#[derive(Debug, PartialEq, Eq)]
pub struct TargetLayout { pub addr_start: usize, pub addr_end: usize, pub port: Option<u16> }

pub open spec fn sep_at(s: Seq<u8>, i: int) -> bool {
    0 <= i && i + 3 <= s.len() && s[i] == 0x3a && s[i+1] == 0x2f && s[i+2] == 0x2f
}
pub open spec fn has_sep_from(s: Seq<u8>, from: int) -> bool {
    exists|i: int| from <= i && sep_at(s, i)
}
pub open spec fn lower(b: u8) -> u8 { if 0x41 <= b <= 0x5a { (b + 0x20) as u8 } else { b } }
pub open spec fn ci_prefix(s: Seq<u8>, lit: Seq<u8>) -> bool {
    lit.len() <= s.len() && forall|i: int| 0 <= i < lit.len() ==> lower(s[i]) == lit[i]
}
pub open spec fn tcp_scheme(s: Seq<u8>) -> bool {
    ci_prefix(s, seq![0x74u8,0x63,0x70,0x3a,0x2f,0x2f]) && !has_sep_from(s, 6)
}
pub open spec fn udp_scheme(s: Seq<u8>) -> bool {
    ci_prefix(s, seq![0x75u8,0x64,0x70,0x3a,0x2f,0x2f]) && !has_sep_from(s, 6)
}
pub fn split_scheme(s: &[u8]) -> (r: Result<(SchemeSel, usize), LayoutError>)
    ensures
        // Exhaustive allowed results: no unlisted variant or offset is possible.
        match r {
            Ok((SchemeSel::Any, start)) => start == 0 && !has_sep_from(s@, 0),
            Ok((SchemeSel::Tcp, start)) => start == 6 && tcp_scheme(s@),
            Ok((SchemeSel::Udp, start)) => start == 6 && udp_scheme(s@),
            Err(e) => e == LayoutError::UnsupportedScheme
                && has_sep_from(s@, 0) && !tcp_scheme(s@) && !udp_scheme(s@),
        },
{
    let tcp = ci_six(s, true);
    let udp = ci_six(s, false);
    if tcp || udp {
        if contains_separator(s, 6) { return Err(LayoutError::UnsupportedScheme); }
        if tcp { Ok((SchemeSel::Tcp, 6)) } else { Ok((SchemeSel::Udp, 6)) }
    } else if contains_separator(s, 0) {
        Err(LayoutError::UnsupportedScheme)
    } else {
        Ok((SchemeSel::Any, 0))
    }
}

pub open spec fn count(s: Seq<u8>, b: u8) -> nat decreases s.len() {
    if s.len() == 0 { 0 } else { count(s.drop_last(), b) + if s.last() == b { 1nat } else { 0nat } }
}
pub open spec fn bracketed(t: Seq<u8>) -> bool { t.len() > 0 && t[0] == 0x5b }
pub open spec fn no_brackets(t: Seq<u8>) -> bool { count(t, 0x5b) == 0 && count(t, 0x5d) == 0 }
// Unique closing bracket, nonempty entire interior, suffix absent or beginning ':'.
// All other brackets (including in the suffix) are forbidden.
pub open spec fn bracket_shape(t: Seq<u8>, k: int) -> bool {
    bracketed(t) && 1 < k < t.len() && t[k] == 0x5d
        && count(t, 0x5b) == 1 && count(t, 0x5d) == 1
        && (k + 1 == t.len() || (k + 1 < t.len() && t[k+1] == 0x3a))
}
pub open spec fn delimiters_ok(t: Seq<u8>) -> bool {
    t.len() > 0 && if bracketed(t) { exists|k: int| bracket_shape(t, k) } else { no_brackets(t) }
}
pub open spec fn bare_port_shape(t: Seq<u8>, whole_address: bool, k: int) -> bool {
    !bracketed(t) && !whole_address && 0 <= k < t.len()
        && t[k] == 0x3a && count(t, 0x3a) == 1
}
pub open spec fn slash_before(t: Seq<u8>, k: int) -> bool {
    exists|i: int| 0 <= i < k && t[i] == 0x2f
}
// Exact accepted layout, independent of executable scan/results.
pub open spec fn exact_layout(t: Seq<u8>, whole_address: bool, a: int, z: int, p: Option<u16>) -> bool {
    delimiters_ok(t) && if bracketed(t) {
        exists|k: int| bracket_shape(t, k) && a == 1 && z == k
            && if k + 1 == t.len() { p.is_none() } else {
                port_text_ok(t.subrange(k+2, t.len() as int)) && p.is_some()
                    && p.unwrap() as nat == decimal_value(t.subrange(k+2, t.len() as int))
            }
    } else if exists|k: int| bare_port_shape(t, whole_address, k) {
        exists|k: int| bare_port_shape(t, whole_address, k) && !slash_before(t, k)
            && a == 0 && z == k && 0 < k
            && port_text_ok(t.subrange(k+1, t.len() as int)) && p.is_some()
            && p.unwrap() as nat == decimal_value(t.subrange(k+1, t.len() as int))
    } else { a == 0 && z == t.len() && p.is_none() }
}
// Error predicates evaluated in order (§4), independently of executable return values.
pub open spec fn bad_placement(t: Seq<u8>, whole_address: bool) -> bool {
    exists|k: int| bare_port_shape(t, whole_address, k) && slash_before(t, k)
}
pub open spec fn bad_port(t: Seq<u8>, whole_address: bool) -> bool {
    if bracketed(t) {
        exists|k: int| bracket_shape(t, k) && k+1 < t.len() && !port_text_ok(t.subrange(k+2, t.len() as int))
    } else {
        exists|k: int| bare_port_shape(t, whole_address, k) && !port_text_ok(t.subrange(k+1, t.len() as int))
    }
}
pub open spec fn empty_bare_address(t: Seq<u8>, whole_address: bool) -> bool {
    bare_port_shape(t, whole_address, 0)
}
#[allow(clippy::len_zero)]
pub fn split_target(t: &[u8], whole_address: bool) -> (r: Result<TargetLayout, LayoutError>)
    ensures
        match r {
            Ok(l) => exact_layout(t@, whole_address, l.addr_start as int, l.addr_end as int, l.port),
            Err(e) => if !delimiters_ok(t@) { e == LayoutError::MalformedAddress }
                else if bad_placement(t@, whole_address) { e == LayoutError::PortNeedsBrackets }
                else if bad_port(t@, whole_address) { e == LayoutError::MalformedPort }
                else { empty_bare_address(t@, whole_address) && e == LayoutError::MalformedAddress },
        },
        // Pin completeness and precedence, not just possible rejection classes.
        (!delimiters_ok(t@)) ==> r == Err::<TargetLayout,_>(LayoutError::MalformedAddress),
        delimiters_ok(t@) && bad_placement(t@, whole_address)
            ==> r == Err::<TargetLayout,_>(LayoutError::PortNeedsBrackets),
        delimiters_ok(t@) && !bad_placement(t@, whole_address) && bad_port(t@, whole_address)
            ==> r == Err::<TargetLayout,_>(LayoutError::MalformedPort),
        delimiters_ok(t@) && !bad_placement(t@, whole_address) && !bad_port(t@, whole_address)
            && !empty_bare_address(t@, whole_address) ==> r.is_ok(),
        r.is_ok() ==> 0 <= r.unwrap().addr_start < r.unwrap().addr_end <= t.len(),
{
    if t.len() == 0 { return Err(LayoutError::MalformedAddress); }
    let opens = count_byte(t, 0x5b);
    let closes = count_byte(t, 0x5d);
    proof { count_properties(t@, 0x5b); count_properties(t@, 0x5d); }
    if t[0] == 0x5b {
        if opens != 1 || closes != 1 { return Err(LayoutError::MalformedAddress); }
        let closing = first_byte(t, 0x5d);
        let k = match closing { Some(k) => k, None => { return Err(LayoutError::MalformedAddress); } };
        proof {
            assert forall|j: int| bracket_shape(t@, j) implies j == k by {};
        }
        if k <= 1 { return Err(LayoutError::MalformedAddress); }
        if k + 1 != t.len() && t[k+1] != 0x3a { return Err(LayoutError::MalformedAddress); }
        proof {
            assert(bracket_shape(t@, k as int));
            assert(delimiters_ok(t@));
        }
        if k + 1 == t.len() {
            proof { assert(exact_layout(t@, whole_address, 1, k as int, None)); }
            return Ok(TargetLayout { addr_start: 1, addr_end: k, port: None });
        }
        let port_bytes = &t[k+2..];
        match port_from_decimal_bytes(port_bytes) {
            Some(port) => {
                proof { assert(exact_layout(t@, whole_address, 1, k as int, Some(port))); }
                Ok(TargetLayout { addr_start: 1, addr_end: k, port: Some(port) })
            },
            None => {
                proof { assert(bad_port(t@, whole_address)); }
                Err(LayoutError::MalformedPort)
            },
        }
    } else {
        if opens != 0 || closes != 0 { return Err(LayoutError::MalformedAddress); }
        let colons = count_byte(t, 0x3a);
        proof { count_properties(t@, 0x3a); }
        if !whole_address && colons == 1 {
            let colon = first_byte(t, 0x3a);
            let k = match colon { Some(k) => k, None => { return Err(LayoutError::MalformedAddress); } };
            proof {
                assert(bare_port_shape(t@, whole_address, k as int));
                assert forall|j: int| bare_port_shape(t@, whole_address, j) implies j == k by {};
            }
            if prefix_has_slash(t, k) { return Err(LayoutError::PortNeedsBrackets); }
            let port_bytes = &t[k+1..];
            match port_from_decimal_bytes(port_bytes) {
                Some(port) => {
                    if k == 0 { return Err(LayoutError::MalformedAddress); }
                    proof { assert(exact_layout(t@, whole_address, 0, k as int, Some(port))); }
                    Ok(TargetLayout { addr_start: 0, addr_end: k, port: Some(port) })
                },
                None => Err(LayoutError::MalformedPort),
            }
        } else {
            proof { assert(exact_layout(t@, whole_address, 0, t.len() as int, None)); }
            Ok(TargetLayout { addr_start: 0, addr_end: t.len(), port: None })
        }
    }
}


#[allow(clippy::manual_range_contains)]
fn lower_byte(b: u8) -> (r: u8)
    ensures r == lower(b),
{
    if 0x41 <= b && b <= 0x5a { b + 0x20 } else { b }
}

fn ci_six(s: &[u8], tcp: bool) -> (r: bool)
    ensures r == if tcp { ci_prefix(s@, seq![0x74u8,0x63,0x70,0x3a,0x2f,0x2f]) }
                        else { ci_prefix(s@, seq![0x75u8,0x64,0x70,0x3a,0x2f,0x2f]) },
{
    if s.len() < 6 { return false; }
    if tcp {
        lower_byte(s[0]) == 0x74 && lower_byte(s[1]) == 0x63 && lower_byte(s[2]) == 0x70
            && s[3] == 0x3a && s[4] == 0x2f && s[5] == 0x2f
    } else {
        lower_byte(s[0]) == 0x75 && lower_byte(s[1]) == 0x64 && lower_byte(s[2]) == 0x70
            && s[3] == 0x3a && s[4] == 0x2f && s[5] == 0x2f
    }
}

fn contains_separator(s: &[u8], from: usize) -> (r: bool)
    requires from <= s.len(),
    ensures r == has_sep_from(s@, from as int),
{
    let mut i = from;
    while s.len() - i >= 3
        invariant from <= i <= s.len(),
            forall|j: int| from <= j < i ==> !sep_at(s@, j),
        decreases s.len() - i,
    {
        proof {
            assert((s[i as int] == 0x3a && s[i as int+1] == 0x2f && s[i as int+2] == 0x2f) ==> sep_at(s@, i as int));
        }
        if s[i] == 0x3a && s[i+1] == 0x2f && s[i+2] == 0x2f { return true; }
        i += 1;
    }
    false
}

proof fn count_append(s: Seq<u8>, b: u8, target: u8)
    ensures count(s.push(b), target) == count(s, target) + if b == target { 1nat } else { 0nat },
{
    assert(s.push(b).drop_last() =~= s);
}

fn count_byte(s: &[u8], target: u8) -> (r: usize)
    ensures r == count(s@, target),
{
    let mut i = 0usize;
    let mut n = 0usize;
    while i < s.len()
        invariant i <= s.len(), n <= i,
            n == count(s@.subrange(0, i as int), target),
        decreases s.len() - i,
    {
        proof {
            let prefix = s@.subrange(0, i as int);
            count_append(prefix, s[i as int], target);
            assert(s@.subrange(0, i as int + 1) =~= prefix.push(s[i as int]));
        }
        if s[i] == target { n += 1; }
        i += 1;
    }
    proof { assert(s@.subrange(0, s@.len() as int) =~= s@); }
    n
}

proof fn count_properties(s: Seq<u8>, b: u8)
    ensures
        (count(s, b) == 0) == (forall|i: int| 0 <= i < s.len() ==> s[i] != b),
        count(s, b) == 1 ==> (forall|i: int, j: int|
            0 <= i < s.len() && 0 <= j < s.len() && s[i] == b && s[j] == b ==> i == j),
    decreases s.len(),
{
    if s.len() > 0 {
        let prefix = s.drop_last();
        count_properties(prefix, b);
        assert forall|i: int| 0 <= i < s.len() implies
            (i < prefix.len() ==> s[i] == prefix[i]) by {};
        assert forall|i: int, j: int| count(s,b) == 1 &&
            0 <= i < s.len() && 0 <= j < s.len() && s[i] == b && s[j] == b
            implies i == j by {
            if i < prefix.len() && j < prefix.len() {} else {}
        };
    }
}

fn first_byte(s: &[u8], b: u8) -> (r: Option<usize>)
    ensures match r {
        Some(k) => k < s.len() && s@[k as int] == b,
        None => forall|i: int| 0 <= i < s.len() ==> s[i] != b,
    },
{
    let mut i = 0usize;
    while i < s.len()
        invariant i <= s.len(), forall|j: int| 0 <= j < i ==> s[j] != b,
        decreases s.len() - i,
    {
        if s[i] == b { return Some(i); }
        i += 1;
    }
    None
}

fn prefix_has_slash(t: &[u8], k: usize) -> (r: bool)
    requires k <= t.len(),
    ensures r == slash_before(t@, k as int),
{
    let mut i = 0usize;
    while i < k
        invariant i <= k <= t.len(), forall|j: int| 0 <= j < i ==> t[j] != 0x2f,
        decreases k - i,
    {
        if t[i] == 0x2f { return true; }
        i += 1;
    }
    false
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllowanceError {
    Empty,
    UnsupportedScheme,
    Hostname,
    MalformedAddress,
    PortNeedsBrackets,
    MalformedPort,
}
impl AllowanceError {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 6] = [
        Self::Empty,
        Self::UnsupportedScheme,
        Self::Hostname,
        Self::MalformedAddress,
        Self::PortNeedsBrackets,
        Self::MalformedPort,
    ];
}
impl std::fmt::Display for AllowanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty allowance",
            Self::UnsupportedScheme => "unsupported scheme; use tcp:// or udp:// (or no scheme for all protocols)",
            Self::Hostname => "hostname allowances are not supported yet; use an IP address or CIDR, or --allow-internet-egress",
            Self::MalformedAddress => "not an IP address or CIDR",
            Self::PortNeedsBrackets => "a port on a CIDR needs brackets, e.g. tcp://[10.0.0.0/24]:22",
            Self::MalformedPort => "port must be a decimal number 1-65535",
        })
    }
}
impl std::error::Error for AllowanceError {}
impl From<LayoutError> for AllowanceError {
    fn from(e: LayoutError) -> Self {
        match e {
            LayoutError::UnsupportedScheme => Self::UnsupportedScheme,
            LayoutError::MalformedAddress => Self::MalformedAddress,
            LayoutError::PortNeedsBrackets => Self::PortNeedsBrackets,
            LayoutError::MalformedPort => Self::MalformedPort,
        }
    }
}
fn address_network(text: &str) -> Result<ipnetwork::IpNetwork, AllowanceError> {
    let parsed = if text.contains('/') {
        text.parse::<ipnetwork::IpNetwork>().map_err(|_| ())
    } else {
        text.parse::<std::net::IpAddr>()
            .map(ipnetwork::IpNetwork::from)
            .map_err(|_| ())
    };
    parsed.map_err(|()| {
        if (1..=253).contains(&text.len())
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            && text.bytes().any(|b| b.is_ascii_alphabetic())
        {
            AllowanceError::Hostname
        } else {
            AllowanceError::MalformedAddress
        }
    })
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
#[derive(Debug)]
pub(crate) struct EgressAuthority {
    groups: GroupGrants,
    allowances: Vec<EgressAllowance>,
}
impl EgressAuthority {
    pub(crate) fn from_cli(input: CliEgress<'_>) -> anyhow::Result<Self> {
        let mut allowances = Vec::new();
        for (i, text) in input.allowances.iter().enumerate() {
            let allowance = EgressAllowance::parse(text)
                .map_err(|e| anyhow::anyhow!("--allow-egress #{}: {e}", i + 1))?;
            if !allowances.contains(&allowance) {
                allowances.push(allowance);
            }
        }
        Ok(Self {
            groups: GroupGrants {
                internet: input.internet.unwrap_or(false),
                lan: input.lan.unwrap_or(false),
                host: input.host.unwrap_or(false),
            },
            allowances,
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
        // from_profiles opens DNS for LAN alone; none() also denies ingress.
        microsandbox::NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules,
        }
    }
    pub(crate) fn write_notices(&self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        if self.allowances.is_empty()
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
            writeln!(output, "==> Egress policy: allowing {allowance}")?;
        }
        if self.groups.internet {
            writeln!(
                output,
                "==> Egress policy: --allow-internet-egress enabled (public internet; does not itself grant LAN or host)"
            )?;
        }
        if self.groups.lan {
            writeln!(
                output,
                "==> Egress policy: --allow-lan enabled (Private RFC1918 + 100.64/10 + fc00::/7 reachable; does not itself enable DNS)"
            )?;
        }
        if self.groups.host {
            writeln!(
                output,
                "==> Egress policy: --allow-host enabled (host.microsandbox.internal → host 127.0.0.1 reachable; includes the host DNS resolver)"
            )?;
        }
        let source = match (self.groups.internet, self.groups.host) {
            (true, true) => Some("both"),
            (true, false) => Some("--allow-internet-egress"),
            (false, true) => Some("--allow-host"),
            (false, false) => None,
        };
        if let Some(source) = source {
            writeln!(
                output,
                "==> Egress DNS: arbitrary-name DNS queries authorized via {source} (resolver/rebind/platform constraints still apply)"
            )
        } else {
            writeln!(
                output,
                "==> Egress DNS: queries denied (NXDOMAIN when forwarder is available; use IP allowances)"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
            (
                Hostname,
                &[
                    "example.com",
                    "tcp://api.example.com:443",
                    "localhost",
                    "example.com:443",
                ],
            ),
        ];
        for (error, inputs) in rows {
            for input in *inputs {
                assert_eq!(EgressAllowance::parse(input), Err(*error), "{input}");
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
        let raw = ["1.1.1.1".to_owned(), "example.com".to_owned()];
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
            format!("--allow-egress #2: {}", AllowanceError::Hostname)
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
                expected.push_str("==> Egress DNS: queries denied (NXDOMAIN when forwarder is available; use IP allowances)\n");
            }
            assert_eq!(String::from_utf8(output).unwrap(), expected);
        }
    }
    proptest! {
        #[test]
        fn rejected_errors_are_fixed_text(s in any::<String>()) {
            if let Err(e) = EgressAllowance::parse(&s) {
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
            if let Ok(a) = EgressAllowance::parse(&s) {
                let displayed = a.to_string();
                let reparsed = EgressAllowance::parse(&displayed);
                prop_assert_eq!(reparsed, Ok(a));
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
