//! Shared allowance syntax must not depend on launch authority.

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllowanceError {
    Empty,
    UnsupportedScheme,
    UdpHostname,
    HostnameDnsPort,
    HostAlias,
    MalformedAddress,
    PortNeedsBrackets,
    MalformedPort,
}
impl AllowanceError {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 8] = [
        Self::Empty,
        Self::UnsupportedScheme,
        Self::UdpHostname,
        Self::HostnameDnsPort,
        Self::HostAlias,
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
            Self::UdpHostname => "hostnames allow TLS over TCP only; use tcp://HOST:PORT, or an IP/CIDR for UDP",
            Self::HostnameDnsPort => "ports 53 and 853 carry the sandbox DNS path and cannot be hostname-allowed; use an IP/CIDR",
            Self::HostAlias => "host.microsandbox.internal is the sandbox host; use --allow-host",
            Self::MalformedAddress => "not an IP address, CIDR or hostname (hostnames: one or more labels of ASCII letters, digits and '-', not ending in a numeric label; write non-ASCII names as A-labels; no wildcards)",
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
