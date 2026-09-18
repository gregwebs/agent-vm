use anyhow::{Context, Result};
use serde::Serialize;
use vstd::prelude::*;

pub(super) struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

verus! {

/// An HTTP `tchar` (RFC 9110 §5.6.2). This is the **only** spelling of the
/// token byte set: the request-line method check and the header-name check
/// both go through [`is_token_bytes`], so the two cannot drift apart.
pub(super) open spec fn is_token_byte_spec(b: u8) -> bool {
    b == 0x21 || b == 0x23 || b == 0x24 || b == 0x25 || b == 0x26 || b == 0x27
        || b == 0x2a || b == 0x2b || b == 0x2d || b == 0x2e || b == 0x5e || b == 0x5f
        || b == 0x60 || b == 0x7c || b == 0x7e
        || (0x30 <= b && b <= 0x39) || (0x41 <= b && b <= 0x5a) || (0x61 <= b && b <= 0x7a)
}

/// The request's header/body separator `\r\n\r\n` begins `i` bytes in.
pub(super) open spec fn separator_at(s: Seq<u8>, i: int) -> bool {
    &&& 0 <= i && i + 4 <= s.len()
    &&& s[i] == 13 && s[i + 1] == 10 && s[i + 2] == 13 && s[i + 3] == 10
}

fn is_token_byte(b: u8) -> (r: bool)
    ensures r == is_token_byte_spec(b),
{
    matches!(b, 0x21 | 0x23 | 0x24 | 0x25 | 0x26 | 0x27 | 0x2a | 0x2b | 0x2d | 0x2e | 0x5e | 0x5f | 0x60 | 0x7c | 0x7e | 0x30..=0x39 | 0x41..=0x5a | 0x61..=0x7a)
}

/// Index of the FIRST `\r\n\r\n`. The `Some` case is what makes
/// `raw[hdr_end + 4..]` a non-panicking slice: `i + 4 <= raw.len()` is proved,
/// not assumed.
pub(super) fn header_block_end(raw: &[u8]) -> (r: Option<usize>)
    ensures match r {
        Some(i) => separator_at(raw@, i as int)
            && forall|j: int| 0 <= j < i ==> !separator_at(raw@, j),
        None => forall|j: int| !separator_at(raw@, j),
    },
{
    let mut index = 0;
    while raw.len() - index >= 4
        invariant
            index <= raw.len(),
            forall|j: int| 0 <= j < index ==> !separator_at(raw@, j),
        decreases raw.len() - index,
    {
        // 13 10 13 10 '\r\n\r\n'
        if raw[index] == 13 && raw[index + 1] == 10 && raw[index + 2] == 13 && raw[index + 3] == 10 {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// A non-empty HTTP token.
pub(super) fn is_token_bytes(name: &[u8]) -> (ok: bool)
    ensures ok ==> name@.len() > 0
        && forall|i: int| 0 <= i < name@.len() ==> is_token_byte_spec(name@[i]),
{
    if name.is_empty() {
        return false;
    }
    let mut index = 0;
    while index < name.len()
        invariant
            index <= name.len(),
            forall|j: int| 0 <= j < index ==> is_token_byte_spec(name@[j]),
        decreases name.len() - index,
    {
        if !is_token_byte(name[index]) {
            return false;
        }
        index += 1;
    }
    true
}

/// No CR and no LF — the header-injection property.
pub(super) fn has_no_crlf(v: &[u8]) -> (ok: bool)
    ensures ok ==> forall|i: int| 0 <= i < v@.len() ==> v@[i] != 13 && v@[i] != 10,
{
    let mut index = 0;
    while index < v.len()
        invariant
            index <= v.len(),
            forall|j: int| 0 <= j < index ==> v@[j] != 13 && v@[j] != 10,
        decreases v.len() - index,
    {
        if v[index] == 13 || v[index] == 10 {
            return false;
        }
        index += 1;
    }
    true
}

} // verus!

impl Request {
    pub(super) fn parse(raw: &[u8]) -> Result<Self> {
        let hdr_end = header_block_end(raw).context("no header/body separator")?;
        let header_block = std::str::from_utf8(&raw[..hdr_end]).context("headers not UTF-8")?;
        let mut lines = header_block.split("\r\n");
        let request_line = lines.next().context("empty request")?;
        let mut parts = request_line.split(' ');
        let method = parts
            .next()
            .filter(|part| !part.is_empty())
            .context("no method")?;
        let target = parts
            .next()
            .filter(|part| !part.is_empty())
            .context("no target")?;
        let version = parts.next().context("no HTTP version")?;
        if parts.next().is_some() || version != "HTTP/1.1" || !is_token_bytes(method.as_bytes()) {
            anyhow::bail!("request line is not strict HTTP/1.1");
        }
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line.split_once(':').context("malformed header")?;
            if !is_token_bytes(name.as_bytes()) || !has_no_crlf(value.as_bytes()) {
                anyhow::bail!("malformed header");
            }
            headers.push((
                name.to_string(),
                value.trim_matches([' ', '\t']).to_string(),
            ));
        }
        Ok(Self {
            method: method.to_string(),
            target: target.to_string(),
            headers,
            body: raw[hdr_end + 4..].to_vec(),
        })
    }

    pub(super) fn method(&self) -> &str {
        &self.method
    }
    pub(super) fn target(&self) -> &str {
        &self.target
    }
    pub(super) fn body(&self) -> &[u8] {
        &self.body
    }
    pub(super) fn headers(&self) -> &[(String, String)] {
        &self.headers
    }
    pub(super) fn header_values(&self, name: &str) -> impl Iterator<Item = &str> {
        self.headers
            .iter()
            .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub(super) struct Response(Vec<u8>);

impl Response {
    pub(super) fn json(status: u16, reason: &str, body: &impl Serialize) -> Result<Self> {
        Self::from_parts(
            status,
            reason,
            &[("Content-Type", "application/json")],
            &serde_json::to_vec(body)?,
        )
    }

    pub(super) fn error(status: u16, message: &str) -> Result<Self> {
        Self::json(
            status,
            "Server Error",
            &serde_json::json!({"message": message}),
        )
    }

    pub(super) fn from_parts(
        status: u16,
        reason: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Self> {
        if headers
            .iter()
            .any(|(name, value)| name.contains(['\r', '\n']) || value.contains(['\r', '\n']))
        {
            anyhow::bail!("response header contains a line break");
        }
        let mut bytes = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
        for (name, value) in headers {
            bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        bytes.extend_from_slice(
            format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        );
        bytes.extend_from_slice(body);
        Ok(Self(bytes))
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

verus! {

pub(super) open spec fn is_hex_digit_spec(b: u8) -> bool {
    (0x30 <= b && b <= 0x39) || (0x41 <= b && b <= 0x46) || (0x61 <= b && b <= 0x66)
}

/// The three escapes that make a request target inexact, as hex digit pairs
/// (both cases): 2e '.' / 2f '/' / 5c '\\'.
pub(super) open spec fn is_escape_pair_spec(hi: u8, lo: u8) -> bool {
    (hi == 0x32 && (lo == 0x65 || lo == 0x45 || lo == 0x66 || lo == 0x46))
        || (hi == 0x35 && (lo == 0x63 || lo == 0x43))
}

pub(super) open spec fn well_formed_spec(hi: u8, lo: u8) -> bool {
    if hi == 0x2b {
        is_hex_digit_spec(lo)
    } else {
        is_hex_digit_spec(hi) && is_hex_digit_spec(lo)
    }
}

/// An escape that makes the target inexact begins at byte `i`.
pub(super) open spec fn escape_at(s: Seq<u8>, i: int) -> bool {
    &&& 0 <= i < s.len()
    &&& s[i] == 0x25
    &&& (i + 3 > s.len() || !well_formed_spec(s[i + 1], s[i + 2]) || is_escape_pair_spec(
        s[i + 1],
        s[i + 2],
    ))
}

fn is_hex_digit(b: u8) -> (r: bool)
    ensures r == is_hex_digit_spec(b),
{
    matches!(b, 0x30..=0x39 | 0x41..=0x46 | 0x61..=0x66)
}

fn is_escape_pair(hi: u8, lo: u8) -> (r: bool)
    ensures r == is_escape_pair_spec(hi, lo),
{
    (hi == 0x32 && (lo == 0x65 || lo == 0x45 || lo == 0x66 || lo == 0x46))
        || (hi == 0x35 && (lo == 0x63 || lo == 0x43))
}

/// No false negatives: if this returns `false`, no byte position begins an
/// escape that would make the target inexact.
pub(super) fn contains_escaped_path_escape_bytes(bytes: &[u8]) -> (result: bool)
    ensures !result ==> forall|i: int| !escape_at(bytes@, i),
{
    let mut index = 0;
    while index < bytes.len()
        invariant
            index <= bytes.len(),
            forall|j: int| 0 <= j < index ==> !escape_at(bytes@, j),
        decreases bytes.len() - index,
    {
        // 0x25 '%'
        if bytes[index] != 0x25 {
            index += 1;
            continue;
        }
        if bytes.len() - index < 3 {
            return true;
        }
        let hi = bytes[index + 1];
        let lo = bytes[index + 2];
        // 0x2b '+': `from_str_radix` accepted a single leading sign, so the
        // pre-Verus behaviour treated "%+f" as well-formed. Preserved here.
        let well_formed = if hi == 0x2b {
            is_hex_digit(lo)
        } else {
            is_hex_digit(hi) && is_hex_digit(lo)
        };
        if !well_formed || is_escape_pair(hi, lo) {
            return true;
        }
        index += 3;
    }
    false
}

} // verus!

// Trusted boundary: `str::as_bytes` is total and infallible, and the property
// is a property of bytes. Everything below `contains_escaped_path_escape_bytes`
// is proved; this adapter is not.
pub(super) fn contains_escaped_path_escape(target: &str) -> bool {
    contains_escaped_path_escape_bytes(target.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_preserves_supplied_body_without_claiming_content_length_completeness() {
        let request = Request::parse(b"POST / HTTP/1.1\r\nHost: example.test\r\nX-Tag: one\r\nX-Tag: two\r\nContent-Length: 9\r\n\r\nbody").unwrap();
        assert_eq!(request.method(), "POST");
        assert_eq!(request.target(), "/");
        assert_eq!(request.body(), b"body");
        assert_eq!(
            request.header_values("x-tag").collect::<Vec<_>>(),
            ["one", "two"]
        );
    }

    #[test]
    fn parser_requires_strict_request_and_header_tokens() {
        for input in [
            b"GET / HTTP/1.0\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1 extra\r\n\r\n",
            b"GE(T / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nBad Header: value\r\n\r\n",
        ] {
            assert!(Request::parse(input).is_err());
        }
    }

    // The contract is stated twice on purpose: as a Verus `ensures` over all
    // inputs in this file, and as a property test against the pre-Verus
    // implementation, so the erased build is checked to have kept deciding the
    // same thing. Neither replaces the other.
    proptest::proptest! {
        #[test]
        fn escape_scanner_matches_the_pre_verus_reference_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..48),
        ) {
            let text = String::from_utf8_lossy(&bytes);
            proptest::prop_assert_eq!(
                contains_escaped_path_escape(&text),
                reference_contains_escaped_path_escape(&text)
            );
        }

        // Arbitrary bytes are mostly ASCII and only rarely spell `%2e`; this
        // case draws from an alphabet that hits the escape paths often.
        #[test]
        fn escape_scanner_matches_the_pre_verus_reference_on_escape_shaped_text(
            text in r"[%+.\\/0-9a-fA-F xyz?#]{0,32}",
        ) {
            proptest::prop_assert_eq!(
                contains_escaped_path_escape(&text),
                reference_contains_escaped_path_escape(&text)
            );
        }
    }

    /// `contains_escaped_path_escape` as it was before the Verus contract was
    /// added, kept as the independent reference the verified rewrite must agree
    /// with (it uses `from_str_radix`, which the contract cannot carry).
    fn reference_contains_escaped_path_escape(target: &str) -> bool {
        let bytes = target.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != b'%' {
                index += 1;
                continue;
            }
            let Some(encoded) = bytes.get(index + 1..index + 3) else {
                return true;
            };
            let Ok(encoded) = std::str::from_utf8(encoded) else {
                return true;
            };
            let Ok(value) = u8::from_str_radix(encoded, 16) else {
                return true;
            };
            if matches!(value, b'.' | b'/' | b'\\') {
                return true;
            }
            index += 3;
        }
        false
    }

    #[test]
    fn response_has_one_content_length_and_connection_close() {
        let response = Response::json(200, "OK", &serde_json::json!({"quote":"\\\""})).unwrap();
        let text = std::str::from_utf8(response.as_bytes()).unwrap();
        assert_eq!(text.matches("Content-Length:").count(), 1);
        assert!(text.contains("Connection: close\r\n\r\n"));
        assert!(text.contains(r#"{"quote":"\\\""}"#));
    }
}
