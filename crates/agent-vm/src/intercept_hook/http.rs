use anyhow::{Context, Result};
use serde::Serialize;

pub(super) struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    pub(super) fn parse(raw: &[u8]) -> Result<Self> {
        let hdr_end = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .context("no header/body separator")?;
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
        if parts.next().is_some() || version != "HTTP/1.1" || method.bytes().any(is_not_token) {
            anyhow::bail!("request line is not strict HTTP/1.1");
        }
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line.split_once(':').context("malformed header")?;
            if name.is_empty() || name.bytes().any(is_not_token) || value.contains(['\r', '\n']) {
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

pub(super) fn contains_escaped_path_escape(target: &str) -> bool {
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

fn is_not_token(byte: u8) -> bool {
    !matches!(byte, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
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

    #[test]
    fn response_has_one_content_length_and_connection_close() {
        let response = Response::json(200, "OK", &serde_json::json!({"quote":"\\\""})).unwrap();
        let text = std::str::from_utf8(response.as_bytes()).unwrap();
        assert_eq!(text.matches("Content-Length:").count(), 1);
        assert!(text.contains("Connection: close\r\n\r\n"));
        assert!(text.contains(r#"{"quote":"\\\""}"#));
    }
}
