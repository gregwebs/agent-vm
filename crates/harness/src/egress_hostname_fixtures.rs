//! Receipt-only TLS, opaque and banner listeners (#692).
//!
//! The `tls` listener records the upstream ClientHello and never completes a
//! handshake, so it observes a *dial*, not an HTTPS success or a certificate
//! trust decision. The `opaque` and `banner` listeners record the bytes a guest
//! sent and, for `banner`, send a fixed greeting first. Every one of them writes
//! a line into the fixture receipt log and answers nothing else.
//!
//! No certificate or crypto dependency: the parse stops at the SNI extension.
//! `dns_reply` answers the ladder's step (c) from a test-owned table; the
//! runtime still checks the query grants, so this is a fixture, not an
//! authority.
//!
//! What it keeps from `egress-hostname-fixtures.py`: the receipt line protocol
//! (`tls|tcp-plain|opaque {port} {peer} {detail}`, detail = SNI, `-` for no SNI,
//! or the hex of what arrived), the per-chunk `opaque` record (a multi-chunk
//! send writes several lines), the truncation refusals, and the 65536-byte and
//! 16384-byte record bounds. What it adds is a typed `ParseError` instead of a
//! bare `ValueError`, and separate `bind`/`run` so a supervisor can learn the
//! bound port before it reports readiness.

use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Where a listener writes its receipt line. The supervisor passes
/// `record_receipt` bound to the fixture directory; the controls pass a
/// collector.
pub type Record = dyn Fn(&str) + Send + Sync + 'static;

/// A shared receipt sink.
pub fn recorder(record: impl Fn(&str) + Send + Sync + 'static) -> Arc<Record> {
    Arc::new(record)
}

/// The bound on one listener's record, matching the Python's `size > 16384`.
const MAX_TLS_RECORD: usize = 16384;
/// The bound on how much of a plain or opaque send is collected.
const MAX_COLLECTED: usize = 65536;
/// Per-connection bound on every read. The Python set 3 s; a listener that
/// mislays it would hold a connection, and its thread, open forever.
const READ_TIMEOUT: Duration = Duration::from_secs(3);
/// The teardown pulse: how often a non-blocking accept re-checks `stop`. Short
/// enough that a check's teardown is not visibly slower than a blocking accept
/// that was woken by a signal, long enough that five idle listeners cost
/// nothing.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// A ClientHello or DNS question this listener refuses to interpret.
///
/// The Python raised `ValueError` from eleven distinct places and the callers
/// caught it uniformly: a refused parse is an *unrecorded* dial, never a
/// failure. The detail keeps the same wording so a log reads the same.
#[derive(Debug)]
pub struct ParseError(&'static str);

impl std::fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ParseError {}

const TRUNCATED: ParseError = ParseError("truncated ClientHello");
const SHORT_HEADER: ParseError = ParseError("short DNS header");

fn take(data: &[u8], offset: usize, length: usize) -> Result<(&[u8], usize), ParseError> {
    let end = offset.checked_add(length).ok_or(TRUNCATED)?;
    let window = data.get(offset..end).ok_or(TRUNCATED)?;
    Ok((window, end))
}

fn be(data: &[u8]) -> usize {
    data.iter()
        .fold(0usize, |value, byte| (value << 8) | usize::from(*byte))
}

/// One listener's recording mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerKind {
    /// Parse the ClientHello for its SNI; record a non-TLS first byte as plain.
    Tls,
    /// Record every chunk verbatim as hex.
    Opaque,
    /// Send `220 fixture\r\n`, then record like `Opaque`.
    Banner,
}

impl ListenerKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Opaque => "opaque",
            Self::Banner => "banner",
        }
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The server name of a single ClientHello record, or `None` when it carries no
/// server-name extension.
///
/// Every length is checked against the bytes that follow, so a truncated or
/// inconsistent record is refused rather than read as "no SNI": a deny row
/// must not pass because its payload was malformed.
pub fn client_hello_sni(record: &[u8]) -> Result<Option<String>, ParseError> {
    let (header, _) = take(record, 0, 5)?;
    if header[0] != 22 {
        return Err(ParseError("not TLS handshake"));
    }
    let (payload, end) = take(record, 5, be(&header[3..5]))?;
    let (handshake, _) = take(payload, 0, 4)?;
    if end != record.len() || handshake[0] != 1 {
        return Err(ParseError("not one ClientHello record"));
    }
    let (body, end) = take(payload, 4, be(&handshake[1..4]))?;
    if end != payload.len() {
        return Err(ParseError("handshake length mismatch"));
    }
    // version(2) random(32) session-id(1+n) ciphers(2+n) compression(1+n)
    // extensions(2+n)
    let (_, position) = take(body, 0, 34)?;
    let (length, position) = take(body, position, 1)?;
    let (_, position) = take(body, position, usize::from(length[0]))?;
    let (length, position) = take(body, position, 2)?;
    let (_, position) = take(body, position, be(length))?;
    let (length, position) = take(body, position, 1)?;
    let (_, position) = take(body, position, usize::from(length[0]))?;
    let (length, position) = take(body, position, 2)?;
    let (extensions, end) = take(body, position, be(length))?;
    if end != body.len() {
        return Err(ParseError("extension length mismatch"));
    }
    let mut position = 0usize;
    let mut names: Vec<String> = Vec::new();
    while position < extensions.len() {
        let (header, next) = take(extensions, position, 4)?;
        position = next;
        let (extension, next) = take(extensions, position, be(&header[2..4]))?;
        position = next;
        if &header[..2] != b"\x00\x00" {
            continue;
        }
        let (length, mut at) = take(extension, 0, 2)?;
        if be(length) != extension.len() - 2 {
            return Err(ParseError("server-name list length mismatch"));
        }
        while at < extension.len() {
            let (kind, next) = take(extension, at, 1)?;
            at = next;
            let (length, next) = take(extension, at, 2)?;
            at = next;
            let (name, next) = take(extension, at, be(length))?;
            at = next;
            if kind != b"\x00" {
                continue;
            }
            let text = std::str::from_utf8(name).map_err(|_| ParseError("unsafe SNI receipt"))?;
            if text.is_empty()
                || !text.is_ascii()
                || text.chars().any(|c| c.is_whitespace() || (c as u32) < 32)
            {
                return Err(ParseError("unsafe SNI receipt"));
            }
            names.push(text.to_owned());
        }
    }
    if names.len() > 1 {
        return Err(ParseError("multiple host names"));
    }
    Ok(names.into_iter().next())
}

fn read_exact_or_eof<R: Read>(conn: &mut R, size: usize) -> io::Result<Vec<u8>> {
    let mut data = vec![0u8; size];
    conn.read_exact(&mut data)?;
    Ok(data)
}

/// Record one connection.
///
/// Generic over the stream so the controls can drive it over a socket pair
/// without a listener, which is how the Python's `self_test` exercised the same
/// function.
pub fn handle<R: Read + Write>(
    conn: &mut R,
    peer: &str,
    port: u16,
    kind: ListenerKind,
    record: &Record,
) {
    if kind == ListenerKind::Tls {
        let Ok(first) = read_exact_or_eof(conn, 1) else {
            return;
        };
        if first[0] != 0x16 {
            let mut data = first;
            while data.len() <= MAX_COLLECTED {
                let mut chunk = [0u8; 4096];
                match conn.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(read) => data.extend_from_slice(&chunk[..read]),
                    Err(_) => break,
                }
            }
            record(&format!("tcp-plain {port} {peer} {}", hex(&data)));
            return;
        }
        let Ok(rest) = read_exact_or_eof(conn, 4) else {
            return;
        };
        let mut header = first;
        header.extend_from_slice(&rest);
        let size = be(&header[3..5]);
        if size > MAX_TLS_RECORD {
            return;
        }
        let Ok(payload) = read_exact_or_eof(conn, size) else {
            return;
        };
        let mut whole = header;
        whole.extend_from_slice(&payload);
        let Ok(name) = client_hello_sni(&whole) else {
            return;
        };
        record(&format!(
            "tls {port} {peer} {}",
            name.unwrap_or_else(|| "-".to_owned())
        ));
        return;
    }
    if kind == ListenerKind::Banner && conn.write_all(b"220 fixture\r\n").is_err() {
        return;
    }
    let mut data = Vec::new();
    while data.len() <= MAX_COLLECTED {
        let mut chunk = [0u8; 4096];
        match conn.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                data.extend_from_slice(&chunk[..read]);
                record(&format!("opaque {port} {peer} {}", hex(&data)));
            }
            Err(_) => return,
        }
    }
}

/// Accept connections until `stop` is set, one thread per connection.
///
/// The caller binds (and so learns the port) before it reports readiness: a
/// listener that only learned its port here could not be announced, and a
/// readiness marker written before the bind is what the Python's `serve` was
/// careful to avoid.
///
/// The accept is non-blocking with a short poll interval rather than blocking:
/// `shutdown(2)` on a listening socket fails, so a blocking accept has no
/// portable way to be woken for a teardown, and a fixture that cannot stop is a
/// hang in whichever check wanted it gone.
pub fn run(
    listener: TcpListener,
    kind: ListenerKind,
    record: Arc<Record>,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let record = Arc::clone(&record);
                std::thread::spawn(move || {
                    let peer = stream
                        .peer_addr()
                        .map(|address: SocketAddr| address.ip().to_string())
                        .unwrap_or_default();
                    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
                    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
                    let mut stream = stream;
                    handle(&mut stream, &peer, port, kind, &*record);
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return Ok(()),
        }
    }
    Ok(())
}

/// One A answer per name, the table the ladder's step (c) would answer from.
pub type Answers = BTreeMap<String, Ipv4Addr>;

/// Answer one DNS query, or refuse it.
///
/// `known` names get an A answer with a 60 s TTL; an unknown name answers
/// NXDOMAIN, which is what a deny row's `rcode=3` expects. Anything that is not
/// one ordinary IN-class question is refused rather than guessed at.
pub fn dns_reply(query: &[u8], answers: &Answers) -> Result<Vec<u8>, ParseError> {
    let (header, mut at) = take(query, 0, 12).map_err(|_| SHORT_HEADER)?;
    let ident = be(&header[0..2]);
    let flags = be(&header[2..4]);
    let questions = be(&header[4..6]);
    if flags & 0xf800 != 0 || questions != 1 {
        return Err(ParseError("not one ordinary DNS question"));
    }
    let mut labels: Vec<&[u8]> = Vec::new();
    loop {
        let (size, next) = take(query, at, 1)?;
        at = next;
        let size = usize::from(size[0]);
        if size == 0 {
            break;
        }
        if size > 63 {
            return Err(ParseError("invalid DNS label"));
        }
        let (label, next) = take(query, at, size)?;
        at = next;
        if !label.is_ascii() {
            return Err(ParseError("invalid DNS label"));
        }
        labels.push(label);
    }
    let (tail, end) = take(query, at, 4)?;
    if end != query.len() {
        return Err(ParseError("question framing"));
    }
    let name = labels
        .iter()
        .map(|label| String::from_utf8_lossy(label).to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(".");
    let qtype = be(&tail[0..2]);
    let qclass = be(&tail[2..4]);
    if qclass != 1 {
        return Err(ParseError("not IN class"));
    }
    let answer = match (answers.get(&name), qtype) {
        (Some(address), 1) => {
            let mut answer = vec![
                0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
            ];
            answer.extend_from_slice(&address.octets());
            answer
        }
        _ => Vec::new(),
    };
    let known = answers.contains_key(&name);
    let response_flags = 0x8080u16 | (flags as u16 & 0x100) | if known { 0 } else { 3 };
    let mut response = Vec::with_capacity(query.len() + answer.len());
    for field in [
        ident as u16,
        response_flags,
        1,
        u16::from(!answer.is_empty()),
        0,
        0,
    ] {
        response.extend_from_slice(&field.to_be_bytes());
    }
    response.extend_from_slice(&query[12..]);
    response.extend_from_slice(&answer);
    Ok(response)
}

/// Serve DNS answers forever from `answers`.
///
/// No `SO_REUSEADDR`: an existing listener on the port must never be shadowed,
/// because a deny row's evidence would then come from someone else's resolver.
pub fn serve_dns(listener: std::net::UdpSocket, answers: Answers) -> io::Result<()> {
    let mut buffer = [0u8; 4096];
    loop {
        let Ok((read, peer)) = listener.recv_from(&mut buffer) else {
            continue;
        };
        if let Ok(reply) = dns_reply(&buffer[..read], &answers) {
            let _ = listener.send_to(&reply, peer);
        }
    }
}

/// A ClientHello captured once from `openssl s_client` (servername
/// `fixture.example`) and committed as bytes.
///
/// It is the parser's *input* fixture, so the parse is graded against a real
/// implementation's output rather than against bytes this code built. The file,
/// not a literal, because 1552 bytes of hex would bury the test that uses it.
pub const CAPTURED_CLIENT_HELLO: &[u8] = include_bytes!("../tests/data/egress-client-hello.bin");

/// The controls `egress-hostname-fixtures.py::self_test` ran, in one call.
///
/// Its oracle for the parser is a ClientHello captured from a real TLS stack, so
/// a parse cannot pass because the bytes were built to suit it. Every strict
/// prefix of that record and of the DNS question must be *refused* rather than
/// read as "no SNI": a deny row must not pass because its payload was
/// malformed.
pub fn self_test() {
    use std::os::unix::net::UnixStream;

    assert_eq!(
        client_hello_sni(CAPTURED_CLIENT_HELLO).expect("a real ClientHello parses"),
        Some("fixture.example".to_owned())
    );
    for length in 0..CAPTURED_CLIENT_HELLO.len() {
        assert!(
            client_hello_sni(&CAPTURED_CLIENT_HELLO[..length]).is_err(),
            "truncated input accepted at {length} bytes"
        );
    }

    let receipts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&receipts);
    let record: Arc<Record> = Arc::new(move |line: &str| {
        sink.lock().expect("receipt log").push(line.to_owned());
    });
    let cases: Vec<(ListenerKind, Vec<u8>, String)> = vec![
        (
            ListenerKind::Tls,
            CAPTURED_CLIENT_HELLO.to_vec(),
            "tls 1234 127.0.0.1 fixture.example".to_owned(),
        ),
        (
            ListenerKind::Opaque,
            b"PING x\r\n\r\n".to_vec(),
            format!("opaque 1234 127.0.0.1 {}", hex(b"PING x\r\n\r\n")),
        ),
        (
            ListenerKind::Opaque,
            (0u8..=255).collect(),
            format!(
                "opaque 1234 127.0.0.1 {}",
                hex(&(0u8..=255).collect::<Vec<u8>>())
            ),
        ),
        (
            ListenerKind::Banner,
            b"QUIT\r\n".to_vec(),
            format!("opaque 1234 127.0.0.1 {}", hex(b"QUIT\r\n")),
        ),
        (
            ListenerKind::Tls,
            b"PING x\r\n\r\n".to_vec(),
            format!("tcp-plain 1234 127.0.0.1 {}", hex(b"PING x\r\n\r\n")),
        ),
    ];
    for (kind, payload, expected) in cases {
        let (mut left, mut right) = UnixStream::pair().expect("a socket pair");
        let record = Arc::clone(&record);
        let worker = std::thread::spawn(move || {
            handle(&mut left, "127.0.0.1", 1234, kind, &*record);
        });
        if kind == ListenerKind::Banner {
            let mut greeting = [0u8; 13];
            right.read_exact(&mut greeting).expect("the greeting");
            assert_eq!(&greeting, b"220 fixture\r\n");
        }
        right.write_all(&payload).expect("the payload");
        right
            .shutdown(std::net::Shutdown::Write)
            .expect("half close");
        worker.join().expect("the handler finishes");
        let receipts = receipts.lock().expect("receipt log");
        assert!(
            receipts.iter().any(|line| line == &expected),
            "{receipts:?}"
        );
    }

    let question = one_question();
    let answers: Answers = [("fixture.example".to_owned(), Ipv4Addr::new(10, 0, 0, 5))].into();
    let reply = dns_reply(&question, &answers).expect("the question is ordinary");
    assert_eq!(&reply[..2], &123u16.to_be_bytes());
    assert_eq!(&reply[2..4], &0x8180u16.to_be_bytes());
    assert_eq!(&reply[4..6], &1u16.to_be_bytes());
    assert_eq!(&reply[6..8], &1u16.to_be_bytes());
    assert_eq!(&reply[8..12], &[0, 0, 0, 0]);
    assert_eq!(&reply[reply.len() - 4..], &[10, 0, 0, 5]);
    let nxdomain = dns_reply(&question, &Answers::new()).expect("the question is ordinary");
    assert_eq!(&nxdomain[2..4], &0x8183u16.to_be_bytes());
    assert_eq!(&nxdomain[4..6], &1u16.to_be_bytes());
    assert_eq!(&nxdomain[6..8], &0u16.to_be_bytes());
    for length in 0..question.len() {
        assert!(
            dns_reply(&question[..length], &Answers::new()).is_err(),
            "truncated question accepted at {length} bytes"
        );
    }
    println!("host-only SNI parser and opaque recorder controls PASS");
}

/// One ordinary IN-class A question for `fixture.example`.
fn one_question() -> Vec<u8> {
    let mut question = vec![
        0x00, 123, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    question.extend_from_slice(b"\x07fixture\x07example\x00");
    question.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    question
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The controls the Python's `self_test` ran, from one place.
    #[test]
    fn the_controls_pass() {
        self_test();
    }

    /// The offset of the first byte of the committed server name.
    ///
    /// Found by its two-byte 0x000f length prefix rather than by a hand-counted
    /// index, so an edit that changes the record's earlier extensions moves the
    /// name and this follows it.
    fn server_name_offset(hello: &[u8]) -> usize {
        let label = b"\x00\x0ffixture.example";
        hello
            .windows(label.len())
            .position(|window| window == label)
            .expect("the captured record carries the committed server name")
            + 2
    }

    /// The offset of the server-name extension's type field, fixed by the
    /// record's own layout: type(2) length(2) list-length(2) entry-kind(1)
    /// entry-length(2) precede the name.
    fn server_name_extension(hello: &[u8]) -> usize {
        server_name_offset(hello) - 9
    }

    #[test]
    fn a_client_hello_without_a_server_name_reports_none() {
        let mut hello = CAPTURED_CLIENT_HELLO.to_vec();
        // Replace the server-name extension type with an unused one, leaving
        // every length intact: the record stays valid, the extension is no
        // longer SNI.
        let extension = server_name_extension(&hello);
        assert_eq!(&hello[extension..extension + 2], b"\x00\x00");
        assert_eq!(&hello[extension + 4..extension + 6], b"\x00\x12");
        hello[extension] = 0x00;
        hello[extension + 1] = 0x15;
        assert_eq!(
            client_hello_sni(&hello).expect("a valid record parses"),
            None
        );
    }

    #[test]
    fn an_unsafe_server_name_is_refused() {
        let mut spaced = CAPTURED_CLIENT_HELLO.to_vec();
        let name = server_name_offset(&spaced);
        spaced[name] = b' '; // a space in the name, every length untouched
        assert!(client_hello_sni(&spaced).is_err());

        let mut control = CAPTURED_CLIENT_HELLO.to_vec();
        let at = server_name_offset(&control);
        control[at] = 0x7f; // DEL is not whitespace, so the name is still read
        assert!(client_hello_sni(&control).is_ok());
    }

    #[test]
    fn a_non_question_or_foreign_class_is_refused() {
        let mut response_flags = one_question();
        response_flags[2] = 0x81; // QR set: this is a response, not a question
        assert!(dns_reply(&response_flags, &Answers::new()).is_err());

        let mut two_questions = one_question();
        two_questions[5] = 2;
        assert!(dns_reply(&two_questions, &Answers::new()).is_err());

        let mut class = one_question();
        let end = class.len();
        class[end - 1] = 3; // CH class
        assert!(dns_reply(&class, &Answers::new()).is_err());
    }
}
