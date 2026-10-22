//! Raw-TCP tests for the loopback OCI registry fixture's request handling.
//!
//! The image-upgrade harness only drives the fixture indirectly, so a `Range`
//! regression there surfaces as a misleading 30s handshake timeout. These tests
//! speak HTTP at `Server` directly and assert on the raw status line, headers,
//! and bytes, which pins resumption behaviour the indirect harness leaves
//! timing-dependent.
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::Duration;

#[path = "support/fake_msb.rs"]
mod fake_msb;
#[path = "support/image_archive.rs"]
mod image_archive;
#[path = "support/oci_registry.rs"]
mod oci_registry;

use oci_registry::Server;

const BLOB_PATH: &str = "/v2/fixture/blobs/sha256:aaaa";
const BLOB_DIGEST: &str = "sha256:aaaa";

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

fn server_with_blob(blob: &[u8]) -> Server {
    let server = Server::new();
    server.put(
        BLOB_PATH,
        blob.to_vec(),
        "application/octet-stream",
        BLOB_DIGEST,
    );
    server
}

struct RawResponse {
    head: String,
    body: Vec<u8>,
}

impl RawResponse {
    fn status(&self) -> &str {
        self.head.lines().next().unwrap_or_default()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then_some(value.trim())
        })
    }
}

fn split_response(bytes: &[u8]) -> RawResponse {
    let Some(split) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        // A bare `expect` here reported only the missing terminator, which is
        // indistinguishable between an empty response (the handler bailed
        // before writing) and a truncated one. Carry the bytes themselves.
        panic!(
            "response header terminator missing in {} bytes: {:?}",
            bytes.len(),
            String::from_utf8_lossy(bytes)
        );
    };
    RawResponse {
        head: String::from_utf8(bytes[..split].to_vec()).unwrap(),
        body: bytes[split + 4..].to_vec(),
    }
}

fn request(raw: &str, server: &Server) -> RawResponse {
    let started = std::time::Instant::now();
    let mut stream = TcpStream::connect(&server.host).expect("connect fixture registry");
    let local = stream.local_addr().ok();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let connected = started.elapsed();
    stream.write_all(raw.as_bytes()).unwrap();
    let written = started.elapsed();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    let finished = started.elapsed();
    if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        return split_response(&bytes);
    }
    // Protocol diagnostics belong with the request that produced them: whether
    // the fixture saw the request at all separates a client-side send/close
    // race from a handler that returned before answering.
    panic!(
        "fixture answered {:?} with {} bytes and no header terminator: {:?}; \
         local={local:?} connect={connected:?} write={written:?} eof={finished:?}; \
         accepted requests={:?} recorded errors={:?}",
        raw.lines().next().unwrap_or_default(),
        bytes.len(),
        String::from_utf8_lossy(&bytes),
        server.requests(),
        server.errors()
    );
}

/// Read one response head plus `body` body bytes without waiting for EOF. Used
/// while a response is deliberately stalled mid-body, where `read_to_end` would
/// block until the release.
fn read_head_and_body(stream: &mut TcpStream, body: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("response head");
        bytes.push(byte[0]);
    }
    let start = bytes.len();
    bytes.resize(start + body, 0);
    stream
        .read_exact(&mut bytes[start..])
        .expect("stalled body prefix");
    bytes
}

fn get(server: &Server, path: &str, range: Option<&str>) -> RawResponse {
    let mut raw = format!("GET {path} HTTP/1.1\r\nHost: {}\r\n", server.host);
    if let Some(range) = range {
        raw.push_str(&format!("Range: {range}\r\n"));
    }
    raw.push_str("\r\n");
    request(&raw, server)
}

/// Send one request but leave the stream open, so a stalled response can be
/// released and read by the caller.
fn open_get(host: &str, path: &str, range: Option<&str>) -> TcpStream {
    let mut stream = TcpStream::connect(host).expect("connect fixture registry");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut raw = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n");
    if let Some(range) = range {
        raw.push_str(&format!("Range: {range}\r\n"));
    }
    raw.push_str("\r\n");
    stream.write_all(raw.as_bytes()).unwrap();
    stream
}

#[test]
fn open_ended_range_serves_byte_exact_suffix() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let response = get(&server, BLOB_PATH, Some("bytes=1024-"));
    assert_eq!(response.status(), "HTTP/1.1 206 Partial Content");
    assert_eq!(
        response.header("content-range"),
        Some("bytes 1024-2047/2048")
    );
    assert_eq!(response.header("content-length"), Some("1024"));
    assert_eq!(response.body.as_slice(), &blob[1024..]);
    assert_eq!(server.errors(), Vec::<String>::new());
}

#[test]
fn bounded_range_serves_byte_exact_slice() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let response = get(&server, BLOB_PATH, Some("bytes=100-199"));
    assert_eq!(response.status(), "HTTP/1.1 206 Partial Content");
    assert_eq!(response.header("content-range"), Some("bytes 100-199/2048"));
    assert_eq!(response.header("content-length"), Some("100"));
    assert_eq!(response.body.as_slice(), &blob[100..=199]);
    assert_eq!(server.errors(), Vec::<String>::new());
}

#[test]
fn suffix_range_serves_last_bytes() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let response = get(&server, BLOB_PATH, Some("bytes=-16"));
    assert_eq!(response.status(), "HTTP/1.1 206 Partial Content");
    assert_eq!(
        response.header("content-range"),
        Some("bytes 2032-2047/2048")
    );
    assert_eq!(response.header("content-length"), Some("16"));
    assert_eq!(response.body.as_slice(), &blob[2032..]);
    assert_eq!(server.errors(), Vec::<String>::new());
}

#[test]
fn range_past_end_is_unsatisfiable() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let response = get(&server, BLOB_PATH, Some("bytes=4096-"));
    assert_eq!(response.status(), "HTTP/1.1 416 Range Not Satisfiable");
    assert_eq!(response.header("content-range"), Some("bytes */2048"));
    assert_eq!(response.header("content-length"), Some("0"));
    assert!(response.body.is_empty());
    // A legitimate unsatisfiable range is not a fixture error.
    assert_eq!(server.errors(), Vec::<String>::new());
}

/// A rejected (`416`) request has no body a stall could hold open, so it is
/// answered promptly and does not fire the blob handshake.
#[test]
fn rejected_request_is_not_stalled() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let ready = server.stall_blob(BLOB_PATH);
    let response = get(&server, BLOB_PATH, Some("bytes=4096-"));
    assert_eq!(response.status(), "HTTP/1.1 416 Range Not Satisfiable");
    assert_eq!(response.header("content-range"), Some("bytes */2048"));
    assert_eq!(
        ready.try_recv().unwrap_err(),
        std::sync::mpsc::TryRecvError::Empty
    );
}

#[test]
fn unsupported_range_is_recorded_and_worker_keeps_serving() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    for range in ["bytes=0-9,20-29", "items=0-1", "bytes=abc-"] {
        let response = get(&server, BLOB_PATH, Some(range));
        assert_eq!(response.status(), "HTTP/1.1 416 Range Not Satisfiable");
        assert_eq!(response.header("content-range"), Some("bytes */2048"));
    }
    let errors = server.take_errors();
    assert_eq!(errors.len(), 3, "recorded: {errors:?}");
    assert!(errors.iter().all(|error| error.contains(BLOB_PATH)));
    // Three distinct causes, not three copies of one diagnostic.
    assert!(errors.iter().any(|error| error.contains("multiple ranges")));
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unsupported Range unit"))
    );
    assert!(errors.iter().any(|error| error.contains("malformed Range")));
    // The worker survived every bad request and still serves correctly.
    let response = get(&server, BLOB_PATH, None);
    assert_eq!(response.status(), "HTTP/1.1 200 OK");
    assert_eq!(response.body.as_slice(), blob.as_slice());
}

#[test]
fn range_against_stalling_path_still_signals_and_releases() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let ready = server.stall_blob(BLOB_PATH);
    let host = server.host.clone();
    let mut stream = open_get(&host, BLOB_PATH, Some("bytes=1024-"));
    ready
        .recv_timeout(Duration::from_secs(10))
        .expect("handshake for a partial (206) request");
    // A stall holds the connection open mid-body: the head and the first half
    // of the body are readable, but the next byte is not, so a short read must
    // time out rather than see EOF. That is what keeps this a kill-mid-blob
    // fixture for phase 1 of the interrupted-upgrade test.
    let mut bytes = read_head_and_body(&mut stream, 512);
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut probe = [0u8; 1];
    let held = stream.read(&mut probe);
    assert!(
        matches!(
            held,
            Err(ref error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                )
        ),
        "stall must hold the connection open, got {held:?}"
    );
    // Restore the timeout so the post-release drain cannot hang.
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    server.release_blob();
    stream.read_to_end(&mut bytes).unwrap();
    let response = split_response(&bytes);
    assert_eq!(response.status(), "HTTP/1.1 206 Partial Content");
    assert_eq!(response.header("content-length"), Some("1024"));
    assert_eq!(
        response.header("content-range"),
        Some("bytes 1024-2047/2048")
    );
    // Only the first 512 bytes are written before the handshake, and releasing
    // drops the stream, so exactly `blob[1024..1536]` arrives.
    assert_eq!(response.body.as_slice(), &blob[1024..1536]);
}

/// Release, then immediately re-arm the stall on the same path with no request
/// in between. The worker must not go back to sleep on the released connection:
/// a predicate of "any stall armed" strands it there and the second request is
/// never accepted.
#[test]
fn restall_after_release_serves_the_next_request() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let host = server.host.clone();
    let ready = server.stall_blob(BLOB_PATH);
    let mut first = open_get(&host, BLOB_PATH, None);
    ready
        .recv_timeout(Duration::from_secs(10))
        .expect("first handshake");
    server.release_blob();
    let ready = server.stall_blob(BLOB_PATH);
    let mut second = open_get(&host, BLOB_PATH, None);
    ready
        .recv_timeout(Duration::from_secs(10))
        .expect("handshake after release-then-re-arm");
    server.release_blob();
    let mut drain = Vec::new();
    let _ = first.read_to_end(&mut drain);
    let mut drain = Vec::new();
    let _ = second.read_to_end(&mut drain);
}

#[test]
fn handler_panic_is_recorded_and_worker_keeps_serving() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let host = server.host.clone();
    server.panic_next_request();
    let mut stream = open_get(&host, BLOB_PATH, None);
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    // The panicking handler writes no response; the caller records it.
    assert!(bytes.is_empty(), "response bytes: {bytes:?}");
    let errors = server.take_errors();
    assert_eq!(errors.len(), 1, "recorded: {errors:?}");
    assert!(
        errors[0].contains("registry worker panicked"),
        "recorded: {errors:?}"
    );
    // The accept loop survived and still serves.
    let response = get(&server, BLOB_PATH, None);
    assert_eq!(response.status(), "HTTP/1.1 200 OK");
    assert_eq!(response.body.as_slice(), blob.as_slice());
}

/// A `Server` dropped with a recorded error must fail the test loudly, so a
/// fixture that could not serve a request cannot pass unnoticed.
#[test]
#[should_panic(expected = "registry fixture recorded errors")]
fn dropping_a_server_with_recorded_errors_fails_the_test() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let response = get(&server, BLOB_PATH, Some("bytes=5-4"));
    assert_eq!(response.status(), "HTTP/1.1 416 Range Not Satisfiable");
    // No `take_errors()`: `Drop` must surface the recorded error.
}

/// A panic in the test body must not abort the process through a second panic
/// in `Drop`. A double panic aborts instead of unwinding, which is the failure
/// this guard exists to prevent, so this test would abort rather than pass if
/// `Drop` panicked unconditionally.
#[test]
#[should_panic(expected = "original failure")]
fn drop_during_unwind_does_not_mask_the_original_failure() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let response = get(&server, BLOB_PATH, Some("bytes=5-4"));
    assert_eq!(response.status(), "HTTP/1.1 416 Range Not Satisfiable");
    panic!("original failure");
}

#[test]
fn range_edge_cases_are_handled() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    // An end past the blob clamps to the last byte.
    let response = get(&server, BLOB_PATH, Some("bytes=0-99999"));
    assert_eq!(response.status(), "HTTP/1.1 206 Partial Content");
    assert_eq!(response.header("content-range"), Some("bytes 0-2047/2048"));
    assert_eq!(response.body.as_slice(), blob.as_slice());
    // A suffix longer than the blob returns the whole blob.
    let response = get(&server, BLOB_PATH, Some("bytes=-5000"));
    assert_eq!(response.status(), "HTTP/1.1 206 Partial Content");
    assert_eq!(response.header("content-range"), Some("bytes 0-2047/2048"));
    assert_eq!(response.body.as_slice(), blob.as_slice());
    // `bytes=-0` is valid but selects no bytes.
    let response = get(&server, BLOB_PATH, Some("bytes=-0"));
    assert_eq!(response.status(), "HTTP/1.1 416 Range Not Satisfiable");
    assert_eq!(response.header("content-range"), Some("bytes */2048"));
    // `M < N` is an invalid range-spec: recorded, not a silent 416.
    let response = get(&server, BLOB_PATH, Some("bytes=5-4"));
    assert_eq!(response.status(), "HTTP/1.1 416 Range Not Satisfiable");
    let errors = server.take_errors();
    assert_eq!(errors.len(), 1, "recorded: {errors:?}");
    assert!(errors[0].contains("before start"), "recorded: {errors:?}");
    // An empty blob has no satisfiable byte.
    let empty = server_with_blob(&[]);
    let response = get(&empty, BLOB_PATH, Some("bytes=0-"));
    assert_eq!(response.status(), "HTTP/1.1 416 Range Not Satisfiable");
    assert_eq!(response.header("content-range"), Some("bytes */0"));
    assert_eq!(empty.take_errors(), Vec::<String>::new());
}

#[test]
fn write_executable_is_executable_and_leaves_no_temporary() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shim");
    fake_msb::write_executable(&path, "#!/bin/sh\necho fixture-shim\n");
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755);
    let mut names: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(names, [std::ffi::OsString::from("shim")]);
    let output = Command::new(&path).output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"fixture-shim\n");
}

/// Teardown accounting: a connection handler is joined by the accept worker
/// before `Drop` reads the recorded-error oracle. Without the join, `Drop`
/// returns while a handler is still parked in its 10s stream read, so a late
/// handler error could be recorded after the oracle had already passed.
///
/// The parked handler is held open deliberately (request headers without the
/// terminating blank line), which makes the join observable: `Drop` must wait
/// for the stream timeout instead of returning immediately.
#[test]
fn drop_joins_an_inflight_connection_handler_before_reading_errors() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let host = server.host.clone();
    let mut parked = TcpStream::connect(&host).expect("connect the fixture");
    parked
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    parked
        .write_all(b"GET /v2/fixture/blobs/sha256:aaaa HTTP/1.1\r\nHost: fixture\r\n")
        .unwrap();
    // Wait for the accept loop to hand this connection to its worker, which
    // then parks in `read_line` (no blank line, no body) until the stream
    // timeout. A fixed sleep would race that acceptance: if `Drop` sets `stop`
    // first, the loop takes the connection and breaks without spawning the
    // handler this test exists to observe.
    server.wait_for_handler();
    let started = std::time::Instant::now();
    drop(server);
    let elapsed = started.elapsed();
    drop(parked);
    assert!(
        elapsed >= Duration::from_secs(5),
        "Drop returned after {elapsed:?}: it did not join the parked handler"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "Drop exceeded the bounded stream timeouts: {elapsed:?}"
    );
}
