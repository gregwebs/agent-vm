//! Test-owned loopback OCI server, serving genuine archive bytes. No runtime
//! acquisition is mocked. Closing each response bounds protocol complexity.
//!
//! The worker catches request panics and records them instead of unwinding, so
//! a poisoned lock is state to reuse, not a reason to fail the process: every
//! lock below recovers with `PoisonError::into_inner`.
#![allow(dead_code)]
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::image_archive::{self, ArchiveSpec, Written};

#[derive(Clone)]
pub struct Image {
    pub written: Written,
    pub blobs: BTreeMap<String, Vec<u8>>,
    pub index: Vec<u8>,
}
impl Image {
    pub fn from_archive(path: &std::path::Path, spec: &ArchiveSpec) -> Self {
        let written = image_archive::write(path, spec);
        let mut blobs = BTreeMap::new();
        let mut index = vec![];
        for entry in tar::Archive::new(std::fs::File::open(path).unwrap())
            .entries()
            .unwrap()
        {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_string_lossy().into_owned();
            let mut bytes = vec![];
            entry.read_to_end(&mut bytes).unwrap();
            if let Some(hex) = name.strip_prefix("blobs/sha256/") {
                blobs.insert(format!("sha256:{hex}"), bytes);
            } else if name == "index.json" {
                index = bytes;
            }
        }
        Self {
            written,
            blobs,
            index,
        }
    }
}
/// The `algorithm:hex` digest of `bytes`, computed with the named hash. Only
/// the three OCI algorithms the fixture uses are supported.
pub fn digest_hex(algorithm: &str, bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256, Sha384, Sha512};
    let hex = match algorithm {
        "sha256" => hex_lower(&Sha256::digest(bytes)),
        "sha384" => hex_lower(&Sha384::digest(bytes)),
        "sha512" => hex_lower(&Sha512::digest(bytes)),
        other => panic!("unsupported fixture digest algorithm {other}"),
    };
    format!("{algorithm}:{hex}")
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).expect("high nibble"));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("low nibble"));
    }
    out
}

#[derive(Clone)]
struct Response {
    bytes: Vec<u8>,
    media: &'static str,
    digest: String,
}

/// A parsed `Range: bytes=...` request. The registry client resumes a partial
/// blob with the open-ended `bytes=N-` form, so the fixture serves it.
enum ByteRange {
    /// `bytes=N-M`, or `bytes=N-` with an open end.
    At { start: u64, end: Option<u64> },
    /// `bytes=-S`, the final `S` bytes.
    Suffix(u64),
}

/// What a byte range resolves to against the length of the routed blob.
enum Served {
    Full,
    Partial {
        start: u64,
        end: u64,
    },
    Unsatisfiable,
    /// A range-spec the fixture does not model. The reason is recorded as a
    /// diagnostic before the `416`.
    Unsupported(String),
}

/// An armed stall: the path it applies to, the generation that identifies it,
/// and the channel the worker signals when the blob body is mid-flight.
struct Stall {
    path: String,
    generation: u64,
    signal: std::sync::mpsc::Sender<()>,
}

type BlobStall = (Mutex<Option<Stall>>, Condvar);

/// State shared between `Server` and its worker thread: routing and stall
/// configuration written by the test thread, and request/error diagnostics
/// written by the worker.
#[derive(Clone)]
struct Shared {
    routes: Arc<Mutex<BTreeMap<String, Response>>>,
    requests: Arc<Mutex<Vec<(String, String)>>>,
    headers: Arc<Mutex<Vec<String>>>,
    errors: Arc<Mutex<Vec<String>>>,
    stall: Arc<BlobStall>,
    basic_challenge: Arc<AtomicBool>,
    panic_next: Arc<AtomicBool>,
    /// Exact manifest paths answered with `401` instead of their routed body.
    /// The Basic challenge above only refuses `/v2/`, which is not enough to
    /// model a registry that denies one already-named manifest.
    denied_manifests: Arc<Mutex<BTreeSet<String>>>,
    /// `(path, status)` for every denied request, in order.
    denied_requests: Arc<Mutex<Vec<(String, u16)>>>,
    /// Connections the accept loop handed to a handler thread. Teardown tests
    /// wait on this instead of sleeping: a sleep only *hopes* the accept loop
    /// has taken the connection before `Drop` sets `stop`, which makes the
    /// join unobservable when the accept loop is slow to be scheduled.
    handlers_started: Arc<AtomicUsize>,
}

pub struct Server {
    pub host: String,
    shared: Shared,
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
    /// Incremented per `stall_blob`; the worker waits only for the generation
    /// it actually took.
    stall_generation: AtomicU64,
}
impl Server {
    pub fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback binding prerequisite");
        let host = listener.local_addr().unwrap().to_string();
        let shared = Shared {
            routes: Arc::new(Mutex::new(BTreeMap::new())),
            requests: Arc::new(Mutex::new(Vec::new())),
            headers: Arc::new(Mutex::new(Vec::new())),
            errors: Arc::new(Mutex::new(Vec::new())),
            stall: Arc::new((Mutex::new(None), Condvar::new())),
            basic_challenge: Arc::new(AtomicBool::new(false)),
            panic_next: Arc::new(AtomicBool::new(false)),
            denied_manifests: Arc::new(Mutex::new(BTreeSet::new())),
            denied_requests: Arc::new(Mutex::new(Vec::new())),
            handlers_started: Arc::new(AtomicUsize::new(0)),
        };
        let worker_shared = shared.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let task = std::thread::spawn(move || {
            // Handles of the live connection workers. They are joined by this
            // accept worker before it exits, so a handler can neither outlive
            // `Server::drop` nor record an error after drop has read the
            // oracle. Each handler's first request line is bounded by
            // `FIRST_LINE_TIMEOUT` (60s) and every later header, body or stall
            // read by `IDLE_TIMEOUT` (10s), and `release_blob` wakes a waiting
            // handler, so the join is bounded.
            let mut handlers: Vec<JoinHandle<()>> = Vec::new();
            let mut consecutive_transient = 0u32;
            loop {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => {
                        consecutive_transient = 0;
                        stream
                    }
                    // A transient accept failure means one connection was lost.
                    // Record it with the OS error and keep accepting rather than
                    // silently exiting the loop: a dead accept worker makes
                    // every later request fail with a bare reset, which hides
                    // the actual cause from the test's diagnostics.
                    Err(error) => {
                        record_error(
                            &worker_shared.errors,
                            format!("registry accept failed: {error:?}"),
                        );
                        // The transient retry below must not outlive a stop. If
                        // teardown's own wake connection is the one that fails,
                        // `Drop` is already blocked in `join` and no further
                        // connection is coming, so retrying would hang. The
                        // error stays recorded, so `Drop` still fails the test.
                        if worker_stop.load(Ordering::SeqCst) {
                            break;
                        }
                        match error.kind() {
                            std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::WouldBlock
                                if consecutive_transient < 64 =>
                            {
                                consecutive_transient += 1;
                                continue;
                            }
                            _ => break,
                        }
                    }
                };
                if worker_stop.load(Ordering::SeqCst) {
                    break;
                }
                // One thread per connection. A client that keeps a connection
                // alive (the native client pools them inside this process) must
                // not starve the accept loop: the launch update probe talks to
                // the same server from the test process itself, after a native
                // cache read has left such a connection open.
                let connection_shared = worker_shared.clone();
                handlers.push(std::thread::spawn(move || {
                    connection_shared
                        .handlers_started
                        .fetch_add(1, Ordering::SeqCst);
                    // Keep the accept loop alive across a handler panic: the panic
                    // is recorded, later requests are still served, and the test
                    // fails on the recorded error instead of hanging.
                    if let Err(panic) =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            handle_connection(&mut stream, &connection_shared);
                        }))
                    {
                        record_error(
                            &connection_shared.errors,
                            format!("registry worker panicked: {}", panic_message(panic)),
                        );
                    }
                }));
            }
            for handler in handlers {
                // A handler that escaped its own catch is still reported, never
                // re-panicked: this join runs inside the accept worker, whose
                // result `Drop` joins during its own potentially unwinding drop.
                if let Err(panic) = handler.join() {
                    record_error(
                        &worker_shared.errors,
                        format!("registry worker panicked: {}", panic_message(panic)),
                    );
                }
            }
        });
        Self {
            host,
            shared,
            stop,
            task: Some(task),
            stall_generation: AtomicU64::new(0),
        }
    }
    pub fn require_basic_auth(&self) {
        self.shared.basic_challenge.store(true, Ordering::SeqCst);
    }
    /// Deny exactly `path` with `401 Unauthorized` and a Basic challenge,
    /// instead of serving its routed body. The Basic challenge only covers
    /// `/v2/`, so this is how a test models a registry that refuses one
    /// *already-routed* manifest (the same key a cached acquisition now
    /// re-resolves). It changes no other route.
    pub fn deny_manifest(&self, path: &str) {
        self.shared
            .denied_manifests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(path.to_owned());
    }
    /// `(path, status)` for every request answered by [`Self::deny_manifest`].
    pub fn denied_requests(&self) -> Vec<(String, u16)> {
        self.shared
            .denied_requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    /// Block until the accept loop has handed a connection to a handler thread.
    /// Teardown tests must not race acceptance against `Drop`: with a sleep,
    /// `Drop` can set `stop` before the accept loop takes the parked connection,
    /// so the loop breaks without spawning the handler the test observes.
    pub fn wait_for_handler(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.shared.handlers_started.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "the fixture accepted no connection within 10s"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    /// Arm a stall on `path`. The returned receiver fires once the worker has
    /// written half of the bytes the next `path` request would serve. Arming a
    /// new stall wakes a worker still waiting on a previous one, so it abandons
    /// that connection and serves this request.
    pub fn stall_blob(&self, path: &str) -> std::sync::mpsc::Receiver<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        let generation = self.stall_generation.fetch_add(1, Ordering::SeqCst) + 1;
        *self
            .shared
            .stall
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Stall {
            path: path.to_owned(),
            generation,
            signal: tx,
        });
        // Overwriting the slot makes every waiting worker's predicate false, so
        // wake them to re-check rather than leaving the previous connection's
        // worker asleep until an unrelated notify.
        self.shared.stall.1.notify_all();
        rx
    }
    pub fn release_blob(&self) {
        *self
            .shared
            .stall
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        self.shared.stall.1.notify_all();
    }
    /// Make the worker panic on its next request. A seam for tests that prove
    /// the catch/record path; inert unless armed.
    pub fn panic_next_request(&self) {
        self.shared.panic_next.store(true, Ordering::SeqCst);
    }
    pub fn image(&self, repo: &str, tag: &str, image: &Image) -> String {
        for (digest, bytes) in &image.blobs {
            let manifest = digest == &image.written.manifest_digest;
            let kind = if manifest { "manifests" } else { "blobs" };
            self.put(
                &format!("/v2/{repo}/{kind}/{digest}"),
                bytes.clone(),
                if manifest {
                    "application/vnd.oci.image.manifest.v1+json"
                } else {
                    "application/octet-stream"
                },
                digest,
            );
        }
        self.put(
            &format!("/v2/{repo}/manifests/{tag}"),
            image.blobs[&image.written.manifest_digest].clone(),
            "application/vnd.oci.image.manifest.v1+json",
            &image.written.manifest_digest,
        );
        format!("{}/{repo}@{}", self.host, image.written.manifest_digest)
    }
    pub fn index(&self, repo: &str, tag: &str, bytes: Vec<u8>) -> String {
        let digest = image_archive::sha256_hex(&bytes);
        for key in [tag, &digest] {
            self.put(
                &format!("/v2/{repo}/manifests/{key}"),
                bytes.clone(),
                "application/vnd.oci.image.index.v1+json",
                &digest,
            );
        }
        format!("{}/{repo}@{digest}", self.host)
    }
    /// Route `bytes` under a digest computed with `algorithm` (sha256/sha384/
    /// sha512), with a matching `Docker-Content-Digest` header. The manifest
    /// body itself still names its own sha256 config/layer blobs, which the
    /// caller must have registered separately: mixed algorithms are valid OCI.
    pub fn put_manifest_under_algorithm(
        &self,
        repo: &str,
        bytes: &[u8],
        algorithm: &str,
    ) -> String {
        let digest = digest_hex(algorithm, bytes);
        self.put(
            &format!("/v2/{repo}/manifests/{digest}"),
            bytes.to_vec(),
            "application/vnd.oci.image.manifest.v1+json",
            &digest,
        );
        format!("{}/{repo}@{digest}", self.host)
    }

    /// Route `bytes` at a caller-chosen digest key and header, independently of
    /// the bytes' own hash. Used only to build a lying-header oracle.
    pub fn put_with_header(&self, path: &str, bytes: &[u8], media: &'static str, header: &str) {
        self.put(path, bytes.to_vec(), media, header);
    }

    /// Route an index under a digest computed with `algorithm`, at both the
    /// digest path and a mutable tag, with a matching header.
    pub fn index_under_algorithm(
        &self,
        repo: &str,
        tag: &str,
        bytes: &[u8],
        algorithm: &str,
    ) -> String {
        let digest = digest_hex(algorithm, bytes);
        for key in [tag, digest.as_str()] {
            self.put(
                &format!("/v2/{repo}/manifests/{key}"),
                bytes.to_vec(),
                "application/vnd.oci.image.index.v1+json",
                &digest,
            );
        }
        format!("{}/{repo}@{digest}", self.host)
    }

    pub fn put(&self, path: &str, bytes: Vec<u8>, media: &'static str, digest: &str) {
        self.shared
            .routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                path.to_owned(),
                Response {
                    bytes,
                    media,
                    digest: digest.to_owned(),
                },
            );
    }
    pub fn remove(&self, path: &str) {
        self.shared
            .routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(path);
    }
    pub fn count(&self) -> usize {
        self.shared
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
    pub fn requests(&self) -> Vec<(String, String)> {
        self.shared
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    pub fn headers(&self) -> Vec<String> {
        self.shared
            .headers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    /// Request-path failures the worker recorded instead of panicking. Tests
    /// that expect only well-formed requests assert this is empty.
    pub fn errors(&self) -> Vec<String> {
        self.shared
            .errors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    /// Drain the recorded errors. Tests that deliberately provoke a bad request
    /// use this so `Drop`'s loud guard does not fire at teardown.
    pub fn take_errors(&self) -> Vec<String> {
        std::mem::take(
            &mut *self
                .shared
                .errors
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.release_blob();
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.host);
        // Joining a panicked worker must not panic again: a second panic during
        // unwind aborts the process. Record it and let the drop finish.
        if let Some(task) = self.task.take()
            && let Err(panic) = task.join()
        {
            record_error(
                &self.shared.errors,
                format!("registry worker panicked: {}", panic_message(panic)),
            );
        }
        let errors = self.take_errors();
        if errors.is_empty() {
            return;
        }
        // A recorded error means the fixture could not serve a request, so
        // surface it for every `Server` user rather than only those that read
        // `errors()`. Panicking is only safe outside an existing unwind;
        // otherwise report and let the in-progress failure stand.
        if std::thread::panicking() {
            // `eprintln!` panics if stderr is unwritable; during an unwind that
            // is an abort, so write best-effort.
            let _ = writeln!(
                std::io::stderr(),
                "registry fixture recorded errors while unwinding: {errors:?}"
            );
        } else {
            panic!("registry fixture recorded errors: {errors:?}");
        }
    }
}

/// Parse the byte-range forms the fixture serves. A range the fixture does not
/// model (multiple ranges, a non-`bytes` unit, malformed syntax) is rejected and
/// the caller records it rather than guessing a body. RFC 9110 would let a
/// server ignore an ununderstood unit, a multi-range, or a malformed range; the
/// fixture is deliberately stricter because a client that sends one is not
/// exercising a shape the tests model.
fn parse_byte_range(value: &str) -> Result<ByteRange, String> {
    let Some((unit, spec)) = value.split_once('=') else {
        return Err(format!("malformed Range: {value:?}"));
    };
    if !unit.trim().eq_ignore_ascii_case("bytes") {
        return Err(format!("unsupported Range unit: {value:?}"));
    }
    let spec = spec.trim();
    if spec.contains(',') {
        return Err(format!("multiple ranges unsupported: {value:?}"));
    }
    let Some((first, second)) = spec.split_once('-') else {
        return Err(format!("malformed Range: {value:?}"));
    };
    let parse = |text: &str| {
        text.parse::<u64>()
            .map_err(|_| format!("malformed Range: {value:?}"))
    };
    match (first.trim(), second.trim()) {
        ("", "") => Err(format!("malformed Range: {value:?}")),
        ("", suffix) => Ok(ByteRange::Suffix(parse(suffix)?)),
        (start, "") => Ok(ByteRange::At {
            start: parse(start)?,
            end: None,
        }),
        (start, end) => Ok(ByteRange::At {
            start: parse(start)?,
            end: Some(parse(end)?),
        }),
    }
}

fn resolve_byte_range(range: ByteRange, total: u64) -> Served {
    if total == 0 {
        return Served::Unsatisfiable;
    }
    match range {
        ByteRange::At { start, end } => {
            if start >= total {
                return Served::Unsatisfiable;
            }
            let end = match end {
                // RFC 9110 makes `M < N` an invalid range-spec, not an
                // unsatisfiable one. `oci-client` can build it when a resume
                // length is zero, so record it rather than answering a silent
                // `416`. The only caller here passes `length: None`, so no
                // request in this repo reaches this arm.
                Some(end) if end < start => {
                    return Served::Unsupported(format!(
                        "invalid Range: end {end} before start {start}"
                    ));
                }
                Some(end) => end.min(total - 1),
                None => total - 1,
            };
            Served::Partial { start, end }
        }
        // `bytes=-0` selects no bytes.
        ByteRange::Suffix(0) => Served::Unsatisfiable,
        ByteRange::Suffix(suffix) => Served::Partial {
            start: total.saturating_sub(suffix),
            end: total - 1,
        },
    }
}

fn record_error(errors: &Arc<Mutex<Vec<String>>>, message: String) {
    errors
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(message);
}

fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = panic.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = panic.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

/// Idle bound for a handler once the request line has arrived: header and body
/// reads, and each deliberately stalled response, must complete within this.
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound for the first request line only. The client's kernel-side handshake
/// completes before `connect` returns to its caller, so a thread stalled inside
/// `connect` (observed: 17s on the first outbound connection of a freshly
/// linked binary on this host) would otherwise be mistaken for a peer that
/// connects and sends nothing.
const FIRST_LINE_TIMEOUT: Duration = Duration::from_secs(60);

/// Serve exactly one request, then close. A bad request is answered with a
/// protocol response (`416`/`404`) or a recorded diagnostic; a handler panic is
/// caught and recorded by the caller, which keeps accepting so one bad request
/// cannot stop the worker.
fn handle_connection(stream: &mut TcpStream, shared: &Shared) {
    // Every early return below would otherwise answer the client with an empty
    // response and *no* recorded error, which is indistinguishable from a
    // client-side send/close race (a bare "no header terminator" panic). Each
    // bail-out therefore names its own stage.
    // The *first* request line gets a generous bound; everything after it is
    // bounded at `IDLE_TIMEOUT`. The kernel completes the handshake before
    // `connect` returns to the client, so the accepted socket can exist while
    // the client thread is still stalled in `connect` — on this host, the first
    // outbound connection of a freshly linked test binary has been observed to
    // block for 17s. Enforcing a 10s send deadline on the request line turns
    // that host stall into an empty response that looks like a protocol defect.
    // A client that never sends is still recorded (and still fails its test),
    // just after `FIRST_LINE_TIMEOUT`.
    if stream.set_read_timeout(Some(FIRST_LINE_TIMEOUT)).is_err() {
        record_error(
            &shared.errors,
            "fixture handler could not set the stream read timeout".into(),
        );
        return;
    }
    let _ = stream.set_write_timeout(Some(IDLE_TIMEOUT));
    let Ok(reader_stream) = stream.try_clone() else {
        record_error(
            &shared.errors,
            "fixture handler could not clone its stream".into(),
        );
        return;
    };
    let mut reader = BufReader::new(reader_stream);
    let mut line = String::new();
    let waiting = Instant::now();
    if let Err(error) = reader.read_line(&mut line) {
        record_error(
            &shared.errors,
            format!(
                "fixture handler waited {:?} for a request line and got no bytes: {error:?}",
                waiting.elapsed()
            ),
        );
        return;
    }
    // The request arrived, so the idle bound applies from here on: headers,
    // bodies and the deliberate stalls are all 10s-bounded.
    if stream.set_read_timeout(Some(IDLE_TIMEOUT)).is_err() {
        record_error(
            &shared.errors,
            "fixture handler could not shorten the stream read timeout".into(),
        );
        return;
    }
    let words: Vec<_> = line.split_whitespace().collect();
    if words.len() < 2 {
        // EOF before any byte is a *readiness probe*, not a malformed request:
        // `default_image_upgrade::warm_loopback` (and the calibration in
        // `image_show::s17`) open and immediately drop a real connection to
        // observe that the listener accepts. A non-empty but unparseable line
        // stays an error.
        if line.is_empty() {
            return;
        }
        record_error(
            &shared.errors,
            format!("fixture handler received a malformed request line: {line:?}"),
        );
        return;
    }
    let (method, path) = (words[0].to_owned(), words[1].to_owned());
    let mut range = None;
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        shared
            .headers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line.clone());
        if let Some((name, value)) = line.trim_end().split_once(':')
            && name.eq_ignore_ascii_case("range")
        {
            range = Some(value.trim().to_owned());
        }
    }
    shared
        .requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((method.clone(), path.clone()));
    if shared.panic_next.swap(false, Ordering::SeqCst) {
        panic!("fixture test seam: intentional handler panic");
    }
    let response = if path == "/v2/" {
        Some(Response {
            bytes: b"{}".to_vec(),
            media: "application/json",
            digest: image_archive::sha256_hex(b"{}"),
        })
    } else {
        shared
            .routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&path)
            .cloned()
    };
    if shared
        .denied_manifests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(&path)
    {
        shared
            .denied_requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((path.clone(), 401));
        let _ = write!(
            stream,
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        return;
    }
    if path == "/v2/" && shared.basic_challenge.load(Ordering::SeqCst) {
        let _ = write!(
            stream,
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        return;
    }
    let Some(response) = response else {
        let body = br#"{"errors":[{"code":"MANIFEST_UNKNOWN","message":"fixture missing"}]}"#;
        let _ = write!(
            stream,
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        if method != "HEAD" {
            let _ = stream.write_all(body);
        }
        return;
    };
    let total = response.bytes.len() as u64;
    let served = match &range {
        None => Served::Full,
        Some(value) => match parse_byte_range(value) {
            Ok(range) => resolve_byte_range(range, total),
            Err(problem) => Served::Unsupported(problem),
        },
    };
    if let Served::Unsupported(problem) = &served {
        record_error(&shared.errors, format!("{method} {path}: {problem}"));
    }
    // A stall holds the connection open mid-body; a rejected request has no body
    // to hold life to, so it must not fire the handshake.
    let stall_eligible = matches!(&served, Served::Full | Served::Partial { .. });
    let (status, content_range, body): (&str, Option<String>, &[u8]) = match &served {
        Served::Full => ("200 OK", None, response.bytes.as_slice()),
        Served::Partial { start, end } => (
            "206 Partial Content",
            Some(format!("bytes {start}-{end}/{total}")),
            &response.bytes[*start as usize..=*end as usize],
        ),
        Served::Unsatisfiable | Served::Unsupported(_) => (
            "416 Range Not Satisfiable",
            Some(format!("bytes */{total}")),
            &[],
        ),
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {}\r\nDocker-Content-Digest: {}\r\nContent-Length: {}\r\n{}Docker-Distribution-Api-Version: registry/2.0\r\nConnection: close\r\n\r\n",
        response.media,
        response.digest,
        body.len(),
        content_range
            .map(|value| format!("Content-Range: {value}\r\n"))
            .unwrap_or_default(),
    );
    if method == "HEAD" {
        return;
    }
    if !stall_eligible {
        let _ = stream.write_all(body);
        return;
    }
    let mut stalled = shared
        .stall
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some(stall) = stalled.as_ref()
        && stall.path == path
    {
        let mine = stall.generation;
        // Signal only after half of the bytes *this request* would serve, so a
        // partial (206) request stalls the same way a full one does.
        let _ = stream.write_all(&body[..body.len() / 2]);
        let _ = stall.signal.send(());
        // Wait only while this request's own stall is armed. A release or a
        // re-arm replaces the slot's generation, so the worker stops waiting
        // instead of going back to sleep on a connection it no longer owns.
        while stalled
            .as_ref()
            .is_some_and(|current| current.generation == mine)
        {
            stalled = shared
                .stall
                .1
                .wait(stalled)
                .unwrap_or_else(PoisonError::into_inner);
        }
        return;
    }
    drop(stalled);
    let _ = stream.write_all(body);
}
