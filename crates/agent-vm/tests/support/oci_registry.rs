//! Test-owned loopback OCI server, serving genuine archive bytes. No runtime
//! acquisition is mocked. Closing each response bounds protocol complexity.
#![allow(dead_code)]
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

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
#[derive(Clone)]
struct Response {
    bytes: Vec<u8>,
    media: &'static str,
    digest: String,
}

/// A parsed `Range: bytes=...` request. The registry client resumes a partial
/// blob with `bytes=N-`, so the fixture serves these rather than assuming
/// native never resumes.
enum ByteRange {
    /// `bytes=N-M`, or `bytes=N-` with an open end.
    At { start: u64, end: Option<u64> },
    /// `bytes=-S`, the final `S` bytes.
    Suffix(u64),
}

/// What a byte range resolves to against the length of the routed blob.
enum Served {
    Full,
    Partial { start: u64, end: u64 },
    Unsatisfiable,
    Unsupported,
}

type BlobStall = (
    Mutex<Option<(String, std::sync::mpsc::Sender<()>)>>,
    std::sync::Condvar,
);

pub struct Server {
    pub host: String,
    routes: Arc<Mutex<BTreeMap<String, Response>>>,
    pub requests: Arc<Mutex<Vec<(String, String)>>>,
    pub headers: Arc<Mutex<Vec<String>>>,
    errors: Arc<Mutex<Vec<String>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    task: Option<JoinHandle<()>>,
    stall: Arc<BlobStall>,
    basic_challenge: Arc<std::sync::atomic::AtomicBool>,
}
impl Server {
    pub fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback binding prerequisite");
        let host = listener.local_addr().unwrap().to_string();
        let routes = Arc::new(Mutex::new(BTreeMap::<String, Response>::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let headers = Arc::new(Mutex::new(Vec::new()));
        let worker_headers = headers.clone();
        let errors = Arc::new(Mutex::new(Vec::new()));
        let worker_errors = errors.clone();
        let basic_challenge = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_challenge = basic_challenge.clone();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stall = Arc::new((
            Mutex::new(None::<(String, std::sync::mpsc::Sender<()>)>),
            std::sync::Condvar::new(),
        ));
        let worker_stall = stall.clone();
        let (r, q, s) = (routes.clone(), requests.clone(), stop.clone());
        let task = std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                if s.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                // A panic in a handler would unwind out of the accept loop and
                // then, via `Drop`'s join, abort the whole test binary. Catch it,
                // record it, and keep serving so one bad request cannot corrupt
                // every other test in the process.
                if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handle_connection(
                        &mut stream,
                        &r,
                        &q,
                        &worker_headers,
                        &worker_stall,
                        &worker_challenge,
                        &worker_errors,
                    );
                })) {
                    record_error(
                        &worker_errors,
                        format!("registry worker panicked: {}", panic_message(panic)),
                    );
                }
            }
        });
        Self {
            host,
            routes,
            requests,
            headers,
            errors,
            stop,
            task: Some(task),
            stall,
            basic_challenge,
        }
    }
    pub fn require_basic_auth(&self) {
        self.basic_challenge
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    pub fn stall_blob(&self, path: &str) -> std::sync::mpsc::Receiver<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        *self.stall.0.lock().unwrap() = Some((path.to_owned(), tx));
        rx
    }
    pub fn release_blob(&self) {
        *self.stall.0.lock().unwrap() = None;
        self.stall.1.notify_all();
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
    pub fn put(&self, path: &str, bytes: Vec<u8>, media: &'static str, digest: &str) {
        self.routes.lock().unwrap().insert(
            path.to_owned(),
            Response {
                bytes,
                media,
                digest: digest.to_owned(),
            },
        );
    }
    pub fn remove(&self, path: &str) {
        self.routes.lock().unwrap().remove(path);
    }
    pub fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    /// Request-path failures the worker recorded instead of panicking. Tests
    /// that expect only well-formed requests assert this is empty.
    pub fn errors(&self) -> Vec<String> {
        self.errors
            .lock()
            .map(|errors| errors.clone())
            .unwrap_or_default()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.release_blob();
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = TcpStream::connect(&self.host);
        // Joining a panicked worker must not panic again: a second panic during
        // unwind aborts the process. Record it and let the drop finish.
        if let Some(task) = self.task.take()
            && let Err(panic) = task.join()
        {
            record_error(
                &self.errors,
                format!("registry worker panicked: {}", panic_message(panic)),
            );
        }
    }
}

/// Parse the byte-range forms the fixture serves. Anything else (multiple
/// ranges, a non-`bytes` unit, malformed syntax) is rejected so the caller can
/// record it instead of guessing a body.
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
            let end = end.unwrap_or(total - 1).min(total - 1);
            if end < start {
                return Served::Unsatisfiable;
            }
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
    if let Ok(mut errors) = errors.lock() {
        errors.push(message);
    }
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

/// Serve exactly one request, then close. Every failure mode is either a
/// protocol response (206/416/404) or a recorded diagnostic, never a panic.
fn handle_connection(
    stream: &mut TcpStream,
    routes: &Arc<Mutex<BTreeMap<String, Response>>>,
    requests: &Arc<Mutex<Vec<(String, String)>>>,
    headers: &Arc<Mutex<Vec<String>>>,
    stall: &Arc<BlobStall>,
    basic_challenge: &Arc<std::sync::atomic::AtomicBool>,
    errors: &Arc<Mutex<Vec<String>>>,
) {
    let Ok(_) = stream.set_read_timeout(Some(Duration::from_secs(10))) else {
        return;
    };
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let Ok(reader_stream) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(reader_stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let words: Vec<_> = line.split_whitespace().collect();
    if words.len() < 2 {
        return;
    }
    let (method, path) = (words[0].to_owned(), words[1].to_owned());
    let mut range = None;
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        if let Ok(mut headers) = headers.lock() {
            headers.push(line.clone());
        }
        if let Some((name, value)) = line.trim_end().split_once(':')
            && name.eq_ignore_ascii_case("range")
        {
            range = Some(value.trim().to_owned());
        }
    }
    if let Ok(mut requests) = requests.lock() {
        requests.push((method.clone(), path.clone()));
    }
    let response = if path == "/v2/" {
        Some(Response {
            bytes: b"{}".to_vec(),
            media: "application/json",
            digest: image_archive::sha256_hex(b"{}"),
        })
    } else {
        routes.lock().unwrap().get(&path).cloned()
    };
    if path == "/v2/" && basic_challenge.load(std::sync::atomic::Ordering::SeqCst) {
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
            Err(problem) => {
                record_error(errors, format!("{method} {path}: {problem}"));
                Served::Unsupported
            }
        },
    };
    let (status, content_range, body): (&str, Option<String>, &[u8]) = match served {
        Served::Full => ("200 OK", None, &response.bytes),
        Served::Partial { start, end } => (
            "206 Partial Content",
            Some(format!("bytes {start}-{end}/{total}")),
            &response.bytes[start as usize..=end as usize],
        ),
        Served::Unsatisfiable | Served::Unsupported => (
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
    let mut stalled = stall.0.lock().unwrap();
    if let Some((stall_path, signal)) = &*stalled
        && stall_path == &path
    {
        // Signal only after half of the bytes *this request* would serve, so a
        // partial (206) request stalls the same way a full one does.
        let _ = stream.write_all(&body[..body.len() / 2]);
        let _ = signal.send(());
        while stalled.is_some() {
            stalled = stall.1.wait(stalled).unwrap();
        }
        return;
    }
    drop(stalled);
    let _ = stream.write_all(body);
}
