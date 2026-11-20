//! Boot-free controls for the egress probe library, `egress-probe.sh` (#693).
//!
//! Ported from `script/test/lib/egress-wire-contract.py` and
//! `script/test/lib/egress-probe-contract.py`. The probe library is *guest*
//! code: the guest runs `bash ./egress-probe.sh <CASE> …`, and its TLS, opaque
//! and banner probes are Python that ADR-0072 keeps as an allowlisted guest
//! exception. What lives here is the other half of the old Python suites — the
//! part that ran the library **on the host**: the pure-bash wire primitives and
//! the case dispatcher, driven through `/bin/bash` with this side playing the
//! peer.
//!
//! Three rows of the Python suites drove the probe's *Python* on the host:
//! `listen` (which prefers `python3` and falls back to `node`),
//! `tls_probe`/`opaque_send`/`server_first`, and `tls_held_two_requests`.
//! ADR-0072 records that fork — "the probe's host half has to become Rust too,
//! or the ported check has to drop the host-run rows and leave them to the guest
//! suite" — and #693 takes the second branch, because the probe stays a guest
//! exception. Those rows are the guest's: IN1/IN2 run `listen`, HN*/OP* run
//! `tls_probe`/`opaque_send`/`server_first`, HP2/HP2c run the held pair, and the
//! oracle half of the receipt rows (a captured ClientHello → SNI, exact
//! payloads → hex receipts) is `egress_hostname_fixtures::self_test`.
//!
//! Rules this keeps: every peer read, accept, send, wait and join is bounded
//! (a hung fixture blocks a gate instead of reporting it), and the oracles are
//! written here rather than asked of the code under test — the byte framing, the
//! DNS reply and the endpoint matrix in `matrix` are this module's own model.

use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{
    egress_allowances::PA2_SIGNALS, egress_cases as cases, egress_fixtures, egress_run,
    egress_witness,
};

pub const LAN: &str = "192.168.20.7";
pub const GW: &str = "100.64.0.1";
pub const HOST: &str = "host.microsandbox.internal";
pub const ANSWER: &str = "93.184.216.34";

/// Bound on one peer's whole life: a listener that never sees its dial gives up
/// rather than outliving the control that started it.
const PEER_BOUND: Duration = Duration::from_secs(20);
/// Bound on one accepted connection's reads and writes, matching the Python's 6 s.
const CONNECTION_BOUND: Duration = Duration::from_secs(6);
/// Bound on joining a peer thread after its stop flag is set.
const JOIN_BOUND: Duration = Duration::from_secs(8);
/// Bound on one whole probe command. The library's own deadlines are 3 s and 5 s;
/// this is the outer guard, and a row that hits it has already failed.
const COMMAND_BOUND: Duration = Duration::from_secs(30);

// --- The probe library ------------------------------------------------------

static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// The repository the controls read. A `#[test]` gets the checkout this crate
/// was compiled in; `--repo-root` points a CLI run at a disposable copy, which is
/// how the mutation suite grades a mutated `egress-probe.sh`.
pub fn set_repo_root(root: PathBuf) -> Result<(), String> {
    ROOT.set(root)
        .map_err(|_| "the repo root is set once".to_owned())
}

fn repo_root() -> PathBuf {
    ROOT.get()
        .cloned()
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

pub fn probe_path() -> PathBuf {
    repo_root().join("script/test/fixtures/egress-probe.sh")
}

/// One shell word: single-quoted, with every embedded quote escaped.
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn quote_path(path: &Path) -> String {
    quote(&path.to_string_lossy())
}

/// Run one probe expression with the library sourced, exactly as the two Python
/// suites did: `EGRESS_PROBE_LIB=1 . egress-probe.sh`, then `setup`, then the
/// expression.
pub fn probe(expression: &str, setup: &str, env: &[(&str, &str)]) -> Result<Output, String> {
    let script = format!(
        "EGRESS_PROBE_LIB=1 . {}\n{setup}\n{expression}\n",
        quote_path(&probe_path())
    );
    run_bounded(&script, env, Duration::from_secs(8))
}

pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
    pub elapsed: Duration,
}

impl Output {
    pub(crate) fn text(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }

    fn lines(&self) -> Vec<&str> {
        self.stdout.lines().collect()
    }
}

/// Run one shell script under a bound, in its own process group.
///
/// Both properties matter: a step that wedges must fail the control instead of
/// the gate (two tickets in this stack wedged on unbounded waits), and a
/// fault-injected `sleep 30` must not survive its case.
pub fn run_bounded(script: &str, env: &[(&str, &str)], bound: Duration) -> Result<Output, String> {
    // `bash` from `PATH`, as the Python's `shutil.which("bash")` did: the probe
    // library needs `EPOCHREALTIME`, which macOS's `/bin/bash` 3.2 does not have.
    let mut command = Command::new("bash");
    command.arg("-c").arg(script).envs(env.iter().copied());
    run_command_bounded(command, bound)
}

pub(crate) fn run_command_bounded(mut command: Command, bound: Duration) -> Result<Output, String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let started = Instant::now();
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let stdout = child.stdout.take().expect("a piped stdout");
    let stderr = child.stderr.take().expect("a piped stderr");
    let out = drain(stdout);
    let err = drain(stderr);
    let status = loop {
        match child.try_wait().map_err(|error| error.to_string())? {
            Some(status) => break status,
            None if started.elapsed() > bound => {
                stop_group(&mut child);
                break child.wait().map_err(|error| error.to_string())?;
            }
            None => thread::sleep(Duration::from_millis(5)),
        }
    };
    Ok(Output {
        status: exit_status(&status),
        stdout: out.join_bounded(JOIN_BOUND).unwrap_or_default(),
        stderr: err.join_bounded(JOIN_BOUND).unwrap_or_default(),
        elapsed: started.elapsed(),
    })
}

fn exit_status(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(-1)
}

/// Kill a child and everything it started.
fn stop_group(child: &mut Child) {
    let pid = child.id() as i32;
    // SAFETY: `kill` on a group this process created; the return value is only
    // ever informational, and the child is reaped by the caller either way.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
}

struct Drain {
    reader: Option<JoinHandle<String>>,
}

fn drain(mut pipe: impl Read + Send + 'static) -> Drain {
    Drain {
        reader: Some(thread::spawn(move || {
            let mut text = String::new();
            let _ = pipe.read_to_string(&mut text);
            text
        })),
    }
}

impl Drain {
    fn join_bounded(mut self, bound: Duration) -> Option<String> {
        let reader = self.reader.take()?;
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(reader.join().ok());
        });
        receiver.recv_timeout(bound).ok().flatten()
    }
}

fn join_bounded(handle: JoinHandle<()>, bound: Duration) -> Result<(), String> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(handle.join().is_ok());
    });
    match receiver.recv_timeout(bound) {
        Ok(true) => Ok(()),
        Ok(false) => Err("a peer thread panicked".to_owned()),
        Err(_) => Err(format!("a peer did not stop within {bound:?}")),
    }
}

/// Wait on a stop flag, bounded. The peers' version of a sleep.
fn wait_for(stop: &AtomicBool, duration: Duration) {
    let deadline = Instant::now() + duration;
    while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
}

// --- Peers ------------------------------------------------------------------

#[derive(Default)]
pub struct PeerLog {
    errors: Mutex<Vec<String>>,
    connections: AtomicUsize,
    datagrams: AtomicUsize,
    empty_datagrams: AtomicUsize,
    peers: Mutex<Vec<SocketAddr>>,
}

impl PeerLog {
    fn error(&self, message: impl Into<String>) {
        self.errors
            .lock()
            .expect("the peer log")
            .push(message.into());
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn empty_datagrams(&self) -> usize {
        self.empty_datagrams.load(Ordering::SeqCst)
    }

    pub fn peers(&self) -> Vec<SocketAddr> {
        self.peers.lock().expect("the peer log").clone()
    }

    fn errors(&self) -> Vec<String> {
        self.errors.lock().expect("the peer log").clone()
    }
}

type Handler = dyn Fn(&mut TcpStream, &AtomicBool, &PeerLog) + Send + Sync;
type DatagramHandler = dyn Fn(&UdpSocket, &[u8], SocketAddr, &AtomicBool, &PeerLog) + Send + Sync;

/// One TCP peer: binds an ephemeral port, accepts until told to stop, and hands
/// each connection to the handler on the accept thread, so `connections` is
/// deterministic for the rows that assert "exactly one connection".
pub struct TcpPeer {
    pub port: u16,
    stop: Arc<AtomicBool>,
    log: Arc<PeerLog>,
    handle: Option<JoinHandle<()>>,
}

impl TcpPeer {
    pub fn start<H>(handler: H) -> Result<Self, String>
    where
        H: Fn(&mut TcpStream, &AtomicBool, &PeerLog) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|error| error.to_string())?;
        listener
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        let port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let stop = Arc::new(AtomicBool::new(false));
        let log = Arc::new(PeerLog::default());
        let handler: Arc<Handler> = Arc::new(handler);
        let (flag, sink, worker) = (Arc::clone(&stop), Arc::clone(&log), Arc::clone(&handler));
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + PEER_BOUND;
            while !flag.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        sink.connections.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(CONNECTION_BOUND));
                        let _ = stream.set_write_timeout(Some(CONNECTION_BOUND));
                        worker(&mut stream, &flag, &sink);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            port,
            stop,
            log,
            handle: Some(handle),
        })
    }

    /// Stop the peer and report anything its handler refused.
    pub fn finish(mut self) -> Result<Arc<PeerLog>, String> {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            join_bounded(handle, JOIN_BOUND)?;
        }
        let errors = self.log.errors();
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        Ok(self.log)
    }
}

pub struct UdpPeer {
    pub port: u16,
    stop: Arc<AtomicBool>,
    log: Arc<PeerLog>,
    handle: Option<JoinHandle<()>>,
}

impl UdpPeer {
    pub fn start<H>(handler: H) -> Result<Self, String>
    where
        H: Fn(&UdpSocket, &[u8], SocketAddr, &AtomicBool, &PeerLog) + Send + Sync + 'static,
    {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).map_err(|error| error.to_string())?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|error| error.to_string())?;
        let port = socket
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let stop = Arc::new(AtomicBool::new(false));
        let log = Arc::new(PeerLog::default());
        let handler: Arc<DatagramHandler> = Arc::new(handler);
        let (flag, sink, worker) = (Arc::clone(&stop), Arc::clone(&log), Arc::clone(&handler));
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + PEER_BOUND;
            let mut buffer = [0u8; 4096];
            while !flag.load(Ordering::SeqCst) && Instant::now() < deadline {
                match socket.recv_from(&mut buffer) {
                    Ok((0, _)) => {
                        // A zero-length datagram carries no wire content and
                        // cannot be the probe's query, whose bytes the rows pin
                        // exactly. Counting and dropping it keeps whichever
                        // datagram arrives first from aborting the case (#315).
                        sink.empty_datagrams.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok((read, peer)) => {
                        sink.datagrams.fetch_add(1, Ordering::SeqCst);
                        sink.peers.lock().expect("the peer log").push(peer);
                        let data = buffer[..read].to_vec();
                        worker(&socket, &data, peer, &flag, &sink);
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            port,
            stop,
            log,
            handle: Some(handle),
        })
    }

    pub fn log(&self) -> Arc<PeerLog> {
        Arc::clone(&self.log)
    }

    pub fn finish(mut self) -> Result<Arc<PeerLog>, String> {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            join_bounded(handle, JOIN_BOUND)?;
        }
        let errors = self.log.errors();
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        Ok(self.log)
    }
}

/// Read exactly `count` bytes, or refuse: a short read is a real EOF, never a
/// reason to accept a partial request.
fn exact(stream: &mut TcpStream, count: usize) -> Result<Vec<u8>, String> {
    let mut data = Vec::with_capacity(count);
    while data.len() < count {
        let mut buffer = vec![0u8; count - data.len()];
        let read = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("early request EOF".to_owned());
        }
        data.extend_from_slice(&buffer[..read]);
    }
    Ok(data)
}

/// One byte at a time, so the probe's framing is what the row exercises.
fn trickle(stream: &mut TcpStream, bytes: &[u8]) {
    for byte in bytes {
        if stream.write_all(&[*byte]).is_err() {
            return;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

// --- The DNS wire oracle ----------------------------------------------------

/// Answer one DNS query: preserve the id and question, and answer NXDOMAIN or
/// one A record. Written here, not asked of the code under test.
pub fn dns_reply(query: &[u8], address: Option<Ipv4Addr>) -> Vec<u8> {
    let flags: u16 = if address.is_none() { 0x8183 } else { 0x8180 };
    let mut reply = Vec::with_capacity(query.len() + 28);
    reply.extend_from_slice(&query[..2]);
    for field in [flags, 1, u16::from(address.is_some()), 0, 0] {
        reply.extend_from_slice(&field.to_be_bytes());
    }
    reply.extend_from_slice(&query[12..]);
    if let Some(address) = address {
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        reply.extend_from_slice(&address.octets());
    }
    reply
}

fn lan_address() -> Ipv4Addr {
    LAN.parse().expect("the fixture LAN address")
}

/// Frame a DNS message for stream transport: a two-byte length, then the body.
fn frame(message: &[u8]) -> Vec<u8> {
    let mut framed = (message.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(message);
    framed
}

// --- The wire controls ------------------------------------------------------

pub fn http_fragmentation_exact_body_and_single_connection() -> Result<(), String> {
    for (body, status) in [
        (b"receipt wire".to_vec(), 0),
        (b"receipt wir".to_vec(), 1),
        (b"receipt wire\n".to_vec(), 1),
        (b"receipt wire\0".to_vec(), 1),
    ] {
        let length = if status == 0 || body.len() < 12 {
            12
        } else {
            body.len()
        };
        let sent = body.clone();
        let peer = TcpPeer::start(move |conn, _stop, _log| {
            let mut request = [0u8; 4096];
            let _ = conn.read(&mut request);
            let mut response =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n").into_bytes();
            response.extend_from_slice(&sent);
            trickle(conn, &response);
        })?;
        let port = peer.port;
        let result = probe(&format!("http_get 127.0.0.1 {port} wire"), "", &[])?;
        let log = peer.finish()?;
        let detail = format!("body {body:?}: {}", result.text());
        let expected = if status == 0 {
            "HTTP_OK wire"
        } else {
            "HTTP_FAIL wire"
        };
        assert_eq!(result.status, status, "{detail}");
        assert_eq!(result.stdout.trim(), expected, "{detail}");
        assert_eq!(log.connections(), 1, "{detail}");
    }
    Ok(())
}

pub fn http_public_keep_open_and_invalid_lines() -> Result<(), String> {
    for (line, status) in [
        (b"HTTP/1.1 204 No Content\r\n".to_vec(), 0),
        (b"HTTP/1.1 204 No Content\n".to_vec(), 1),
        (b"garbage\r\n".to_vec(), 1),
    ] {
        let sent = line.clone();
        let peer = TcpPeer::start(move |conn, stop, _log| {
            let mut request = [0u8; 4096];
            let _ = conn.read(&mut request);
            trickle(conn, &sent);
            wait_for(stop, Duration::from_secs(6));
        })?;
        let port = peer.port;
        let result = probe(&format!("http_public 127.0.0.1 {port}"), "", &[])?;
        let log = peer.finish()?;
        let detail = format!("line {line:?}: {}", result.text());
        assert_eq!(result.status, status, "{detail}");
        assert!(
            result.elapsed < Duration::from_secs(2),
            "{detail} took {:?}",
            result.elapsed
        );
        assert_eq!(log.connections(), 1, "{detail}");
    }
    Ok(())
}

pub fn udp_one_socket_wrong_ack_no_ack_and_usage() -> Result<(), String> {
    for (reply, status) in [
        (Some(b"ack wire".to_vec()), 0),
        (Some(b"ack wrong".to_vec()), 1),
        (None, 1),
    ] {
        let acknowledgement = reply.clone();
        let peer = UdpPeer::start(move |socket, data, peer, _stop, log| {
            if data != b"id=wire" {
                log.error(format!("datagram from {peer}: {data:?}"));
                return;
            }
            if let Some(reply) = &acknowledgement {
                let _ = socket.send_to(reply, peer);
            }
        })?;
        let port = peer.port;
        let result = probe(&format!("udp_send 127.0.0.1 {port} wire"), "", &[])?;
        let log = peer.finish()?;
        let detail = format!("reply {reply:?}: {}", result.text());
        assert_eq!(result.status, status, "{detail}");
        assert_eq!(log.peers().len(), 1, "{detail}");
    }
    // A command with no arguments is a usage error, never a network failure: a
    // case that certified a denial from a usage status would prove nothing.
    for command in [
        "http_get",
        "http_public",
        "udp_send",
        "dns_status",
        "listen",
    ] {
        let result = probe(command, "", &[])?;
        assert_eq!(result.status, 2, "{command}: {}", result.text());
    }
    Ok(())
}

pub fn dns_fragmented_keep_open_nx_ok_and_invalid_frames() -> Result<(), String> {
    for mode in [
        "nx",
        "ok",
        "short-prefix",
        "short-body",
        "zero",
        "oversize",
        "wrong-id",
        "wrong-question",
        "wrong-qr",
        "cycle",
    ] {
        let status = if matches!(mode, "nx" | "ok") { 0 } else { 1 };
        let peer = TcpPeer::start(move |conn, stop, log| {
            let size = match exact(conn, 2) {
                Ok(prefix) => u16::from_be_bytes([prefix[0], prefix[1]]) as usize,
                Err(error) => return log.error(format!("{mode}: {error}")),
            };
            let query = match exact(conn, size) {
                Ok(query) => query,
                Err(error) => return log.error(format!("{mode}: {error}")),
            };
            let answer = if mode == "ok" {
                Some(lan_address())
            } else {
                None
            };
            let mut response = dns_reply(&query, answer);
            match mode {
                "wrong-id" => response[0] ^= 1,
                "wrong-question" => response[13] = b'X',
                "wrong-qr" => response[2] = 0x01,
                "cycle" => {
                    response.truncate(12);
                    response.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
                }
                _ => {}
            }
            let mut framed = frame(&response);
            match mode {
                "short-prefix" => framed.truncate(1),
                "short-body" => {
                    framed.pop();
                }
                "zero" => framed = vec![0, 0],
                "oversize" => framed = 4097u16.to_be_bytes().to_vec(),
                _ => {}
            }
            trickle(conn, &framed);
            if matches!(mode, "nx" | "ok") {
                wait_for(stop, Duration::from_secs(6));
            }
        })?;
        let port = peer.port.to_string();
        let result = probe(
            "dns_status 127.0.0.1 example.com tcp",
            "",
            &[("EGRESS_PROBE_DNS_PORT", &port)],
        )?;
        peer.finish()?;
        let detail = format!("mode {mode}: {}", result.text());
        assert_eq!(result.status, status, "{detail}");
        assert!(
            result.elapsed < Duration::from_secs(2),
            "{detail} took {:?}",
            result.elapsed
        );
        if mode == "ok" {
            assert!(result.stdout.contains("a=192.168.20.7"), "{detail}");
        }
        if mode == "nx" {
            assert!(result.stdout.contains("rcode=3"), "{detail}");
        }
    }
    Ok(())
}

pub fn total_deadlines_withheld_prefix_body_connect_and_write() -> Result<(), String> {
    for kind in [
        "prefix",
        "body",
        "split-deadline",
        "http",
        "connect-http",
        "connect-dns",
        "write-http",
        "write-dns",
    ] {
        let peer = TcpPeer::start(move |conn, stop, log| {
            if matches!(kind, "prefix" | "body" | "split-deadline") {
                let size = match exact(conn, 2) {
                    Ok(prefix) => u16::from_be_bytes([prefix[0], prefix[1]]) as usize,
                    Err(error) => return log.error(format!("{kind}: {error}")),
                };
                let query = match exact(conn, size) {
                    Ok(query) => query,
                    Err(error) => return log.error(format!("{kind}: {error}")),
                };
                let response = dns_reply(&query, None);
                match kind {
                    "body" => {
                        let _ = conn.write_all(&(response.len() as u16).to_be_bytes());
                    }
                    "split-deadline" => {
                        wait_for(stop, Duration::from_millis(1800));
                        let _ = conn.write_all(&(response.len() as u16).to_be_bytes());
                        wait_for(stop, Duration::from_millis(1800));
                        let _ = conn.write_all(&response);
                    }
                    _ => {}
                }
            } else {
                let mut request = [0u8; 4096];
                let _ = conn.read(&mut request);
            }
            wait_for(stop, Duration::from_secs(7));
        })?;
        let is_http = kind.contains("http");
        // A blocked shell redirection cannot be reproduced reliably with host
        // routing, so the exec primitive itself is fault-injected.
        let setup = match kind {
            "connect-http" | "connect-dns" => "exec() { sleep 30; }",
            "write-http" => {
                r#"printf() { if [[ $1 == GET* ]]; then sleep 30; else builtin printf "$@"; fi; }"#
            }
            "write-dns" => {
                r#"printf() { if [[ -e /dev/fd/6 && $1 == %b ]]; then sleep 30; else builtin printf "$@"; fi; }"#
            }
            _ => "",
        };
        let command = if is_http {
            format!("http_get 127.0.0.1 {} wire", peer.port)
        } else {
            "dns_status 127.0.0.1 example.com tcp".to_owned()
        };
        let port = peer.port.to_string();
        let result = probe(&command, setup, &[("EGRESS_PROBE_DNS_PORT", &port)])?;
        peer.finish()?;
        let detail = format!("kind {kind}: {}", result.text());
        assert_eq!(result.status, 1, "{detail}");
        assert!(
            result
                .stdout
                .contains(if is_http { "HTTP_FAIL" } else { "TIMEOUT" }),
            "{detail}"
        );
        let (lower, upper) = if is_http { (3.5, 6.5) } else { (2.5, 4.5) };
        let elapsed = result.elapsed.as_secs_f64();
        assert!(
            elapsed > lower && elapsed < upper,
            "kind {kind}: {elapsed:.2}s outside ({lower}s, {upper}s)"
        );
    }
    Ok(())
}

pub fn dns_query_encoding_and_udp_short_datagram() -> Result<(), String> {
    let expected = "123401000001000000000000076578616d706c6503636f6d0000010001";
    let result = probe(
        r#"printf '%b' "$(_dns_query_escapes 4660 example.com)" | od -An -tx1 -v"#,
        "",
        &[],
    )?;
    assert_eq!(result.status, 0, "{}", result.stderr);
    let encoded: String = result.stdout.split_whitespace().collect();
    assert_eq!(encoded, expected);
    let committed =
        fs::read_to_string(repo_root().join("script/test/fixtures/egress-dns-query.hex"))
            .map_err(|error| error.to_string())?;
    let committed: String = committed.split_whitespace().collect();
    assert_eq!(committed, expected);

    for short in [false, true] {
        let peer = UdpPeer::start(move |socket, data, peer, _stop, log| {
            let observed: String = data[2..].iter().map(|byte| format!("{byte:02x}")).collect();
            if observed != expected[4..] {
                log.error(format!("query from {peer}: {}", hex(data)));
                return;
            }
            let response = dns_reply(data, None);
            let _ = socket.send_to(if short { &response[..10] } else { &response }, peer);
        })?;
        let port = peer.port;
        // A zero-length datagram is not the probe's query; the peer must ignore
        // it and still validate the query that follows.
        let stray = UdpSocket::bind(("127.0.0.1", 0)).map_err(|error| error.to_string())?;
        let _ = stray.send_to(b"", ("127.0.0.1", port));
        let deadline = Instant::now() + Duration::from_secs(2);
        while peer.log().empty_datagrams() == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            peer.log().empty_datagrams(),
            1,
            "peer did not ignore the zero-length datagram"
        );
        let port = port.to_string();
        let result = probe(
            "dns_status 127.0.0.1 example.com udp",
            "",
            &[("EGRESS_PROBE_DNS_PORT", &port)],
        )?;
        let log = peer.finish()?;
        let detail = format!("short {short}: {}", result.text());
        assert_eq!(result.status, if short { 1 } else { 0 }, "{detail}");
        assert_eq!(log.peers().len(), 1, "{detail}");
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn gateway_skips_ipv6() -> Result<(), String> {
    // The production /etc/resolv.conf is preserved; a mixed-family stream is
    // supplied to the actual awk program, not to a substituted gateway helper.
    let setup = "awk() { command awk \"$1\" <<'EOF'\n\
        nameserver 2606:4700:4700::1111\n\
        nameserver 192.168.20.1\n\
        nameserver 100.64.0.1\n\
        EOF\n\
        }\n";
    let result = probe("gateway", setup, &[])?;
    assert_eq!(result.status, 0, "{}", result.text());
    assert_eq!(result.stdout, "192.168.20.1");
    Ok(())
}

// --- The dispatcher controls ------------------------------------------------

/// One endpoint row of the independent §10.2 matrix: what the guest dispatcher
/// must emit, in order, for a case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    kind: String,
    host: String,
    port: String,
    expected: String,
    name: String,
}

fn flow(kind: &str, host: &str, port: u16, allowed: bool) -> Row {
    Row {
        kind: kind.to_owned(),
        host: host.to_owned(),
        port: port.to_string(),
        expected: if allowed { "0" } else { "1" }.to_owned(),
        name: String::new(),
    }
}

fn dns(server: &str, allowed: bool, name: &str) -> Vec<Row> {
    ["udp", "tcp"]
        .iter()
        .map(|proto| Row {
            kind: format!("dns-{proto}"),
            host: server.to_owned(),
            port: "53".to_owned(),
            expected: if allowed { "OK" } else { "NX" }.to_owned(),
            name: name.to_owned(),
        })
        .collect()
}

/// The endpoint matrix, derived from plan §10.2 rather than from the
/// dispatcher's own tables: a case that disappears here disappears from the
/// control's expectation too, so it cannot pass by emitting nothing.
pub fn matrix() -> Vec<(&'static str, Vec<Row>)> {
    let t80 = |yes: bool| flow("tcp", LAN, 18080, yes);
    let t81 = |yes: bool| flow("tcp", LAN, 18081, yes);
    let u80 = |yes: bool| flow("udp", LAN, 18080, yes);
    let u90 = |yes: bool| flow("udp", LAN, 19090, yes);
    let h80 = |yes: bool| flow("tcp", HOST, 18080, yes);
    let public = |host: &str, yes: bool| flow("public", host, 80, yes);
    vec![
        ("LC1", vec![t80(true), t81(true), u90(true), u80(true)]),
        (
            "HC1",
            [vec![h80(true)], dns(GW, true, "example.com")].concat(),
        ),
        (
            "I1",
            [
                vec![public("1.1.1.1", true), public("1.0.0.1", true)],
                dns(GW, true, "example.com"),
                dns("1.1.1.1", true, "example.com"),
                vec![t80(false), h80(false)],
            ]
            .concat(),
        ),
        (
            "D1",
            [
                vec![t80(false), u90(false), h80(false), public("1.1.1.1", false)],
                dns(GW, false, "example.com"),
                dns("1.1.1.1", false, "example.com"),
            ]
            .concat(),
        ),
        (
            "D1f",
            [
                vec![t80(false), public("1.1.1.1", false)],
                vec![dns(GW, false, "example.com")[0].clone()],
            ]
            .concat(),
        ),
        (
            "L1",
            [
                vec![t80(true), u90(true), public("1.1.1.1", false), h80(false)],
                dns(GW, false, "example.com"),
            ]
            .concat(),
        ),
        (
            "H1",
            [
                vec![h80(true), t80(false), public("1.1.1.1", false)],
                dns(GW, true, "example.com"),
                vec![public(ANSWER, false)],
            ]
            .concat(),
        ),
        ("I1a", vec![public(ANSWER, true)]),
        ("LH1", vec![t80(true), h80(true), public("1.1.1.1", false)]),
        (
            "AD1",
            [
                vec![public("1.1.1.1", true), public("1.0.0.1", false)],
                dns(GW, false, "example.com"),
                dns("1.1.1.1", false, "example.com"),
            ]
            .concat(),
        ),
        ("TP1", vec![t80(true), u80(false), t81(false)]),
        ("UP1", vec![u90(true), u80(false), t80(false)]),
        ("UP2", vec![t80(true), u80(true), t81(false)]),
        ("CI1", vec![t80(true), t81(false)]),
        // ADR-0065: the same grant as TP1, held as a project allowance record.
        ("PA1", vec![t80(true), t81(false)]),
        ("PA1x", vec![t80(false)]),
        ("PX1", vec![t80(true), t81(false)]),
        ("PX2", vec![t80(true)]),
        ("PX3", vec![t80(false), public("1.1.1.1", false)]),
        ("FL0", vec![public("1.1.1.1", true)]),
        ("FL1", vec![t80(false)]),
        ("FL2", vec![t80(false)]),
        (
            "CR1c",
            [
                dns(GW, true, "api.anthropic.com"),
                vec![public("1.1.1.1", true)],
            ]
            .concat(),
        ),
        (
            "CR1",
            [
                dns(GW, false, "api.anthropic.com"),
                vec![public("1.1.1.1", false)],
            ]
            .concat(),
        ),
        ("IN1", vec![public("1.1.1.1", false)]),
        ("IN2", vec![public("1.1.1.1", false)]),
        (
            "V6c",
            vec![
                public("2606:4700:4700::1111", true),
                public("2606:4700:4700::1001", true),
            ],
        ),
        ("DNS6c", dns("2606:4700:4700::1111", true, "example.com")),
        (
            "V6",
            vec![
                public("2606:4700:4700::1111", true),
                public("2606:4700:4700::1001", false),
            ],
        ),
        // The hook cases own their attempt: the sourced project hook makes it.
        ("HK1", Vec::new()),
        ("HK1c", Vec::new()),
        ("HK2", Vec::new()),
        ("HK2c", Vec::new()),
    ]
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    None,
    Internal,
    Invert,
    SlowDns,
    WrongQuestion,
    EmptyAnswer,
    WrongRebindAnswer,
}

/// Drive one named case through the real dispatcher with a scripted probe: only
/// the four primitives are stubbed, so the case's own asserts and their order are
/// what runs.
pub fn run_case(
    case: &str,
    rows: &[Row],
    variant: &str,
    extra: &str,
    fault: Fault,
) -> Result<Output, String> {
    let mut routes = Vec::new();
    let mut dns_routes = Vec::new();
    for row in rows {
        if let Some(proto) = row.kind.strip_prefix("dns-") {
            let code = if row.expected == "OK" { 0 } else { 3 };
            let count = if code == 0 { 1 } else { 0 };
            let address = if case == "RB1" { LAN } else { ANSWER };
            let mut line = format!(
                "DNS {proto} {} {} id_ok=1 qr=1 question_ok=1 tc=0 rcode={code} ancount={count} a={} ms=10",
                row.host,
                row.name,
                if count == 0 { "" } else { address }
            );
            match fault {
                Fault::SlowDns => line = line.replace("ms=10", "ms=1000"),
                Fault::WrongQuestion => line = line.replace("question_ok=1", "question_ok=0"),
                Fault::EmptyAnswer => line = line.replace(&format!("a={address}"), "a="),
                Fault::WrongRebindAnswer => {
                    line = line.replace(&format!("a={LAN}"), &format!("a={ANSWER}"))
                }
                _ => {}
            }
            dns_routes.push(format!(
                "{}) echo {}; return 0 ;;",
                quote(&format!("{} {} {proto}", row.host, row.name)),
                quote(&line)
            ));
        } else {
            let mut status = if fault == Fault::Internal {
                2
            } else {
                row.expected.parse::<i32>().expect("a flow expectation")
            };
            if fault == Fault::Invert {
                status = 1 - status;
            }
            routes.push(format!(
                "{}) return {status} ;;",
                quote(&format!("{} {} {}", row.kind, row.host, row.port))
            ));
        }
    }
    let script = format!(
        "EGRESS_PROBE_LIB=1 . {probe}\n\
         gateway() {{ echo {GW}; }}\n\
         _route() {{ case \"$*\" in {routes} *) return 2 ;; esac; }}\n\
         http_get() {{ _route tcp \"$1\" \"$2\"; }}\n\
         udp_send() {{ _route udp \"$1\" \"$2\"; }}\n\
         http_public() {{ _route public \"$1\" \"$2\"; }}\n\
         dns_status() {{ case \"$*\" in {dns_routes} *) return 2 ;; esac; }}\n\
         listen() {{ echo \"INGRESS_READY $2 $1\"; }}\n\
         dispatch {} attempt_1 {LAN} {} {}\n",
        quote(case),
        quote(variant),
        quote(extra),
        probe = quote_path(&probe_path()),
        routes = routes.join(" "),
        dns_routes = dns_routes.join(" "),
    );
    run_bounded(&script, &[], COMMAND_BOUND)
}

/// One `ATTEMPT` row as the dispatcher emitted it.
#[derive(Debug, PartialEq, Eq)]
pub struct Attempt {
    pub kind: String,
    pub host: String,
    pub port: String,
    pub expected: String,
    pub ident: String,
}

/// Join the emitted rows against the matrix and refuse a duplicate identity.
pub fn attempt_rows(case: &str, output: &Output) -> Vec<Attempt> {
    let mut attempts = Vec::new();
    for line in output
        .lines()
        .into_iter()
        .filter(|line| line.starts_with("ATTEMPT "))
    {
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 8, "malformed ATTEMPT line: {line}");
        assert_eq!(fields[1], case, "attempt for another case: {line}");
        attempts.push(Attempt {
            kind: fields[3].to_owned(),
            host: fields[4].to_owned(),
            port: fields[5].to_owned(),
            expected: fields[6].to_owned(),
            ident: fields[7].to_owned(),
        });
    }
    attempts
}

fn assert_case(case: &str, rows: &[Row], variant: &str, extra: &str) -> Result<Output, String> {
    let result = run_case(case, rows, variant, extra, Fault::None)?;
    let detail = format!("{case}/{variant}: {}", result.text());
    assert_eq!(result.status, 0, "{detail}");
    let attempts = attempt_rows(case, &result);
    let observed: Vec<(String, String, String, String)> = attempts
        .iter()
        .map(|attempt| {
            (
                attempt.kind.clone(),
                attempt.host.clone(),
                attempt.port.clone(),
                attempt.expected.clone(),
            )
        })
        .collect();
    let expected: Vec<(String, String, String, String)> = rows
        .iter()
        .map(|row| {
            (
                row.kind.clone(),
                row.host.clone(),
                row.port.clone(),
                row.expected.clone(),
            )
        })
        .collect();
    assert_eq!(observed, expected, "{detail}");
    let ids: Vec<&str> = attempts
        .iter()
        .map(|attempt| attempt.ident.as_str())
        .filter(|ident| *ident != "-")
        .collect();
    let unique: std::collections::BTreeSet<&&str> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "duplicate attempt id: {detail}");
    assert!(
        result.stdout.contains(&format!("CASE {case} END")),
        "{detail}"
    );
    Ok(result)
}

pub fn every_named_case_endpoint_matrix() -> Result<(), String> {
    for (case, rows) in matrix() {
        let extra = if case == "I1a" { ANSWER } else { "" };
        let result = assert_case(case, &rows, "ipv4", extra)?;
        if case == "H1" {
            assert!(
                result.stdout.contains(&format!("ANSWER {ANSWER}")),
                "H1: missing the decoded answer: {}",
                result.text()
            );
        }
        if case == "IN1" || case == "IN2" {
            let port = if case == "IN1" { 8000 } else { 18555 };
            assert!(
                result
                    .stdout
                    .contains(&format!("INGRESS_READY attempt_1 {port}")),
                "{case}: missing readiness: {}",
                result.text()
            );
        }
    }
    Ok(())
}

pub fn paired_ipv6_and_all_rebind_variants() -> Result<(), String> {
    assert_case(
        "D1",
        &dns("2606:4700:4700::1111", false, "example.com"),
        "ipv6",
        "",
    )?;
    for variant in [
        "internet", "address", "tcp", "udp", "port", "tcp-port", "udp-port",
    ] {
        let allowed = matches!(variant, "address" | "tcp" | "udp");
        let rows = dns(GW, allowed, "192-168-20-7.sslip.io");
        assert_case("RB1", &rows, variant, "192-168-20-7.sslip.io")?;
    }
    Ok(())
}

pub fn network_and_internal_errors_cannot_be_swallowed() -> Result<(), String> {
    for (case, rows) in matrix() {
        if !rows.iter().any(|row| !row.kind.starts_with("dns-")) {
            continue;
        }
        for fault in [Fault::Internal, Fault::Invert] {
            let result = run_case(case, &rows, "ipv4", ANSWER, fault)?;
            let detail = format!("{case}: {}", result.text());
            assert_eq!(result.status, 2, "{detail}");
            assert!(
                !result.stdout.contains(&format!("CASE {case} END")),
                "{detail}"
            );
        }
    }
    Ok(())
}

pub fn dns_identity_timing_and_answer_oracles() -> Result<(), String> {
    let rows = matrix();
    let lookup = |case: &str| -> Vec<Row> {
        rows.iter()
            .find(|(name, _)| *name == case)
            .map(|(_, rows)| rows.clone())
            .expect("a named case")
    };
    for (case, fault) in [
        ("D1", Fault::SlowDns),
        ("D1", Fault::WrongQuestion),
        ("HC1", Fault::WrongQuestion),
        ("HC1", Fault::EmptyAnswer),
    ] {
        let result = run_case(case, &lookup(case), "ipv4", "", fault)?;
        assert_eq!(result.status, 2, "{case}: {}", result.text());
    }
    let rows = dns(GW, true, "192-168-20-7.sslip.io");
    let result = run_case(
        "RB1",
        &rows,
        "tcp",
        "192-168-20-7.sslip.io",
        Fault::WrongRebindAnswer,
    )?;
    assert_eq!(result.status, 2, "RB1: {}", result.text());
    Ok(())
}

pub fn validation_only_and_unknown_cases_never_succeed() -> Result<(), String> {
    for case in ["RJ1", "shell", "http_get", "unknown"] {
        let result = run_case(case, &[], "ipv4", "", Fault::None)?;
        assert_eq!(result.status, 2, "{case}: {}", result.text());
    }
    let rows = matrix();
    let d1 = rows
        .iter()
        .find(|(name, _)| *name == "D1")
        .expect("D1")
        .1
        .clone();
    let result = run_case("D1", &d1, "unknown", "", Fault::None)?;
    assert_eq!(result.status, 2, "D1/unknown: {}", result.text());
    let result = run_case("RB1", &[], "unknown", "", Fault::None)?;
    assert_eq!(result.status, 2, "RB1/unknown: {}", result.text());
    Ok(())
}

pub fn library_source_is_silent_and_preserves_positionals() -> Result<(), String> {
    let script = format!(
        "set -- one two\nEGRESS_PROBE_LIB=1 . {}\nprintf '%s\\n' \"$@\"\n",
        quote_path(&probe_path())
    );
    let result = run_bounded(&script, &[], Duration::from_secs(5))?;
    assert_eq!(result.status, 0, "{}", result.stderr);
    assert_eq!(result.stdout, "one\ntwo\n");
    Ok(())
}

// --- The generated hook -----------------------------------------------------

/// ADR-0067's project hook, as the launcher sources it, against a receipt
/// listener this side owns. Three events × two hooks: the hook must not leak a
/// `command not found`, must report a denial on HK1, must fail hard on HK2, and
/// must not fail at all when the fixture answers.
pub fn generated_hook_status_matrix() -> Result<(), String> {
    let work = scratch("hook")?;
    let outcome = hook_matrix(&work);
    let _ = fs::remove_dir_all(&work);
    outcome
}

fn hook_matrix(work: &Path) -> Result<(), String> {
    for event in ["denial", "functioning", "internal"] {
        let stop = Arc::new(AtomicBool::new(false));
        let socket = if event == "functioning" {
            Some(egress_fixtures::bind_tcp(0).map_err(|error| error.to_string())?)
        } else {
            None
        };
        let port = match &socket {
            Some(socket) => socket
                .local_addr()
                .map_err(|error| error.to_string())?
                .port(),
            // A kernel-selected port without a listener, rather than a shared
            // fixed one: the denial control must be the only owner of it.
            None => free_port()?,
        };
        let thread = socket.map(|socket| {
            let directory = work.to_path_buf();
            let flag = Arc::clone(&stop);
            thread::spawn(move || {
                let _ = egress_fixtures::serve_tcp(socket, directory, flag);
            })
        });
        let outcome = hook_rows(work, event, port);
        stop.store(true, Ordering::SeqCst);
        if let Some(thread) = thread {
            join_bounded(thread, JOIN_BOUND)?;
        }
        outcome?;
    }
    Ok(())
}

fn hook_rows(work: &Path, event: &str, port: u16) -> Result<(), String> {
    for hook in ["HK1", "HK2"] {
        let ident = if event == "internal" {
            String::new()
        } else {
            format!("{hook}-{event}")
        };
        egress_run::write_hook(work, hook, "127.0.0.1", &ident, port);
        let project = work.join(hook);
        // The launcher's sourcing conditional, followed by the actual configured
        // probe tool (not a mock).
        let script = "set -euo pipefail\n\
                      _hook=\"$PWD/.agent-vm.runtime.sh\"\n\
                      . \"$_hook\" || { rc=$?; echo \"==> .agent-vm.runtime.sh failed (exit $rc)\" >&2; exit \"$rc\"; }\n\
                      exec bash ./egress-probe.sh \"$1\" hook-tool 127.0.0.1 ipv4\n";
        let result = run_in(script, &project, hook)?;
        let expected = if event == "internal" {
            2
        } else if event == "denial" && hook == "HK2" {
            7
        } else {
            0
        };
        let detail = format!("{hook}/{event}: {}", result.text());
        assert_eq!(result.status, expected, "{detail}");
        assert!(
            !result.text().contains("command not found")
                && !result.text().contains("command-not-found"),
            "{detail}"
        );
        assert_eq!(
            result.stdout.contains(&format!("CASE {hook} BEGIN")),
            expected == 0,
            "{detail}"
        );
        assert_eq!(
            result.stdout.contains(&format!("CASE {hook} END")),
            expected == 0,
            "{detail}"
        );
        assert_eq!(
            result.stdout.contains("HOOK_EGRESS_DENIED"),
            event == "denial" && hook == "HK1",
            "{detail}"
        );
        if expected != 0 {
            assert!(
                result
                    .stderr
                    .contains(&format!(".agent-vm.runtime.sh failed (exit {expected})")),
                "{detail}"
            );
        }
        if event == "functioning" {
            assert!(
                result
                    .lines()
                    .contains(&format!("HTTP_OK {ident}").as_str()),
                "{detail}"
            );
            assert_eq!(
                egress_fixtures::wait_for_receipt(work, &ident, Duration::from_millis(500)),
                0,
                "{detail}"
            );
        } else if event == "denial" {
            assert!(
                result
                    .lines()
                    .contains(&format!("HTTP_FAIL {ident}").as_str()),
                "{detail}"
            );
            assert_eq!(
                egress_fixtures::wait_for_receipt(work, &ident, Duration::from_secs(3)),
                1,
                "{detail}"
            );
        }
    }
    Ok(())
}

fn run_in(script: &str, directory: &Path, argument: &str) -> Result<Output, String> {
    let mut command = Command::new("bash");
    command
        .arg("-c")
        .arg(script)
        .arg("hook-launch")
        .arg(argument)
        .current_dir(directory);
    run_command_bounded(command, Duration::from_secs(15))
}

fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|error| error.to_string())?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| error.to_string())
}

fn scratch(label: &str) -> Result<PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let directory = std::env::temp_dir().join(format!(
        "harness-probe-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    Ok(directory)
}

// --- The hostname primitives that do not need Python -------------------------

/// `_hostname_preflight` with a stubbed `PATH`: the probe must refuse a runtime
/// that cannot finish its own probes, instead of silently passing a case.
pub fn preflight_refuses_a_missing_runtime() -> Result<(), String> {
    let root = scratch("preflight")?;
    let outcome = preflight_controls(&root);
    let _ = fs::remove_dir_all(&root);
    outcome
}

fn preflight_controls(root: &Path) -> Result<(), String> {
    let python = root.join("python3");
    let curl = root.join("curl");
    write_executable(&python, "#!/bin/sh\nexit 1\n")?;
    write_executable(&curl, "#!/bin/sh\nexit 0\n")?;
    let path = root.to_string_lossy().into_owned();
    let preflight = |tls: &str| -> Result<Output, String> {
        let script = format!(
            "EGRESS_PROBE_LIB=1 . {}; _hostname_preflight {tls}",
            quote_path(&probe_path())
        );
        let mut command = Command::new("/bin/bash");
        command
            .arg("-c")
            .arg(script)
            .env("PATH", &path)
            .env_remove("SSL_CERT_FILE");
        run_command_bounded(command, Duration::from_secs(10))
    };
    let result = preflight("0")?;
    assert_eq!(result.status, 2, "{}", result.text());
    assert!(
        result.stdout.contains("PREFLIGHT missing=ssl,socket"),
        "{}",
        result.text()
    );
    write_executable(&python, "#!/bin/sh\nexit 0\n")?;
    fs::remove_file(&curl).map_err(|error| error.to_string())?;
    let result = preflight("0")?;
    assert_eq!(result.status, 2, "{}", result.text());
    assert!(
        result.stdout.contains("PREFLIGHT missing=curl"),
        "{}",
        result.text()
    );
    write_executable(&curl, "#!/bin/sh\nexit 0\n")?;
    assert!(
        !Path::new("/.msb/tls/ca.pem").exists(),
        "host-only control requires an absent guest CA"
    );
    let result = preflight("1")?;
    assert_eq!(result.status, 2, "{}", result.text());
    assert!(
        result.stdout.contains("PREFLIGHT missing=ca"),
        "{}",
        result.text()
    );
    let result = preflight("0")?;
    assert_eq!(result.status, 0, "{}", result.text());
    Ok(())
}

fn write_executable(path: &Path, contents: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, contents).map_err(|error| error.to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())
}

/// The zero-provision CA installation is part of the contract, so `https_get`
/// keeps certificate verification and HTTP/1.1.
pub fn https_probe_keeps_verification_and_http1() -> Result<(), String> {
    let result = probe(
        r#"curl() { printf "%s\n" "$@"; }; https_get https://fixture.example/"#,
        "",
        &[],
    )?;
    assert_eq!(result.status, 0, "{}", result.text());
    assert!(result.stdout.contains("--http1.1"), "{}", result.stdout);
    assert!(result.stdout.contains("--max-time"), "{}", result.stdout);
    assert!(
        !result.lines().contains(&"-k"),
        "https_get disabled verification: {}",
        result.stdout
    );
    Ok(())
}

// --- ADR-0066 PA2 -----------------------------------------------------------

/// Drive the real `PA2` dispatch branch with a scripted probe.
///
/// Only `http_get` is stubbed — the three probes' outcomes *are* the script, so
/// the case's own assertions (refused, allowed, refused) and their ordering are
/// what this exercises. The signal files and the wait bound are real.
pub fn live_allowance(work: &Path, routes: &[i32], signals: bool) -> Result<Output, String> {
    for name in PA2_SIGNALS {
        let path = work.join(name);
        if signals {
            fs::write(&path, "").map_err(|error| error.to_string())?;
        } else {
            let _ = fs::remove_file(&path);
        }
    }
    let rc_lines: String = routes.iter().map(|rc| format!("{rc}\n")).collect();
    fs::write(work.join("probe-rcs"), rc_lines).map_err(|error| error.to_string())?;
    fs::write(work.join("probe-count"), "0\n").map_err(|error| error.to_string())?;
    let script = format!(
        "EGRESS_PROBE_LIB=1 . {probe}\n\
         cd {work}\n\
         gateway() {{ echo {GW}; }}\n\
         http_get() {{\n    \
         local n rc\n    \
         n=$(cat probe-count)\n    \
         n=$(( n + 1 ))\n    \
         echo \"$n\" > probe-count\n    \
         rc=$(sed -n \"${{n}}p\" probe-rcs)\n    \
         return \"${{rc:-2}}\"\n\
         }}\n\
         dispatch PA2 attempt_1 {LAN} ipv4 \"\"\n",
        probe = quote_path(&probe_path()),
        work = quote(&work.to_string_lossy()),
    );
    // `_case_live_allowance` opens with the guest preflight, so a stub `python3`
    // stands in for the runtime the guest image ships: this control must not
    // need one on the host.
    let stub = work.join("preflight-bin");
    fs::create_dir_all(&stub).map_err(|error| error.to_string())?;
    write_executable(&stub.join("python3"), "#!/bin/sh\nexit 0\n")?;
    let ambient = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{ambient}", stub.display());
    run_bounded(
        &script,
        &[("PA2_WAIT", "1"), ("PATH", &path)],
        Duration::from_secs(60),
    )
}

pub fn pa2_is_dispatched_and_probes_in_order() -> Result<(), String> {
    let work = scratch("pa2")?;
    let outcome = (|| {
        let result = live_allowance(&work, &[1, 0, 1], true)?;
        let detail = result.text();
        assert_eq!(result.status, 0, "{detail}");
        let observed: Vec<&str> = result
            .lines()
            .into_iter()
            .filter(|line| line.starts_with("PA2"))
            .collect();
        let expected: Vec<&str> = egress_witness::PA2_MARKERS.to_vec();
        assert_eq!(observed, expected, "{detail}");
        assert!(result.stdout.contains("CASE PA2 END"), "{detail}");
        Ok(())
    })();
    let _ = fs::remove_dir_all(&work);
    outcome
}

pub fn pa2_cannot_complete_without_its_signals() -> Result<(), String> {
    let work = scratch("pa2-nosignal")?;
    let outcome = (|| {
        // No host signal ever arrives: the case must fail on its own bounded
        // wait, not hang the harness and not report a transition it never saw.
        let result = live_allowance(&work, &[1, 0, 1], false)?;
        let detail = result.text();
        assert_ne!(result.status, 0, "{detail}");
        assert!(result.stdout.contains("PA2 PROBE 1 DENIED"), "{detail}");
        assert!(
            result.stdout.contains("PA2 FAIL no grant signal within 1s"),
            "{detail}"
        );
        assert!(!result.stdout.contains("PA2 DONE"), "{detail}");
        assert!(!result.stdout.contains("CASE PA2 END"), "{detail}");
        assert!(!result.stdout.contains("PA2 PROBE 2"), "{detail}");
        Ok(())
    })();
    let _ = fs::remove_dir_all(&work);
    outcome
}

pub fn pa2_fails_on_a_policy_that_did_not_change() -> Result<(), String> {
    for (routes, marker) in [
        ([0, 0, 0], "PA2 PROBE 1 UNEXPECTEDLY ALLOWED"),
        ([1, 1, 1], "PA2 PROBE 2 STILL DENIED"),
        ([1, 0, 0], "PA2 PROBE 3 UNEXPECTEDLY ALLOWED"),
    ] {
        let work = scratch("pa2-unchanged")?;
        let outcome: Result<(), String> = (|| {
            let result = live_allowance(&work, &routes, true)?;
            let detail = format!("{routes:?}: {}", result.text());
            assert_eq!(result.status, 2, "{detail}");
            assert!(result.lines().contains(&marker), "{detail}");
            assert!(!result.stdout.contains("PA2 DONE"), "{detail}");
            assert!(!result.stdout.contains("CASE PA2 END"), "{detail}");
            Ok(())
        })();
        let _ = fs::remove_dir_all(&work);
        outcome?;
    }
    Ok(())
}

/// The vocabulary the host witness and the guest probe must agree on, spelled
/// once: a marker or signal renamed on one side only would make the witness wait
/// for something the guest never says.
pub fn pa2_vocabulary_is_shared_with_the_host_witness() -> Result<(), String> {
    let source = fs::read_to_string(probe_path()).map_err(|error| error.to_string())?;
    for marker in egress_witness::PA2_MARKERS {
        assert_eq!(source.matches(marker).count(), 1, "{marker}");
    }
    for name in PA2_SIGNALS {
        assert_eq!(source.matches(name).count(), 1, "{name}");
    }
    // The bound is one number: the probe's default and the witness's deadline.
    assert!(
        source.contains(&format!("PA2_WAIT:-{}", egress_witness::PA2_WAIT_SECONDS)),
        "the probe's default bound and the witness's deadline disagree"
    );
    // A case that is not routed here falls through to `CASE PA2 UNKNOWN`.
    assert!(source.contains("PA2) _case_live_allowance"));
    assert!(!matrix().iter().any(|(case, _)| *case == "PA2"));
    // The host case is declared once, and declares no probe inventory of its
    // own: its evidence is the transition, checked by `check_live_allowance`.
    let declared: Vec<&cases::Case> = cases::CASES
        .iter()
        .filter(|case| case.case == "PA2")
        .collect();
    assert_eq!(declared.len(), 1);
    assert!(
        cases::expected_attempts(declared[0]).is_empty(),
        "PA2 must not declare a probe inventory"
    );
    // The port the PA2 guest probes and the fixture agree on, spelled once.
    assert_eq!(egress_witness::PA2_PROBE_PORT, 18080);
    Ok(())
}

// --- The driver -------------------------------------------------------------

/// Every control, named and separately asserted, in the order the two Python
/// suites ran them.
pub fn self_test() -> Result<(), String> {
    type Control = (&'static str, fn() -> Result<(), String>);
    let controls: [Control; 17] = [
        (
            "http fragmentation, exact body and single connection",
            http_fragmentation_exact_body_and_single_connection,
        ),
        (
            "http_public keep-open and invalid lines",
            http_public_keep_open_and_invalid_lines,
        ),
        (
            "udp one socket, wrong ack, no ack, usage",
            udp_one_socket_wrong_ack_no_ack_and_usage,
        ),
        (
            "dns fragmented, keep-open, NX/OK and invalid frames",
            dns_fragmented_keep_open_nx_ok_and_invalid_frames,
        ),
        (
            "total deadlines: withheld prefix, body, connect, write",
            total_deadlines_withheld_prefix_body_connect_and_write,
        ),
        (
            "dns query encoding and the zero-length datagram",
            dns_query_encoding_and_udp_short_datagram,
        ),
        ("gateway skips IPv6", gateway_skips_ipv6),
        (
            "every named case's endpoint matrix",
            every_named_case_endpoint_matrix,
        ),
        (
            "paired ipv6 and all rebind variants",
            paired_ipv6_and_all_rebind_variants,
        ),
        (
            "network and internal errors cannot be swallowed",
            network_and_internal_errors_cannot_be_swallowed,
        ),
        (
            "dns identity, timing and answer oracles",
            dns_identity_timing_and_answer_oracles,
        ),
        (
            "validation-only and unknown cases never succeed",
            validation_only_and_unknown_cases_never_succeed,
        ),
        (
            "library source is silent and preserves positionals",
            library_source_is_silent_and_preserves_positionals,
        ),
        ("generated hook status matrix", generated_hook_status_matrix),
        (
            "preflight refuses a missing runtime",
            preflight_refuses_a_missing_runtime,
        ),
        (
            "https_get keeps verification and HTTP/1.1",
            https_probe_keeps_verification_and_http1,
        ),
        (
            "PA2 vocabulary is shared with the host witness",
            pa2_vocabulary_is_shared_with_the_host_witness,
        ),
    ];
    for (name, control) in controls {
        control()?;
        println!("ok: {name}");
    }
    pa2_is_dispatched_and_probes_in_order()?;
    println!("ok: PA2 is dispatched and probes in order");
    pa2_cannot_complete_without_its_signals()?;
    println!("ok: PA2 cannot complete without its signals");
    pa2_fails_on_a_policy_that_did_not_change()?;
    println!("ok: PA2 fails on a policy that did not change");
    Ok(())
}

pub fn run(args: EgressProbeArgs) -> Result<crate::Outcome, String> {
    if !args.self_test {
        return Err("usage: egress-probe --self-test".to_owned());
    }
    if let Some(root) = args.repo_root {
        set_repo_root(root)?;
    }
    self_test()?;
    Ok(crate::Outcome::Report(
        "egress probe controls passed: the wire primitives, the dispatcher's endpoint matrix and PA2"
            .to_owned(),
    ))
}

#[derive(Debug, clap::Args)]
pub struct EgressProbeArgs {
    /// Run every control. Each one is also a `cargo test` name.
    #[arg(long)]
    self_test: bool,
    /// Repository root; `CARGO_MANIFEST_DIR/../..` when absent.
    #[arg(long, value_name = "PATH")]
    repo_root: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every control is its own named check, as the Python suite's methods were.
    #[test]
    fn the_http_wire_is_framed_exactly() {
        http_fragmentation_exact_body_and_single_connection().expect("http fragmentation");
        http_public_keep_open_and_invalid_lines().expect("http_public");
    }

    #[test]
    fn the_udp_and_dns_wires_are_framed_exactly() {
        udp_one_socket_wrong_ack_no_ack_and_usage().expect("udp");
        dns_fragmented_keep_open_nx_ok_and_invalid_frames().expect("dns framing");
        dns_query_encoding_and_udp_short_datagram().expect("dns query encoding");
    }

    #[test]
    fn every_probe_deadline_bounds_a_withheld_response() {
        total_deadlines_withheld_prefix_body_connect_and_write().expect("deadlines");
    }

    #[test]
    fn the_gateway_helper_skips_ipv6() {
        gateway_skips_ipv6().expect("gateway");
    }

    #[test]
    fn the_dispatcher_emits_the_endpoint_matrix() {
        every_named_case_endpoint_matrix().expect("matrix");
        paired_ipv6_and_all_rebind_variants().expect("rebind");
    }

    #[test]
    fn the_dispatcher_cannot_swallow_an_error() {
        network_and_internal_errors_cannot_be_swallowed().expect("faults");
        dns_identity_timing_and_answer_oracles().expect("dns oracles");
        validation_only_and_unknown_cases_never_succeed().expect("unknown cases");
    }

    #[test]
    fn sourcing_the_library_changes_nothing() {
        library_source_is_silent_and_preserves_positionals().expect("library sourcing");
    }

    #[test]
    fn the_generated_hook_reports_its_three_events() {
        generated_hook_status_matrix().expect("hook matrix");
    }

    #[test]
    fn the_hostname_primitives_keep_their_refusals() {
        preflight_refuses_a_missing_runtime().expect("preflight");
        https_probe_keeps_verification_and_http1().expect("https_get");
    }

    #[test]
    fn the_pa2_signals_and_bound_are_one_vocabulary() {
        pa2_vocabulary_is_shared_with_the_host_witness().expect("vocabulary");
        pa2_is_dispatched_and_probes_in_order().expect("dispatch");
        pa2_cannot_complete_without_its_signals().expect("bound");
        pa2_fails_on_a_policy_that_did_not_change().expect("unchanged policy");
    }
}
