//! Host-side egress fixtures: the receipt servers, the CONNECT proxy, the
//! TLS/opaque listeners and the small oracles the egress suites read (#692).
//!
//! Ported from `script/test/lib/egress-fixtures.py` and
//! `script/test/lib/egress-hostname-fixtures.py`. This module holds what the
//! boot-free contract and the empty-state driver need without a VM: `serve`,
//! `wait-receipt`, `health`, `resolve`, `exec-shim`, `ingress` and `self-test`.
//! The case catalogue and its JSONL plan live in `egress_cases`, the allowance
//! store in `egress_allowances`, the supervisor (`launch`) in `egress_launch`,
//! the live witnesses in `egress_witness` and `run`'s execution half in
//! `egress_run`; their Python consumers follow in #693-#695.
//!
//! Three behaviours here are load-bearing and easy to get wrong:
//!
//! * A receipt is written with `sync_all`, not just a flush, because a poller in
//!   another process must see the line the moment the fixture answered. A
//!   page-cache-only write would make `wait-receipt` miss what the guest
//!   already got.
//! * Binding never resolves a name. `http.server.HTTPServer.server_bind` filled
//!   `server_name` from `socket.getfqdn("0.0.0.0")`, and a stalled resolver cost
//!   30.089 s on the machine that found it -- past the 5 s a `serve` gives its
//!   listeners, so every case became NOT RUN. Nothing reads a server name, so
//!   the bind keeps the address it bound.
//! * Every read, accept, connect and wait is bounded. A fixture that hangs is
//!   worse than one that fails: it blocks the gate instead of reporting it.
//!
//! `wait-receipt`'s three exit statuses are its interface: 0 as soon as the id
//! is seen, 1 only after the *whole* bound elapses unseen (a denial oracle needs
//! the full bound), 2 on an internal error.

use std::{
    ffi::OsString,
    io::{self, Read, Write},
    net::{
        IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket,
    },
    ops::RangeInclusive,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI32, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use clap::{Args, Subcommand};
use rustix::net::{
    AddressFamily, SocketType, bind as socket_bind, listen as socket_listen, socket,
    sockopt::set_socket_reuseaddr,
};

use crate::{
    Outcome, egress_cases as cases, egress_hostname_fixtures as hostname, egress_launch as launch,
    egress_run,
};

pub const READY_NAME: &str = "ready";
pub const RECEIPTS_NAME: &str = "receipts.log";
pub const PORTS_NAME: &str = "ports.json";

/// The ports the guest probes and this fixture agree on.
pub const TCP_RECEIPT_PORTS: [u16; 2] = [18080, 18081];
pub const UDP_RECEIPT_PORTS: [u16; 2] = [19090, 18080];
pub const PROXY_PORT: u16 = 18888;
/// `(port, kind)` for the TLS/opaque/banner listeners.
pub const HOSTNAME_PORTS: [(u16, hostname::ListenerKind); 4] = [
    (18443, hostname::ListenerKind::Tls),
    (18444, hostname::ListenerKind::Tls),
    (18090, hostname::ListenerKind::Opaque),
    (18091, hostname::ListenerKind::Banner),
];

/// How long `serve` gives its ten listeners to bind before it refuses.
const READINESS_BOUND: Duration = Duration::from_secs(5);
/// How long a `serve` waits between checks for its teardown signal.
const STOP_SLICE: Duration = Duration::from_millis(200);
/// Bound on one health probe's connect, read and write.
const PROBE_BOUND: Duration = Duration::from_millis(500);
/// Bound on one receipt-poll cycle, matching the Python's `time.sleep(0.05)`.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Bound on the bytes one request head may occupy, matching the Python's 8192.
const MAX_REQUEST: usize = 8192;
/// Bound on one tunnel's idle read. The Python set none on the tunnelled
/// sockets; a proxy thread that waits forever is a leak the fixture's own
/// teardown cannot see, so an idle tunnel is closed instead.
const TUNNEL_IDLE: Duration = Duration::from_secs(60);
/// Bound on the upstream connect in a CONNECT tunnel, matching the Python's 5 s.
const UPSTREAM_BOUND: Duration = Duration::from_secs(5);
/// Bound on joining one listener thread during teardown, matching the Python's
/// `thread.join(timeout=4)`.
const JOIN_BOUND: Duration = Duration::from_secs(4);

// --- Receipts ---------------------------------------------------------------

fn receipts_path(directory: &Path) -> PathBuf {
    directory.join(RECEIPTS_NAME)
}

/// Append one receipt line, durably.
///
/// The `sync_all` is the point: a concurrent `wait-receipt` in another process
/// must see the line as soon as the fixture answered, and a page-cache-only
/// write is not visible to a `read` until it lands.
pub fn record_receipt(directory: &Path, line: &str) -> io::Result<()> {
    std::fs::create_dir_all(directory)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(receipts_path(directory))?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.sync_all()
}

/// Whether one already-read receipt line names `id` as a whole field.
///
/// The Python matched `(?:^|\s)ID(?:\s|$)`, so `selftest-tcp` must not match
/// `selftest-tcp-18080`: an id that is a prefix of another id would let a stale
/// receipt certify a probe that never arrived.
fn line_names(line: &str, id: &str) -> bool {
    line.split_whitespace().any(|field| field == id)
}

/// 0 as soon as `id` appears, 1 only after the whole `timeout` elapses unseen,
/// 2 when the log cannot be read.
///
/// The order is check-then-bound, which is what makes `--timeout 0` a useful
/// "is it there yet?" question instead of an unconditional 1.
pub fn wait_for_receipt(directory: &Path, id: &str, timeout: Duration) -> i32 {
    let deadline = Instant::now() + timeout;
    loop {
        let text = match std::fs::read_to_string(receipts_path(directory)) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
            Err(error) => {
                eprintln!("wait-receipt: {error}");
                return 2;
            }
        };
        if text.lines().any(|line| line_names(line, id)) {
            return 0;
        }
        if Instant::now() >= deadline {
            return 1;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

// --- Listeners --------------------------------------------------------------

/// A listening TCP socket with `SO_REUSEADDR` already set.
///
/// `std::net::TcpListener::bind` sets no socket option, and a fixture that is
/// restarted while its previous instance is closing must still be able to bind:
/// a stale `TIME_WAIT` port would otherwise read as "this run has no fixtures".
/// `rustix` is the only place the option can be set before the bind.
pub fn bind_tcp(port: u16) -> io::Result<TcpListener> {
    let fd = socket(AddressFamily::INET, SocketType::STREAM, None)?;
    set_socket_reuseaddr(&fd, true)?;
    socket_bind(
        &fd,
        &SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
    )?;
    socket_listen(&fd, 16)?;
    Ok(TcpListener::from(fd))
}

fn peer_ip(stream: &TcpStream) -> String {
    stream
        .peer_addr()
        .map(|address| address.ip().to_string())
        .unwrap_or_default()
}

fn bound_port(listener: &TcpListener) -> io::Result<u16> {
    Ok(listener.local_addr()?.port())
}

/// Read a request head, bounded in bytes and in time.
fn read_head(stream: &mut TcpStream, bound: Duration) -> io::Result<Vec<u8>> {
    let _ = stream.set_read_timeout(Some(bound));
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") && request.len() < MAX_REQUEST {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
    }
    Ok(request)
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    length: Option<usize>,
    body: &[u8],
) -> io::Result<()> {
    let mut head = format!("HTTP/1.1 {status}\r\n");
    head.push_str(&format!(
        "Content-Length: {}\r\n",
        length.unwrap_or(body.len())
    ));
    head.push_str("Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Handle one receipt-server request.
///
/// `GET /r/<id>` and `HEAD /r/<id>` record `tcp {port} {peer} {id}` and answer
/// 200; every other path is a 404 and records nothing, so a stray request cannot
/// be mistaken for a dial the guest made.
fn serve_receipt_connection(mut stream: TcpStream, directory: &Path, port: u16) {
    let peer = peer_ip(&stream);
    let Ok(request) = read_head(&mut stream, PROBE_BOUND.max(TUNNEL_IDLE)) else {
        return;
    };
    let text = String::from_utf8_lossy(&request);
    let mut first = text.lines().next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default();
    let path = first.next().unwrap_or_default();
    let id = path
        .strip_prefix("/r/")
        .filter(|id| !id.is_empty() && !id.chars().any(char::is_whitespace));
    let Some(id) = id else {
        let _ = respond(&mut stream, "404 Not Found", Some(0), b"");
        return;
    };
    if record_receipt(directory, &format!("tcp {port} {peer} {id}")).is_err() {
        return;
    }
    let body = format!("receipt {id}");
    match method {
        "GET" => {
            let _ = respond(&mut stream, "200 OK", None, body.as_bytes());
        }
        "HEAD" => {
            let _ = respond(&mut stream, "200 OK", Some(0), b"");
        }
        _ => {
            let _ = respond(&mut stream, "404 Not Found", Some(0), b"");
        }
    }
}

/// Accept receipt requests forever, one thread each.
///
/// An accept error ends the loop: it is how a teardown wakes this thread. The
/// Python caught `OSError` and returned for the same reason.
pub fn serve_tcp(
    listener: TcpListener,
    directory: PathBuf,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    let port = bound_port(&listener)?;
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let directory = directory.clone();
                std::thread::spawn(move || serve_receipt_connection(stream, &directory, port));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return Ok(()),
        }
    }
    Ok(())
}

/// Answer one UDP datagram: `id=<id>` records and is acked, anything else is
/// silent. A reply to an unparsable datagram would be a receipt the guest never
/// earned.
fn reply_udp(directory: &Path, socket: &UdpSocket, data: &[u8], peer: SocketAddr) {
    let text = String::from_utf8_lossy(data);
    let Some(id) = text.trim().strip_prefix("id=") else {
        return;
    };
    if id.is_empty() || id.chars().any(char::is_whitespace) {
        return;
    }
    let Ok(port) = socket.local_addr().map(|address| address.port()) else {
        return;
    };
    let receipt = format!("udp {port} {} {id}", peer.ip());
    if record_receipt(directory, &receipt).is_err() {
        return;
    }
    let _ = socket.send_to(format!("ack {id}").as_bytes(), peer);
}

/// Receive UDP receipts until `stop` is set.
///
/// No `SO_REUSEADDR`: two fixtures answering on one port would each record half
/// the dials, and a receipt would then depend on which one answered. The read
/// timeout is the stop seam, and it also bounds every read.
pub fn serve_udp(socket: UdpSocket, directory: PathBuf, stop: Arc<AtomicBool>) -> io::Result<()> {
    socket.set_read_timeout(Some(POLL_INTERVAL))?;
    let mut buffer = [0u8; 512];
    while !stop.load(Ordering::SeqCst) {
        match socket.recv_from(&mut buffer) {
            Ok((read, peer)) => reply_udp(&directory, &socket, &buffer[..read], peer),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Ok(()),
        }
    }
    Ok(())
}

fn pump(mut source: TcpStream, mut sink: TcpStream) {
    let mut buffer = [0u8; 4096];
    loop {
        match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if sink.write_all(&buffer[..read]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = sink.shutdown(Shutdown::Both);
    let _ = source.shutdown(Shutdown::Both);
}

/// Handle one CONNECT request.
///
/// A request that is not `CONNECT host:port HTTP/...` is refused with a 400 and
/// records nothing: the proxy receipt is the evidence that the *guest* asked for
/// that name and port, so it may only be written for a request this code
/// understood.
fn serve_connect(mut conn: TcpStream, directory: &Path) {
    let Ok(request) = read_head(&mut conn, TUNNEL_IDLE) else {
        return;
    };
    let text = String::from_utf8_lossy(&request);
    let target = text
        .strip_prefix("CONNECT ")
        .and_then(|rest| rest.split(' ').next())
        .filter(|target| !target.is_empty());
    let refusal = b"HTTP/1.1 400 Bad Request\r\n\r\n";
    let Some(target) = target else {
        let _ = conn.write_all(refusal);
        return;
    };
    let Some((host, port)) = target.rsplit_once(':') else {
        let _ = conn.write_all(refusal);
        return;
    };
    let Ok(port) = port.parse::<u16>() else {
        let _ = conn.write_all(refusal);
        return;
    };
    let Ok(addresses) = (host, port).to_socket_addrs() else {
        return;
    };
    let Some(address) = addresses.into_iter().next() else {
        return;
    };
    let Ok(upstream) = TcpStream::connect_timeout(&address, UPSTREAM_BOUND) else {
        return;
    };
    if record_receipt(directory, &format!("proxy {target}")).is_err() {
        return;
    }
    if conn
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let _ = conn.set_read_timeout(Some(TUNNEL_IDLE));
    let _ = upstream.set_read_timeout(Some(TUNNEL_IDLE));
    let (Ok(twin), Ok(back)) = (conn.try_clone(), upstream.try_clone()) else {
        return;
    };
    // One direction on its own thread, the other here: cpump the two halves of
    // the tunnel so neither direction waits behind the other.
    let thread = std::thread::spawn(move || pump(twin, back));
    pump(upstream, conn);
    let _ = thread.join();
}

/// Accept CONNECT requests forever, one thread each.
pub fn serve_proxy(
    listener: TcpListener,
    directory: PathBuf,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((conn, _peer)) => {
                let _ = conn.set_nonblocking(false);
                let directory = directory.clone();
                std::thread::spawn(move || serve_connect(conn, &directory));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return Ok(()),
        }
    }
    Ok(())
}

// --- The fixture supervisor -------------------------------------------------

static STOP_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn record_stop(signal: libc::c_int) {
    STOP_SIGNAL.store(signal, Ordering::SeqCst);
}

/// Install the handlers that turn SIGTERM/SIGINT into an orderly `serve` exit.
///
/// `rustix` exposes no signal-handler registration, so `sigaction` comes from
/// `libc` -- the same escape hatch `released_image_launch` and `pty` use. The
/// handler only stores an integer: it may not allocate, lock or unwind.
fn install_stop_handlers() -> io::Result<()> {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = record_stop as *const () as libc::sighandler_t;
        action.sa_flags = 0;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGTERM, libc::SIGINT] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// The six port lists `serve` publishes, in the order the Python wrote them.
#[derive(Debug)]
pub struct FixturePorts {
    pub tcp: Vec<u16>,
    pub udp: Vec<u16>,
    pub proxy: Vec<u16>,
    pub tls: Vec<u16>,
    pub opaque: Vec<u16>,
    pub banner: Vec<u16>,
}

impl FixturePorts {
    /// The `ports.json` body, written by hand rather than by `serde_json` so it
    /// matches `json.dumps` byte for byte: the key order of the Python dict and
    /// its `", "` / `": "` separators. A reader here is a person looking at a
    /// failed case's fixture directory, and an unchanged file is one less
    /// difference to explain.
    pub fn json(&self) -> String {
        let list = |ports: &[u16]| {
            ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!(
            "{{\"tcp\": [{}], \"udp\": [{}], \"proxy\": [{}], \"tls\": [{}], \"opaque\": [{}], \"banner\": [{}]}}",
            list(&self.tcp),
            list(&self.udp),
            list(&self.proxy),
            list(&self.tls),
            list(&self.opaque),
            list(&self.banner)
        )
    }
}

/// Every listener `serve` starts, already bound.
///
/// Binding is separated from accepting so `serve` can publish `ready` only once
/// all ten have bound: a stale port must never satisfy the readiness marker.
pub struct Fixtures {
    directory: PathBuf,
    tcp: Vec<TcpListener>,
    udp: Vec<UdpSocket>,
    proxy: TcpListener,
    hostnames: Vec<(TcpListener, hostname::ListenerKind)>,
}

fn ports_for(fixed: &[u16], ephemeral: bool) -> Vec<u16> {
    fixed
        .iter()
        .map(|port| if ephemeral { 0 } else { *port })
        .collect()
}

fn sorted(ports: impl IntoIterator<Item = u16>) -> Vec<u16> {
    let mut ports: Vec<u16> = ports.into_iter().collect();
    ports.sort_unstable();
    ports
}

impl Fixtures {
    /// Bind all ten listeners. `ephemeral` makes every one bind port 0, which is
    /// how the controls exercise each handler without occupying the ports the
    /// native harness needs.
    pub fn bind(directory: &Path, ephemeral: bool) -> io::Result<Self> {
        let mut tcp = Vec::new();
        for port in ports_for(&TCP_RECEIPT_PORTS, ephemeral) {
            tcp.push(bind_tcp(port)?);
        }
        let mut udp = Vec::new();
        for port in ports_for(&UDP_RECEIPT_PORTS, ephemeral) {
            udp.push(UdpSocket::bind(("0.0.0.0", port))?);
        }
        let proxy = bind_tcp(if ephemeral { 0 } else { PROXY_PORT })?;
        let mut hostnames = Vec::new();
        for (port, kind) in HOSTNAME_PORTS {
            hostnames.push((bind_tcp(if ephemeral { 0 } else { port })?, kind));
        }
        Ok(Self {
            directory: directory.to_path_buf(),
            tcp,
            udp,
            proxy,
            hostnames,
        })
    }

    pub fn ports(&self) -> io::Result<FixturePorts> {
        let mut tls = Vec::new();
        let mut opaque = Vec::new();
        let mut banner = Vec::new();
        for (listener, kind) in &self.hostnames {
            let port = bound_port(listener)?;
            match kind {
                hostname::ListenerKind::Tls => tls.push(port),
                hostname::ListenerKind::Opaque => opaque.push(port),
                hostname::ListenerKind::Banner => banner.push(port),
            }
        }
        Ok(FixturePorts {
            tcp: sorted(
                self.tcp
                    .iter()
                    .map(bound_port)
                    .collect::<io::Result<Vec<_>>>()?,
            ),
            udp: sorted(
                self.udp
                    .iter()
                    .map(|socket| socket.local_addr().map(|address| address.port()))
                    .collect::<io::Result<Vec<_>>>()?,
            ),
            proxy: sorted([bound_port(&self.proxy)?]),
            tls: sorted(tls),
            opaque: sorted(opaque),
            banner: sorted(banner),
        })
    }

    /// Start every listener on its own thread and publish `ports.json` then
    /// `ready`.
    ///
    /// The order matters: `ready` is the promise that everything in
    /// `ports.json` answers, so it is written last. Its content is the start
    /// time in whole seconds, which is what the Python wrote and what a case log
    /// cites.
    pub fn start(self) -> io::Result<RunningFixtures> {
        let ports = self.ports()?;
        std::fs::create_dir_all(&self.directory)?;
        std::fs::write(self.directory.join(PORTS_NAME), ports.json())?;
        let stop = Arc::new(AtomicBool::new(false));
        let record = hostname::recorder({
            let directory = self.directory.clone();
            move |line: &str| {
                let _ = record_receipt(&directory, line);
            }
        });
        let mut threads: Vec<JoinHandle<()>> = Vec::new();
        for listener in self.tcp {
            let directory = self.directory.clone();
            let stop = Arc::clone(&stop);
            threads.push(std::thread::spawn(move || {
                let _ = serve_tcp(listener, directory, stop);
            }));
        }
        for socket in self.udp {
            let directory = self.directory.clone();
            let stop = Arc::clone(&stop);
            threads.push(std::thread::spawn(move || {
                let _ = serve_udp(socket, directory, stop);
            }));
        }
        {
            let directory = self.directory.clone();
            let stop = Arc::clone(&stop);
            threads.push(std::thread::spawn(move || {
                let _ = serve_proxy(self.proxy, directory, stop);
            }));
        }
        for (listener, kind) in self.hostnames {
            let record = Arc::clone(&record);
            let stop = Arc::clone(&stop);
            threads.push(std::thread::spawn(move || {
                let _ = hostname::run(listener, kind, record, stop);
            }));
        }
        let started = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or_default();
        std::fs::write(self.directory.join(READY_NAME), started.to_string())?;
        Ok(RunningFixtures { stop, threads })
    }
}

/// A started fixture cluster: what a teardown needs and nothing else.
pub struct RunningFixtures {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl RunningFixtures {
    /// Stop every listener thread, bounded.
    ///
    /// Every loop re-checks `stop` within one poll interval, so setting it is the
    /// whole teardown. A thread still alive after the bound is a hang, and
    /// reporting it instead of waiting for it is the point of joining at all.
    pub fn stop(self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        for thread in self.threads {
            let deadline = Instant::now() + JOIN_BOUND;
            while !thread.is_finished() {
                if Instant::now() >= deadline {
                    return Err("self-test fixture did not stop".to_owned());
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            let _ = thread.join();
        }
        Ok(())
    }
}

/// `serve`: bind every listener, publish readiness, then wait to be told to stop.
///
/// Returns 0 for SIGTERM or SIGINT. The listener threads are not joined: they
/// are daemon threads in the Python too, and a fixture that is asked to stop has
/// already answered everything the case needed.
pub fn serve(directory: &Path, ephemeral: bool) -> Result<i32, String> {
    std::fs::create_dir_all(directory).map_err(|error| format!("serve: {error}"))?;
    let bound = Instant::now();
    let fixtures = match Fixtures::bind(directory, ephemeral) {
        Ok(fixtures) => fixtures,
        Err(error) => return Err(format!("serve: listeners failed to bind: {error}")),
    };
    if bound.elapsed() > READINESS_BOUND {
        return Err("serve: listeners failed to bind in time".to_owned());
    }
    install_stop_handlers().map_err(|error| format!("serve: {error}"))?;
    STOP_SIGNAL.store(0, Ordering::SeqCst);
    let running = fixtures
        .start()
        .map_err(|error| format!("serve: {error}"))?;
    let _ = running;
    while STOP_SIGNAL.load(Ordering::SeqCst) == 0 {
        std::thread::sleep(STOP_SLICE);
    }
    Ok(0)
}

// --- The launch environment -------------------------------------------------

/// The environment every fixtured launch replaces its own with.
///
/// The launch helpers hand this to `exec-shim`, which *replaces* the
/// environment: a variable the harness happens to carry (a token, a proxy, a
/// different state directory) must not reach a deny row. `AGENT_VM_SHARE_MSB_CACHE=0`
/// keeps the shared microsandbox cache out of a private-state run.
pub fn base_environment(work: &Path) -> Vec<(String, String)> {
    [
        ("HOME", work.join("home")),
        ("XDG_CONFIG_HOME", work.join("config")),
        ("AGENT_VM_STATE_DIR", work.join("state")),
        ("PATH", PathBuf::from("/usr/bin:/bin")),
        ("TERM", PathBuf::from("dumb")),
        ("AGENT_VM_SHARE_MSB_CACHE", PathBuf::from("0")),
        // No real banner: a desktop run would post one, and the notifications-off
        // line could then land in exact-byte terminal evidence.
        ("AGENT_VM_NO_NOTIFICATIONS", PathBuf::from("1")),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.to_string_lossy().into_owned()))
    .collect()
}

// --- Health -----------------------------------------------------------------

/// Read a whole HTTP response, bounded in bytes and in time.
fn read_response(stream: &mut TcpStream, bound: Duration) -> io::Result<Vec<u8>> {
    let _ = stream.set_read_timeout(Some(bound));
    let mut response = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(response),
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                return Ok(response);
            }
            Err(error) => return Err(error),
        }
        if response.len() > MAX_REQUEST {
            return Ok(response);
        }
    }
}

/// The status code and body of one response, when it is HTTP at all.
fn status_and_body(response: &[u8]) -> Option<(u16, String)> {
    let text = String::from_utf8_lossy(response);
    let status = text
        .lines()
        .next()?
        .split(' ')
        .nth(1)?
        .parse::<u16>()
        .ok()?;
    let body = text.split_once("\r\n\r\n").map(|(_, body)| body)?;
    Some((status, body.to_owned()))
}

/// `health --dir DIR`: 0 when every listener answers and records, 1 otherwise.
///
/// The probe id carries the clock in nanoseconds, so a receipt from an earlier
/// run of this same check cannot satisfy it.
pub fn health(directory: &Path) -> i32 {
    if !directory.join(READY_NAME).is_file() {
        return 1;
    }
    let Ok(text) = std::fs::read_to_string(directory.join(PORTS_NAME)) else {
        return 1;
    };
    let Ok(ports) = serde_json::from_str::<serde_json::Value>(&text) else {
        return 1;
    };
    let Some(lists) = parse_ports(&ports) else {
        return 1;
    };
    let ident = format!("health-{}", monotonic_nanos());
    for port in &lists.tcp {
        if probe_http(*port, &format!("{ident}-{port}"), PROBE_BOUND) != 0 {
            return 1;
        }
    }
    for port in &lists.udp {
        if probe_udp(*port, &format!("{ident}-{port}")) != 0 {
            return 1;
        }
    }
    if probe_proxy(&lists) != 0 {
        return 1;
    }
    if wait_for_receipt(directory, &format!("{ident}-{}", lists.tcp[0]), PROBE_BOUND) == 0 {
        0
    } else {
        1
    }
}

struct HealthPorts {
    tcp: Vec<u16>,
    udp: Vec<u16>,
    proxy: u16,
}

/// The five ports `health` insists on: two tcp, two udp and one proxy, each in
/// 1..=65535. A shorter list, or a port 0, means the fixture never bound.
fn parse_ports(ports: &serde_json::Value) -> Option<HealthPorts> {
    let valid: RangeInclusive<u16> = 1..=65535;
    let list = |name: &str, count: usize| -> Option<Vec<u16>> {
        let rows = ports.get(name)?.as_array()?;
        if rows.len() != count {
            return None;
        }
        rows.iter()
            .map(|row| row.as_u64().and_then(|port| u16::try_from(port).ok()))
            .map(|port| port.filter(|port| valid.contains(port)))
            .collect()
    };
    Some(HealthPorts {
        tcp: list("tcp", 2)?,
        udp: list("udp", 2)?,
        proxy: list("proxy", 1)?.into_iter().next()?,
    })
}

pub(crate) fn monotonic_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or_default()
}

fn connect(port: u16) -> io::Result<TcpStream> {
    TcpStream::connect_timeout(
        &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        PROBE_BOUND,
    )
}

fn probe_http(port: u16, id: &str, bound: Duration) -> i32 {
    let Ok(mut stream) = connect(port) else {
        return 1;
    };
    let _ = stream.set_write_timeout(Some(bound));
    let request = format!("GET /r/{id} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return 1;
    }
    let Ok(response) = read_response(&mut stream, bound) else {
        return 1;
    };
    match status_and_body(&response) {
        Some((200, body)) if body == format!("receipt {id}") => 0,
        _ => 1,
    }
}

fn probe_udp(port: u16, id: &str) -> i32 {
    let Ok(socket) = UdpSocket::bind(("127.0.0.1", 0)) else {
        return 1;
    };
    if socket.set_read_timeout(Some(PROBE_BOUND)).is_err() {
        return 1;
    }
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    if socket
        .send_to(format!("id={id}").as_bytes(), target)
        .is_err()
    {
        return 1;
    }
    let mut buffer = [0u8; 512];
    match socket.recv_from(&mut buffer) {
        Ok((read, _)) if buffer[..read] == *format!("ack {id}").as_bytes() => 0,
        _ => 1,
    }
}

/// Ask the proxy for one tunnel to the first receipt port and require the 200.
fn probe_proxy(lists: &HealthPorts) -> i32 {
    let Ok(mut stream) = connect(lists.proxy) else {
        return 1;
    };
    let _ = stream.set_write_timeout(Some(PROBE_BOUND));
    let request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        lists.tcp[0]
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return 1;
    }
    let Ok(head) = read_head(&mut stream, PROBE_BOUND) else {
        return 1;
    };
    if head.starts_with(b"HTTP/1.1 200 ") {
        0
    } else {
        1
    }
}

// --- Resolver ---------------------------------------------------------------

/// `resolve NAME ADDRESS`: report the system resolver's IPv4 answer for `name`
/// and whether `address` is among them.
///
/// The answer is printed either way, because a failing calibration step is
/// diagnosed from what the resolver *did* say.
pub fn resolve(name: &str, address: &str) -> Result<i32, String> {
    let mut addresses: Vec<String> = (name, 80u16)
        .to_socket_addrs()
        .map_err(|error| format!("resolve: {name}: {error}"))?
        .filter(|resolved| resolved.is_ipv4())
        .map(|resolved| resolved.ip().to_string())
        .collect();
    addresses.sort();
    addresses.dedup();
    let found = addresses.iter().any(|resolved| resolved == address);
    println!(
        "{}",
        serde_json::json!({"name": name, "addresses": addresses})
    );
    Ok(if found { 0 } else { 1 })
}

// --- The launch shim --------------------------------------------------------

/// A process's start-time identity: `(seconds, microseconds)`.
///
/// `None` means absent or a zombie, which is what a supervisor may act on.
/// A lookup *error* is never absence evidence: a caller that read it that way
/// would report a live process as gone and leave a session behind.
pub fn process_identity(pid: u32) -> Result<Option<[u64; 2]>, String> {
    if pid == 0 {
        return Err("invalid owned PID".to_owned());
    }
    platform_identity(pid)
}

#[cfg(target_os = "linux")]
fn platform_identity(pid: u32) -> Result<Option<[u64; 2]>, String> {
    let path = format!("/proc/{pid}/stat");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{path}: {error}")),
    };
    // Everything after the command name, which may itself contain a `)`.
    let tail = text.rsplit_once(')').map(|(_, tail)| tail).unwrap_or("");
    let fields: Vec<&str> = tail.split_whitespace().collect();
    if matches!(fields.first(), Some(&"Z" | &"X" | &"x")) {
        return Ok(None);
    }
    let start = fields
        .get(19)
        .ok_or_else(|| format!("{path}: truncated stat"))?;
    start
        .parse::<u64>()
        .map(|start| Some([start, 0]))
        .map_err(|error| format!("{path}: {error}"))
}

#[cfg(target_os = "macos")]
fn platform_identity(pid: u32) -> Result<Option<[u64; 2]>, String> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let count = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            3, // PROC_PIDTBSDINFO
            0,
            std::ptr::from_mut(&mut info).cast(),
            size,
        )
    };
    if count != size {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ESRCH) | Some(libc::ENOENT) => Ok(None),
            _ => Err(format!(
                "proc_pidinfo could not establish identity: {error}"
            )),
        };
    }
    if info.pbi_pid != pid {
        return Err("libproc PID mismatch".to_owned());
    }
    if info.pbi_status == 5 {
        // SZOMB
        return Ok(None);
    }
    Ok(Some([info.pbi_start_tvsec, info.pbi_start_tvusec]))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_identity(_pid: u32) -> Result<Option<[u64; 2]>, String> {
    Err("unsupported native identity adapter".to_owned())
}

/// Signal one owned process, refusing when the pid has been recycled.
///
/// Returns whether a signal was delivered: `false` means the process was already
/// gone, which is not an error, and `Err` means the caller asked to signal a
/// different process than the one it recorded.
pub fn signal_identity(identity: &serde_json::Value, signal: i32) -> Result<bool, String> {
    let pid = identity
        .get("pid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
        .ok_or("identity has no PID")?;
    let recorded: [u64; 2] = {
        let start = identity
            .get("start")
            .and_then(serde_json::Value::as_array)
            .ok_or("identity has no start time")?;
        let mut pair = [0u64; 2];
        for (slot, value) in pair.iter_mut().zip(start) {
            *slot = value
                .as_u64()
                .ok_or("identity start time is not a number")?;
        }
        pair
    };
    let Some(current) = process_identity(pid)? else {
        return Ok(false);
    };
    if current != recorded {
        return Err(format!("PID reuse: refusing signal to {pid}"));
    }
    // `kill(2)` through `libc`: `rustix` takes a `Signal`, and this entry point
    // is handed a number from a JSON receipt, so a `Signal` conversion would
    // only add a step that can disagree with the caller's intent.
    if unsafe { libc::kill(pid as libc::pid_t, signal) } != 0 {
        return Err(format!(
            "cannot signal {pid}: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(true)
}

/// `exec-shim`: record this process's identity, point its stdio at the case log
/// and exec the candidate.
///
/// The identity is written *before* the exec, so even a launch the candidate
/// refuses to start has an ownership receipt and can be reaped. The environment
/// is replaced, not extended: a shim that inherited the harness's own
/// environment could leak a variable into a deny row.
pub fn exec_shim(
    identity_file: Option<&Path>,
    output: &Path,
    argv: &[OsString],
    environment: &serde_json::Map<String, serde_json::Value>,
) -> Result<Outcome, String> {
    if let Some(path) = identity_file {
        let pid = std::process::id();
        let identity = serde_json::json!({
            "pid": pid,
            "start": process_identity(pid)?,
            "pgid": pgid()?,
        });
        std::fs::write(path, identity.to_string())
            .map_err(|error| format!("exec-shim: {path:?}: {error}"))?;
    }
    use std::os::fd::AsFd;
    let devnull =
        std::fs::File::open("/dev/null").map_err(|error| format!("exec-shim: {error}"))?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(output)
        .map_err(|error| format!("exec-shim: {output:?}: {error}"))?;
    rustix::stdio::dup2_stdin(devnull.as_fd()).map_err(|error| format!("exec-shim: {error}"))?;
    rustix::stdio::dup2_stdout(log.as_fd()).map_err(|error| format!("exec-shim: {error}"))?;
    rustix::stdio::dup2_stderr(log.as_fd()).map_err(|error| format!("exec-shim: {error}"))?;
    let Some(program) = argv.first() else {
        return Err("exec-shim: no program".to_owned());
    };
    let program = std::ffi::CString::new(program.as_encoded_bytes())
        .map_err(|_| "exec-shim: the program name contains a NUL".to_owned())?;
    let mut arguments: Vec<std::ffi::CString> = Vec::with_capacity(argv.len());
    for argument in argv {
        arguments.push(
            std::ffi::CString::new(argument.as_encoded_bytes())
                .map_err(|_| "exec-shim: an argument contains a NUL".to_owned())?,
        );
    }
    // `execve` wants `name=value` strings; keep the owned bodies alive in
    // `pairs` so the pointer array below cannot dangle before the call.
    let mut pairs: Vec<std::ffi::CString> = Vec::with_capacity(environment.len());
    for (name, value) in environment {
        let Some(value) = value.as_str() else {
            return Err(format!("exec-shim: {name} is not a string"));
        };
        pairs.push(
            std::ffi::CString::new(format!("{name}={value}"))
                .map_err(|_| format!("exec-shim: {name} contains a NUL"))?,
        );
    }
    let mut argument_pointers: Vec<*const libc::c_char> =
        arguments.iter().map(|argument| argument.as_ptr()).collect();
    argument_pointers.push(std::ptr::null());
    let mut environment_pointers: Vec<*const libc::c_char> =
        pairs.iter().map(|pair| pair.as_ptr()).collect();
    environment_pointers.push(std::ptr::null());
    unsafe {
        libc::execve(
            program.as_ptr(),
            argument_pointers.as_ptr(),
            environment_pointers.as_ptr(),
        );
    }
    Err(format!(
        "exec-shim: cannot exec {program:?}: {}",
        io::Error::last_os_error()
    ))
}

fn pgid() -> Result<u32, String> {
    let pgid = rustix::process::getpgrp();
    u32::try_from(pgid.as_raw_nonzero().get()).map_err(|error| format!("exec-shim: {error}"))
}

// --- CLI --------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct EgressFixturesArgs {
    #[command(subcommand)]
    command: EgressCommand,
}

#[derive(Debug, Subcommand)]
enum EgressCommand {
    /// Serve the receipt, proxy and TLS fixtures and record what each one sees.
    Serve(ServeArgs),
    /// Wait for an exact receipt id, distinguishing "not yet" from "never".
    WaitReceipt(WaitReceiptArgs),
    /// Ask the fixture cluster whether every listener still answers.
    Health(HealthArgs),
    /// Wait for a published guest port, then join its body against the case id.
    Ingress(IngressArgs),
    /// Launch a candidate in its own private state and clean it up afterwards.
    Launch(LaunchArgs),
    /// Report the system resolver's IPv4 answer for one name.
    Resolve(ResolveArgs),
    /// Record a launch's identity, redirect its stdio, then exec it.
    ExecShim(ExecShimArgs),
    /// The egress sweep: its JSONL plan today, its execution half next.
    Run(RunArgs),
    /// Run the boot-free fixture controls.
    SelfTest,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Print the JSONL plan instead of running anything.
    #[arg(long)]
    print_plan: bool,
    /// The numeric subset the readiness sweep runs.
    #[arg(long)]
    smoke: bool,
    #[arg(long)]
    work: Option<PathBuf>,
    /// The candidate binary; `AGENT_VM_BIN` when the flag is absent.
    #[arg(long)]
    binary: Option<String>,
    /// The release assets; `AGENT_VM_E2E_RELEASE_ASSETS_DIR` when absent.
    #[arg(long)]
    assets: Option<String>,
    /// The fixture LAN address; `AGENT_VM_EGRESS_LAN` when absent.
    #[arg(long)]
    lan: Option<String>,
    /// A name the system resolver maps into the LAN; `AGENT_VM_EGRESS_REBIND_NAME`.
    #[arg(long)]
    rebind: Option<String>,
    /// A second test-owned address; `AGENT_VM_EGRESS_LAN2`.
    #[arg(long)]
    lan2: Option<String>,
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Directory for `receipts.log`, `ports.json` and `ready`.
    #[arg(long)]
    dir: PathBuf,
    /// Accepted for call-site parity; the DNS fixture that would use it is not
    /// wired into the supervisor (see the ladder's step (c)).
    #[arg(long, default_value = "")]
    lan: String,
    /// Bind every listener on port 0.
    #[arg(long)]
    ephemeral_ports: bool,
}

#[derive(Debug, Args)]
struct WaitReceiptArgs {
    #[arg(long)]
    dir: PathBuf,
    id: String,
    #[arg(long, default_value_t = 3.0)]
    timeout: f64,
}

#[derive(Debug, Args)]
struct LaunchArgs {
    /// The work directory: `state/`, the project and the receipts live here.
    #[arg(long)]
    work: PathBuf,
    #[arg(long)]
    case: String,
    #[arg(long, default_value_t = 300.0)]
    timeout: f64,
    #[arg(long, default_value_t = 10.0)]
    grace: f64,
    /// A permitted environment extra: the proxy variables for `PX*`, the floor
    /// config for `FL*`, nothing else.
    #[arg(long = "env", value_name = "K=V")]
    envs: Vec<String>,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    argv: Vec<OsString>,
}

#[derive(Debug, Args)]
struct IngressArgs {
    #[arg(long)]
    work: PathBuf,
    #[arg(long)]
    case: String,
    #[arg(long)]
    id: String,
}

#[derive(Debug, Args)]
struct HealthArgs {
    #[arg(long)]
    dir: PathBuf,
}

#[derive(Debug, Args)]
struct ResolveArgs {
    name: String,
    address: String,
}

#[derive(Debug, Args)]
struct ExecShimArgs {
    #[arg(long)]
    identity: Option<PathBuf>,
    /// The replacement environment, as a JSON object of strings.
    #[arg(long)]
    environment: String,
    #[arg(long)]
    output: PathBuf,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    argv: Vec<OsString>,
}

/// A wait bound. `Duration` cannot hold a negative or non-finite value, and the
/// Python's `--timeout inf` would have waited forever; refusing both is the one
/// deliberate difference here, because a fixture that hangs blocks the gate.
fn seconds(value: f64, name: &str) -> Result<Duration, String> {
    if !value.is_finite() || value < 0.0 {
        return Err(format!(
            "usage: {name} must be a finite, non-negative number of seconds"
        ));
    }
    Ok(Duration::from_secs_f64(value))
}

pub fn run(args: EgressFixturesArgs) -> Result<Outcome, String> {
    match args.command {
        EgressCommand::Serve(args) => {
            let status = serve(&args.dir, args.ephemeral_ports)?;
            Ok(Outcome::Exit(status))
        }
        EgressCommand::WaitReceipt(args) => {
            let timeout = seconds(args.timeout, "--timeout")?;
            Ok(Outcome::Exit(wait_for_receipt(
                &args.dir, &args.id, timeout,
            )))
        }
        EgressCommand::Health(args) => Ok(Outcome::Exit(health(&args.dir))),
        EgressCommand::Launch(args) => {
            // `argparse.REMAINDER` kept the separator and the Python dropped it;
            // clap drops it too, but a caller that passes two must not shift the
            // candidate's own arguments.
            let argv = match args.argv.split_first() {
                Some((first, rest)) if first == "--" => rest.to_vec(),
                _ => args.argv.clone(),
            };
            let argv: Vec<String> = argv
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect();
            Ok(Outcome::Exit(launch::launch(
                &args.work,
                &args.case,
                args.timeout,
                args.grace,
                &args.envs,
                &argv,
            )?))
        }
        EgressCommand::Ingress(args) => Ok(Outcome::Exit(cases::ingress_driver(
            &args.work, &args.case, &args.id, None,
        )?)),
        EgressCommand::Resolve(args) => Ok(Outcome::Exit(resolve(&args.name, &args.address)?)),
        EgressCommand::ExecShim(args) => {
            let environment = serde_json::from_str::<serde_json::Value>(&args.environment)
                .map_err(|error| format!("exec-shim: --environment: {error}"))?;
            let serde_json::Value::Object(environment) = environment else {
                return Err("exec-shim: --environment must be a JSON object".to_owned());
            };
            exec_shim(
                args.identity.as_deref(),
                &args.output,
                &args.argv,
                &environment,
            )
        }
        EgressCommand::Run(args) => run_plan(args),
        EgressCommand::SelfTest => {
            self_test()?;
            Ok(Outcome::Exit(0))
        }
    }
}

/// `run`: the JSONL plan, or the sweep that executes it.
///
/// `--print-plan` comes first and takes the Python's defaults, because the plan is
/// what the boot-free §6.7 join reads: it must be printable on a host with no
/// candidate, no assets and no fixture LAN. The execution half has no such
/// defaults — an absolute binary, the release assets and a fixture LAN are
/// required, and a run that guessed them would be a run against the wrong
/// candidate.
fn run_plan(args: RunArgs) -> Result<Outcome, String> {
    let environment = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    if args.print_plan {
        let work = args
            .work
            .unwrap_or_else(|| PathBuf::from("/var/tmp/av302.PLAN"));
        let binary = args
            .binary
            .or_else(|| environment("AGENT_VM_BIN"))
            .unwrap_or_else(|| "/absolute/bundle/bin/agent-vm".to_owned());
        let lan = args
            .lan
            .or_else(|| environment("AGENT_VM_EGRESS_LAN"))
            .unwrap_or_else(|| "192.168.1.2".to_owned());
        return Ok(Outcome::Report(cases::print_plan(
            &work, &binary, &lan, args.smoke,
        )));
    }
    let request = egress_run::RunRequest {
        binary: args
            .binary
            .or_else(|| environment("AGENT_VM_BIN"))
            .unwrap_or_default(),
        assets: args
            .assets
            .or_else(|| environment("AGENT_VM_E2E_RELEASE_ASSETS_DIR"))
            .unwrap_or_default(),
        lan: args
            .lan
            .or_else(|| environment("AGENT_VM_EGRESS_LAN"))
            .unwrap_or_default(),
        rebind: args
            .rebind
            .or_else(|| environment("AGENT_VM_EGRESS_REBIND_NAME")),
        lan2: args.lan2.or_else(|| environment("AGENT_VM_EGRESS_LAN2")),
        smoke: args.smoke,
    };
    Ok(Outcome::Exit(egress_run::orchestrate(&request)?))
}

// --- Controls ---------------------------------------------------------------

/// The boot-free fixture controls.
///
/// Three blocks of the Python's `self_test` live here: the receipt listeners with
/// their absence bound, the HN/OP completion gate, and -- through
/// `egress_cases::default_request_self_test` -- the default-request diagnostic
/// mutants, which need the case catalogue.
pub fn self_test() -> Result<(), String> {
    hostname::self_test();
    cases::default_request_self_test()?;
    receipt_self_test()?;
    println!("self-test: both TCP, both UDP, CONNECT and full 3s absence OK");
    gate_self_test();
    println!("self-test: HN/OP gate and outcome-(d) wording OK");
    Ok(())
}

fn receipt_self_test() -> Result<(), String> {
    let directory = std::env::temp_dir().join(format!("harness-egress-{}", monotonic_nanos()));
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let fixtures = Fixtures::bind(&directory, true).map_err(|error| error.to_string())?;
    let ports = fixtures.ports().map_err(|error| error.to_string())?;
    let running = fixtures.start().map_err(|error| error.to_string())?;
    let outcome = receipt_self_test_against(&directory, &ports);
    // Teardown runs even when a control failed: a panic here must not leave ten
    // listeners behind for the next check.
    let stopped = running.stop();
    let _ = std::fs::remove_dir_all(&directory);
    outcome?;
    stopped
}

fn receipt_self_test_against(directory: &Path, ports: &FixturePorts) -> Result<(), String> {
    // Each fixed listener's handler, on an ephemeral port: the native ports stay
    // free and no stale external service can answer as evidence.
    for (index, port) in ports.tcp.iter().enumerate() {
        let ident = format!("selftest-tcp-{}", TCP_RECEIPT_PORTS[index]);
        assert_eq!(
            probe_http(*port, &ident, JOIN_BOUND),
            0,
            "TCP receipt: {ident}"
        );
        assert_eq!(
            wait_for_receipt(directory, &ident, PROBE_BOUND),
            0,
            "TCP receipt was not recorded: {ident}"
        );
    }
    for (index, port) in ports.udp.iter().enumerate() {
        let ident = format!("selftest-udp-{}", UDP_RECEIPT_PORTS[index]);
        assert_eq!(probe_udp(*port, &ident), 0, "UDP receipt: {ident}");
        assert_eq!(
            wait_for_receipt(directory, &ident, PROBE_BOUND),
            0,
            "UDP receipt was not recorded: {ident}"
        );
    }
    assert_eq!(
        probe_http_through_proxy(ports.proxy[0], ports.tcp[0], "selftest-proxy"),
        0
    );
    assert_eq!(
        wait_for_receipt(directory, "selftest-proxy", PROBE_BOUND),
        0,
        "the tunnelled receipt was not recorded"
    );
    let receipts = std::fs::read_to_string(receipts_path(directory)).unwrap_or_default();
    assert!(
        receipts
            .lines()
            .any(|line| line == format!("proxy 127.0.0.1:{}", ports.tcp[0])),
        "the proxy did not record its target: {receipts}"
    );
    let started = Instant::now();
    assert_eq!(
        wait_for_receipt(directory, "selftest-never", READINESS_BOUND.mul_f32(0.6)),
        1
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(3) && elapsed <= Duration::from_millis(3500),
        "absence bound: {elapsed:?}"
    );
    // An id that is a prefix of a recorded one must not match: that is what
    // separates "wait-receipt saw it" from "something similar was there".
    assert_eq!(
        wait_for_receipt(directory, "selftest-tcp", Duration::ZERO),
        1,
        "an ID prefix matched"
    );
    Ok(())
}

fn probe_http_through_proxy(proxy: u16, target: u16, id: &str) -> i32 {
    let Ok(mut stream) = connect(proxy) else {
        return 1;
    };
    let _ = stream.set_write_timeout(Some(JOIN_BOUND));
    let connect = format!("CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    if stream.write_all(connect.as_bytes()).is_err() {
        return 1;
    }
    let Ok(head) = read_head(&mut stream, JOIN_BOUND) else {
        return 1;
    };
    if !head.starts_with(b"HTTP/1.1 200 ") {
        return 1;
    }
    let request = format!("GET /r/{id} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return 1;
    }
    let Ok(response) = read_response(&mut stream, JOIN_BOUND) else {
        return 1;
    };
    match status_and_body(&response) {
        Some((200, body)) if body == format!("receipt {id}") => 0,
        _ => 1,
    }
}

/// One row of the HN/OP completion gate.
pub struct GateResult {
    pub case: &'static str,
    pub status: &'static str,
}

/// ADR-0037 / plan §7.5: the HN rows gate only once HNc calibrated.
pub const HN_GATE_CASES: [&str; 7] = ["HN1", "HN2", "HN3", "HN4", "HN5", "HN5c", "HN6"];
/// The OP rows need no DNS lookup or private-answer admission, so they gate
/// whatever the ladder did.
const OP_GATE_CASES: [&str; 6] = ["OP1", "OP1c", "OP2", "OP2c", "OP3", "OP3c"];

pub const OUTCOME_D: &str = "HNc failed on every available ladder step (outcome (d): the name x port \
matrix has NO native evidence in this environment)";
pub const HNC_STEP_C_REASON: &str = "not implemented: the <lan>:53 DNS fixture (serve_dns) is not \
wired into the fixture supervisor; it also needs operator approval for a privileged bind";
pub const HOSTNAME_PROXY_REFUSAL: &str = "hostname allowances cannot be enforced through the host \
HTTP proxy (HTTPS_PROXY/HTTP_PROXY/ALL_PROXY): the proxy resolves the name, so the address scope \
is not checked; unset the proxy, use an IP/CIDR allowance, or use --allow-internet-egress";

/// The blocking HN/OP rows, given the ladder step HNc calibrated with.
///
/// Step (b) is `--allow-lan`, which authorizes the LAN address-wide: it is
/// diagnostic and cannot support deny evidence, so it neither certifies nor
/// gates an HN row. With no successful step, outcome (d) records that the name x
/// port matrix has no native evidence here and the HN NOT RUN rows are expected.
pub fn hostname_gate(hnc_step: Option<char>, results: &[GateResult]) -> (bool, Vec<String>) {
    let calibrated = matches!(hnc_step, Some('a' | 'c'));
    let blockers: Vec<String> = results
        .iter()
        .filter(|result| result.status != "PASS")
        .filter(|result| {
            OP_GATE_CASES.contains(&result.case)
                || (calibrated && HN_GATE_CASES.contains(&result.case))
        })
        .map(|result| format!("{}:{}", result.case, result.status))
        .collect();
    (!blockers.is_empty(), blockers)
}

fn gate_self_test() {
    let row = |case: &'static str, status: &'static str| GateResult { case, status };
    assert_eq!(
        hostname_gate(Some('a'), &[row("HN1", "NOT RUN")]),
        (true, vec!["HN1:NOT RUN".to_owned()])
    );
    assert_eq!(
        hostname_gate(Some('c'), &[row("OP3", "FAIL"), row("HN5", "PASS")]),
        (true, vec!["OP3:FAIL".to_owned()])
    );
    assert_eq!(
        hostname_gate(Some('a'), &[row("HN1", "PASS"), row("HP1", "NOT RUN")]),
        (false, Vec::new())
    );
    // (b) is diagnostic only: it can neither certify nor gate an HN deny row.
    assert_eq!(
        hostname_gate(Some('b'), &[row("HN1", "NOT RUN")]),
        (false, Vec::new())
    );
    // (d): no non-confounding calibration, so HN NOT RUN is allowed.
    assert_eq!(
        hostname_gate(None, &[row("HN1", "NOT RUN")]),
        (false, Vec::new())
    );
    // The OP rows are always gated: a NOT RUN blocks whatever the ladder step.
    assert_eq!(
        hostname_gate(None, &[row("OP1", "NOT RUN")]),
        (true, vec!["OP1:NOT RUN".to_owned()])
    );
    assert_eq!(
        hostname_gate(Some('b'), &[row("OP2c", "NOT RUN"), row("HN1", "NOT RUN")]),
        (true, vec!["OP2c:NOT RUN".to_owned()])
    );
    assert!(OUTCOME_D.contains("outcome (d)") && OUTCOME_D.contains("NO native evidence"));
    assert!(
        HNC_STEP_C_REASON.contains("not implemented") && HNC_STEP_C_REASON.contains("serve_dns")
    );
    assert!(HOSTNAME_PROXY_REFUSAL.contains("hostname allowances cannot be enforced"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("harness-{name}-{}", monotonic_nanos()));
        std::fs::create_dir_all(&path).expect("a scratch directory");
        path
    }

    #[test]
    fn an_id_is_matched_as_a_whole_field_only() {
        assert!(line_names(
            "tcp 18080 127.0.0.1 selftest-tcp-18080",
            "selftest-tcp-18080"
        ));
        assert!(!line_names(
            "tcp 18080 127.0.0.1 selftest-tcp-18080",
            "selftest-tcp"
        ));
        assert!(!line_names(
            "tcp 18080 127.0.0.1 xselftest-tcp-18080x",
            "selftest-tcp-18080"
        ));
        assert!(line_names("proxy 127.0.0.1:18080", "127.0.0.1:18080"));
        assert!(line_names("  lead-18080  trail", "lead-18080"));
    }

    #[test]
    fn a_receipt_is_visible_to_a_poller_and_a_missing_log_is_empty() {
        let directory = scratch("receipt");
        record_receipt(&directory, "tcp 1 127.0.0.1 one").expect("a recorded receipt");
        assert_eq!(wait_for_receipt(&directory, "one", Duration::ZERO), 0);
        assert_eq!(wait_for_receipt(&directory, "two", Duration::ZERO), 1);
        // A missing log is empty text, not an error: the fixtures may not have
        // started, and the answer to "did it arrive" is still "no".
        assert_eq!(
            wait_for_receipt(&directory.join("absent"), "one", Duration::ZERO),
            1
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_absence_bound_elapses_before_it_answers_never() {
        let directory = scratch("absence");
        let started = Instant::now();
        assert_eq!(
            wait_for_receipt(&directory, "never", Duration::from_millis(300)),
            1
        );
        assert!(started.elapsed() >= Duration::from_millis(300));
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_listeners_answer_record_and_stop() {
        let directory = scratch("health");
        let fixtures = Fixtures::bind(&directory, true).expect("ephemeral binds");
        fixtures.start().expect("the listeners start");
        assert!(directory.join(READY_NAME).is_file());
        assert_eq!(health(&directory), 0, "the fixture cluster is healthy");
        let running = Fixtures::bind(&directory, true)
            .expect("ephemeral binds")
            .start()
            .expect("the listeners start");
        // One cluster is still up, so this is a second, healthy directory write.
        assert_eq!(health(&directory), 0);
        running.stop().expect("the listeners stop");
        // A run whose fixtures stopped: nothing may report health from a stale
        // port, so the readiness marker goes with them.
        std::fs::remove_file(directory.join(READY_NAME)).expect("remove readiness");
        assert_eq!(health(&directory), 1);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_health_probe_refuses_a_short_or_unbound_port_list() {
        let short = serde_json::json!({"tcp":[1,2],"udp":[3],"proxy":[4]});
        assert!(parse_ports(&short).is_none(), "one UDP port is not two");
        let unbound = serde_json::json!({"tcp":[1,0],"udp":[3,4],"proxy":[5]});
        assert!(
            parse_ports(&unbound).is_none(),
            "port 0 is not a bound port"
        );
        let ok = serde_json::json!({"tcp":[1,2],"udp":[3,4],"proxy":[5]});
        assert!(parse_ports(&ok).is_some());
    }

    #[test]
    fn the_published_ports_keep_their_order_and_lists() {
        let ports = FixturePorts {
            tcp: vec![18080, 18081],
            udp: vec![18080, 19090],
            proxy: vec![18888],
            tls: vec![18443, 18444],
            opaque: vec![18090],
            banner: vec![18091],
        };
        assert_eq!(
            ports.json(),
            "{\"tcp\": [18080, 18081], \"udp\": [18080, 19090], \"proxy\": [18888], \"tls\": \
[18443, 18444], \"opaque\": [18090], \"banner\": [18091]}"
        );
    }

    #[test]
    fn the_controls_pass() {
        self_test().expect("the boot-free fixture controls");
    }

    #[test]
    fn a_process_identity_is_a_pair_and_an_absent_pid_is_not_an_error() {
        let own = process_identity(std::process::id()).expect("this process has an identity");
        assert!(own.is_some(), "a running process has an identity");
        // A pid that cannot exist: the lookup says "absent", never a made-up
        // identity and never an error.
        assert_eq!(
            process_identity(u32::MAX).expect("absent is not an error"),
            None
        );
        assert!(process_identity(0).is_err(), "PID 0 is refused, not absent");
    }

    #[test]
    fn a_recycled_pid_is_refused_a_signal() {
        let mut stale = serde_json::json!({
            "pid": std::process::id(),
            "start": [1, 1],
        });
        let error =
            signal_identity(&stale, libc::SIGTERM).expect_err("a stale identity is refused");
        assert!(error.contains("PID reuse"), "{error}");
        // The same process with its real start time is signalled only when the
        // signal is harmless; 0 is the portable "does this pid exist" probe.
        let start = process_identity(std::process::id())
            .expect("an identity")
            .expect("present");
        stale["start"] = serde_json::json!(start);
        assert!(signal_identity(&stale, 0).expect("signal 0 is permitted"));
    }

    #[test]
    fn the_launch_environment_is_exactly_the_private_one() {
        let environment = base_environment(Path::new("/work"));
        let names: Vec<&str> = environment.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "HOME",
                "XDG_CONFIG_HOME",
                "AGENT_VM_STATE_DIR",
                "PATH",
                "TERM",
                "AGENT_VM_SHARE_MSB_CACHE",
                "AGENT_VM_NO_NOTIFICATIONS"
            ]
        );
        assert_eq!(environment[0].1, "/work/home");
        assert_eq!(environment[1].1, "/work/config");
        assert_eq!(environment[2].1, "/work/state");
        assert_eq!(environment[3].1, "/usr/bin:/bin");
        assert_eq!(environment[4].1, "dumb");
        assert_eq!(environment[5].1, "0");
        assert_eq!(
            environment[6].1, "1",
            "a fixtured launch posts no real banner"
        );
    }

    #[test]
    fn a_wait_bound_must_be_finite_and_non_negative() {
        assert!(seconds(0.0, "--timeout").is_ok());
        assert!(seconds(f64::INFINITY, "--timeout").is_err());
        assert!(seconds(f64::NAN, "--timeout").is_err());
        assert!(seconds(-1.0, "--timeout").is_err());
    }
}
