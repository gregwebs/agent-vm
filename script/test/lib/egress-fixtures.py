#!/usr/bin/env python3
"""Host-side fixtures and the bounded launch supervisor for the #302 A1 egress
harness (``script/test/egress-default-deny.sh``).

Three roles, deliberately in one file so the boot-free contract can exercise
them without a VM:

* ``serve --dir DIR --lan LAN`` -- one tracked host process owning the HTTP/UDP
  receipt servers and the CONNECT proxy. It records every receipt to
  ``DIR/receipts.log`` and writes ``DIR/ready`` only after every bind succeeds,
  so a stale port cannot satisfy the readiness marker. Cases observe receipts
  through ``wait-receipt``; the fixture outlives any one launch.
* ``wait-receipt --dir DIR ID --timeout SECS`` -- poll ``receipts.log`` for an
  exact ID: 0 as soon as it is seen, 1 only after the whole bound elapses
  unseen, 2 on an internal error. A denial oracle needs the full bound, so the
  exit code distinguishes "not yet" from "never".
* ``launch --work WORK --case CASE ... -- argv`` -- run one candidate launch in
  an owned process group via the shared ``released-image-launch.py`` helper
  (imported by absolute repository path), with a bounded timeout and a recorded
  ownership receipt. It never reaps the fixture; the harness's ``cleanup_run``
  owns that.

``self-test`` proves the fixtures on ephemeral ports without a VM. It is the
boot-free contract's oracle, not a release check.
"""

from __future__ import annotations

import argparse
import http.server
import importlib.util
import json
import os
import re
import socket
import struct
import sys
import threading
import time
from pathlib import Path

READY_NAME = "ready"
RECEIPTS_NAME = "receipts.log"

# Fixed fixture ports (the harness and the guest probes agree on these).
TCP_RECEIPT_PORTS = (18080, 18081)
UDP_RECEIPT_PORTS = (19090, 18080)
PROXY_ADDR = ("127.0.0.1", 18888)


def repo_root() -> Path:
    """The repository root, resolved from this file, never from the cwd.

    ``script/test/lib/egress-fixtures.py`` -> parents[3].
    """
    return Path(__file__).resolve().parents[3]


def _receipts_path(directory: Path) -> Path:
    return directory / RECEIPTS_NAME


def record_receipt(directory: Path, line: str) -> None:
    """Append one receipt line and flush, so a poller running concurrently sees
    it immediately (a buffered write would make ``wait-receipt`` miss it)."""
    directory.mkdir(parents=True, exist_ok=True)
    with open(_receipts_path(directory), "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def wait_for_receipt(directory: Path, receipt_id: str, timeout: float) -> int:
    """Return 0 if the exact ID appears within ``timeout``, 1 if never, 2 on an
    internal error."""
    pattern = re.compile(r"(?:^|\s)" + re.escape(receipt_id) + r"(?:\s|$)")
    deadline = time.monotonic() + timeout
    while True:
        try:
            text = _receipts_path(directory).read_text(encoding="utf-8")
        except FileNotFoundError:
            text = ""
        except OSError as error:  # pragma: no cover - filesystem level
            print(f"wait-receipt: {error}", file=sys.stderr)
            return 2
        if any(pattern.search(line) for line in text.splitlines()):
            return 0
        if time.monotonic() >= deadline:
            return 1
        time.sleep(0.05)


# ---------------------------------------------------------------------------
# Fixture servers
# ---------------------------------------------------------------------------


class _ReceiptHTTP(http.server.BaseHTTPRequestHandler):
    directory: Path
    port: int

    def log_message(self, *_args):  # silence the default stderr chatter
        pass

    def _body(self) -> bytes | None:
        # ``GET /r/<ID>`` returns the body; ``HEAD`` carries only the status.
        match = re.fullmatch(r"/r/(\S+)", self.path)
        if match is None:
            self.send_error(404)
            return None
        receipt_id = match.group(1)
        record_receipt(self.directory, f"tcp {self.port} {self.client_address[0]} {receipt_id}")
        return f"receipt {receipt_id}".encode()

    def do_GET(self):  # noqa: N802 - http.server API
        body = self._body()
        if body is None:
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):  # noqa: N802 - http.server API
        if self._body() is None:
            return
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()


def _serve_tcp(directory: Path, port: int, ready: list, lock: threading.Lock):
    handler = type(
        f"_ReceiptHTTP{port}",
        (_ReceiptHTTP,),
        {"directory": directory, "port": port},
    )
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), handler)
    handler.port = server.server_address[1]
    with lock:
        ready.append(("tcp", server.server_address[1]))
    server.serve_forever(poll_interval=0.2)


def _serve_udp(directory: Path, port: int, ready: list, lock: threading.Lock):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    with lock:
        ready.append(("udp", sock.getsockname()[1]))
    while True:
        try:
            data, peer = sock.recvfrom(512)
        except OSError:
            return
        _reply_udp(directory, sock, data, peer)


def _reply_udp(directory, sock, data, peer):
    match = re.fullmatch(rb"id=(\S+)", data.strip())
    if match is None:
        return
    receipt_id = match.group(1).decode("utf-8", "replace")
    record_receipt(directory, f"udp {sock.getsockname()[1]} {peer[0]} {receipt_id}")
    sock.sendto(f"ack {receipt_id}".encode(), peer)


def _pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            chunk = src.recv(4096)
            if not chunk:
                return
            dst.sendall(chunk)
    except OSError:
        return
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _serve_proxy(directory: Path, ready: list, lock: threading.Lock, address=PROXY_ADDR):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(address)
    listener.listen(8)
    with lock:
        ready.append(("proxy", listener.getsockname()[1]))
    while True:
        try:
            conn, _peer = listener.accept()
        except OSError:
            return
        threading.Thread(target=_handle_connect, args=(directory, conn), daemon=True).start()


def _handle_connect(directory: Path, conn: socket.socket) -> None:
    try:
        request = b""
        while b"\r\n\r\n" not in request and len(request) < 8192:
            chunk = conn.recv(1024)
            if not chunk:
                return
            request += chunk
        match = re.match(rb"CONNECT ([^\s]+) HTTP/", request)
        if match is None:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        target = match.group(1).decode()
        record_receipt(directory, f"proxy {target}")
        host, _, port_text = target.rpartition(":")
        upstream = socket.create_connection((host, int(port_text)), timeout=5)
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        threading.Thread(target=_pump, args=(conn, upstream), daemon=True).start()
        _pump(upstream, conn)
    except (OSError, ValueError):
        return
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(directory: Path, ephemeral_ports=False) -> int:
    directory.mkdir(parents=True, exist_ok=True)
    ready: list = []
    lock = threading.Lock()
    threads = []
    for port in ((0, 0) if ephemeral_ports else TCP_RECEIPT_PORTS):
        threads.append(threading.Thread(target=_serve_tcp, args=(directory, port, ready, lock)))
    for port in ((0, 0) if ephemeral_ports else UDP_RECEIPT_PORTS):
        threads.append(threading.Thread(target=_serve_udp, args=(directory, port, ready, lock)))
    threads.append(threading.Thread(target=_serve_proxy, args=(directory, ready, lock, ("127.0.0.1", 0) if ephemeral_ports else PROXY_ADDR)))
    for thread in threads:
        thread.daemon = True
        thread.start()
    # Ready only once every listener has bound.
    deadline = time.monotonic() + 5
    expected = len(TCP_RECEIPT_PORTS) + len(UDP_RECEIPT_PORTS) + 1
    while True:
        with lock:
            count = len(ready)
        if count >= expected:
            break
        if time.monotonic() >= deadline:
            print("serve: listeners failed to bind in time", file=sys.stderr)
            return 1
        time.sleep(0.05)
    (directory / "ports.json").write_text(json.dumps({
        kind: sorted(port for protocol, port in ready if protocol == kind)
        for kind in ("tcp", "udp", "proxy")}))
    (directory / READY_NAME).write_text(str(int(time.time())), encoding="utf-8")
    stop = threading.Event()

    def _term(_signum, _frame):
        stop.set()

    import signal

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    while not stop.wait(0.2):
        pass
    return 0


# ---------------------------------------------------------------------------
# Bounded supervisor
# ---------------------------------------------------------------------------


_OWNED_HELPER = None


def _load_owned_launch():
    """Import the shared owned-group helper by absolute path.

    Resolving from ``__file__`` (not the caller cwd) is what the boot-free
    contract pins; a sibling of ``lib/`` would not exist.
    """
    global _OWNED_HELPER
    if _OWNED_HELPER is not None:
        return _OWNED_HELPER
    helper_path = repo_root() / "script/test/released-image-launch.py"
    spec = importlib.util.spec_from_file_location("owned_launch", helper_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _OWNED_HELPER = module
    return module


# ---------------------------------------------------------------------------
# One command model for execution and JSONL plans
# ---------------------------------------------------------------------------
from dataclasses import dataclass, asdict
import hashlib
import shlex
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import platform
import ctypes
import errno
from contextlib import closing

IMAGE = "av302:egress"
CLEANUP_BOUND = 120.0
ADMIN_GRACE = 1.0


@dataclass(frozen=True)
class Case:
    case: str
    variant: str = "ipv4"
    flags: tuple[str, ...] = ()
    extras: tuple[str, ...] = ()
    optional: str = ""
    tool: str = "egressprobe"
    guest: bool = True


# Order is significant: calibrations precede dependent probes, except I1a,
# whose endpoint must first be decoded by H1.
CASES = (
    Case("P0"), Case("LC1", flags=("--allow-lan",)),
    Case("HC1", flags=("--allow-host",)),
    Case("I1", flags=("--allow-internet-egress",)),
    Case("D1"), Case("D1f", flags=("--allow-lan=false", "--allow-host=false", "--allow-internet-egress=false")),
    Case("L1", flags=("--allow-lan",)), Case("H1", flags=("--allow-host",)),
    Case("I1a", flags=("--allow-internet-egress",)),
    Case("LH1", flags=("--allow-lan", "--allow-host")),
    Case("AD1", flags=("--allow-egress", "1.1.1.1")),
    Case("TP1", flags=("--allow-egress", "tcp://{lan}:18080")),
    Case("UP1", flags=("--allow-egress", "udp://[{lan}/32]:19090")),
    Case("UP2", flags=("--allow-egress", "{lan}:18080")),
    Case("CI1", flags=("--allow-egress", "tcp://[{cidr}]:18080")),
    Case("PX1", flags=("--allow-egress", "tcp://{lan}:18080"), extras=("HTTP_PROXY",)),
    Case("PX2", flags=("--allow-egress", "tcp://{lan}:18080"), extras=("HTTP_PROXY", "NO_PROXY")),
    Case("PX3", extras=("HTTP_PROXY", "HTTPS_PROXY")),
    Case("FL0", flags=("--allow-internet-egress",), extras=("MSB_CONFIG_PATH",)),
    Case("FL1", flags=("--allow-lan",), extras=("MSB_CONFIG_PATH",)),
    Case("FL2", flags=("--allow-egress", "tcp://{lan}:18080"), extras=("MSB_CONFIG_PATH",)),
    Case("CR1c", flags=("--allow-internet-egress",), tool="egresscreds"),
    Case("CR1", tool="egresscreds"),
    Case("IN1", flags=("-p", "18556:8000")), Case("IN2", flags=("--auto-publish",)),
    Case("HK1c", flags=("--allow-lan",)), Case("HK1"),
    Case("HK2c", flags=("--allow-lan",)), Case("HK2"),
    Case("V6c", "ipv6", flags=("--allow-internet-egress",), optional="ipv6"),
    Case("DNS6c", "ipv6", flags=("--allow-internet-egress",), optional="ipv6"),
    Case("V6", "ipv6", flags=("--allow-egress", "tcp://[2606:4700:4700::1111]:80"), optional="ipv6"),
    Case("D1", "ipv6", optional="ipv6"),
    *(Case("RB1", variant, flags=("--allow-internet-egress", *grant), optional="rebind")
      for variant, grant in (
          ("address", ("--allow-egress", "{cidr}")),
          ("tcp", ("--allow-egress", "tcp://{cidr}")),
          ("udp", ("--allow-egress", "udp://{cidr}")),
          ("internet", ()), ("port", ("--allow-egress", "[{cidr}]:18080")),
          ("tcp-port", ("--allow-egress", "tcp://[{cidr}]:18080")),
          ("udp-port", ("--allow-egress", "udp://[{cidr}]:18080")))),
    *(Case("RJ1", variant, flags=("--allow-egress", value), guest=False)
      for variant, value in (("hostname", "reject.invalid"), ("cidr-port", "{cidr}:18080"),
                             ("scheme", "http://1.1.1.1:80"))),
    Case("CL1"),
)


def base_environment(work: Path) -> dict[str, str]:
    return {"HOME": str(work / "home"), "XDG_CONFIG_HOME": str(work / "config"),
            "AGENT_VM_STATE_DIR": str(work / "state"), "PATH": "/usr/bin:/bin",
            "TERM": "dumb", "AGENT_VM_SHARE_MSB_CACHE": "0"}


# Links identify the exact successful attempt, including resolver/name/transport.
FLOW_CONTROLS = {"lan-tcp80": "LC1:ipv4:lan-tcp80", "lan-tcp81": "LC1:ipv4:lan-tcp81",
                 "lan-udp90": "LC1:ipv4:lan-udp90", "lan-udp80": "LC1:ipv4:lan-udp80",
                 "host-tcp80": "HC1:ipv4:host-tcp80", "public-1111": "I1:ipv4:public-1111",
                 "public-1001": "I1:ipv4:public-1001", "answer": "I1a:ipv4:answer",
                 "public-v6-1001": "V6c:ipv6:public-v6-1001"}


def control_links(case: Case) -> dict[str, str]:
    links = dict(FLOW_CONTROLS)
    for proto in ("udp", "tcp"):
        for resolver in ("gateway", "explicit"):
            links[f"{resolver}-{proto}"] = f"I1:ipv4:{resolver}-{proto}"
        links[f"provider-{proto}"] = f"CR1c:ipv4:provider-{proto}"
        links[f"explicit-v6-{proto}"] = f"DNS6c:ipv6:explicit-v6-{proto}"
        links[f"rebind-{proto}"] = f"RB1:address:rebind-{proto}"
    if case.case.startswith("HK"):
        links["hook"] = f"{case.case[:3]}c:ipv4:hook"
    if case.case in ("FL1", "FL2"):
        links["floor"] = "FL0:ipv4:public-1111"
    return links


@dataclass(frozen=True)
class Command:
    case: str
    variant: str
    tool: str | None
    kind: str
    env: dict[str, str]
    argv: tuple[str, ...]
    cwd: str
    timeout: float
    grace: float
    declared_extras: tuple[str, ...] = ()
    prerequisites: tuple[str, ...] = ()
    controls: dict[str, str] | None = None
    setup: tuple[str, ...] = ()
    expected_attempts: tuple[str, ...] = ()
    attempt_expectations: dict[str, str] | None = None
    attempt_protocols: dict[str, str] | None = None
    supervisor: str = "owned-launch: python shim writes identity, redirects IO, execs argv"

    def plan(self, output=None, identity=None):
        result = asdict(self)
        work = Path(self.env["AGENT_VM_STATE_DIR"]).parent
        output = output or work / f"{self.case}-{self.variant}.log"
        if identity is None and self.kind in ("guest", "validation-only"):
            identity = work / f"{self.case}-{self.variant}.identity.json"
        result["shim"] = None if self.case == "fixture-start" else {
            "argv": _shim_argv(self.argv, output, self.env, identity), "stdin": "devnull",
            "output": str(output), "identity_file": str(identity) if identity else None}
        result["cleanup_bounds"] = {"launch": CLEANUP_BOUND, "absence_poll": 10, "fixture": 5}
        return result


def expected_attempts(case: Case) -> tuple[str, ...]:
    gateway = ("gateway-udp", "gateway-tcp")
    explicit = ("explicit-udp", "explicit-tcp")
    common = ("lan-tcp80", "public-1111")
    labels = {
        "P0": (), "CL1": (), "RJ1": (),
        "LC1": ("lan-tcp80", "lan-tcp81", "lan-udp90", "lan-udp80"),
        "HC1": ("host-tcp80", *gateway),
        "I1": ("public-1111", "public-1001", *gateway, *explicit, "lan-tcp80", "host-tcp80"),
        "D1": ("explicit-v6-udp", "explicit-v6-tcp") if case.variant == "ipv6" else (
            "lan-tcp80", "lan-udp90", "host-tcp80", "public-1111", *gateway, *explicit),
        "D1f": (*common, "gateway-udp"),
        "L1": ("lan-tcp80", "lan-udp90", "public-1111", "host-tcp80", *gateway),
        "H1": ("host-tcp80", *common, *gateway, "answer"), "I1a": ("answer",),
        "LH1": ("lan-tcp80", "host-tcp80", "public-1111"),
        "AD1": ("public-1111", "public-1001", *gateway, *explicit),
        "TP1": ("lan-tcp80", "lan-udp80", "lan-tcp81"),
        "UP1": ("lan-udp90", "lan-udp80", "lan-tcp80"),
        "UP2": ("lan-tcp80", "lan-udp80", "lan-tcp81"),
        "CI1": ("lan-tcp80", "lan-tcp81"),
        "PX1": ("lan-tcp80", "lan-tcp81"), "PX2": ("lan-tcp80",), "PX3": common,
        "FL0": ("public-1111",), "FL1": ("lan-tcp80",), "FL2": ("lan-tcp80",),
        "CR1": ("provider-udp", "provider-tcp", "public-1111"),
        "CR1c": ("provider-udp", "provider-tcp", "public-1111"),
        "IN1": ("public-1111",), "IN2": ("public-1111",),
        "HK1": ("hook",), "HK1c": ("hook",), "HK2": ("hook",), "HK2c": ("hook",),
        "V6": ("public-v6-1111", "public-v6-1001"),
        "V6c": ("public-v6-1111", "public-v6-1001"),
        "DNS6c": ("explicit-v6-udp", "explicit-v6-tcp"), "RB1": ("rebind-udp", "rebind-tcp"),
    }
    return labels[case.case]


def attempt_expectations(case: Case) -> dict[str, str]:
    denied = {
        "I1": ("lan-tcp80", "host-tcp80"),
        "D1": ("lan-tcp80", "lan-udp90", "host-tcp80", "public-1111"),
        "D1f": ("lan-tcp80", "public-1111"), "L1": ("public-1111", "host-tcp80"),
        "H1": ("lan-tcp80", "public-1111", "answer"), "LH1": ("public-1111",),
        "AD1": ("public-1001",), "TP1": ("lan-udp80", "lan-tcp81"),
        "UP1": ("lan-udp80", "lan-tcp80"), "UP2": ("lan-tcp81",), "CI1": ("lan-tcp81",),
        "PX1": ("lan-tcp81",), "PX3": ("lan-tcp80", "public-1111"),
        "FL1": ("lan-tcp80",), "FL2": ("lan-tcp80",), "CR1": ("public-1111",),
        "IN1": ("public-1111",), "IN2": ("public-1111",),
        "HK1": ("hook",), "HK2": ("hook",), "V6": ("public-v6-1001",),
    }.get(case.case, ())
    dns_ok = case.case in ("HC1", "H1", "I1", "CR1c", "DNS6c") or (
        case.case == "RB1" and case.variant in ("address", "tcp", "udp"))
    return {label: ("OK" if dns_ok else "NX") if attempt_protocol(label).startswith("dns-") else
            "1" if label in denied else "0" for label in expected_attempts(case)}


def attempt_protocol(label: str) -> str:
    if label.startswith(("gateway-", "explicit-", "provider-", "rebind-")):
        return "dns-" + label.rsplit("-", 1)[1]
    if label.startswith("public-") or label == "answer":
        return "public"
    return "udp" if "-udp" in label else "tcp"


def build_command(case: Case, work: Path, binary: str, lan: str, *, answer="ANSWER_FROM_H1",
                  rebind="", attempt="") -> Command:
    cidr = lan.rsplit(".", 1)[0] + ".0/24"
    values = {"lan": lan, "cidr": cidr}
    env = base_environment(work)
    extras = {"HTTP_PROXY": "http://127.0.0.1:18888", "HTTPS_PROXY": "http://127.0.0.1:18888",
              "NO_PROXY": lan, "MSB_CONFIG_PATH": str(work / "floor.json")}
    env.update({key: extras[key] for key in case.extras})
    argv = [binary, case.tool, "--no-git", "--image", IMAGE,
            *(flag.format(**values) for flag in case.flags)]
    ident = attempt or f"{case.case}-{case.variant}"
    if case.guest:
        argv.extend(("--", case.case, ident, lan, case.variant,
                     answer if case.case == "I1a" else rebind if case.case == "RB1" else ""))
    project = work / (case.case[:3] if case.case.startswith("HK") else "creds" if case.tool == "egresscreds" else "proj")
    setup = ("private synthetic anthropic OAuth seed; remove seed and captured material",) if case.tool == "egresscreds" else ()
    return Command(case.case, case.variant, case.tool, "guest" if case.guest else "validation-only",
                   env, tuple(argv), str(project), 300 if case.guest else 10, 10,
                   case.extras, (case.optional,) if case.optional else (), control_links(case), setup,
                   expected_attempts=expected_attempts(case), attempt_expectations=attempt_expectations(case),
                   attempt_protocols={label: attempt_protocol(label) for label in expected_attempts(case)})


def admin_command(work: Path, binary: str, verb: str, args=(), bound=10) -> Command:
    return Command(verb, "admin", None, "admin", base_environment(work),
                   (binary, "msb", *args), str(work / "proj"), bound, ADMIN_GRACE)


def append_owned(work: Path, receipt: dict) -> None:
    with open(work / "owned.jsonl", "a", encoding="utf-8") as handle:
        handle.write(json.dumps(receipt, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def bounded_command(command: Command, *, deadline=None) -> int:
    helper = _load_owned_launch()
    bound = command.timeout
    if deadline is not None:
        remaining = deadline - time.monotonic() - command.grace
        if remaining <= 0:
            raise TimeoutError("administrative cleanup deadline exhausted")
        bound = min(bound, remaining)
    try:
        return helper.run_in_owned_group(list(command.argv), env=command.env, cwd=command.cwd,
                                         timeout=bound, grace=command.grace)
    except helper.LaunchTimedOut:
        return 124
    except helper.LaunchInterrupted as error:
        return 128 + error.signum
    except KeyboardInterrupt:
        return 130


class _BsdInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid",
        "svuid", "svgid", "rfu")] + [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)] + [
        (name, ctypes.c_uint32) for name in ("nfiles", "pgid", "pjobc", "tdev", "tpgid", "nice")] + [
        ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]


def process_identity(pid: int):
    """None means absent/nonexecuting; lookup errors are never absence evidence."""
    if pid <= 0:
        raise ValueError("invalid owned PID")
    if sys.platform.startswith("linux"):
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        except FileNotFoundError:
            return None
        if fields[0] in ("Z", "X", "x"):
            return None
        return [int(fields[19]), 0]
    if sys.platform == "darwin":
        lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        info = _BsdInfo()
        size = ctypes.sizeof(info)
        count = lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), size)
        if count != size:
            code = ctypes.get_errno()
            if code in (errno.ESRCH, errno.ENOENT):
                return None
            raise OSError(code, "proc_pidinfo could not establish identity")
        if info.pid != pid:
            raise RuntimeError("libproc PID mismatch")
        if info.status == 5:  # SZOMB
            return None
        return [info.start_sec, info.start_usec]
    raise RuntimeError("unsupported native identity adapter")


def signal_identity(identity: dict, sig: int) -> bool:
    current = process_identity(identity["pid"])
    if current is None:
        return False
    if current != identity["start"]:
        raise RuntimeError(f"PID reuse: refusing signal to {identity['pid']}")
    os.kill(identity["pid"], sig)
    return True


def within(path: Path, root: Path) -> Path:
    result = path.resolve()
    if not result.is_relative_to(root.resolve()):
        raise RuntimeError(f"path outside owned root: {path}")
    return result


def socket_paths(root: Path, name: str) -> list[Path]:
    digest = hashlib.sha256(name.encode()).hexdigest()
    return [root / "run/sandboxes" / digest[:24] / "agent.sock",
            root / "run/sandboxes" / digest[:24] / "control.sock",
            root / "run/agent" / f"{digest[:32]}.sock",
            root / "run/agent" / f"{digest[:32]}.control.sock"]


def catalog_rows(root: Path) -> list[dict]:
    db = root / "db/msb.db"
    if not db.exists():
        return []
    deadline = time.monotonic() + 1
    # A read-only connection to the WAL database can transiently fail with
    # "unable to open database file" while the runtime holds/rotates the
    # ``-wal``/``-shm`` files (observed ~1 in 700 polls). That is not absence
    # evidence, so retry inside the same 1 s bound before reporting it.
    while True:
        try:
            return _catalog_query(db, deadline)
        except sqlite3.OperationalError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def _catalog_query(db: Path, deadline: float) -> list[dict]:
    with closing(sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=0.2)) as conn:
        conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 100)
        for table, columns in (("sandbox", {"id", "name", "config", "status"}),
                               ("run", {"id", "sandbox_id", "pid", "status"})):
            observed = {row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')}
            if not columns <= observed:
                raise RuntimeError(f"private catalog schema mismatch: {table}")
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(
            'SELECT s.name, s.config, s.status, r.id AS run_id, r.pid, r.status AS run_status '
            'FROM sandbox s LEFT JOIN "run" r ON s.id=r.sandbox_id')]


def exec_shim(identity_file: Path | None, output: Path, argv: list[str], env: dict[str, str]) -> int:
    if identity_file is not None:
        identity = {"pid": os.getpid(), "start": process_identity(os.getpid()), "pgid": os.getpgrp()}
        # Write before exec so even validation-only invocations have ownership.
        identity_file.write_text(json.dumps(identity))
    with open(os.devnull, "rb") as stdin, open(output, "ab", buffering=0) as log:
        os.dup2(stdin.fileno(), 0)
        os.dup2(log.fileno(), 1)
        os.dup2(log.fileno(), 2)
    os.execve(argv[0], argv, env)
    return 2


def _shim_argv(argv, output, env, identity=None):
    return [sys.executable, str(Path(__file__).resolve()), "exec-shim", "--output", str(output), "--environment", json.dumps(env),
            *(["--identity", str(identity)] if identity else []), "--", *argv]


class OwnedLaunch:
    def __init__(self, work: Path, command: Command, ident: str):
        self.work = work.resolve()
        self.command = command
        self.ident = ident
        self.root = within(work / "state/msb-home", work)
        self.project = within(Path(command.cwd), work)
        self.project_hash = hashlib.sha256(os.fsencode(self.project)).hexdigest()[:12]
        self.log = work / f"{ident}.log"
        self.identity_file = work / f"{ident}.identity.json"
        self.launcher = None
        self.names = set()
        self.runtimes = {}
        self.auxiliaries = []
        self.errors = []
        self.primary = None
        self.effective_profile = None
        self.cleaned = False
        self.cleanup_errors = []
        self.stop_observing = threading.Event()
        self.lock = threading.Lock()
        append_owned(work, self.receipt("prepared"))

    def receipt(self, phase):
        return {"phase": phase, "launch": self.ident, "command": self.command.plan(self.log, self.identity_file),
                "project": str(self.project), "msb_root": str(self.root),
                "launcher": self.launcher, "names": sorted(self.names),
                "runtimes": list(self.runtimes.values()),
                "auxiliaries": [identity for _, identity in self.auxiliaries], "primary_status": self.primary,
                "effective_profile": self.effective_profile,
                "sockets": [str(path) for name in self.names for path in socket_paths(self.root, name)],
                "observation_errors": self.errors, "cleanup_errors": self.cleanup_errors}

    def observe(self):
        if self.launcher is None and self.identity_file.exists():
            self.launcher = json.loads(self.identity_file.read_text())
            if not self.launcher["start"]:
                raise RuntimeError("launcher lacks start identity")
            append_owned(self.work, self.receipt("launcher"))
        if self.launcher is None:
            return
        expected = f"agent-vm-{self.project_hash}-{self.launcher['pid']}"
        if self.log.exists():
            for name, project, state in re.findall(r"==> (agent-vm-\S+) in (.*?) \(state: (.*?)\)", self.log.read_text(errors="replace")):
                if name != expected or Path(project).resolve() != self.project:
                    raise RuntimeError("launch banner ownership mismatch")
                if within(Path(state), self.work) != self.work / "state" / self.project_hash:
                    raise RuntimeError("launch banner private state mismatch")
                self.names.add(name)
        for row in catalog_rows(self.root):
            if row["name"] != expected:
                # Other recorded launches are handled by run-wide inventory.
                continue
            self.names.add(expected)
            config = json.loads(row["config"])
            self.effective_profile = config.get("spec", {}).get("deployment_profile")
            if row["pid"] is not None and row["run_status"] == "Running":
                token = process_identity(row["pid"])
                key = str(row["run_id"])
                if token is not None and key not in self.runtimes:
                    self.runtimes[key] = {"pid": row["pid"], "start": token, "run_id": row["run_id"],
                                          "pgid": os.getpgid(row["pid"]),
                                          "group_relation": "launcher-group" if os.getpgid(row["pid"]) == self.launcher["pgid"] else "separate-group"}
                    append_owned(self.work, self.receipt("runtime"))
                elif key in self.runtimes and token not in (None, self.runtimes[key]["start"]):
                    raise RuntimeError("runtime identity changed during observation")
        if len(self.names) > 1:
            raise RuntimeError("more than one owned sandbox")

    def _monitor(self):
        while not self.stop_observing.is_set():
            try:
                with self.lock:
                    self.observe()
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                message = str(error)
                if message not in self.errors:
                    self.errors.append(message)
            self.stop_observing.wait(0.05)

    def run(self):
        monitor = threading.Thread(target=self._monitor)
        monitor.start()
        helper = _load_owned_launch()
        try:
            self.primary = helper.run_in_owned_group(
                _shim_argv(self.command.argv, self.log, self.command.env, self.identity_file),
                env=self.command.env, cwd=self.command.cwd,
                timeout=self.command.timeout, grace=self.command.grace)
        except helper.LaunchTimedOut:
            self.primary = 124
        except helper.LaunchInterrupted as error:
            self.primary = 128 + error.signum
        except KeyboardInterrupt:
            self.primary = 130
        except (OSError, ValueError) as error:
            self.primary = 2
            self.errors.append(str(error))
        finally:
            self.stop_observing.set()
            monitor.join(timeout=2)
            if monitor.is_alive():
                self.errors.append("observation did not stop within bound")
            else:
                try:
                    self.observe()
                except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                    self.errors.append(str(error))
            if self.launcher is None:
                self.errors.append("launcher identity was never recorded")
            append_owned(self.work, self.receipt("primary"))
        return self.primary

    def alive(self):
        result = []
        for identity in [self.launcher, *self.runtimes.values()]:
            if identity is not None:
                token = process_identity(identity["pid"])
                if token is not None:
                    if token != identity["start"]:
                        raise RuntimeError("owned PID reused; no absence claim")
                    result.append(identity)
        return result


def run_admin(work: Path, command: Command, *, deadline=None) -> tuple[int, str]:
    index = time.monotonic_ns()
    log = work / f"admin-{index}.log"
    append_owned(work, {"phase": "admin", "command": command.plan(output=log), "log": str(log)})
    shim = Command(**{**asdict(command), "argv": tuple(_shim_argv(command.argv, log, command.env))})
    status = bounded_command(shim, deadline=deadline)
    text = log.read_text(errors="replace") if log.exists() else ""
    append_owned(work, {"phase": "admin-result", "argv": command.argv, "status": status})
    return status, text


def list_catalog(work: Path, binary: str, deadline) -> set[str]:
    status, text = run_admin(work, admin_command(work, binary, "list", ("list", "--format", "json")), deadline=deadline)
    if status != 0:
        raise RuntimeError(f"private list failed: {status}")
    rows = json.loads(text)
    if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get("name"), str) for row in rows):
        raise RuntimeError("private list JSON schema mismatch")
    return {row["name"] for row in rows}


def cleanup_launch(launch: OwnedLaunch, *, deadline=None) -> list[str]:
    if launch.cleaned:
        return launch.cleanup_errors
    limit = min(deadline or float("inf"), time.monotonic() + CLEANUP_BOUND)
    errors = launch.cleanup_errors
    binary = launch.command.argv[0]
    previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for proc, identity in launch.auxiliaries:
            try:
                if proc.poll() is None:
                    signal_identity(identity, signal.SIGTERM)
                    try:
                        proc.wait(timeout=min(2, max(0.01, limit - time.monotonic())))
                    except subprocess.TimeoutExpired:
                        signal_identity(identity, signal.SIGKILL)
                        proc.wait(timeout=min(2, max(0.01, limit - time.monotonic())))
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                errors.append(str(error))
        try:
            launch.observe()
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
            errors.append(str(error))
        errors.extend(launch.errors)
        try:
            names = list_catalog(launch.work, binary, limit)
        except (OSError, ValueError, RuntimeError, TimeoutError) as error:
            errors.append(str(error))
            names = set(launch.names)
        for name in sorted(launch.names & names):
            # CLI mutations, never direct SQLite writes or prefix-based kill.
            stop_status = None
            for verb, args, bound in (("stop", ("stop", "--timeout", "5", name), 15),
                                      ("force-stop", ("stop", "--force", name), 10),
                                      ("remove", ("remove", name), 10)):
                try:
                    if verb == "force-stop" and stop_status == 0 and not launch.alive():
                        continue
                    status, _ = run_admin(launch.work, admin_command(launch.work, binary, verb, args, bound), deadline=limit)
                    if verb == "stop":
                        stop_status = status
                    launch.observe()
                    if status:
                        errors.append(f"{verb} {name}: status {status}")
                except (OSError, ValueError, RuntimeError, TimeoutError) as error:
                    errors.append(str(error))
        try:
            for identity in launch.alive():
                for sig in (signal.SIGTERM, signal.SIGKILL):
                    if time.monotonic() >= limit:
                        raise TimeoutError("cleanup identity deadline")
                    signal_identity(identity, sig)
                    until = min(limit, time.monotonic() + 1)
                    while process_identity(identity["pid"]) == identity["start"] and time.monotonic() < until:
                        time.sleep(0.05)
        except (OSError, ValueError, RuntimeError, TimeoutError) as error:
            errors.append(str(error))
        verify_until = min(limit, time.monotonic() + 10)
        while True:
            try:
                launch.observe()
                remaining = list_catalog(launch.work, binary, verify_until) & launch.names
                live = launch.alive()
                paths = [path for name in launch.names for path in socket_paths(launch.root, name)]
                for path in paths:
                    if path.is_symlink() or within(path, launch.work) != path:
                        raise RuntimeError(f"owned socket path redirected: {path}")
                if not remaining and not live:
                    for path in paths:
                        if path.exists():
                            # Only a stale socket, not an arbitrary file or symlink.
                            import stat
                            if not stat.S_ISSOCK(path.lstat().st_mode):
                                raise RuntimeError(f"owned socket is not a socket: {path}")
                            path.unlink()
                            append_owned(launch.work, {"phase": "stale-socket-removed", "path": str(path)})
                    break
                if time.monotonic() >= verify_until:
                    raise RuntimeError(f"cleanup survivors: catalog={sorted(remaining)} identities={live}")
                time.sleep(0.1)
            except (OSError, ValueError, RuntimeError, TimeoutError, sqlite3.Error) as error:
                errors.append(str(error))
                break
        launch.cleaned = True
        append_owned(launch.work, launch.receipt("cleanup"))
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return errors


def cleanup_run(work: Path, binary: str, launches: list[OwnedLaunch], fixture=None) -> list[str]:
    deadline = time.monotonic() + CLEANUP_BOUND * len(launches) + 20
    errors = []
    previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for owned in launches:
            errors.extend(cleanup_launch(owned, deadline=deadline))
        if fixture is not None:
            proc, identity = fixture
            try:
                signal_identity(identity, signal.SIGTERM)
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    signal_identity(identity, signal.SIGKILL)
                    proc.wait(timeout=2)
                if process_identity(identity["pid"]) is not None:
                    errors.append("host fixture survived cleanup")
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                errors.append(str(error))
        try:
            remaining = list_catalog(work, binary, deadline)
            if remaining:
                errors.append(f"run catalog not empty (unowned entries retained): {sorted(remaining)}")
            for owned in launches:
                if any(process_identity(identity["pid"]) is not None for _, identity in owned.auxiliaries):
                    errors.append(f"live launch auxiliary after run cleanup: {owned.ident}")
                if owned.alive():
                    errors.append(f"live identities after run cleanup: {owned.ident}")
                if any(path.exists() for name in owned.names for path in socket_paths(owned.root, name)):
                    errors.append(f"owned sockets after run cleanup: {owned.ident}")
        except (OSError, RuntimeError, ValueError, TimeoutError) as error:
            errors.append(str(error))
        append_owned(work, {"phase": "cleanup-run", "cleanup_errors": errors})
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return errors


def launch(work: Path, case: str, timeout: float, grace: float, envs, argv) -> int:
    work = work.resolve()
    env = base_environment(work)
    for item in envs:
        key, sep, value = item.partition("=")
        permitted = {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"} if case.startswith("PX") else {"MSB_CONFIG_PATH"} if case.startswith("FL") else set()
        if not sep or key not in permitted:
            raise ValueError("launch environment permits only PX/FL extras")
        env[key] = value
    command = Command(case, "manual", None, "guest", env, tuple(argv), str(work / "proj"), timeout, grace)
    owned = OwnedLaunch(work, command, f"{case}-{time.monotonic_ns()}")
    status = owned.run()
    failures = cleanup_launch(owned)
    return status or (1 if failures else 0)


def prepare_project(work: Path, project: Path):
    project.mkdir(parents=True, exist_ok=True)
    # The project tool catalog is discovered at `<cwd>/.agent-vm/config.toml`
    # (config.rs PROJECT_CONFIG_RELATIVE), not at a bare `.agent-vm.toml`.
    (project / ".agent-vm").mkdir(exist_ok=True)
    for source, dest in (("egress-probe.sh", "egress-probe.sh"), ("egress-config.toml", ".agent-vm/config.toml")):
        shutil.copyfile(repo_root() / "script/test/fixtures" / source, project / dest)


def write_hook(work: Path, name: str, lan: str, ident: str, port=18080):
    project = work / name
    prepare_project(work, project)
    failure = 'echo "HOOK_EGRESS_DENIED"; return 0' if name == "HK1" else "return 7"
    hook = ("EGRESS_PROBE_LIB=1 . ./egress-probe.sh\n"
            f"if http_get {shlex.quote(lan)} {port} {shlex.quote(ident)}; then\n"
            "    return 0\nelse\n    rc=$?\n    if [ \"$rc\" -eq 1 ]; then\n"
            f"        {failure}\n    fi\n    return \"$rc\"\nfi\n")
    (project / ".agent-vm.runtime.sh").write_text(hook)


def rejection_diagnostic(variant: str) -> str:
    """The exact `--allow-egress #1:` message for an RJ1 variant.

    Mirrors `AllowanceError`'s Display and the host-side test
    `allowance_rejections_report_exact_messages`; a native RJ1 pass therefore
    cannot come from a clap error or an unrelated egress-worded failure.
    """
    return "--allow-egress #1: " + {
        "hostname": "hostname allowances are not supported yet; use an IP address or CIDR, or --allow-internet-egress",
        "cidr-port": "a port on a CIDR needs brackets, e.g. tcp://[10.0.0.0/24]:22",
        "scheme": "unsupported scheme; use tcp:// or udp:// (or no scheme for all protocols)",
    }[variant]


def validation_rejected(status: int, text: str, variant: str) -> bool:
    return (status not in (0, 124, 130, 143) and "CASE " not in text
            and "reject.invalid" not in text and rejection_diagnostic(variant) in text)


def strict_hook_rejected(text: str) -> bool:
    return "CASE HK2 BEGIN" not in text and ".agent-vm.runtime.sh failed (exit 7)" in text


def snapshot_validation(work: Path) -> dict:
    result = {}
    for directory in ("home", "config", "state", "proj"):
        root = work / directory
        for path in sorted(root.rglob("*")):
            # SQLite rewrites the WAL shared-memory/index sidecars whenever a
            # connection attaches, including this harness's own read-only
            # catalog observation. Hashing them is not evidence that a
            # validation-only invocation created launch state.
            if path.name.endswith(("-shm", "-wal", "-journal")):
                continue
            st = path.lstat()
            result[str(path.relative_to(work))] = [st.st_mode, st.st_size,
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and not path.is_symlink()
                else os.readlink(path) if path.is_symlink() else ""]
    return result


def seed_credentials(work: Path):
    directory = work / "home/.claude"
    directory.mkdir(parents=True, exist_ok=True)
    seed = directory / ".credentials.json"
    seed.write_text(json.dumps({"claudeAiOauth": {"accessToken": "av302-synthetic-access",
        "refreshToken": "av302-synthetic-refresh", "expiresAt": 9999999999999,
        "scopes": ["user:inference"], "subscriptionType": "synthetic", "rateLimitTier": "synthetic"}}))
    seed.chmod(0o600)


def remove_credentials(work: Path) -> list[str]:
    failures = []
    paths = [work / "home/.claude/.credentials.json"]
    # Only the CR project is seeded; never touch another launch or operator HOME.
    project_hash = hashlib.sha256(os.fsencode(work / "creds")).hexdigest()[:12]
    paths.append(work / "state" / f"{project_hash}.secrets" / "anthropic")
    for path in paths:
        try:
            within(path, work)
            if path.is_symlink():
                raise RuntimeError("credential material symlink refused")
            path.unlink(missing_ok=True)
            if path.exists():
                failures.append(f"credential material remains: {path}")
        except (OSError, RuntimeError) as error:
            failures.append(str(error))
    return failures


def verified_archive(assets: Path) -> Path:
    manifest = repo_root() / "crates/agent-vm/tests/fixtures/standard-release/release.json"
    if (assets / "release.json").read_bytes() != manifest.read_bytes():
        raise RuntimeError("release manifest differs from committed pin")
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine())
    if arch is None:
        raise RuntimeError("unsupported native architecture")
    row = next(row for row in json.loads(manifest.read_bytes())["platforms"] if row["graph"]["architecture"] == arch)
    archive = assets / row["archive"]["name"]
    digest = hashlib.sha256()
    with archive.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    if "sha256:" + digest.hexdigest() != row["archive"]["sha256"] or archive.stat().st_size != row["archive"]["size"]:
        raise RuntimeError("pinned native archive digest/size mismatch")
    return archive


def ingress_command(work: Path, case: str, host_port=None) -> Command:
    port = host_port if host_port is not None else 18556 if case == "IN1" else 18555
    return Command(case, "curl", None, "admin", base_environment(work),
                   ("/usr/bin/curl", "--silent", "--show-error", "--connect-timeout", "2", "--max-time", "3",
                    f"http://127.0.0.1:{port}/"), str(work / "proj"), 5, ADMIN_GRACE)


def ingress_driver(work: Path, case: str, ident: str, host_port=None) -> int:
    log = work / f"{ident}.log"
    port = 8000 if case == "IN1" else 18555
    ready = f"INGRESS_READY {ident} {port}"
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if log.exists() and ready in log.read_text(errors="replace").splitlines():
            break
        time.sleep(0.05)
    else:
        return 1
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        status, body = run_admin(work, ingress_command(work, case, host_port), deadline=deadline)
        if status in (130, 143):
            return status
        if status == 0:
            return 0 if body == f"ingress {ident}" else 1
        time.sleep(0.1)
    return 1


def attempts_for(case: Case, ident: str, text: str):
    rows = []
    for line in text.splitlines():
        if rows and not line.startswith("ATTEMPT "):
            rows[-1]["output"] += line + "\n"
        if line.startswith("ATTEMPT "):
            parts = line.split()
            if len(parts) != 8 or parts[1] != case.case:
                raise RuntimeError("malformed guest attempt")
            _, _, label, protocol, endpoint, port, expectation, receipt = parts
            rows.append({"key": f"{case.case}:{case.variant}:{label}", "label": label,
                         "protocol": protocol, "endpoint": endpoint, "port": port,
                         "expectation": expectation, "receipt": receipt, "output": ""})
    if case.case.startswith("HK"):
        rows.append({"key": f"{case.case}:{case.variant}:hook", "label": "hook", "protocol": "tcp",
                     "endpoint": "LAN", "port": "18080", "expectation": "0" if case.case.endswith("c") else "1",
                     "receipt": ident + "-hook", "output": text})
    return rows


def check_attempt_inventory(command: Command, rows: list[dict]) -> list[str]:
    errors = []
    if tuple(row["label"] for row in rows) != command.expected_attempts:
        errors.append("missing, duplicate or reordered guest attempts")
    for row in rows:
        if row.get("expectation") != (command.attempt_expectations or {}).get(row["label"]):
            errors.append(f"attempt expectation changed: {row['label']}")
        if row.get("protocol") != (command.attempt_protocols or {}).get(row["label"]):
            errors.append(f"attempt protocol changed: {row['label']}")
    return errors


def check_attempts(work: Path, case: Case, text: str, rows: list[dict]) -> list[str]:
    failures = []
    for row in rows:
        expected = row["expectation"]
        receipt = row["receipt"]
        if row["protocol"] in ("tcp", "udp"):
            status = wait_for_receipt(work / "fx", receipt, 3)
            marker = ("HTTP_OK " if row["protocol"] == "tcp" else "UDP_ACK ") if expected == "0" else (
                "HTTP_FAIL " if row["protocol"] == "tcp" else "UDP_NOACK ")
            if status != (0 if expected == "0" else 1) or marker + receipt not in row["output"].splitlines():
                failures.append(f"receipt/probe mismatch: {row['label']}")
            if status == 0:
                records = (work / "fx/receipts.log").read_text().splitlines()
                if not any(line.split()[:2] == [row["protocol"], row["port"]] and line.split()[-1:] == [receipt] for line in records):
                    failures.append(f"wrong receipt protocol/port: {row['label']}")
            if case.case in ("HC1", "H1", "LH1") and row["label"] == "host-tcp80":
                lines = (work / "fx/receipts.log").read_text().splitlines()
                if not any(line == f"tcp 18080 127.0.0.1 {receipt}" for line in lines):
                    failures.append("host receipt peer is not loopback")
        elif row["protocol"] == "public":
            marker = rf"^HTTP_STATUS [0-9]{{3}}$" if expected == "0" else rf"^HTTP_FAIL {re.escape(row['endpoint'])}:{row['port']}$"
            if not re.search(marker, row["output"], re.M):
                failures.append(f"public status missing: {row['label']}")
        elif row["protocol"].startswith("dns-"):
            proto = row["protocol"][4:]
            marker = f"DNS {proto} {row['endpoint']} "
            if not any(line.startswith(marker) and " id_ok=1 qr=1 question_ok=1 tc=0 " in line
                       and f" rcode={3 if expected == 'NX' else 0} " in line for line in row["output"].splitlines()):
                failures.append(f"validated DNS response missing: {row['label']}")
        else:
            failures.append(f"unknown attempt protocol: {row['protocol']}")
    return failures


def fixture_health(directory: Path) -> int:
    import http.client
    if not (directory / "ready").is_file():
        return 1
    ports = json.loads((directory / "ports.json").read_text())
    if any(len(ports[kind]) != count or any(not 1 <= port <= 65535 for port in ports[kind])
           for kind, count in (("tcp", 2), ("udp", 2), ("proxy", 1))):
        return 1
    ident = f"health-{time.monotonic_ns()}"
    for port in ports["tcp"]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
        try:
            connection.request("GET", f"/r/{ident}-{port}")
            response = connection.getresponse()
            if response.status != 200 or response.read() != f"receipt {ident}-{port}".encode():
                return 1
        finally:
            connection.close()
    for port in ports["udp"]:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(0.5)
            client.sendto(f"id={ident}-{port}".encode(), ("127.0.0.1", port))
            if client.recv(512) != f"ack {ident}-{port}".encode():
                return 1
    with socket.create_connection(("127.0.0.1", ports["proxy"][0]), timeout=0.5) as client:
        client.sendall(f"CONNECT 127.0.0.1:{ports['tcp'][0]} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
        response = b""
        while b"\r\n\r\n" not in response and len(response) < 4096:
            data = client.recv(512)
            if not data:
                return 1
            response += data
        if not response.startswith(b"HTTP/1.1 200 "):
            return 1
    return wait_for_receipt(directory, f"{ident}-{ports['tcp'][0]}", 0.5)


def health_command(work: Path) -> Command:
    return Command("fixture-health", "admin", None, "admin", base_environment(work),
                   (sys.executable, str(Path(__file__).resolve()), "health", "--dir", str(work / "fx")),
                   str(work / "proj"), 5, ADMIN_GRACE)


def selected_cases(smoke=False):
    return tuple(case for case in CASES if not smoke or (case.case in ("P0", "LC1", "HC1", "I1", "D1", "L1") and not case.optional))


def fixture_command(work: Path) -> Command:
    return Command("fixture-start", "admin", None, "admin", base_environment(work),
                   (sys.executable, str(Path(__file__).resolve()), "serve", "--dir", str(work / "fx")),
                   str(work / "proj"), 5, ADMIN_GRACE,
                   supervisor="run-owned host fixture; readiness 5s, identity-checked teardown/reap <=5s")


def print_plan(work: Path, binary: str, lan: str, smoke=False):
    for case in selected_cases(smoke):
        print(json.dumps(build_command(case, work, binary, lan).plan(), sort_keys=True))
    for command in (
        admin_command(work, binary, "image-load", ("image", "load", "--input", "VERIFIED_NATIVE_ARCHIVE", "--tag", IMAGE), 900),
        admin_command(work, binary, "list", ("list", "--format", "json")),
        admin_command(work, binary, "stop", ("stop", "--timeout", "5", "NAME_FROM_OWNED_RECEIPT"), 15),
        admin_command(work, binary, "force-stop", ("stop", "--force", "NAME_FROM_OWNED_RECEIPT")),
        admin_command(work, binary, "remove", ("remove", "NAME_FROM_OWNED_RECEIPT")),
        ingress_command(work, "IN1"), ingress_command(work, "IN2"), health_command(work), fixture_command(work)):
        print(json.dumps(command.plan(), sort_keys=True))


def orchestrate(args) -> int:
    if args.print_plan:
        print_plan(args.work or Path("/var/tmp/av302.PLAN"), args.binary or "/absolute/bundle/bin/agent-vm", args.lan or "192.168.1.2", args.smoke)
        return 0
    if not args.binary or not Path(args.binary).is_absolute() or not args.assets or not args.lan:
        raise ValueError("native run requires absolute AGENT_VM_BIN, release assets and --lan/AGENT_VM_EGRESS_LAN")
    import ipaddress
    address = ipaddress.IPv4Address(args.lan)
    if not any(address in ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")):
        raise ValueError("fixture LAN must be RFC1918/CGN IPv4")
    parent = "/tmp" if sys.platform == "darwin" else "/var/tmp"
    work = Path(tempfile.mkdtemp(prefix="av302.", dir=parent)).resolve()
    if any(work == Path(prefix) or Path(prefix) in work.parents for prefix in ("/tmp", "/run", "/dev/shm", "/var/run")):
        raise RuntimeError("canonical project would be under guest tmpfs")
    print(f"{'SMOKE' if args.smoke else 'NATIVE'} evidence: {work}", flush=True)
    for directory in ("home", "config", "state", "fx"):
        (work / directory).mkdir()
    prepare_project(work, work / "proj")
    (work / "floor.json").write_text('{"deployment_profile":"multi-tenant"}\n')
    launches, results, all_attempts = [], [], {}
    fixture = None
    primary, cleanup_errors = 0, []
    answer = ""
    v6_available = False
    rebind = args.rebind or args.lan.replace(".", "-") + ".sslip.io"
    rebind_available = False
    floor_available = True
    interrupted = None

    def on_term(signum, _frame):
        raise _load_owned_launch().LaunchInterrupted(signum)

    previous_term = signal.signal(signal.SIGTERM, on_term)
    try:
        archive = verified_archive(Path(args.assets).resolve())
        status, _ = run_admin(work, admin_command(work, args.binary, "image-load",
                            ("image", "load", "--input", str(archive), "--tag", IMAGE), 900))
        if status:
            raise RuntimeError(f"image import failed: {status}")
        if list_catalog(work, args.binary, time.monotonic() + 12):
            raise RuntimeError("initial private catalog not empty")
        fixture_start = fixture_command(work)
        append_owned(work, {"phase": "fixture-command", "command": fixture_start.plan()})
        with open(work / "fixture.log", "ab") as fixture_log:
            proc = subprocess.Popen(fixture_start.argv, env=fixture_start.env, cwd=fixture_start.cwd, stdin=subprocess.DEVNULL,
                                    stdout=fixture_log, stderr=subprocess.STDOUT, start_new_session=True)
        identity = {"pid": proc.pid, "start": process_identity(proc.pid)}
        fixture = (proc, identity)
        append_owned(work, {"phase": "fixture", "identity": identity})
        deadline = time.monotonic() + 5
        while not (work / "fx/ready").exists():
            if proc.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("host fixtures not ready")
            time.sleep(0.05)
        # System resolver calibration is bounded in its own owned process.
        calibration = Command("RB1", "preflight", None, "admin", base_environment(work),
            (sys.executable, str(Path(__file__).resolve()), "resolve", rebind, args.lan), str(work / "proj"), 5, ADMIN_GRACE)
        status, _ = run_admin(work, calibration)
        rebind_available = status == 0
        for case in selected_cases(args.smoke):
            reason = ""
            if case.optional == "rebind" and not rebind_available:
                reason = "host resolver did not return fixture LAN A"
            elif case.optional == "ipv6" and not v6_available:
                reason = "paired IPv6 family/controls unavailable"
            elif case.case.startswith("FL") and not floor_available:
                reason = "floor-unsupported (E-owned native evidence)"
            if reason:
                results.append({"case": case, "status": "NOT RUN", "failures": [reason], "attempts": []})
                continue
            if proc.poll() is not None or process_identity(proc.pid) != identity["start"]:
                raise RuntimeError("run-scoped host fixture died")
            health_status, _ = run_admin(work, health_command(work))
            if health_status:
                raise RuntimeError(f"host fixture health failed: {health_status}")
            ident = f"{case.case}-{case.variant}-{len(launches)}"
            if case.case.startswith("HK"):
                write_hook(work, case.case[:3], args.lan, ident + "-hook")
            command = build_command(case, work, args.binary, args.lan, answer=answer, rebind=rebind, attempt=ident)
            if case.tool == "egresscreds":
                prepare_project(work, work / "creds")
                seed_credentials(work)
            before = snapshot_validation(work) if not case.guest else None
            proxy_before = (work / "fx/receipts.log").read_text() if (work / "fx/receipts.log").exists() else ""
            owned = OwnedLaunch(work, command, ident)
            launches.append(owned)
            ingress = None
            if case.case in ("IN1", "IN2"):
                ingress = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "ingress", "--work", str(work),
                                           "--case", case.case, "--id", ident], env=base_environment(work),
                                           stdin=subprocess.DEVNULL, start_new_session=True)
                ingress_identity = {"pid": ingress.pid, "start": process_identity(ingress.pid)}
                owned.auxiliaries.append((ingress, ingress_identity))
                append_owned(work, {"phase": "ingress-driver", "identity": ingress_identity})
            status = owned.run()
            failures = []
            if ingress is not None:
                if status:
                    signal_identity(ingress_identity, signal.SIGTERM)
                try:
                    ingress_status = ingress.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    signal_identity(ingress_identity, signal.SIGTERM)
                    try:
                        ingress_status = ingress.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        signal_identity(ingress_identity, signal.SIGKILL)
                        ingress_status = ingress.wait(timeout=2)
                if ingress_status:
                    failures.append(f"ingress driver status {ingress_status}")
            text = owned.log.read_text(errors="replace") if owned.log.exists() else ""
            rows = attempts_for(case, ident, text)
            failures.extend(check_attempt_inventory(command, rows))
            expected = 124 if case.case == "CL1" else 7 if case.case == "HK2" else 0
            if case.guest:
                if status != expected:
                    failures.append(f"primary expected {expected}, actual {status}")
                if case.case != "HK2" and f"CASE {case.case} BEGIN" not in text.splitlines():
                    failures.append("guest BEGIN missing")
                if case.case not in ("CL1", "HK2") and f"CASE {case.case} END" not in text.splitlines():
                    failures.append("guest END missing")
                if case.case == "HK2" and not strict_hook_rejected(text):
                    failures.append("strict hook did not reject before tool execution")
                if case.case == "HK1" and "HOOK_EGRESS_DENIED" not in text.splitlines():
                    failures.append("recovered hook denial marker missing")
                if case.case == "D1" and ("Egress policy: all guest egress denied" not in text or "DNS: queries denied" not in text):
                    failures.append("default-deny notice missing")
                if case.case not in ("P0", "CL1") and not rows:
                    failures.append("no attempts observed")
                failures.extend(check_attempts(work, case, text, rows))
            else:
                if not validation_rejected(status, text, case.variant):
                    failures.append("validation rejection oracle failed")
                if before != snapshot_validation(work):
                    failures.append("validation-only invocation mutated private launch state")
            if "EXPECT_FAIL" in text or "command not found" in text:
                failures.append("probe/hook internal error")
            if case.case == "H1":
                match = re.search(r"^ANSWER ([0-9.]+)$", text, re.M)
                answer = match.group(1) if match else ""
                if not answer:
                    failures.append("decoded H1 endpoint missing")
            if case.case == "P0":
                # The stored sandbox spec only pins a profile that some config
                # layer set explicitly; DeploymentProfile::default() is
                # SingleTenant, so an absent spec field is the private default.
                # A host-wide multi-tenant managed policy would still appear
                # here as "multi-tenant" and must fail this row.
                if owned.effective_profile not in (None, "single-tenant"):
                    failures.append(f"effective private profile not established: {owned.effective_profile}")
                v6_available = "ipv6=1" in text and socket.has_ipv6
                if "PREFLIGHT gateway=" not in text:
                    failures.append("guest preflight missing")
            proxy_after = (work / "fx/receipts.log").read_text() if (work / "fx/receipts.log").exists() else ""
            proxy_new = [line for line in proxy_after[len(proxy_before):].splitlines() if line.startswith("proxy ")]
            if case.case == "PX1" and proxy_new != [f"proxy {args.lan}:18080"]:
                failures.append("proxy route/deny receipt mismatch")
            if case.case in ("PX2", "PX3") and proxy_new:
                failures.append("unexpected proxy CONNECT")
            if case.case.startswith("FL") and owned.effective_profile != "multi-tenant":
                failures.append(f"floor profile not established: {owned.effective_profile}")
                # A successful FL0 launch that does not pin the private floor in
                # the stored spec means this launcher path cannot establish the
                # profile from a private MSB_CONFIG_PATH; the plan defers the
                # platform-floor native evidence to E and prints NOT RUN.
                if case.case == "FL0" and status == 0:
                    floor_available = False
            failures.extend(cleanup_launch(owned))
            if case.tool == "egresscreds":
                failures.extend(remove_credentials(work))
            if (work / "config/agent-vm/default-image.json").exists() or (work / "home/.config/agent-vm/default-image.json").exists():
                failures.append("explicit image adopted default")
            result = {"case": case, "status": "FAIL" if failures else "PASS", "failures": failures, "attempts": rows}
            if case.case == "FL0" and not floor_available and not owned.cleanup_errors:
                result["status"] = "NOT RUN"
                result["failures"].append("floor-unsupported (E-owned native evidence)")
            results.append(result)
            for row in rows:
                all_attempts[row["key"]] = result
            if status in (130, 143):
                interrupted = status
                break
        # Optional v6 denials never count without both exact positive controls.
        v6_controls = [r for r in results if r["case"].case in ("V6c", "DNS6c")]
        if not args.smoke and (len(v6_controls) != 2 or any(r["status"] != "PASS" for r in v6_controls)):
            for result in results:
                if result["case"].optional == "ipv6":
                    result["status"] = "NOT RUN"
                    result["failures"].append("paired IPv6 positive controls unavailable")
        # Optional rebind evidence is E-owned. If the guest forwarder returns no
        # DNS response at all for the rebind name (an indeterminate TIMEOUT, not
        # a denial), the group cannot be evaluated and is NOT RUN.
        rebind = [r for r in results if r["case"].optional == "rebind"]
        rebind_timeout = any(
            line.startswith("DNS ") and " TIMEOUT" in line
            for result in rebind for row in result["attempts"] for line in row["output"].splitlines())
        if rebind and rebind_timeout:
            for result in rebind:
                result["status"] = "NOT RUN"
                result["failures"].append(
                    "guest forwarder returned no DNS response for the rebind name "
                    "(rebind-unavailable; E-owned native evidence)")
        for result in results:
            if result["status"] != "PASS":
                continue
            links = control_links(result["case"])
            for row in result["attempts"]:
                if row["expectation"] in ("1", "NX"):
                    target = links.get(row["label"])
                    control = all_attempts.get(target)
                    if control is None or control["status"] != "PASS":
                        result["failures"].append(f"missing/failed exact positive control: {row['label']} -> {target}")
            if result["case"].case in ("FL1", "FL2"):
                for target in (links["floor"], "TP1:ipv4:lan-tcp80" if result["case"].case == "FL2" else "LC1:ipv4:lan-tcp80"):
                    if target not in all_attempts or all_attempts[target]["status"] != "PASS":
                        result["failures"].append(f"floor control failed: {target}")
            if result["failures"]:
                result["status"] = "FAIL"
        primary = interrupted or (1 if any(r["status"] == "FAIL" for r in results) else 0)
    except _load_owned_launch().LaunchInterrupted as error:
        primary = 128 + error.signum
    except KeyboardInterrupt:
        primary = 130
    except (OSError, ValueError, RuntimeError, TimeoutError) as error:
        primary = 1
        append_owned(work, {"phase": "run-primary-error", "error": str(error)})
        print(f"harness: {error}", file=sys.stderr)
    finally:
        cleanup_errors = cleanup_run(work, args.binary, launches, fixture)
        cleanup_errors.extend(remove_credentials(work))
        observed_cases = {(r["case"].case, r["case"].variant) for r in results}
        for case in selected_cases(args.smoke):
            if (case.case, case.variant) not in observed_cases:
                results.append({"case": case, "status": "NOT RUN", "failures": ["run aborted before case"], "attempts": []})
        with (work / "summary.tsv").open("w") as summary:
            summary.write("mode\tcase\tvariant\tattempt\tprotocol\tendpoint\tcontrol\tstatus\treason\n")
            for result in results:
                case = result["case"]
                for row in result["attempts"] or [{"label": "case", "protocol": "-", "endpoint": "-"}]:
                    summary.write("\t".join(("SMOKE" if args.smoke else "NATIVE", case.case, case.variant,
                        row["label"], row["protocol"], row["endpoint"], control_links(case).get(row["label"], "-"),
                        result["status"], "; ".join(result["failures"]))) + "\n")
            summary.write(f"RUN\tprimary\t-\t-\t-\t-\t-\t{'FAIL' if primary else 'PASS'}\tstatus={primary}\n")
            summary.write(f"RUN\tcleanup\t-\t-\t-\t-\t-\t{'FAIL' if cleanup_errors else 'PASS'}\t{'; '.join(cleanup_errors)}\n")
        append_owned(work, {"phase": "run-result", "primary_status": primary, "cleanup_errors": cleanup_errors})
        signal.signal(signal.SIGTERM, previous_term)
    return primary or (1 if cleanup_errors else 0)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def self_test() -> int:
    import http.client

    # Ephemeral binds exercise each fixed listener's handler without occupying
    # the native harness ports or accepting a stale external service as evidence.
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        servers, udp_sockets, threads = [], [], []
        stop = threading.Event()
        try:
            for fixed_port in TCP_RECEIPT_PORTS:
                handler = type(f"SelfTestHTTP{fixed_port}", (_ReceiptHTTP,),
                               {"directory": directory})
                server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
                handler.port = server.server_address[1]
                servers.append(server)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                threads.append(thread)
                ident = f"selftest-tcp-{fixed_port}"
                conn = http.client.HTTPConnection("127.0.0.1", handler.port, timeout=3)
                try:
                    conn.request("GET", f"/r/{ident}")
                    response = conn.getresponse()
                    assert response.status == 200
                    assert response.read() == f"receipt {ident}".encode()
                    assert response.getheader("Connection") == "close"
                finally:
                    conn.close()
                assert wait_for_receipt(directory, ident, 0.5) == 0

            for fixed_port in UDP_RECEIPT_PORTS:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", 0))
                sock.settimeout(0.1)
                udp_sockets.append(sock)

                def echo(listener=sock):
                    while not stop.is_set():
                        try:
                            data, peer = listener.recvfrom(512)
                        except socket.timeout:
                            continue
                        _reply_udp(directory, listener, data, peer)

                thread = threading.Thread(target=echo, daemon=True)
                thread.start()
                threads.append(thread)
                ident = f"selftest-udp-{fixed_port}"
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(3)
                    client.sendto(f"id={ident}".encode(), sock.getsockname())
                    assert client.recv(512) == f"ack {ident}".encode()
                assert wait_for_receipt(directory, ident, 0.5) == 0

            with socket.socket() as proxy:
                proxy.bind(("127.0.0.1", 0))
                proxy.listen(1)
                proxy.settimeout(3)

                def connect():
                    conn, _ = proxy.accept()
                    _handle_connect(directory, conn)

                thread = threading.Thread(target=connect, daemon=True)
                thread.start()
                threads.append(thread)
                conn = http.client.HTTPConnection(*proxy.getsockname(), timeout=3)
                target_port = servers[0].server_address[1]
                try:
                    conn.set_tunnel("127.0.0.1", target_port)
                    conn.request("GET", "/r/selftest-proxy")
                    response = conn.getresponse()
                    assert response.status == 200
                    assert response.read() == b"receipt selftest-proxy"
                finally:
                    conn.close()
                assert wait_for_receipt(directory, "selftest-proxy", 0.5) == 0
                assert f"proxy 127.0.0.1:{target_port}" in (directory / RECEIPTS_NAME).read_text().splitlines()

            started = time.monotonic()
            assert wait_for_receipt(directory, "selftest-never", 3) == 1
            elapsed = time.monotonic() - started
            assert 3 <= elapsed <= 3.5, f"absence bound: {elapsed}"
            assert wait_for_receipt(directory, "selftest-tcp", 0) == 1, "ID prefix matched"
        finally:
            stop.set()
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=4)
                if thread.is_alive():
                    raise RuntimeError("self-test fixture did not stop")
            for sock in udp_sockets:
                sock.close()
        print("self-test: both TCP, both UDP, CONNECT and full 3s absence OK")
        return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    serve_p = sub.add_parser("serve")
    serve_p.add_argument("--dir", required=True, type=Path)
    serve_p.add_argument("--lan", default="")
    serve_p.add_argument("--ephemeral-ports", action="store_true")

    wait_p = sub.add_parser("wait-receipt")
    wait_p.add_argument("--dir", required=True, type=Path)
    wait_p.add_argument("id")
    wait_p.add_argument("--timeout", type=float, default=3.0)

    launch_p = sub.add_parser("launch")
    launch_p.add_argument("--work", required=True, type=Path)
    launch_p.add_argument("--case", required=True)
    launch_p.add_argument("--timeout", type=float, default=300.0)
    launch_p.add_argument("--grace", type=float, default=10.0)
    launch_p.add_argument("--env", action="append", default=[])
    launch_p.add_argument("argv", nargs=argparse.REMAINDER)

    shim_p = sub.add_parser("exec-shim")
    shim_p.add_argument("--identity", type=Path)
    shim_p.add_argument("--environment", required=True)
    shim_p.add_argument("--output", required=True, type=Path)
    shim_p.add_argument("argv", nargs=argparse.REMAINDER)

    health_p = sub.add_parser("health")
    health_p.add_argument("--dir", required=True, type=Path)

    ingress_p = sub.add_parser("ingress")
    ingress_p.add_argument("--work", required=True, type=Path)
    ingress_p.add_argument("--case", required=True)
    ingress_p.add_argument("--id", required=True)
    resolve_p = sub.add_parser("resolve")
    resolve_p.add_argument("name")
    resolve_p.add_argument("address")

    run_p = sub.add_parser("run")
    run_p.add_argument("--print-plan", action="store_true")
    run_p.add_argument("--smoke", action="store_true")
    run_p.add_argument("--work", type=Path)
    run_p.add_argument("--binary", default=os.environ.get("AGENT_VM_BIN"))
    run_p.add_argument("--assets", default=os.environ.get("AGENT_VM_E2E_RELEASE_ASSETS_DIR"))
    run_p.add_argument("--lan", default=os.environ.get("AGENT_VM_EGRESS_LAN"))
    run_p.add_argument("--rebind", default=os.environ.get("AGENT_VM_EGRESS_REBIND_NAME", ""))

    sub.add_parser("self-test")

    args = parser.parse_args(argv)
    if args.command == "exec-shim":
        return exec_shim(args.identity, args.output, args.argv[1:] if args.argv[:1] == ["--"] else args.argv, json.loads(args.environment))
    if args.command == "health":
        return fixture_health(args.dir)
    if args.command == "ingress":
        return ingress_driver(args.work, args.case, args.id)
    if args.command == "resolve":
        addresses = {row[4][0] for row in socket.getaddrinfo(args.name, 80, socket.AF_INET)}
        print(json.dumps({"name": args.name, "addresses": sorted(addresses)}))
        return 0 if args.address in addresses else 1
    if args.command == "run":
        return orchestrate(args)
    if args.command == "serve":
        return serve(args.dir, args.ephemeral_ports)
    if args.command == "wait-receipt":
        return wait_for_receipt(args.dir, args.id, args.timeout)
    if args.command == "self-test":
        return self_test()
    if args.command == "launch":
        argv = args.argv
        if argv and argv[0] == "--":
            argv = argv[1:]
        return launch(args.work, args.case, args.timeout, args.grace, args.env, argv)
    return 2


if __name__ == "__main__":
    sys.exit(main())
