#!/usr/bin/env python3
"""Host-only live-wire primitive controls; never native VM evidence."""
import os
from pathlib import Path
import shlex
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

PROBE = Path(__file__).resolve().parents[1] / "fixtures/egress-probe.sh"
BASH = shutil.which("bash")


def probe(command, setup="", env=None, timeout=8):
    return subprocess.run([BASH, "-c", f"EGRESS_PROBE_LIB=1 . {shlex.quote(str(PROBE))}\n"
                           + setup + "\n" + command], capture_output=True, text=True,
                          env=env, timeout=timeout)


class Peer:
    def __init__(self, handler, udp=False):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        self.error = None
        self.connections = 0
        self.peers = []
        self.stop = threading.Event()
        self.udp = udp
        if not udp:
            self.socket.listen(8)
        self.socket.settimeout(0.1)

        def run():
            while not self.stop.is_set():
                try:
                    if udp:
                        data, addr = self.socket.recvfrom(4096)
                        self.peers.append(addr)
                        handler(self.socket, data, addr, self.stop)
                    else:
                        conn, addr = self.socket.accept()
                        self.connections += 1
                        with conn:
                            conn.settimeout(6)
                            handler(conn, self.stop)
                except socket.timeout:
                    continue
                except (BrokenPipeError, ConnectionResetError):
                    continue
                except OSError as error:
                    if not self.stop.is_set():
                        self.error = error
                    return
                except Exception as error:
                    self.error = error
                    return
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.stop.set()
        self.thread.join(7)
        self.socket.close()
        if self.thread.is_alive():
            raise AssertionError("peer did not stop")
        if self.error:
            raise self.error


def exact(conn, count):
    data = b""
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise AssertionError("early request EOF")
        data += chunk
    return data


def dns_reply(query, address=None):
    # Independent wire oracle: preserve ID and question, provide NX or one A RR.
    answer = b"" if address is None else b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
    return query[:2] + struct.pack("!HHHHH", 0x8183 if address is None else 0x8180,
                                  1, 0 if address is None else 1, 0, 0) + query[12:] + answer


class WireContract(unittest.TestCase):
    def test_http_fragmentation_exact_body_and_single_connection(self):
        for body, status in [(b"receipt wire", 0), (b"receipt wir", 1),
                             (b"receipt wire\n", 1), (b"receipt wire\x00", 1)]:
            def handler(conn, stop):
                conn.recv(4096)
                length = 12 if status == 0 or len(body) < 12 else len(body)
                response = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(length).encode() + b"\r\n\r\n" + body
                for byte in response:
                    conn.sendall(bytes([byte]))
                    time.sleep(0.001)
            with self.subTest(body=body), Peer(handler) as peer:
                result = probe(f"http_get 127.0.0.1 {peer.port} wire")
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertEqual(result.stdout.strip(), "HTTP_OK wire" if status == 0 else "HTTP_FAIL wire")
                self.assertEqual(peer.connections, 1)

    def test_http_public_keep_open_and_invalid_lines(self):
        for line, status in [(b"HTTP/1.1 204 No Content\r\n", 0),
                             (b"HTTP/1.1 204 No Content\n", 1), (b"garbage\r\n", 1)]:
            def handler(conn, stop):
                conn.recv(4096)
                for byte in line:
                    conn.sendall(bytes([byte]))
                stop.wait(6)
            with self.subTest(line=line), Peer(handler) as peer:
                start = time.monotonic()
                result = probe(f"http_public 127.0.0.1 {peer.port}")
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertLess(time.monotonic() - start, 2)
                self.assertEqual(peer.connections, 1)

    def test_udp_one_socket_wrong_ack_no_ack_and_usage(self):
        for reply, status in [(b"ack wire", 0), (b"ack wrong", 1), (None, 1)]:
            def handler(sock, data, addr, stop):
                self.assertEqual(data, b"id=wire")
                if reply is not None:
                    sock.sendto(reply, addr)
            with self.subTest(reply=reply), Peer(handler, udp=True) as peer:
                result = probe(f"udp_send 127.0.0.1 {peer.port} wire")
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertEqual(len(peer.peers), 1)
        for command in ["http_get", "http_public", "udp_send", "dns_status", "listen"]:
            self.assertEqual(probe(command).returncode, 2)

    def test_dns_fragmented_keep_open_nx_ok_and_invalid_frames(self):
        for mode, status in [("nx", 0), ("ok", 0), ("short-prefix", 1),
                             ("short-body", 1), ("zero", 1), ("oversize", 1),
                             ("wrong-id", 1), ("wrong-question", 1), ("wrong-qr", 1),
                             ("cycle", 1)]:
            def handler(conn, stop):
                size = struct.unpack("!H", exact(conn, 2))[0]
                query = exact(conn, size)
                response = dns_reply(query, "192.168.20.7" if mode == "ok" else None)
                if mode == "wrong-id":
                    response = bytes([response[0] ^ 1]) + response[1:]
                if mode == "wrong-question":
                    response = response[:13] + b"X" + response[14:]
                if mode == "wrong-qr":
                    response = response[:2] + b"\x01" + response[3:]
                if mode == "cycle":
                    response = response[:12] + b"\xc0\x0c\x00\x01\x00\x01"
                frame = struct.pack("!H", len(response)) + response
                if mode == "short-prefix": frame = frame[:1]
                if mode == "short-body": frame = frame[:-1]
                if mode == "zero": frame = b"\x00\x00"
                if mode == "oversize": frame = struct.pack("!H", 4097)
                for byte in frame:
                    conn.sendall(bytes([byte]))
                    time.sleep(0.001)
                if mode in ("nx", "ok"):
                    stop.wait(6)
            with self.subTest(mode=mode), Peer(handler) as peer:
                env = {**os.environ, "EGRESS_PROBE_DNS_PORT": str(peer.port)}
                start = time.monotonic()
                result = probe("dns_status 127.0.0.1 example.com tcp", env=env)
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertLess(time.monotonic() - start, 2)
                if mode == "ok": self.assertIn("a=192.168.20.7", result.stdout)
                if mode == "nx": self.assertIn("rcode=3", result.stdout)

    def test_total_deadlines_withheld_prefix_body_connect_and_write(self):
        for kind in ("prefix", "body", "split-deadline", "http", "connect-http", "connect-dns", "write-http", "write-dns"):
            def handler(conn, stop):
                if kind in ("prefix", "body", "split-deadline"):
                    size = struct.unpack("!H", exact(conn, 2))[0]
                    query = exact(conn, size)
                    if kind == "body":
                        conn.sendall(struct.pack("!H", len(dns_reply(query))))
                    elif kind == "split-deadline":
                        stop.wait(1.8)
                        response = dns_reply(query)
                        conn.sendall(struct.pack("!H", len(response)))
                        stop.wait(1.8)
                        conn.sendall(response)
                else:
                    conn.recv(4096)
                stop.wait(7)
            with self.subTest(kind=kind), Peer(handler) as peer:
                is_http = "http" in kind
                setup = ""
                if kind.startswith("connect"):
                    # A blocked shell redirection cannot be reproduced reliably
                    # using host routing. Fault-inject the exec primitive itself.
                    setup = "exec() { sleep 30; }"
                if kind == "write-http":
                    setup = "printf() { if [[ $1 == GET* ]]; then sleep 30; else builtin printf \"$@\"; fi; }"
                if kind == "write-dns":
                    setup = "printf() { if [[ -e /dev/fd/6 && $1 == %b ]]; then sleep 30; else builtin printf \"$@\"; fi; }"
                command = f"http_get 127.0.0.1 {peer.port} wire" if is_http else "dns_status 127.0.0.1 example.com tcp"
                env = {**os.environ, "EGRESS_PROBE_DNS_PORT": str(peer.port)}
                start = time.monotonic()
                result = probe(command, setup, env)
                elapsed = time.monotonic() - start
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("HTTP_FAIL" if is_http else "TIMEOUT", result.stdout)
                self.assertGreater(elapsed, 3.5 if is_http else 2.5)
                self.assertLess(elapsed, 6.5 if is_http else 4.5)

    def test_dns_query_encoding_and_udp_short_datagram(self):
        expected = "123401000001000000000000076578616d706c6503636f6d0000010001"
        result = probe("printf '%b' \"$(_dns_query_escapes 4660 example.com)\" | od -An -tx1 -v")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual("".join(result.stdout.split()), expected)
        committed = PROBE.with_name("egress-dns-query.hex").read_text()
        self.assertEqual("".join(committed.split()), expected)
        for short in (False, True):
            def handler(sock, data, addr, stop):
                self.assertEqual(data[2:].hex(), expected[4:])
                response = dns_reply(data)
                sock.sendto(response[:10] if short else response, addr)
            with self.subTest(short=short), Peer(handler, udp=True) as peer:
                result = probe("dns_status 127.0.0.1 example.com udp",
                               env={**os.environ, "EGRESS_PROBE_DNS_PORT": str(peer.port)})
                self.assertEqual(result.returncode, 1 if short else 0, result.stdout + result.stderr)
                self.assertEqual(len(peer.peers), 1)

    def test_gateway_skips_ipv6(self):
        # Preserve the production /etc/resolv.conf; supply a mixed-family stream
        # to the actual awk program rather than substituting the gateway helper.
        setup = """awk() { command awk "$1" <<'EOF'
nameserver 2606:4700:4700::1111
nameserver 192.168.20.1
nameserver 100.64.0.1
EOF
}
"""
        result = probe("gateway", setup)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "192.168.20.1")

    def test_listener_python_and_node_with_real_curl_and_reap(self):
        for implementation in ("python3", "node"):
            self.assertIsNotNone(shutil.which(implementation), f"required host-only control: {implementation}")
            with self.subTest(implementation=implementation), tempfile.TemporaryDirectory() as tmp:
                # Reserve a free port, then release it before the listener binds.
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    port = reservation.getsockname()[1]
                log = Path(tmp) / "listener.log"
                setup = ""
                if implementation == "node":
                    setup = "command() { if [[ ${1:-} == -v && ${2:-} == python3 ]]; then return 1; fi; builtin command \"$@\"; }"
                with log.open("w") as output:
                    proc = subprocess.Popen([BASH, "-c", f"EGRESS_PROBE_LIB=1 . {shlex.quote(str(PROBE))}\n" + setup + f"\nlisten {port} unique_wire"], stdout=output, stderr=output)
                    try:
                        deadline = time.monotonic() + 3
                        while f"INGRESS_READY unique_wire {port}\n" not in log.read_text():
                            self.assertIsNone(proc.poll(), log.read_text())
                            self.assertLess(time.monotonic(), deadline, log.read_text())
                            time.sleep(0.02)
                        result = subprocess.run(["curl", "--silent", "--show-error", "--noproxy", "*", "--connect-timeout", "2", "--max-time", "3", f"http://127.0.0.1:{port}/"], capture_output=True, timeout=5)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout, b"ingress unique_wire")
                        self.assertEqual(proc.wait(timeout=3), 0, log.read_text())
                    finally:
                        if proc.poll() is None:
                            proc.terminate()
                            proc.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
