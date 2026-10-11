#!/usr/bin/env python3
"""Receipt-only TLS and opaque listeners: no certificate or crypto dependency.

The TLS listener records the upstream ClientHello, never completes a handshake.
It therefore observes a dial, not an HTTPS success or upstream certificate trust.
"""
import socket
import struct
import threading


def client_hello_sni(record):
    """Reject truncated framing instead of treating it as a no-SNI ClientHello."""
    def take(data, offset, length):
        if offset + length > len(data):
            raise ValueError("truncated ClientHello")
        return data[offset:offset + length], offset + length

    header, _ = take(record, 0, 5)
    if header[0] != 22:
        raise ValueError("not TLS handshake")
    payload, end = take(record, 5, int.from_bytes(header[3:5], "big"))
    handshake, _ = take(payload, 0, 4)
    if end != len(record) or handshake[0] != 1:
        raise ValueError("not one ClientHello record")
    body, end = take(payload, 4, int.from_bytes(handshake[1:4], "big"))
    if end != len(payload):
        raise ValueError("handshake length mismatch")
    _, pos = take(body, 0, 34)
    length, pos = take(body, pos, 1)
    _, pos = take(body, pos, length[0])
    length, pos = take(body, pos, 2)
    _, pos = take(body, pos, int.from_bytes(length, "big"))
    length, pos = take(body, pos, 1)
    _, pos = take(body, pos, length[0])
    length, pos = take(body, pos, 2)
    extensions, end = take(body, pos, int.from_bytes(length, "big"))
    if end != len(body):
        raise ValueError("extension length mismatch")
    pos = 0
    names = []
    while pos < len(extensions):
        header, pos = take(extensions, pos, 4)
        extension, pos = take(extensions, pos, int.from_bytes(header[2:4], "big"))
        if header[:2] != b"\x00\x00":
            continue
        length, at = take(extension, 0, 2)
        if int.from_bytes(length, "big") != len(extension) - 2:
            raise ValueError("server-name list length mismatch")
        while at < len(extension):
            kind, at = take(extension, at, 1)
            length, at = take(extension, at, 2)
            name, at = take(extension, at, int.from_bytes(length, "big"))
            if kind == b"\x00":
                text = name.decode("ascii")
                if not text or any(c.isspace() or ord(c) < 32 for c in text):
                    raise ValueError("unsafe SNI receipt")
                names.append(text)
    if len(names) > 1:
        raise ValueError("multiple host names")
    return names[0] if names else None


def read_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ValueError("EOF")
        data += chunk
    return data


def handle(conn, peer, port, kind, record):
    with conn:
        conn.settimeout(3)
        try:
            if kind == "tls":
                first = read_exact(conn, 1)
                if first != b"\x16":
                    data = first
                    while len(data) <= 65536:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    record(f"tcp-plain {port} {peer[0]} {data.hex()}")
                    return
                header = first + read_exact(conn, 4)
                size = int.from_bytes(header[3:5], "big")
                if size > 16384:
                    raise ValueError("oversized TLS record")
                name = client_hello_sni(header + read_exact(conn, size))
                record(f"tls {port} {peer[0]} {name or '-'}")
            else:
                if kind == "banner":
                    conn.sendall(b"220 fixture\r\n")
                data = b""
                while len(data) <= 65536:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    record(f"opaque {port} {peer[0]} {data.hex()}")
        except (OSError, ValueError, UnicodeError):
            return


def serve(directory, port, kind, ready, lock, record):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(16)
    with lock:
        ready.append((kind, listener.getsockname()[1]))
    while True:
        conn, peer = listener.accept()
        threading.Thread(target=handle, args=(conn, peer, listener.getsockname()[1], kind, record), daemon=True).start()


def dns_reply(query, answers):
    """Test-owned A answers for ladder c; the runtime still checks query grants."""
    if len(query) < 12:
        raise ValueError("short DNS header")
    ident, flags, questions, _, _, _ = struct.unpack("!6H", query[:12])
    if flags & 0xf800 or questions != 1:
        raise ValueError("not one ordinary DNS question")
    at, labels = 12, []
    while True:
        if at >= len(query):
            raise ValueError("short DNS name")
        size = query[at]
        at += 1
        if size == 0:
            break
        if size > 63 or at + size > len(query):
            raise ValueError("invalid DNS label")
        labels.append(query[at:at + size].decode("ascii"))
        at += size
    if at + 4 != len(query):
        raise ValueError("question framing")
    qtype, qclass = struct.unpack("!2H", query[at:])
    name = ".".join(labels).lower()
    if qclass != 1:
        raise ValueError("not IN class")
    known = name in answers
    answer = b""
    if known and qtype == 1:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(answers[name])
    response_flags = 0x8080 | (flags & 0x100) | (0 if known else 3)
    return struct.pack("!6H", ident, response_flags, 1, int(bool(answer)), 0, 0) + query[12:] + answer


def serve_dns(address, answers, ready, lock):
    # No SO_REUSEADDR: an existing :53 listener must never be shadowed.
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(address)
    with lock:
        ready.append(("dns", listener.getsockname()[1]))
    while True:
        query, peer = listener.recvfrom(4096)
        try:
            listener.sendto(dns_reply(query, answers), peer)
        except (ValueError, UnicodeError):
            continue


def self_test():
    import ssl
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    outgoing = ssl.MemoryBIO()
    tls = client.wrap_bio(ssl.MemoryBIO(), outgoing, server_side=False, server_hostname="fixture.example")
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = outgoing.read()
    assert client_hello_sni(hello) == "fixture.example"
    for length in range(len(hello)):
        try:
            client_hello_sni(hello[:length])
        except (ValueError, IndexError):
            continue
        raise AssertionError(f"truncated input accepted: {length}")
    for kind, payload in [("tls", hello), ("opaque", b"PING x\r\n\r\n"), ("opaque", bytes(range(256))), ("banner", b"QUIT\r\n"),
                          ("tls", b"PING x\r\n\r\n")]:
        left, right = socket.socketpair()
        receipts = []
        thread = threading.Thread(target=handle, args=(left, ("127.0.0.1", 1), 1234, kind, receipts.append))
        thread.start()
        with right:
            if kind == "banner":
                assert read_exact(right, 13) == b"220 fixture\r\n"
            right.sendall(payload)
            right.shutdown(socket.SHUT_WR)
        thread.join(4)
        assert not thread.is_alive()
        if kind == "tls" and payload != hello:
            expected = f"tcp-plain 1234 127.0.0.1 {payload.hex()}"
        elif kind == "tls":
            expected = "tls 1234 127.0.0.1 fixture.example"
        else:
            expected = f"opaque 1234 127.0.0.1 {payload.hex()}"
        assert expected in receipts, receipts
    question = struct.pack("!6H", 123, 0x100, 1, 0, 0, 0) + b"\x07fixture\x07example\x00" + struct.pack("!HH", 1, 1)
    reply = dns_reply(question, {"fixture.example": "10.0.0.5"})
    assert struct.unpack("!6H", reply[:12]) == (123, 0x8180, 1, 1, 0, 0)
    assert reply[-4:] == socket.inet_aton("10.0.0.5")
    assert struct.unpack("!6H", dns_reply(question, {})[:12]) == (123, 0x8183, 1, 0, 0, 0)
    for length in range(len(question)):
        try:
            dns_reply(question[:length], {})
        except ValueError:
            continue
        raise AssertionError(f"truncated DNS question accepted: {length}")
    print("host-only SNI parser and opaque recorder controls PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(self_test())
