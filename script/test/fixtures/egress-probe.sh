#!/usr/bin/env bash
# Guest/host probe library for the #302 A1 egress harness.
#
# Two roles:
#   * sourced as a library (`EGRESS_PROBE_LIB=1 . ./egress-probe.sh`) for the
#     project `.agent-vm.runtime.sh` hooks, where it defines the probe
#     functions and returns without dispatching or printing a banner;
#   * executed as the guest tool (`bash ./egress-probe.sh <CASE> ...`), where it
#     dispatches one named case and prints `CASE <ID> BEGIN/END`.
#
# Exit-status contract (the harness treats any other status as a harness bug):
#   0  the probe validated its success
#   1  a network, timeout, or invalid-reply failure
#   2  usage / internal encoding / decoder error
# The documented machine line is printed in both the 0 and the 1 case, so the
# harness can distinguish a genuine denial from a probe mistake.
#
# `set -e` is deliberately omitted: every probe converts a failed syscall into
# its status code rather than aborting, which is the whole point of the tool.
set -uo pipefail

PROBE_OK=0
PROBE_NET=1
PROBE_USAGE=2

# Milliseconds since the epoch (bash 5 `EPOCHREALTIME`), for the DNS `ms=` field.
_epoch_ms() {
    local t="${EPOCHREALTIME/./}"
    echo $(( t / 1000 ))
}

# A total deadline in whole seconds, measured from `_probe_now`.
_probe_now() { date +%s; }

# Read one CRLF/LF-terminated line from file descriptor $1 before absolute epoch
# deadline $2 into the variable named by $3. Returns 1 at the deadline or EOF.
_probe_read_line() {
    local fd="$1" deadline="$2" __var="$3" __line remaining
    remaining=$(( deadline - $(_probe_now) ))
    (( remaining > 0 )) || return 1
    IFS= read -r -t "$remaining" -u "$fd" __line || return 1
    [[ "$__line" == *$'\r' ]] || return 1
    __line="${__line%$'\r'}"
    printf -v "$__var" '%s' "$__line"
}

# The deadline owns the entire worker, including shell socket redirections and
# builtin writes. Read-only deadlines cannot bound a blocked connect or write.
_probe_bounded() {
    local seconds="$1" worker="$2" failure="$3" rc=0 definitions
    shift 3
    definitions=$(declare -f)
    timeout --kill-after=1 "$seconds" bash -c "PROBE_OK=0; PROBE_NET=1; PROBE_USAGE=2
$definitions
$worker \"\$@\"" probe-worker "$@" || rc=$?
    case "$rc" in
        124|137) echo "$failure"; return "$PROBE_NET" ;;
        *) return "$rc" ;;
    esac
}

http_get() { _probe_bounded 5 _http_get "HTTP_FAIL ${3:-usage}" "$@"; }
http_public() { _probe_bounded 5 _http_public "HTTP_FAIL ${1:-usage}:${2:-}" "$@"; }
dns_status() { _probe_bounded 3 _dns_status "DNS ${3:-} ${1:-} ${2:-} TIMEOUT" "$@"; }

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

# http_get HOST PORT ID: request `GET /r/ID` and require a complete, framed 200
# with an exact body `receipt ID`. Aggregates every read under one 5 s deadline
# and never treats a partial body as success.
_http_get() {
    local host="${1:-}" port="${2:-}" id="${3:-}" deadline
    if [[ -z "$host" || -z "$port" || -z "$id" ]]; then
        echo "HTTP_FAIL usage"
        return "$PROBE_USAGE"
    fi
    deadline=$(( $(_probe_now) + 5 ))
    local body status="" length="" line headers_done=0 expected_hex actual_hex cleanup
    { exec 3<>"/dev/tcp/$host/$port"; } 2>/dev/null || {
        echo "HTTP_FAIL $id"
        return "$PROBE_NET"
    }
    printf 'GET /r/%s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n' "$id" "$host" >&3 || {
        exec 3<&- 3>&-
        echo "HTTP_FAIL $id"
        return "$PROBE_NET"
    }
    if ! _probe_read_line 3 "$deadline" line; then
        exec 3<&- 3>&-
        echo "HTTP_FAIL $id"
        return "$PROBE_NET"
    fi
    if [[ "$line" =~ ^HTTP/1\.[01][[:space:]]([0-9]{3})[[:space:]] ]]; then
        status="${BASH_REMATCH[1]}"
    fi
    while _probe_read_line 3 "$deadline" line; do
        [[ -z "$line" ]] && { headers_done=1; break; }
        case "${line,,}" in
            content-length:*) length="${line#*: }" ;;
        esac
    done
    if [[ "$status" != "200" || ! "$length" =~ ^[0-9]{1,9}$ ]] ||
       (( headers_done != 1 || 10#$length != ${#id} + 8 )); then
        exec 3<&- 3>&-
        echo "HTTP_FAIL $id"
        return "$PROBE_NET"
    fi
    body=$(mktemp) || return "$PROBE_USAGE"
    printf -v cleanup 'rm -f -- %q' "$body"
    # Capture the shell-escaped owned path before local variables go out of scope.
    # shellcheck disable=SC2064
    trap "$cleanup" EXIT
    dd bs=1 count="$length" <&3 >"$body" 2>/dev/null
    exec 3<&- 3>&-
    expected_hex=$(printf 'receipt %s' "$id" | od -An -tx1 -v)
    actual_hex=$(od -An -tx1 -v "$body")
    if [[ "$actual_hex" != "$expected_hex" ]]; then
        echo "HTTP_FAIL $id"
        return "$PROBE_NET"
    fi
    echo "HTTP_OK $id"
    return "$PROBE_OK"
}

# http_public IP PORT: read a complete status line from `HEAD / HTTP/1.0`
# (read until CRLF, never a single socket read). No third-party receipt is
# expected; only the status line is validated.
_http_public() {
    local ip="${1:-}" port="${2:-}" deadline line
    if [[ -z "$ip" || -z "$port" ]]; then
        echo "HTTP_FAIL usage"
        return "$PROBE_USAGE"
    fi
    deadline=$(( $(_probe_now) + 5 ))
    { exec 3<>"/dev/tcp/$ip/$port"; } 2>/dev/null || {
        echo "HTTP_FAIL $ip:$port"
        return "$PROBE_NET"
    }
    printf 'HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n' "$ip" >&3 || {
        exec 3<&- 3>&-
        echo "HTTP_FAIL $ip:$port"
        return "$PROBE_NET"
    }
    if ! _probe_read_line 3 "$deadline" line; then
        exec 3<&- 3>&-
        echo "HTTP_FAIL $ip:$port"
        return "$PROBE_NET"
    fi
    exec 3<&- 3>&-
    if [[ "$line" =~ ^HTTP/1\.[01][[:space:]]([0-9]{3})[[:space:]] ]]; then
        echo "HTTP_STATUS ${BASH_REMATCH[1]}"
        return "$PROBE_OK"
    fi
    echo "HTTP_FAIL $ip:$port"
    return "$PROBE_NET"
}

# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------

# udp_send HOST PORT ID: send `id=ID` and read one reply datagram from the *same*
# socket (never a second ephemeral socket). The reply must equal `ack ID`.
udp_send() {
    local host="${1:-}" port="${2:-}" id="${3:-}"
    if [[ -z "$host" || -z "$port" || -z "$id" ]]; then
        echo "UDP_NOACK usage"
        return "$PROBE_USAGE"
    fi
    { exec 4<>"/dev/udp/$host/$port"; } 2>/dev/null || {
        echo "UDP_NOACK $id"
        return "$PROBE_NET"
    }
    printf 'id=%s' "$id" >&4 || {
        exec 4<&- 4>&-
        echo "UDP_NOACK $id"
        return "$PROBE_NET"
    }
    local reply
    reply=$(timeout 3 dd bs=512 count=1 <&4 2>/dev/null)
    exec 4<&- 4>&-
    if [[ "$reply" == "ack $id" ]]; then
        echo "UDP_ACK $id"
        return "$PROBE_OK"
    fi
    echo "UDP_NOACK $id"
    return "$PROBE_NET"
}

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

# The octal-escape text for a `NAME` A/IN query with the given 16-bit ID. The
# *text* carries no NUL, so it is safe in a shell variable; `printf '%b'`
# materializes the binary query onto a UDP/TCP fd with a builtin (an external
# `cat >&N` does not reliably send on macOS).
_dns_query_escapes() {
    local id="$1" name="$2" label out
    out=$(printf '\\%03o' $(( (id >> 8) & 0xFF )) $(( id & 0xFF )) 1 0 0 1 0 0 0 0 0 0)
    local IFS='.'
    for label in $name; do
        out+=$(printf '\\%03o' "${#label}")
        out+="$label"
    done
    out+=$(printf '\\%03o' 0 0 1 0 1)
    printf '%s' "$out"
}

# Parse the name starting at byte offset $1 of the global DNS_BYTES array.
# Sets DNS_NAME_END (offset just past the name in the current record) and
# DNS_NAME (reconstructed). Rejects out-of-range and cyclic compression
# pointers. Returns 1 on any structural error.
_dns_parse_name() {
    local start="$1"
    local i="$start" end=-1 jumps=0 total=0 b
    DNS_NAME=""
    while :; do
        (( i < ${#DNS_BYTES[@]} )) || return 1
        b="${DNS_BYTES[i]}"
        if (( b == 0 )); then
            (( end < 0 )) && end=$(( i + 1 ))
            break
        fi
        if (( (b & 0xC0) == 0xC0 )); then
            (( i + 1 < ${#DNS_BYTES[@]} )) || return 1
            local ptr=$(( ((b & 0x3F) << 8) | DNS_BYTES[i+1] ))
            (( ptr < ${#DNS_BYTES[@]} )) || return 1
            (( end < 0 )) && end=$(( i + 2 ))
            (( jumps++ )) && :
            (( jumps <= 16 )) || return 1
            i="$ptr"
            continue
        fi
        (( (b & 0xC0) == 0 )) || return 1
        (( i + 1 + b <= ${#DNS_BYTES[@]} )) || return 1
        (( total += b )); (( total <= 255 )) || return 1
        local j
        for (( j = 0; j < b; j++ )); do
            local c="${DNS_BYTES[i+1+j]}"
            local ch
            printf -v ch '%b' "\\$(printf '%03o' "$c")"
            DNS_NAME+="$ch"
        done
        DNS_NAME+="."
        i=$(( i + 1 + b ))
    done
    DNS_NAME="${DNS_NAME%.}"
    DNS_NAME_END="$end"
    return 0
}

# dns_status SERVER NAME udp|tcp: send one query with a random 16-bit ID and
# decode the framed response under a 3 s whole-transaction deadline. Prints the
# documented machine line in every non-usage case; the rcode is for the caller
# to assert (NXDOMAIN is a valid, status-0 response).
_dns_status() {
    local server="${1:-}" name="${2:-}" proto="${3:-}"
    if [[ -z "$server" || -z "$name" || -z "$proto" ]]; then
        echo "DNS usage"
        return "$PROBE_USAGE"
    fi
    # The resolver port is 53 in production; the boot-free contract overrides it
    # so it can run the fake peer without binding a privileged port.
    local port="${EGRESS_PROBE_DNS_PORT:-53}"
    local id=$(( (RANDOM << 1 | RANDOM) & 0xFFFF ))
    DNS_START_MS=$(_epoch_ms)
    local escapes qbytes
    escapes=$(_dns_query_escapes "$id" "$name")
    qbytes=$(printf '%b' "$escapes" | wc -c)
    local rfile cleanup
    rfile=$(mktemp) || { echo "DNS INVALID internal"; return "$PROBE_USAGE"; }

    printf -v cleanup 'rm -f -- %q' "$rfile"
    # Capture the shell-escaped owned path before local variables go out of scope.
    # shellcheck disable=SC2064
    trap "$cleanup" EXIT

    if [[ "$proto" == "udp" ]]; then
        { exec 5<>"/dev/udp/$server/$port"; } 2>/dev/null || {
            rm -f "$rfile"; echo "DNS udp $server $name TIMEOUT"; return "$PROBE_NET";
        }
        printf '%b' "$escapes" >&5 || {
            exec 5<&- 5>&-; rm -f "$rfile"; echo "DNS udp $server $name TIMEOUT"; return "$PROBE_NET";
        }
        timeout 3 dd bs=4096 count=1 <&5 2>/dev/null >"$rfile"
        exec 5<&- 5>&-
    elif [[ "$proto" == "tcp" ]]; then
        { exec 6<>"/dev/tcp/$server/$port"; } 2>/dev/null || {
            rm -f "$rfile"; echo "DNS tcp $server $name TIMEOUT"; return "$PROBE_NET";
        }
        printf '%b' "$(printf '\\%03o' $(( (qbytes >> 8) & 0xFF )) $(( qbytes & 0xFF )))" >&6
        printf '%b' "$escapes" >&6
        # Read exactly the two-byte length prefix, then exactly that many body
        # bytes; never read until EOF, so a peer that keeps the socket open
        # still completes one frame.
        local prefix
        prefix=$(timeout 3 dd bs=1 count=2 2>/dev/null <&6 | od -An -tu1 -v)
        local -a prefix_bytes
        read -r -a prefix_bytes <<<"$prefix"
        set -- "${prefix_bytes[@]}"
        if [[ $# -ne 2 ]]; then
            exec 6<&- 6>&-; rm -f "$rfile"
            echo "DNS tcp $server $name TIMEOUT"; return "$PROBE_NET"
        fi
        local frame=$(( ($1 << 8) | $2 ))
        if (( frame < 12 || frame > 4096 )); then
            exec 6<&- 6>&-; rm -f "$rfile"
            echo "DNS tcp $server $name INVALID"; return "$PROBE_NET"
        fi
        timeout 3 dd bs=1 count="$frame" 2>/dev/null <&6 >"$rfile"
        exec 6<&- 6>&-
        local got
        got=$(wc -c <"$rfile")
        if (( got != frame )); then
            rm -f "$rfile"
            echo "DNS tcp $server $name INVALID"; return "$PROBE_NET"
        fi
    else
        rm -f "$rfile"
        echo "DNS usage"
        return "$PROBE_USAGE"
    fi

    _dns_decode "$rfile" "$id" "$name" "$server" "$proto"
    local rc=$?
    rm -f "$rfile"
    return "$rc"
}

# Decode a response file against the query identity and print the machine line.
_dns_decode() {
    local file="$1" id="$2" name="$3" server="$4" proto="$5"
    DNS_BYTES=()
    local line b
    while IFS= read -r line; do
        for b in $line; do DNS_BYTES+=("$b"); done
    done < <(od -An -tu1 -v "$file")
    local n=${#DNS_BYTES[@]}
    local ms=$(( $(_epoch_ms) - ${DNS_START_MS:-0} ))
    if (( n < 12 )); then
        echo "DNS $proto $server $name INVALID ms=$ms"
        return "$PROBE_NET"
    fi
    local rid=$(( (DNS_BYTES[0] << 8) | DNS_BYTES[1] ))
    local flags=$(( (DNS_BYTES[2] << 8) | DNS_BYTES[3] ))
    local qdcount=$(( (DNS_BYTES[4] << 8) | DNS_BYTES[5] ))
    local ancount=$(( (DNS_BYTES[6] << 8) | DNS_BYTES[7] ))
    local qr=$(( (flags >> 15) & 1 ))
    local opcode=$(( (flags >> 11) & 0xF ))
    local tc=$(( (flags >> 9) & 1 ))
    local rcode=$(( flags & 0xF ))
    local id_ok=0 question_ok=0
    (( rid == id )) && id_ok=1
    local qvalid=1
    if (( qdcount == 1 )); then
        _dns_parse_name 12 || qvalid=0
        if (( qvalid )) && (( DNS_NAME_END + 4 <= n )); then
            local qtype=$(( (DNS_BYTES[DNS_NAME_END] << 8) | DNS_BYTES[DNS_NAME_END+1] ))
            local qclass=$(( (DNS_BYTES[DNS_NAME_END+2] << 8) | DNS_BYTES[DNS_NAME_END+3] ))
            if [[ "$DNS_NAME" == "$name" ]] && (( qtype == 1 && qclass == 1 )); then
                question_ok=1
            fi
        fi
    else
        qvalid=0
    fi
    # Parse the answer section, tolerating names that use compression pointers,
    # and collect A records so RB1/H1 can assert the returned endpoint.
    local a_records="" answers_ok=1
    # The answer section starts just past the question's QTYPE/QCLASS (4 bytes).
    local offset=0
    (( question_ok )) && offset=$(( DNS_NAME_END + 4 ))
    local i
    for (( i = 0; i < ancount; i++ )); do
        _dns_parse_name "$offset" || { answers_ok=0; break; }
        offset="$DNS_NAME_END"
        (( offset + 10 <= n )) || { answers_ok=0; break; }
        local atype=$(( (DNS_BYTES[offset] << 8) | DNS_BYTES[offset+1] ))
        local rdlength=$(( (DNS_BYTES[offset+8] << 8) | DNS_BYTES[offset+9] ))
        offset=$(( offset + 10 ))
        (( offset + rdlength <= n )) || { answers_ok=0; break; }
        if (( atype == 1 && rdlength == 4 )); then
            a_records+="${a_records:+,}${DNS_BYTES[offset]}.${DNS_BYTES[offset+1]}.${DNS_BYTES[offset+2]}.${DNS_BYTES[offset+3]}"
        fi
        offset=$(( offset + rdlength ))
    done
    DNS_A="$a_records"
    if (( id_ok == 1 && qr == 1 && opcode == 0 && tc == 0 && question_ok == 1 && answers_ok == 1 )); then
        echo "DNS $proto $server $name id_ok=1 qr=1 question_ok=1 tc=0 rcode=$rcode ancount=$ancount a=$DNS_A ms=$ms"
        return "$PROBE_OK"
    fi
    echo "DNS $proto $server $name INVALID id_ok=$id_ok qr=$qr question_ok=$question_ok tc=$tc rcode=$rcode ms=$ms"
    return "$PROBE_NET"
}

# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

# The first IPv4 nameserver in /etc/resolv.conf, or empty.
gateway() {
    local ns
    ns=$(awk '/^nameserver[[:space:]]/ && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $2; exit}' /etc/resolv.conf 2>/dev/null)
    [[ "$ns" == *.* ]] && printf '%s' "$ns"
}

# 1 iff an IPv6 address is configured; NOT proof of public IPv6 reachability.
has_ipv6() {
    if command -v ip >/dev/null 2>&1 && ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'; then
        echo 1
    elif ifconfig 2>/dev/null | grep -q 'inet6 .*global'; then
        echo 1
    else
        echo 0
    fi
}

# listen PORT ID: bind before advertising readiness, then serve `ingress ID` to
# a single host request. Prefers python3, falls back to node (A5).
listen() {
    local port="${1:-}" id="${2:-}" ready
    if [[ -z "$port" || -z "$id" ]]; then
        echo "LISTEN usage"
        return "$PROBE_USAGE"
    fi
    ready="${3:-INGRESS}"
    if command -v python3 >/dev/null 2>&1; then
        timeout --kill-after=1 15 python3 - "$port" "$id" "$ready" <<'PY'
import socket, sys
port, ident, ready = int(sys.argv[1]), sys.argv[2], sys.argv[3]
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port))
srv.listen(1)
print(f"{ready}_READY {ident} {port}", flush=True)
conn, _ = srv.accept()
conn.recv(1024)
body = f"ingress {ident}".encode()
conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
             b"\r\nConnection: close\r\n\r\n" + body)
conn.close()
PY
        local rc=$?
        (( rc == 0 )) && return "$PROBE_OK"
        return "$PROBE_NET"
    elif command -v node >/dev/null 2>&1; then
        timeout --kill-after=1 15 node - "$port" "$id" "$ready" <<'JS'
const http = require('http');
const [port, ident, ready] = process.argv.slice(2);
const server = http.createServer((req, res) => {
    const body = Buffer.from(`ingress ${ident}`);
    res.writeHead(200, {'Content-Length': body.length, 'Connection': 'close'});
    res.end(body);
    server.close();
});
server.on('error', error => { console.error(error.message); process.exit(1); });
server.listen(Number(port), '0.0.0.0', () => {
    console.log(`${ready}_READY ${ident} ${port}`);
});
JS
        local rc=$?
        (( rc == 0 )) && return "$PROBE_OK"
        return "$PROBE_NET"
    fi
    echo "LISTEN usage (no python3/node)"
    return "$PROBE_USAGE"
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

_probe_case_begin() { echo "CASE $1 BEGIN"; }
_probe_case_end() { echo "CASE $1 END"; }

# Attempts are individually named so the host can join exact receipts and positive
# controls; a tool exit alone is not evidence that a denied host dial never occurred.
_case_flow() {
    local expected="$1" kind="$2" host="$3" port="$4" label="$5" rc=0
    local receipt_id="$attempt_id-$label"
    printf 'ATTEMPT %s %s %s %s %s %s %s\n' "$case_id" "$label" "$kind" "$host" "$port" "$expected" "$receipt_id"
    case "$kind" in
        tcp) http_get "$host" "$port" "$receipt_id" || rc=$? ;;
        udp) udp_send "$host" "$port" "$receipt_id" || rc=$? ;;
        public) http_public "$host" "$port" || rc=$? ;;
        *) return "$PROBE_USAGE" ;;
    esac
    # In particular, usage/internal status 2 must never certify a denial.
    [[ "$rc" -eq "$expected" ]] || { echo "EXPECT_FAIL $label expected=$expected actual=$rc"; return "$PROBE_USAGE"; }
}

_case_dns() {
    local expected="$1" server="$2" name="$3" proto="$4" label="$5" output rc=0
    printf 'ATTEMPT %s %s dns-%s %s 53 %s -\n' "$case_id" "$label" "$proto" "$server" "$expected"
    output=$(dns_status "$server" "$name" "$proto") || rc=$?
    printf '%s\n' "$output"
    (( rc == 0 )) || return "$PROBE_USAGE"
    [[ "$output" == *" id_ok=1 qr=1 question_ok=1 tc=0 "* ]] || return "$PROBE_USAGE"
    local code count addresses ms
    code=${output#* rcode=}; code=${code%% *}
    count=${output#* ancount=}; count=${count%% *}
    addresses=${output#* a=}; addresses=${addresses%% *}
    ms=${output##* ms=}
    [[ "$code" =~ ^[0-9]+$ && "$count" =~ ^[0-9]+$ && "$ms" =~ ^[0-9]+$ ]] || return "$PROBE_USAGE"
    case "$expected" in
        NX) (( code == 3 && ms < 1000 )) || return "$PROBE_USAGE" ;;
        OK) (( code == 0 && count >= 1 )) && [[ -n "$addresses" ]] || return "$PROBE_USAGE" ;;
        *) return "$PROBE_USAGE" ;;
    esac
    CASE_DNS_A=${addresses%%,*}
}

_case_dns_pair() {
    local expected="$1" server="$2" name="$3" label="$4" proto
    for proto in udp tcp; do
        _case_dns "$expected" "$server" "$name" "$proto" "$label-$proto" || return "$PROBE_USAGE"
    done
}

# Receipt-tier TLS probes report an attempt, not handshake success: upstream
# receipt listeners deliberately close before certificate verification completes.
tls_probe() {
    python3 - "$@" <<'PY'
import socket, ssl, sys
if len(sys.argv) != 4:
    raise SystemExit(2)
host, port, name = sys.argv[1:]
try:
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("port")
    context = ssl.create_default_context()
    if name == "-":
        context.check_hostname = False
        name = None
    with socket.create_connection((host, port), timeout=3) as conn:
        with context.wrap_socket(conn, server_hostname=name):
            pass
except ValueError:
    raise SystemExit(2)
except OSError:
    pass
print("TLS_ATTEMPT", host, port, name or "-")
PY
}

https_get() {
    # The dial IP may be pinned only after a same-sandbox forwarded lookup.
    # No -k: the zero-provision CA installation is part of the contract.
    curl -4 --http1.1 --max-time 10 --silent --show-error "$@"
}

opaque_send() {
    python3 - "$@" <<'PY'
import socket, sys
if len(sys.argv) != 4:
    raise SystemExit(2)
try:
    host, port, encoded = sys.argv[1:]
    payload = bytes.fromhex(encoded)
    if len(payload) > 65536:
        raise ValueError("payload budget")
    with socket.create_connection((host, int(port)), timeout=3) as conn:
        conn.sendall(payload)
        conn.shutdown(socket.SHUT_WR)
    print("OPAQUE_SENT", encoded)
except ValueError:
    raise SystemExit(2)
except OSError:
    raise SystemExit(1)
PY
}

server_first() {
    python3 - "$@" <<'PY'
import socket, sys
if len(sys.argv) != 4:
    raise SystemExit(2)
try:
    host, port, encoded = sys.argv[1:]
    with socket.create_connection((host, int(port)), timeout=3) as conn:
        banner = b""
        while len(banner) < 13:
            part = conn.recv(13 - len(banner))
            if not part:
                raise OSError("short banner")
            banner += part
        if banner != b"220 fixture\r\n":
            raise OSError("wrong banner")
        conn.sendall(bytes.fromhex(encoded))
        conn.shutdown(socket.SHUT_WR)
    print("BANNER_OK", banner.hex())
except ValueError:
    raise SystemExit(2)
except OSError:
    raise SystemExit(1)
PY
}

tls_held_two_requests() {
    python3 - "$@" <<'PY'
import http.client, socket, ssl, sys
if len(sys.argv) != 5:
    raise SystemExit(2)
ip, sni, second_host, expectation = sys.argv[1:]
if expectation not in ("allow", "deny"):
    raise SystemExit(2)
connects = 0
try:
    conn = socket.create_connection((ip, 443), timeout=10)
    connects += 1
    with ssl.create_default_context().wrap_socket(conn, server_hostname=sni) as held:
        fd = held.fileno()
        for index, authority in enumerate((sni, second_host)):
            held.sendall(f"GET / HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\n\r\n".encode("ascii"))
            try:
                response = http.client.HTTPResponse(held)
                response.begin()
                # A close-delimited body cannot establish a held connection.
                if response.length is None and not response.chunked:
                    raise ValueError("response has no bounded body framing")
                body = response.read(8 * 1024 * 1024 + 1)
                if len(body) > 8 * 1024 * 1024:
                    raise ValueError("response budget")
                if response.length not in (None, 0):
                    raise OSError("incomplete response body")
                status = response.status
                response.close()
            except (OSError, http.client.HTTPException):
                if index != 1 or expectation != "deny":
                    raise
                if held.fileno() != fd or connects != 1:
                    raise ValueError("connection reopened")
                print("HELD_DENIED connects=1")
                break
            if index == 1 and expectation == "deny":
                raise ValueError("second authority returned an HTTP response")
            if not 200 <= status < 300:
                raise ValueError("non-2xx response")
            if held.fileno() != fd or connects != 1:
                raise ValueError("connection reopened")
            print(f"HELD_OK request={index + 1} connects={connects} fd={fd}")
except (OSError, ValueError, http.client.HTTPException):
    raise SystemExit(1)
PY
}

# ---- #306 hostname tier ---------------------------------------------------
# These attempts are judged by host-side receipts (TLS SNI, opaque payload,
# banner bytes), not by the probe's exit status: a denied dial and a framing or
# rule denial both surface as "no receipt". `expected` is 0 (receipt required)
# or 1 (no receipt). The payload/SNI is the trailing ATTEMPT field so the host
# can join the exact receipt without duplicating the constant.

_case_tls() {  # NAME HOST PORT EXPECTED LABEL
    local name="$1" host="$2" port="$3" expected="$4" label="$5" rc=0
    printf 'ATTEMPT %s %s tls %s %s %s %s %s\n' "$case_id" "$label" "$host" "$port" "$expected" "$attempt_id-$label" "$name"
    tls_probe "$host" "$port" "$name" || rc=$?
    (( rc == PROBE_USAGE )) && return "$PROBE_USAGE"
    return 0
}

_case_binary() {  # PROTOCOL HOST PORT HEX EXPECTED LABEL
    local proto="$1" host="$2" port="$3" hex="$4" expected="$5" label="$6" rc=0
    printf 'ATTEMPT %s %s %s %s %s %s %s %s\n' "$case_id" "$label" "$proto" "$host" "$port" "$expected" "$attempt_id-$label" "$hex"
    if [[ "$proto" == banner ]]; then
        server_first "$host" "$port" "$hex" || rc=$?
    else
        opaque_send "$host" "$port" "$hex" || rc=$?
    fi
    (( rc == PROBE_USAGE )) && return "$PROBE_USAGE"
    return 0
}

_case_https() {  # URL EXPECTED LABEL [RESOLVE_SPEC] [FOLLOW]
    # EXPECTED is "0" (2xx), "1" (not 2xx, or no response), or a 3-digit
    # status. The trailing ATTEMPT field is the resolve spec ("-" when none).
    local url="$1" expected="$2" label="$3" resolve="${4:-}" follow="${5:-}" rc=0 out
    printf 'ATTEMPT %s %s https %s 443 %s %s %s\n' "$case_id" "$label" "$url" "$expected" "$attempt_id-$label" "${resolve:--}"
    local argv=(-o /dev/null -w '%{http_code}')
    [[ -n "$resolve" ]] && argv+=(--resolve "$resolve")
    [[ "$follow" == follow ]] && argv+=(-L)
    out=$(https_get "${argv[@]}" "$url" 2>&1) || rc=$?
    printf 'HTTP_CODE %s rc=%s\n' "${out##*$'\n'}" "$rc"
    return 0
}

_case_http_nohost() {  # HOST PORT EXPECTED LABEL
    # HTTP/1.0 with no Host header: D1 blocks it on numeric flows once any
    # hostname rule exists, so the receipt must be absent.
    local host="$1" port="$2" expected="$3" label="$4" rc=0
    printf 'ATTEMPT %s %s tcp %s %s %s %s %s\n' "$case_id" "$label" "$host" "$port" "$expected" "$attempt_id-$label" "nohost"
    _probe_bounded 5 _http_nohost "HTTP_FAIL $attempt_id-$label" "$host" "$port" "$attempt_id-$label" || rc=$?
    (( rc == PROBE_USAGE )) && return "$PROBE_USAGE"
    return 0
}

_http_nohost() {  # HOST PORT ID
    local host="$1" port="$2" id="$3"
    { exec 3<>"/dev/tcp/$host/$port"; } 2>/dev/null || { echo "HTTP_FAIL $id"; return "$PROBE_NET"; }
    printf 'GET /r/%s HTTP/1.0\r\nConnection: close\r\n\r\n' "$id" >&3 2>/dev/null || true
    exec 3<&- 3>&-
    echo "HTTP_FAIL $id"
    return "$PROBE_NET"
}

_case_held() {  # IP SNI SECOND EXPECTED LABEL
    local ip="$1" sni="$2" second="$3" expected="$4" label="$5" rc=0 expectation
    printf 'ATTEMPT %s %s held %s 443 %s %s %s\n' "$case_id" "$label" "$ip" "$expected" "$attempt_id-$label" "$sni->$second"
    expectation=deny
    [[ "$expected" == 0 ]] && expectation=allow
    tls_held_two_requests "$ip" "$sni" "$second" "$expectation" || rc=$?
    (( rc == PROBE_USAGE )) && return "$PROBE_USAGE"
    return 0
}

_hostname_preflight() {
    local tls_enabled="$1" cmd
    for cmd in python3 curl; do
        command -v "$cmd" >/dev/null || { echo "PREFLIGHT missing=$cmd"; return "$PROBE_USAGE"; }
    done
    python3 -c 'import ssl, socket' >/dev/null 2>&1 || { echo 'PREFLIGHT missing=ssl,socket'; return "$PROBE_USAGE"; }
    if [[ "$tls_enabled" == 1 ]]; then
        [[ -r /.msb/tls/ca.pem ]] || { echo 'PREFLIGHT missing=ca'; return "$PROBE_USAGE"; }
        [[ -n "${SSL_CERT_FILE:-}" && -r "$SSL_CERT_FILE" ]] || { echo 'PREFLIGHT missing=SSL_CERT_FILE'; return "$PROBE_USAGE"; }
        python3 -c 'import os; from pathlib import Path; ca=Path("/.msb/tls/ca.pem").read_bytes().strip(); assert ca in Path(os.environ["SSL_CERT_FILE"]).read_bytes()' || { echo 'PREFLIGHT missing=trusted-ca'; return "$PROBE_USAGE"; }
    elif [[ -e /.msb/tls/ca.pem ]]; then
        echo 'PREFLIGHT unexpected=ca'
        return "$PROBE_USAGE"
    fi
}

_case_preflight() {
    local cmd
    for cmd in bash dd od timeout; do
        command -v "$cmd" >/dev/null || { echo "PREFLIGHT missing=$cmd"; return "$PROBE_USAGE"; }
    done
    [[ -n "${EPOCHREALTIME:-}" ]] || { echo "PREFLIGHT missing=EPOCHREALTIME"; return "$PROBE_USAGE"; }
    _hostname_preflight "${1:-0}" || return "$PROBE_USAGE"
    local gw
    gw=$(gateway) || return "$PROBE_USAGE"
    [[ -n "$gw" ]] || return "$PROBE_USAGE"
    printf 'PREFLIGHT gateway=%s ipv6=%s bash=%s\n' "$gw" "$(has_ipv6)" "$BASH_VERSION"
    # /dev/tcp and /dev/udp availability is calibrated by LC1/HC1, not inferred
    # from an unavailable default-deny endpoint.
}

# CASE ATTEMPT_ID LAN [VARIANT [EXTRA]]. Only declared named cases may execute;
# the host builder supplies unique attempt IDs and runs calibrations first.
_case_dispatch() {
    local gw hmi=host.microsandbox.internal proto expected
    case "$case_id" in
        P0) _case_preflight; return $? ;;
        CL1) sleep 600; return $? ;;
        HK1|HK1c|HK2|HK2c) return 0 ;; # the sourced project hook owns the attempt
    esac
    [[ -n "$lan" ]] || return "$PROBE_USAGE"
    gw=$(gateway) || return "$PROBE_USAGE"
    [[ -n "$gw" ]] || return "$PROBE_USAGE"
    case "$case_id" in
        HNc|HN1|HN2|HN3|HN4|HN5|HN6|OP1|OP2|OP3|RB2|HP1|HP2|HP2c|HP3|HP4|HP5|HP6|HP6c)
            _case_preflight 1 || return "$PROBE_USAGE" ;;
        HN5c|OP1c|OP2c|OP3c)
            _case_preflight 0 || return "$PROBE_USAGE" ;;
    esac
    case "$case_id" in
        LC1)
            _case_flow 0 tcp "$lan" 18080 lan-tcp80 || return 2
            _case_flow 0 tcp "$lan" 18081 lan-tcp81 || return 2
            _case_flow 0 udp "$lan" 19090 lan-udp90 || return 2
            _case_flow 0 udp "$lan" 18080 lan-udp80 || return 2 ;;
        HC1)
            _case_flow 0 tcp "$hmi" 18080 host-tcp80 || return 2
            _case_dns_pair OK "$gw" example.com gateway || return 2 ;;
        I1)
            _case_flow 0 public 1.1.1.1 80 public-1111 || return 2
            _case_flow 0 public 1.0.0.1 80 public-1001 || return 2
            _case_dns_pair OK "$gw" example.com gateway || return 2
            _case_dns_pair OK 1.1.1.1 example.com explicit || return 2
            _case_flow 1 tcp "$lan" 18080 lan-tcp80 || return 2
            _case_flow 1 tcp "$hmi" 18080 host-tcp80 || return 2 ;;
        D1)
            if [[ "$variant" == ipv6 ]]; then
                _case_dns_pair NX 2606:4700:4700::1111 example.com explicit-v6 || return 2
            elif [[ "$variant" == ipv4 ]]; then
                _case_flow 1 tcp "$lan" 18080 lan-tcp80 || return 2
                _case_flow 1 udp "$lan" 19090 lan-udp90 || return 2
                _case_flow 1 tcp "$hmi" 18080 host-tcp80 || return 2
                _case_flow 1 public 1.1.1.1 80 public-1111 || return 2
                _case_dns_pair NX "$gw" example.com gateway || return 2
                _case_dns_pair NX 1.1.1.1 example.com explicit || return 2
            else return 2; fi ;;
        D1f)
            _case_flow 1 tcp "$lan" 18080 lan-tcp80 || return 2
            _case_flow 1 public 1.1.1.1 80 public-1111 || return 2
            _case_dns NX "$gw" example.com udp gateway-udp || return 2 ;;
        L1)
            _case_flow 0 tcp "$lan" 18080 lan-tcp80 || return 2
            _case_flow 0 udp "$lan" 19090 lan-udp90 || return 2
            _case_flow 1 public 1.1.1.1 80 public-1111 || return 2
            _case_flow 1 tcp "$hmi" 18080 host-tcp80 || return 2
            _case_dns_pair NX "$gw" example.com gateway || return 2 ;;
        H1)
            _case_flow 0 tcp "$hmi" 18080 host-tcp80 || return 2
            _case_flow 1 tcp "$lan" 18080 lan-tcp80 || return 2
            _case_flow 1 public 1.1.1.1 80 public-1111 || return 2
            _case_dns_pair OK "$gw" example.com gateway || return 2
            printf 'ANSWER %s\n' "$CASE_DNS_A"
            _case_flow 1 public "$CASE_DNS_A" 80 answer || return 2 ;;
        I1a)
            [[ "$extra" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 2
            _case_flow 0 public "$extra" 80 answer || return 2 ;;
        LH1)
            _case_flow 0 tcp "$lan" 18080 lan-tcp80 || return 2
            _case_flow 0 tcp "$hmi" 18080 host-tcp80 || return 2
            _case_flow 1 public 1.1.1.1 80 public-1111 || return 2 ;;
        AD1)
            _case_flow 0 public 1.1.1.1 80 public-1111 || return 2
            _case_flow 1 public 1.0.0.1 80 public-1001 || return 2
            _case_dns_pair NX "$gw" example.com gateway || return 2
            _case_dns_pair NX 1.1.1.1 example.com explicit || return 2 ;;
        TP1|UP2|CI1|PX1|PX2)
            _case_flow 0 tcp "$lan" 18080 lan-tcp80 || return 2
            if [[ "$case_id" == UP2 ]]; then
                _case_flow 0 udp "$lan" 18080 lan-udp80 || return 2
            elif [[ "$case_id" == TP1 ]]; then
                _case_flow 1 udp "$lan" 18080 lan-udp80 || return 2
            fi
            if [[ "$case_id" != PX2 ]]; then
                _case_flow 1 tcp "$lan" 18081 lan-tcp81 || return 2
            fi ;;
        UP1)
            _case_flow 0 udp "$lan" 19090 lan-udp90 || return 2
            _case_flow 1 udp "$lan" 18080 lan-udp80 || return 2
            _case_flow 1 tcp "$lan" 18080 lan-tcp80 || return 2 ;;
        RB1)
            case "$variant" in
                internet|port|tcp-port|udp-port) expected=NX ;;
                address|tcp|udp) expected=OK ;;
                *) return 2 ;;
            esac
            [[ -n "$extra" ]] || return 2
            for proto in udp tcp; do
                _case_dns "$expected" "$gw" "$extra" "$proto" "rebind-$proto" || return 2
                if [[ "$expected" == OK ]]; then
                    [[ "$CASE_DNS_A" == "$lan" ]] || return 2
                fi
            done ;;
        PX3)
            _case_flow 1 tcp "$lan" 18080 lan-tcp80 || return 2
            _case_flow 1 public 1.1.1.1 80 public-1111 || return 2 ;;
        FL0) _case_flow 0 public 1.1.1.1 80 public-1111 || return 2 ;;
        FL1|FL2) _case_flow 1 tcp "$lan" 18080 lan-tcp80 || return 2 ;;
        CR1|CR1c)
            expected=NX; [[ "$case_id" == CR1c ]] && expected=OK
            _case_dns_pair "$expected" "$gw" api.anthropic.com provider || return 2
            expected=1; [[ "$case_id" == CR1c ]] && expected=0
            _case_flow "$expected" public 1.1.1.1 80 public-1111 || return 2 ;;
        IN1|IN2)
            local port=8000; [[ "$case_id" == IN2 ]] && port=18555
            listen "$port" "$attempt_id" || return 2
            _case_flow 1 public 1.1.1.1 80 public-1111 || return 2 ;;
        V6c)
            _case_flow 0 public 2606:4700:4700::1111 80 public-v6-1111 || return 2
            _case_flow 0 public 2606:4700:4700::1001 80 public-v6-1001 || return 2 ;;
        DNS6c) _case_dns_pair OK 2606:4700:4700::1111 example.com explicit-v6 || return 2 ;;
        V6)
            _case_flow 0 public 2606:4700:4700::1111 80 public-v6-1111 || return 2
            _case_flow 1 public 2606:4700:4700::1001 80 public-v6-1001 || return 2 ;;
        HNc)
            # Admission is host-side (ladder step); the probe warms the cache
            # through the step's DNS path, then dials TLS with SNI=name.
            local name step
            IFS=, read -r name step <<<"$extra"
            [[ -n "$name" && -n "$step" ]] || return 2
            if [[ "$step" == c ]]; then
                _case_dns OK "$lan" "$name" udp hnc-dns || return 2
            else
                _case_dns OK "$gw" "$name" udp hnc-dns || return 2
            fi
            [[ "$CASE_DNS_A" == "$lan" ]] || return 2
            _case_tls "$name" "$lan" 18443 0 hnc-tls || return 2 ;;
        HN1)
            local a b c d
            IFS=, read -r a b c d <<<"$extra"
            [[ -n "$a" && -n "$b" && -n "$c" && -n "$d" ]] || return 2
            _case_dns OK "$gw" "$a" udp hn1a-dns || return 2
            [[ "$CASE_DNS_A" == "$lan" ]] || return 2
            _case_dns OK "$gw" "$b" udp hn1b-dns || return 2
            [[ "$CASE_DNS_A" == "$lan" ]] || return 2
            _case_dns OK "$gw" "$c" udp hn1c-dns || return 2
            [[ "$CASE_DNS_A" == "$lan" ]] || return 2
            _case_tls "$a" "$lan" 18443 0 hn1a-18443 || return 2
            _case_tls "$a" "$lan" 18444 1 hn1a-18444 || return 2
            _case_tls "$b" "$lan" 18444 0 hn1b-18444 || return 2
            _case_tls "$b" "$lan" 18443 1 hn1b-18443 || return 2
            _case_tls "$c" "$lan" 18443 0 hn1c-18443 || return 2
            _case_tls "$c" "$lan" 18444 0 hn1c-18444 || return 2
            _case_dns NX "$gw" "$d" udp hn1d-dns || return 2
            _case_tls "$d" "$lan" 18443 1 hn1d-18443 || return 2 ;;
        HN2)
            local a b lan2
            IFS=, read -r a b lan2 <<<"$extra"
            [[ -n "$a" && -n "$b" && -n "$lan2" ]] || return 2
            _case_dns OK "$gw" "$a" udp hn2a-dns || return 2
            [[ "$CASE_DNS_A" == "$lan" ]] || return 2
            _case_dns OK "$gw" "$b" udp hn2b-dns || return 2
            [[ "$CASE_DNS_A" == "$lan2" ]] || return 2
            _case_tls "$a" "$lan" 18443 0 hn2a-lan || return 2
            _case_tls "$b" "$lan2" 18443 0 hn2b-lan2 || return 2
            _case_tls "$a" "$lan2" 18443 1 hn2a-wrong || return 2
            _case_tls "$b" "$lan" 18443 1 hn2b-wrong || return 2 ;;
        HN3)
            local n="$extra"
            [[ -n "$n" ]] || return 2
            _case_dns OK "$gw" "$n" udp hn3-dns || return 2
            [[ "$CASE_DNS_A" == "$lan" ]] || return 2
            _case_tls "$n" "$lan" 18443 0 hn3-sni || return 2
            _case_tls - "$lan" 18443 1 hn3-nosni || return 2
            _case_binary opaque "$lan" 18443 50494e4720780d0a0d0a 1 hn3-plain || return 2
            _case_flow 1 tcp "$lan" 18080 lan-tcp80 || return 2 ;;
        HN4)
            local a b
            IFS=, read -r a b <<<"$extra"
            [[ -n "$a" && -n "$b" ]] || return 2
            _case_dns OK "$gw" "$a" udp hn4a-dns || return 2
            [[ "$CASE_DNS_A" == "$lan" ]] || return 2
            _case_dns OK "$gw" "$b" udp hn4b-dns || return 2
            [[ "$CASE_DNS_A" == "$lan" ]] || return 2
            _case_tls "$a" "$lan" 18443 0 hn4a-tls || return 2
            _case_tls "$b" "$lan" 18443 1 hn4b-tls || return 2 ;;
        HN5)
            local n="$extra"
            [[ -n "$n" ]] || return 2
            _case_dns OK "$gw" "$n" udp hn5-dns || return 2
            [[ "$CASE_DNS_A" == "$lan" ]] || return 2
            _case_tls arbitrary.invalid "$lan" 18443 0 hn5-numeric || return 2
            _case_tls "$n" "$lan" 18443 0 hn5-name || return 2
            _case_binary opaque "$lan" 18443 50494e47 1 hn5-plain || return 2 ;;
        HN5c) _case_binary opaque "$lan" 18443 50494e47 0 hn5c-plain || return 2 ;;
        HN6)
            local n="$extra"
            [[ -n "$n" ]] || return 2
            _case_dns OK "$gw" "$n" udp hn6-dns || return 2
            [[ "$CASE_DNS_A" == "$lan" ]] || return 2
            _case_flow 0 tcp "$lan" 18080 lan-tcp80 || return 2
            _case_http_nohost "$lan" 18080 1 hn6-nohost || return 2 ;;
        OP1|OP1c)
            # The guest dials the numeric LAN grant; the hostname rule only has
            # to exist so the emitted Domain rule turns on D1 authority
            # enforcement. OP1c is the same flow without the hostname rule.
            _case_binary opaque "$lan" 18090 50494e4720780d0a0d0a "$([ "$case_id" == OP1 ] && echo 1 || echo 0)" op-printable || return 2 ;;
        OP2|OP2c)
            _case_binary opaque "$lan" 18090 000102030405060708090a0b0c0d0e0f10 0 op-binary || return 2 ;;
        OP3|OP3c)
            _case_binary banner "$lan" 18091 515549540d0a 0 op-banner || return 2 ;;
        RB2)
            # Admission is the variant grant; the query is authorized by the
            # Domain rule. Assert the variant's expected DNS outcome and, for
            # the admitted variants, that the private answer formed a binding.
            local name="$extra" expected
            [[ -n "$name" ]] || return 2
            case "$variant" in
                hostname-only|port|tcp-port) expected=NX ;;
                lan|udp|tcp) expected=OK ;;
                *) return 2 ;;
            esac
            _case_dns "$expected" "$gw" "$name" udp "rb2-$variant-udp" || return 2
            [[ "$expected" != OK || "$CASE_DNS_A" == "$lan" ]] || return 2
            _case_dns "$expected" "$gw" "$name" tcp "rb2-$variant-tcp" || return 2
            [[ "$expected" != OK || "$CASE_DNS_A" == "$lan" ]] || return 2 ;;
        HP1)
            local n="$extra"
            _case_dns OK "$gw" "$n" udp hp1-com-dns || return 2
            _case_https "https://$n/" 0 hp1-https || return 2
            _case_dns_pair NX "$gw" example.org hp1-scope || return 2
            _case_https "http://$n/" 1 hp1-http || return 2 ;;
        HP2)
            local a b
            IFS=, read -r a b <<<"$extra"
            _case_dns OK "$gw" "$a" udp hp2-dns || return 2
            _case_held "$CASE_DNS_A" "$a" "$b" 1 hp2-switch || return 2 ;;
        HP2c)
            local a
            IFS=, read -r a _ <<<"$extra"
            _case_dns OK "$gw" "$a" udp hp2c-dns || return 2
            _case_held "$CASE_DNS_A" "$a" "$a" 0 hp2c-same || return 2 ;;
        HP3)
            local a b
            IFS=, read -r a b <<<"$extra"
            _case_dns OK "$gw" "$b" udp hp3b-dns || return 2
            local spoof="$CASE_DNS_A"
            _case_dns OK "$gw" "$a" udp hp3a-dns || return 2
            # The spoof control is only meaningful when the two names resolve
            # to disjoint public addresses.
            [[ "$spoof" != "$CASE_DNS_A" ]] || return 2
            _case_https "https://$a/" 0 hp3-control || return 2
            _case_https "https://$a/" 1 hp3-spoof "$a:443:$spoof" || return 2 ;;
        HP4)
            local a b
            IFS=, read -r a b <<<"$extra"
            _case_dns OK "$gw" "$a" udp hp4a-dns || return 2
            local ip="$CASE_DNS_A"
            _case_dns OK "$gw" "$b" udp hp4b-dns || return 2
            [[ "$CASE_DNS_A" == "$ip" ]] || return 2
            _case_https "https://$a/" 0 hp4-a "$a:443:$ip" || return 2
            _case_https "https://$b/" 1 hp4-b "$b:443:$ip" || return 2 ;;
        HP5)
            local n="$extra"
            _case_dns OK "$gw" "$n" udp hp5-dns || return 2
            _case_https "https://$n/" 0 hp5-control || return 2
            _case_tls - "$CASE_DNS_A" 443 1 hp5-nosni || return 2 ;;
        HP6|HP6c)
            # The control case also allows the redirect target, so the same
            # first hop must then follow successfully.
            local a b expected=1
            IFS=, read -r a b <<<"$extra"
            [[ "$case_id" == HP6c ]] && expected=0
            _case_dns OK "$gw" "$b" udp hp6b-dns || return 2
            [[ "$CASE_DNS_A" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 2
            _case_dns OK "$gw" "$a" udp hp6a-dns || return 2
            _case_https "https://$a/" 301 hp6-first || return 2
            _case_https "https://$a/" "$expected" hp6-redirect "" follow || return 2 ;;
        PXH1) return 0 ;; # validation-only: no guest probe runs
        *) echo "CASE $case_id UNKNOWN"; return "$PROBE_USAGE" ;;
    esac
}

dispatch() {
    local case_id="${1:-}" attempt_id="${2:-}" lan="${3:-}" variant="${4:-ipv4}" extra="${5:-}" rc=0
    [[ "$attempt_id" =~ ^[A-Za-z0-9_-]+$ ]] || return "$PROBE_USAGE"
    _probe_case_begin "$case_id"
    _case_dispatch || rc=$?
    if (( rc == 0 )); then _probe_case_end "$case_id"; fi
    return "$rc"
}

# Sourcing must define the functions only: no dispatch, no banner, no change to
# the caller's positional parameters.
if [[ "${EGRESS_PROBE_LIB:-}" == "1" ]]; then
    return 0
fi

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    dispatch "$@"
    exit $?
fi
