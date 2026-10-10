#!/usr/bin/env python3
"""Boot-free dispatcher controls. Wire/framing and native receipts are separate gates.

The endpoint matrix is derived from plan §10.2, not from the dispatcher's output.
The top-level egress contract invokes this helper once its other controls exist.
"""
import os
import importlib.util
import http.server
import sys
import socket
import tempfile
import threading
from pathlib import Path
import shlex
import subprocess
import unittest

PROBE = Path(__file__).resolve().parents[1] / "fixtures/egress-probe.sh"
LAN = "192.168.20.7"
GW = "100.64.0.1"
HOST = "host.microsandbox.internal"
ANSWER = "93.184.216.34"


def flow(kind, host, port, allowed):
    return kind, host, str(port), "0" if allowed else "1"


def dns(server, allowed, name="example.com"):
    return [("dns-" + p, server, "53", "OK" if allowed else "NX", name)
            for p in ("udp", "tcp")]


T80 = lambda yes: flow("tcp", LAN, 18080, yes)
T81 = lambda yes: flow("tcp", LAN, 18081, yes)
U80 = lambda yes: flow("udp", LAN, 18080, yes)
U90 = lambda yes: flow("udp", LAN, 19090, yes)
H80 = lambda yes: flow("tcp", HOST, 18080, yes)
P = lambda host, yes: flow("public", host, 80, yes)

# Distinct endpoint/protocol positives are pinned here: LC1 includes TCP18081
# and UDP18080; I1 includes explicit-resolver positives; V6c includes endpoint 2.
MATRIX = {
    "LC1": [T80(True), T81(True), U90(True), U80(True)],
    "HC1": [H80(True)] + dns(GW, True),
    "I1": [P("1.1.1.1", True), P("1.0.0.1", True)] + dns(GW, True)
          + dns("1.1.1.1", True) + [T80(False), H80(False)],
    "D1": [T80(False), U90(False), H80(False), P("1.1.1.1", False)]
          + dns(GW, False) + dns("1.1.1.1", False),
    "D1f": [T80(False), P("1.1.1.1", False), dns(GW, False)[0]],
    "L1": [T80(True), U90(True), P("1.1.1.1", False), H80(False)] + dns(GW, False),
    "H1": [H80(True), T80(False), P("1.1.1.1", False)] + dns(GW, True)
          + [P(ANSWER, False)],
    "I1a": [P(ANSWER, True)],
    "LH1": [T80(True), H80(True), P("1.1.1.1", False)],
    "AD1": [P("1.1.1.1", True), P("1.0.0.1", False)] + dns(GW, False)
           + dns("1.1.1.1", False),
    "TP1": [T80(True), U80(False), T81(False)],
    "UP1": [U90(True), U80(False), T80(False)],
    "UP2": [T80(True), U80(True), T81(False)],
    "CI1": [T80(True), T81(False)],
    "PX1": [T80(True), T81(False)],
    "PX2": [T80(True)],
    "PX3": [T80(False), P("1.1.1.1", False)],
    "FL0": [P("1.1.1.1", True)],
    "FL1": [T80(False)], "FL2": [T80(False)],
    "CR1c": dns(GW, True, "api.anthropic.com") + [P("1.1.1.1", True)],
    "CR1": dns(GW, False, "api.anthropic.com") + [P("1.1.1.1", False)],
    "IN1": [P("1.1.1.1", False)], "IN2": [P("1.1.1.1", False)],
    "V6c": [P("2606:4700:4700::1111", True), P("2606:4700:4700::1001", True)],
    "DNS6c": dns("2606:4700:4700::1111", True),
    "V6": [P("2606:4700:4700::1111", True), P("2606:4700:4700::1001", False)],
    "HK1": [], "HK1c": [], "HK2": [], "HK2c": [],
}


def run_case(case, rows, variant="ipv4", extra="", fault=""):
    routes = []
    dns_routes = []
    for row in rows:
        kind, host, port, expected = row[:4]
        if kind.startswith("dns-"):
            proto, name = kind[4:], row[4]
            code = 0 if expected == "OK" else 3
            count = 1 if code == 0 else 0
            address = LAN if case == "RB1" else ANSWER
            line = (f"DNS {proto} {host} {name} id_ok=1 qr=1 question_ok=1 tc=0 "
                    f"rcode={code} ancount={count} a={address if count else ''} ms=10")
            if fault == "slow-dns":
                line = line.replace("ms=10", "ms=1000")
            if fault == "wrong-question":
                line = line.replace("question_ok=1", "question_ok=0")
            if fault == "empty-A":
                line = line.replace(f"a={address}", "a=")
            if fault == "wrong-rebind-A":
                line = line.replace(f"a={LAN}", f"a={ANSWER}")
            dns_routes.append(f"{shlex.quote(host+' '+name+' '+proto)}) echo {shlex.quote(line)}; return 0 ;;")
        else:
            rc = 2 if fault == "internal" else int(expected)
            if fault == "invert":
                rc = 1 - rc
            routes.append(f"{shlex.quote(kind+' '+host+' '+port)}) return {rc} ;;")
    script = f"""
EGRESS_PROBE_LIB=1 . {shlex.quote(str(PROBE))}
gateway() {{ echo {GW}; }}
_route() {{ case "$*" in {' '.join(routes)} *) return 2 ;; esac; }}
http_get() {{ _route tcp "$1" "$2"; }}
udp_send() {{ _route udp "$1" "$2"; }}
http_public() {{ _route public "$1" "$2"; }}
dns_status() {{ case "$*" in {' '.join(dns_routes)} *) return 2 ;; esac; }}
listen() {{ echo "INGRESS_READY $2 $1"; }}
dispatch {shlex.quote(case)} attempt_1 {LAN} {shlex.quote(variant)} {shlex.quote(extra)}
"""
    return subprocess.run([os.environ.get("BASH", "bash"), "-c", script],
                          capture_output=True, text=True, timeout=5)


class DispatchContract(unittest.TestCase):
    def assert_case(self, case, rows, variant="ipv4", extra=""):
        result = run_case(case, rows, variant, extra)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        observed = []
        ids = []
        for line in result.stdout.splitlines():
            if not line.startswith("ATTEMPT "):
                continue
            _, emitted_case, _label, kind, host, port, expected, ident = line.split()
            self.assertEqual(emitted_case, case)
            observed.append((kind, host, port, expected))
            if ident != "-":
                ids.append(ident)
        self.assertEqual(observed, [row[:4] for row in rows])
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn(f"CASE {case} END", result.stdout)
        return result

    def test_every_named_case_endpoint_matrix(self):
        for case, rows in MATRIX.items():
            with self.subTest(case=case):
                result = self.assert_case(case, rows, extra=ANSWER if case == "I1a" else "")
                if case == "H1":
                    self.assertIn(f"ANSWER {ANSWER}", result.stdout)
                if case in ("IN1", "IN2"):
                    self.assertIn(f"INGRESS_READY attempt_1 {8000 if case == 'IN1' else 18555}", result.stdout)

    def test_paired_ipv6_and_all_rebind_variants(self):
        self.assert_case("D1", dns("2606:4700:4700::1111", False), variant="ipv6")
        for variant in ("internet", "address", "tcp", "udp", "port", "tcp-port", "udp-port"):
            rows = dns(GW, variant in ("address", "tcp", "udp"), "192-168-20-7.sslip.io")
            self.assert_case("RB1", rows, variant, "192-168-20-7.sslip.io")

    def test_network_and_internal_errors_cannot_be_swallowed(self):
        for case, rows in MATRIX.items():
            if not any(not row[0].startswith("dns-") for row in rows):
                continue
            for fault in ("internal", "invert"):
                with self.subTest(case=case, fault=fault):
                    result = run_case(case, rows, extra=ANSWER, fault=fault)
                    self.assertEqual(result.returncode, 2, result.stdout)
                    self.assertNotIn(f"CASE {case} END", result.stdout)

    def test_dns_identity_timing_and_answer_oracles(self):
        for case, fault in (("D1", "slow-dns"), ("D1", "wrong-question"),
                            ("HC1", "wrong-question"), ("HC1", "empty-A")):
            with self.subTest(case=case, fault=fault):
                result = run_case(case, MATRIX[case], fault=fault)
                self.assertEqual(result.returncode, 2, result.stdout)
        rows = dns(GW, True, "192-168-20-7.sslip.io")
        self.assertEqual(run_case("RB1", rows, "tcp", "192-168-20-7.sslip.io",
                                 "wrong-rebind-A").returncode, 2)

    def test_validation_only_and_unknown_cases_never_succeed(self):
        for case in ("RJ1", "shell", "http_get", "unknown"):
            self.assertEqual(run_case(case, []).returncode, 2)
        self.assertEqual(run_case("D1", MATRIX["D1"], "unknown").returncode, 2)
        self.assertEqual(run_case("RB1", [], "unknown").returncode, 2)

    def test_library_source_is_silent_and_preserves_positionals(self):
        result = subprocess.run(["bash", "-c", f'''set -- one two
EGRESS_PROBE_LIB=1 . {shlex.quote(str(PROBE))}
printf '%s\\n' "$@"
'''], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "one\ntwo\n")


class GeneratedHookContract(unittest.TestCase):
    def test_generated_hook_status_matrix(self):
        module_path = PROBE.parents[1] / "lib/egress-fixtures.py"
        spec = importlib.util.spec_from_file_location("hook_fixtures", module_path)
        fixtures = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = fixtures
        spec.loader.exec_module(fixtures)
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            for event in ("denial", "functioning", "internal"):
                server = None
                thread = None
                if event == "functioning":
                    handler = type("HookHTTP", (fixtures._ReceiptHTTP,),
                                   {"directory": work, "port": 0})
                    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
                    port = server.server_address[1]
                    handler.port = port
                    thread = threading.Thread(target=server.serve_forever)
                    thread.start()
                else:
                    # Use a kernel-selected port without a fixture listener for
                    # the denial control, rather than a shared fixed port.
                    with socket.socket() as reservation:
                        reservation.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        reservation.bind(("127.0.0.1", 0))
                        port = reservation.getsockname()[1]
                try:
                    for hook in ("HK1", "HK2"):
                        with self.subTest(event=event, hook=hook):
                            ident = "" if event == "internal" else f"{hook}-{event}"
                            fixtures.write_hook(work, hook, "127.0.0.1", ident, port)
                            project = work / hook
                            # The launcher's sourcing conditional, followed by
                            # the actual configured probe tool (not a mock).
                            script = '''set -euo pipefail
_hook="$PWD/.agent-vm.runtime.sh"
. "$_hook" || { rc=$?; echo "==> .agent-vm.runtime.sh failed (exit $rc)" >&2; exit "$rc"; }
exec bash ./egress-probe.sh "$1" hook-tool 127.0.0.1 ipv4
'''
                            result = subprocess.run(["bash", "-c", script, "hook-launch", hook],
                                                    cwd=project, capture_output=True, text=True, timeout=8)
                            expected = 2 if event == "internal" else 7 if event == "denial" and hook == "HK2" else 0
                            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                            output = result.stdout + result.stderr
                            self.assertNotRegex(output, r"command[ -]not[ -]found")
                            self.assertEqual(f"CASE {hook} BEGIN" in result.stdout, expected == 0)
                            self.assertEqual(f"CASE {hook} END" in result.stdout, expected == 0)
                            self.assertEqual("HOOK_EGRESS_DENIED" in result.stdout,
                                             event == "denial" and hook == "HK1")
                            if expected:
                                self.assertIn(f".agent-vm.runtime.sh failed (exit {expected})", result.stderr)
                            if event == "functioning":
                                self.assertIn(f"HTTP_OK {ident}", result.stdout.splitlines())
                                self.assertEqual(fixtures.wait_for_receipt(work, ident, 0.5), 0)
                            elif event == "denial":
                                self.assertIn(f"HTTP_FAIL {ident}", result.stdout.splitlines())
                                self.assertEqual(fixtures.wait_for_receipt(work, ident, 3), 1)
                finally:
                    if server:
                        server.shutdown()
                        server.server_close()
                        thread.join(timeout=2)
                        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
