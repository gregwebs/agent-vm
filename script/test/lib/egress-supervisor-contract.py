#!/usr/bin/env python3
"""Host-only owned-launch/command controls. No VM or native egress evidence."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import threading
import unittest
from unittest.mock import patch
from contextlib import closing
from dataclasses import replace

MODULE_PATH = Path(__file__).resolve().with_name("egress-fixtures.py")
spec = importlib.util.spec_from_file_location("egress_fixtures", MODULE_PATH)
egress = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = egress
spec.loader.exec_module(egress)

# A real executable fake candidate: detached VMM, catalog and sockets have the
# pinned schema/path shape; mutations are performed only through its CLI.
FAKE = r'''#!/usr/bin/env python3
import hashlib, json, os, signal, socket, sqlite3, subprocess, sys, time
from pathlib import Path
if Path('startup-delay').exists() and sys.argv[1] == 'egressprobe':
    time.sleep(float(Path('startup-delay').read_text()))
root = Path(os.environ['AGENT_VM_STATE_DIR']) / 'msb-home'
root.mkdir(parents=True, exist_ok=True)
(root/'db').mkdir(exist_ok=True)
db = sqlite3.connect(root/'db/msb.db')
db.execute('CREATE TABLE IF NOT EXISTS sandbox(id INTEGER PRIMARY KEY, name TEXT, config TEXT, status TEXT)')
db.execute('CREATE TABLE IF NOT EXISTS run(id INTEGER PRIMARY KEY, sandbox_id INTEGER, pid INTEGER, status TEXT)')
args = sys.argv[1:]
if Path('recorder-mode').exists() or args[0] == 'record':
    Path('record.json').write_text(json.dumps({'argv':sys.argv,'env':dict(os.environ)}))
    sys.exit(0)
if args[0] == 'msb':
    verb = args[1]
    with (root/'calls').open('a') as f: f.write(json.dumps(args)+'\n')
    if verb == 'list':
        if (root/'wedge-list').exists(): time.sleep(600)
        print(json.dumps([{'name':r[0]} for r in db.execute('SELECT name FROM sandbox')]))
    elif verb == 'stop':
        if '--force' not in args or (root/'fail-force').exists(): sys.exit(9) # inject primary stop failure
        for pid, in db.execute('SELECT pid FROM run'):
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
    elif verb == 'remove':
        if (root/'fail-remove').exists(): sys.exit(8)
        db.execute('DELETE FROM sandbox WHERE name=?',(args[-1],)); db.commit()
    sys.exit(0)
if args[0] == 'record':
    Path('record.json').write_text(json.dumps({'argv':sys.argv,'env':dict(os.environ)}))
    sys.exit(0)
project = Path.cwd().resolve()
hash = hashlib.sha256(os.fsencode(project)).hexdigest()[:12]
name = f'agent-vm-{hash}-{os.getpid()}'
print(f'==> {name} in {project} (state: {Path(os.environ["AGENT_VM_STATE_DIR"])/hash})', flush=True)
child = subprocess.Popen([sys.executable,'-c','import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(600)'],start_new_session=True)
db.execute('INSERT INTO sandbox VALUES(1,?, ?, "Running")',(name,'{}'))
db.execute('INSERT INTO run VALUES(1,1,?,"Running")',(child.pid,)); db.commit()
hash = hashlib.sha256(name.encode()).hexdigest()[:24]
path = root/'run/sandboxes'/hash
path.mkdir(parents=True)
sockets=[]
for filename in ('agent.sock','control.sock'):
    s=socket.socket(socket.AF_UNIX);s.bind(str(path/filename));sockets.append(s)
# TERM-ignoring descendant in the attached group, independent of detached VMM.
attached = subprocess.Popen([sys.executable,'-c','import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(600)'])
(project/'attached.pid').write_text(str(attached.pid))
(project/'launcher-ready').touch()
print('CASE CL1 BEGIN',flush=True)
time.sleep(600)
'''


class Contracts(unittest.TestCase):
    def setUp(self):
        # Keep Darwin Unix socket paths below sun_path's limit.
        self.tmp = tempfile.TemporaryDirectory(prefix="a3", dir="/tmp" if sys.platform == "darwin" else "/var/tmp")
        self.work = Path(self.tmp.name).resolve()
        for name in ("proj", "home", "config", "state"):
            (self.work / name).mkdir()
        self.binary = self.work / "fake"
        # env-i PATH intentionally has no brew Python; use vetted interpreter.
        self.binary.write_text(FAKE.replace("#!/usr/bin/env python3", f"#!{sys.executable}"))
        self.binary.chmod(0o700)
        self.root = self.work / "state/msb-home"
        self.owned = []

    def tearDown(self):
        for owned in self.owned:
            for identity in owned.runtimes.values():
                try:
                    egress.signal_identity(identity, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.tmp.cleanup()

    # Fresh Python + SQLite startup needs headroom on loaded pre-build runners.
    def command(self, timeout=5):
        return egress.Command("CL1", "ipv4", "egressprobe", "guest", egress.base_environment(self.work),
                              (str(self.binary), "egressprobe"), str(self.work / "proj"), timeout, 0.1)

    def test_table_and_recorder(self):
        commands = [egress.build_command(case, self.work, str(self.binary), "192.168.1.2") for case in egress.CASES]
        self.assertEqual(len(commands), len({(c.case, c.variant) for c in commands}))
        self.assertEqual({c.variant for c in commands if c.case == "RB1"},
                         {"internet", "address", "tcp", "udp", "port", "tcp-port", "udp-port"})
        self.assertEqual(len([c for c in commands if c.case == "RJ1"]), 3)
        expected_keys = {"HOME", "XDG_CONFIG_HOME", "AGENT_VM_STATE_DIR", "PATH", "TERM", "AGENT_VM_SHARE_MSB_CACHE"}
        for case, command in zip(egress.CASES, commands):
            self.assertEqual(command.tool == "egresscreds", case.case in ("CR1", "CR1c"))
            self.assertEqual(command.argv[1], command.tool)
            self.assertEqual(set(command.env), expected_keys | set(case.extras))
            self.assertEqual(command.kind == "validation-only", case.case == "RJ1")
            self.assertEqual("--" in command.argv, case.guest)
            if case.guest:
                self.assertEqual(command.argv[command.argv.index("--")+1], case.case)
            self.assertNotIn("shell", command.argv)
            self.assertNotIn("-c", command.argv)
            self.assertFalse(case.extras and not case.case.startswith(("PX", "FL")))
        printed = subprocess.check_output([sys.executable, str(MODULE_PATH), "run", "--print-plan",
            "--work", str(self.work), "--binary", str(self.binary), "--lan", "192.168.1.2"], cwd="/")
        plan = [json.loads(line) for line in printed.splitlines()]
        self.assertEqual([c.plan()["case"] for c in commands], [c["case"] for c in plan[:len(commands)]])
        for command, printed in zip(commands, plan):
            self.assertEqual(list(command.argv), printed["argv"])
            self.assertEqual(command.env, printed["env"])
            project = Path(command.cwd)
            egress.prepare_project(self.work, project)
            (project / "recorder-mode").touch()
            status, _ = egress.run_admin(self.work, command)
            self.assertEqual(status, 0)
            recorded = json.loads((project / "record.json").read_text())
            self.assertEqual(recorded["argv"], printed["argv"])
            env_command = replace(command, argv=("/usr/bin/env",), kind="admin", tool=None)
            status, output = egress.run_admin(self.work, env_command)
            self.assertEqual(status, 0)
            self.assertEqual(dict(line.split("=", 1) for line in output.splitlines()), printed["env"])
            (project / "recorder-mode").unlink()
        self.assertEqual({c["case"] for c in plan[len(commands):]},
                         {"image-load", "list", "stop", "force-stop", "remove", "IN1", "IN2", "fixture-health", "fixture-start"})
        egress.prepare_project(self.work, self.work / "proj")
        # Pin the real discovery path (config.rs PROJECT_CONFIG_RELATIVE); a
        # bare `.agent-vm.toml` is not read, so every guest launch would fail
        # with "unrecognized subcommand" while the harness blamed "helper misuse".
        self.assertEqual((self.work / "proj/.agent-vm/config.toml").read_bytes(),
                         (egress.repo_root() / "script/test/fixtures/egress-config.toml").read_bytes())
        # Compare a shared command's actual exec argv/environment to its plan.
        command = egress.Command("record", "ipv4", None, "admin", egress.base_environment(self.work),
                                (str(self.binary), "record", "--", "D1"), str(self.work / "proj"), 3, 0.1)
        status, _ = egress.run_admin(self.work, command)
        self.assertEqual(status, 0)
        recorded = json.loads((self.work / "proj/record.json").read_text())
        self.assertEqual(recorded["argv"], list(command.plan()["argv"]))
        # Native env sees the exec environment, unlike Python's mutated os.environ.
        env_command = egress.Command("env", "admin", None, "admin", command.env,
                                    ("/usr/bin/env",), command.cwd, 3, 0.1)
        status, output = egress.run_admin(self.work, env_command)
        self.assertEqual(status, 0)
        self.assertEqual(dict(line.split("=", 1) for line in output.splitlines()), command.env)

    def test_required_calibrations_and_links(self):
        # Independent endpoint/protocol inventory: deleting a calibration must
        # not delete its oracle along with it.
        cases = {(case.case, case.variant): case for case in egress.CASES}
        required = {
            ("LC1", "ipv4"): {"lan-tcp80", "lan-tcp81", "lan-udp90", "lan-udp80"},
            ("I1", "ipv4"): {"public-1111", "public-1001", "gateway-udp", "gateway-tcp",
                              "explicit-udp", "explicit-tcp", "lan-tcp80", "host-tcp80"},
            ("V6c", "ipv6"): {"public-v6-1111", "public-v6-1001"},
            ("DNS6c", "ipv6"): {"explicit-v6-udp", "explicit-v6-tcp"},
        }
        for key, labels in required.items():
            self.assertEqual(set(egress.expected_attempts(cases[key])), labels, key)
        for case in egress.CASES:
            command = egress.build_command(case, self.work, str(self.binary), "192.168.1.2")
            for label, expectation in command.attempt_expectations.items():
                if expectation not in ("1", "NX"):
                    continue
                self.assertIn(label, command.controls, (case, label))
                control, variant, attempt = command.controls[label].split(":")
                self.assertEqual(attempt, label, (case, label))
                positive = cases[(control, variant)]
                self.assertIn(attempt, egress.expected_attempts(positive))
                self.assertIn(egress.attempt_expectations(positive)[attempt], ("0", "OK"))

    def test_missing_attempts_and_reply_markers_fail(self):
        case = next(case for case in egress.CASES if case.case == "D1" and case.variant == "ipv4")
        command = egress.build_command(case, self.work, str(self.binary), "192.168.1.2")
        rows = [{"label": label, "expectation": command.attempt_expectations[label],
                 "protocol": command.attempt_protocols[label]} for label in command.expected_attempts]
        self.assertEqual(egress.check_attempt_inventory(command, rows), [])
        self.assertTrue(egress.check_attempt_inventory(command, [{**rows[0], "expectation": "0"}, *rows[1:]]))
        self.assertTrue(egress.check_attempt_inventory(command, [{**rows[0], "protocol": "public"}, *rows[1:]]))
        self.assertTrue(egress.check_attempt_inventory(command, rows[:-1]))
        self.assertTrue(egress.check_attempt_inventory(command, rows + rows[:1]))
        public = {"label": "public-1111", "protocol": "public", "endpoint": "1.1.1.1", "port": "80",
                  "expectation": "1", "receipt": "-", "output": "HTTP_FAIL 1.1.1.1:80\n"}
        self.assertEqual(egress.check_attempts(self.work, case, "", [public]), [])
        self.assertTrue(egress.check_attempts(self.work, case, "", [{**public, "output": ""}]))
        dns = {**public, "protocol": "dns-udp", "expectation": "NX", "output":
               "DNS udp 1.1.1.1 example.com id_ok=1 qr=1 question_ok=1 tc=0 rcode=3 ancount=0 a= ms=10\n"}
        self.assertEqual(egress.check_attempts(self.work, case, "", [dns]), [])
        self.assertTrue(egress.check_attempts(self.work, case, "", [{**dns, "output": dns["output"].replace("id_ok=1", "id_ok=0")}]))

    def run_until_timeout(self, owned):
        ready = self.work / "proj/launcher-ready"
        ready.unlink(missing_ok=True)
        self.assertEqual(owned.run(), 124)
        self.assertTrue(ready.is_file(),
                        f"fake launcher did not finish state initialization within "
                        f"{owned.command.timeout}s; inspect {owned.log}")
        self.assertTrue((self.root / "db/msb.db").is_file(), "ready launcher lacks catalog")
        self.assertTrue((self.work / "proj/attached.pid").is_file(), "ready launcher lacks attached PID")

    def assert_attached_disappeared(self):
        self.assertTrue((self.work / "proj/attached.pid").is_file(),
                        "fake launcher never recorded attached child PID")
        pid = int((self.work / "proj/attached.pid").read_text())
        deadline = time.monotonic() + 2
        while egress.process_identity(pid) is not None and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertIsNone(egress.process_identity(pid), "TERM-ignoring attached child survived escalation")

    def test_timeout_detached_catalog_sockets_and_separate_failures(self):
        owned = egress.OwnedLaunch(self.work, self.command(), "timeout")
        self.owned.append(owned)
        self.run_until_timeout(owned)
        self.assert_attached_disappeared()
        self.assertEqual(len(owned.runtimes), 1)
        self.assertEqual(len(owned.names), 1)
        start = time.monotonic()
        errors = egress.cleanup_launch(owned)
        self.assertLess(time.monotonic()-start, 15)
        self.assertTrue(any("status 9" in error for error in errors))
        calls = [json.loads(line) for line in (self.root / "calls").read_text().splitlines()]
        name = next(iter(owned.names))
        self.assertIn(["msb", "stop", "--timeout", "5", name], calls)
        self.assertIn(["msb", "stop", "--force", name], calls)
        self.assertIn(["msb", "remove", name], calls)
        self.assertFalse(owned.alive())
        self.assertFalse(egress.catalog_rows(self.root))
        self.assertTrue(all(not p.exists() for p in egress.socket_paths(self.root, name)))
        receipt = json.loads((self.work / "owned.jsonl").read_text().splitlines()[-1])
        self.assertEqual(receipt["primary_status"], 124)
        self.assertTrue(receipt["cleanup_errors"])

    def test_slow_startup_and_missing_readiness_diagnostic(self):
        owned = egress.OwnedLaunch(self.work, self.command(), "slow-startup")
        self.owned.append(owned)
        with patch.object(owned, "run", return_value=124):
            with self.assertRaisesRegex(AssertionError, "fake launcher did not finish state initialization"):
                self.run_until_timeout(owned)
        # Exceeds the former 0.8s bound even without CPU contention.
        (self.work / "proj/startup-delay").write_text("1.2")
        self.run_until_timeout(owned)
        self.assert_attached_disappeared()
        self.assertEqual(len(owned.runtimes), 1)
        errors = egress.cleanup_launch(owned)
        self.assertTrue(any("status 9" in error for error in errors))
        self.assertFalse(owned.alive())
        self.assertFalse(egress.catalog_rows(self.root))

    def test_failed_force_stop_uses_identity_checked_fallback(self):
        owned = egress.OwnedLaunch(self.work, self.command(), "force-fallback")
        self.owned.append(owned)
        self.run_until_timeout(owned)
        (self.root / "fail-force").touch()
        errors = egress.cleanup_launch(owned)
        self.assertTrue(any("force-stop" in error for error in errors))
        self.assertFalse(owned.alive())
        self.assertFalse(egress.catalog_rows(self.root))

    def test_socket_mirror_known_hash(self):
        paths = egress.socket_paths(Path("/tmp/av302-msb-home"), "agent-vm-0123456789ab-4242")
        self.assertEqual([str(path) for path in paths], [
            "/tmp/av302-msb-home/run/sandboxes/e6b31ea46b06a7e0865241dd/agent.sock",
            "/tmp/av302-msb-home/run/sandboxes/e6b31ea46b06a7e0865241dd/control.sock",
            "/tmp/av302-msb-home/run/agent/e6b31ea46b06a7e0865241dd3e4a49ac.sock",
            "/tmp/av302-msb-home/run/agent/e6b31ea46b06a7e0865241dd3e4a49ac.control.sock"])

    def test_pid_reuse_and_outside_paths_refuse_signal(self):
        with patch.object(egress, "process_identity", return_value=[2, 0]), patch.object(egress.os, "kill") as kill:
            with self.assertRaisesRegex(RuntimeError, "PID reuse"):
                egress.signal_identity({"pid": os.getpid(), "start": [1, 0]}, signal.SIGKILL)
            kill.assert_not_called()
        with self.assertRaises(RuntimeError):
            egress.within(self.work / "../unowned", self.work)

    def test_wedged_list_total_deadline_and_failed_remove(self):
        for fault in ("wedge-list", "fail-remove"):
            with self.subTest(fault=fault):
                owned = egress.OwnedLaunch(self.work, self.command(), fault)
                self.owned.append(owned)
                self.run_until_timeout(owned)
                (self.root / fault).touch()
                start = time.monotonic()
                errors = egress.cleanup_launch(owned, deadline=start+3)
                self.assertTrue(errors)
                self.assertLess(time.monotonic()-start, 4)
                (self.root / fault).unlink()
                # Keep teardown safe even when intentionally wedged cleanup failed.
                for identity in owned.runtimes.values():
                    egress.signal_identity(identity, signal.SIGKILL)
                with closing(__import__('sqlite3').connect(self.root / "db/msb.db")) as db, db:
                    db.execute('DELETE FROM sandbox'); db.execute('DELETE FROM run')

    def test_fixture_survives_two_launch_cleanups_and_run_inventory(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(600)"], start_new_session=True)
        identity = {"pid": proc.pid, "start": egress.process_identity(proc.pid)}
        try:
            for index in range(2):
                command = egress.Command("record", "ipv4", None, "guest", egress.base_environment(self.work),
                    (str(self.binary), "record"), str(self.work / "proj"), 3, 0.1)
                owned = egress.OwnedLaunch(self.work, command, f"success{index}")
                self.owned.append(owned)
                self.assertEqual(owned.run(), 0)
                self.assertEqual(egress.cleanup_launch(owned), [])
                self.assertIsNone(proc.poll())
            # Unexpected catalog object must fail and remain; never broad-killed.
            with closing(__import__('sqlite3').connect(self.root / "db/msb.db")) as db, db:
                db.execute('INSERT INTO sandbox VALUES(99,"unowned", "{}", "Stopped")')
            errors = egress.cleanup_run(self.work, str(self.binary), self.owned, (proc, identity))
            self.assertTrue(any("unowned" in error for error in errors))
            self.assertIsNotNone(proc.poll())
            self.assertEqual(egress.catalog_rows(self.root)[0]["name"], "unowned")
        finally:
            if proc.poll() is None:
                egress.signal_identity(identity, signal.SIGKILL)
                proc.wait(timeout=2)

    def test_rejection_diagnostics_are_specific_and_fault_detecting(self):
        errors = {
            "hostname": "hostname allowances are not supported yet; use an IP address or CIDR, or --allow-internet-egress",
            "cidr-port": "a port on a CIDR needs brackets, e.g. tcp://[10.0.0.0/24]:22",
            "scheme": "unsupported scheme; use tcp:// or udp:// (or no scheme for all protocols)",
        }
        for variant, error in errors.items():
            diagnostic = "--allow-egress #1: " + error
            self.assertTrue(egress.validation_rejected(1, diagnostic, variant))
            for status in (0, 124, 130, 143):
                self.assertFalse(egress.validation_rejected(status, diagnostic, variant))
            for text in ("unrelated egress failure", "clap: --allow-egress missing argument",
                         diagnostic.replace("#1", "#2"), diagnostic + " CASE RJ1 BEGIN",
                         diagnostic + " reject.invalid", *[
                             "--allow-egress #1: " + other for other in errors.values() if other != error]):
                self.assertFalse(egress.validation_rejected(1, text, variant), text)
        diagnostic = ".agent-vm.runtime.sh failed (exit 7)"
        self.assertTrue(egress.strict_hook_rejected(diagnostic))
        for text in ("127.0.0.1", "id=7", diagnostic.replace("7", "2"),
                     diagnostic + " CASE HK2 BEGIN"):
            self.assertFalse(egress.strict_hook_rejected(text), text)

    def test_validation_snapshot_ignores_sqlite_wal_sidecars(self):
        # A read-only catalog observation (and SQLite itself) rewrites the
        # -shm/-wal sidecars whenever a connection attaches; those bytes are
        # not launch state and must not fail the validation-only mutation oracle.
        directory = self.root / "db"
        directory.mkdir(parents=True)
        sidecars = [directory / "msb.db-shm", directory / "msb.db-wal", directory / "msb.db-journal"]
        for path in sidecars:
            path.write_bytes(b"initial")
        secrets = self.work / "state/abc.secrets/token"
        secrets.parent.mkdir()
        secrets.write_bytes(b"secret")
        before = egress.snapshot_validation(self.work)
        for path in sidecars:
            path.write_bytes(b"rewritten sidecar payload")
        self.assertEqual(before, egress.snapshot_validation(self.work))
        secrets.write_bytes(b"secret changed")
        self.assertNotEqual(before, egress.snapshot_validation(self.work))

    def test_host_fixture_health_and_ingress_driver(self):
        directory = self.work / "fx"
        fixture_start = egress.fixture_command(self.work)
        fixture_start = replace(fixture_start, argv=(*fixture_start.argv, "--ephemeral-ports"))
        with (self.work / "fixture.log").open("ab") as log:
            proc = subprocess.Popen(fixture_start.argv, env=fixture_start.env, cwd=fixture_start.cwd,
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        identity = {"pid": proc.pid, "start": egress.process_identity(proc.pid)}
        try:
            deadline = time.monotonic()+5
            while not (directory / "ready").exists():
                if proc.poll() is not None or time.monotonic() > deadline:
                    self.fail("host-only fixture failed to bind owned ports")
                time.sleep(0.05)
            status, _ = egress.run_admin(self.work, egress.health_command(self.work))
            self.assertEqual(status, 0)
            ports = json.loads((directory / "ports.json").read_text())
            receipts = (directory / "receipts.log").read_text().splitlines()
            for protocol in ("tcp", "udp"):
                self.assertEqual(len(ports[protocol]), 2)
                for port in ports[protocol]:
                    self.assertGreater(port, 0)
                    self.assertTrue(any(line.startswith(f"{protocol} {port} ") for line in receipts))
            self.assertIsNone(proc.poll())
            self.assertEqual(egress.cleanup_run(self.work, str(self.binary), [], (proc, identity)), [])
            self.assertIsNotNone(proc.poll())
            status, _ = egress.run_admin(self.work, egress.health_command(self.work))
            self.assertNotEqual(status, 0)
        finally:
            if proc.poll() is None:
                egress.signal_identity(identity, signal.SIGKILL)
                proc.wait(timeout=2)
        for body, expected in ((b"ingress ingress-test", 0), (b"wrong body", 1)):
            with self.subTest(body=body), socket.socket() as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("127.0.0.1", 0))
                server.listen()
                server.settimeout(5)
                def serve():
                    conn, _ = server.accept()
                    with conn:
                        conn.recv(4096)
                        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                                     b"\r\nConnection: close\r\n\r\n" + body)
                thread = threading.Thread(target=serve)
                thread.start()
                (self.work / "ingress-test.log").write_text("INGRESS_READY ingress-test 8000\n")
                self.assertEqual(egress.ingress_driver(self.work, "IN1", "ingress-test", server.getsockname()[1]), expected)
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

    def test_cli_outside_cwd_interrupts(self):
        for sig, expected in ((signal.SIGINT, 130), (signal.SIGTERM, 143)):
            with self.subTest(signal=sig):
                wrapper = subprocess.Popen([sys.executable, str(MODULE_PATH), "launch", "--work", str(self.work),
                    "--case", "CL1", "--timeout", "10", "--grace", "0.1", "--", str(self.binary), "egressprobe"],
                    cwd="/", start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                until = time.monotonic()+5
                while not list(self.work.glob("CL1-*.log")) or not any("CASE CL1 BEGIN" in p.read_text() for p in self.work.glob("CL1-*.log")):
                    if time.monotonic() > until:
                        wrapper.kill(); self.fail("fake guest not ready")
                    time.sleep(0.05)
                os.kill(wrapper.pid, sig)
                stdout, stderr = wrapper.communicate(timeout=15)
                self.assertEqual(wrapper.returncode, expected, stderr.decode())
                self.assertFalse(egress.catalog_rows(self.root))
                self.assert_attached_disappeared()
                receipts = [json.loads(line) for line in (self.work / "owned.jsonl").read_text().splitlines()]
                cleanup = [row for row in receipts if row["phase"] == "cleanup"][-1]
                self.assertEqual(cleanup["primary_status"], expected)
                self.assertTrue(cleanup["cleanup_errors"])
                self.assertTrue(all(not Path(path).exists() for path in cleanup["sockets"]))
                self.assertTrue(all(egress.process_identity(identity["pid"]) is None
                                    for identity in cleanup["runtimes"]))
                for path in self.work.glob("CL1-*.log"):
                    path.unlink()
                with closing(__import__('sqlite3').connect(self.root / "db/msb.db")) as db, db:
                    db.execute('DELETE FROM run')


if __name__ == "__main__":
    unittest.main()
