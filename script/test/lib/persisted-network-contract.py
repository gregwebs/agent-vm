import http.server
import importlib.util
import os
from pathlib import Path
import py_compile
import shutil
import socket
import subprocess
import sys
sys.dont_write_bytecode = True
import signal
import time
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[3]

# Operational signal budgets shared by every control that waits on or tears down
# an owned fixture. The readiness deadline, the TERM->KILL teardown grace and the
# liveness poll interval are named here so every call site agrees on when a
# fixture has failed; retuning one must not leave another spelling a stale value.
READINESS_DEADLINE_SECONDS = 15
TEARDOWN_TIMEOUT_SECONDS = 15
SIGNAL_POLL_INTERVAL_SECONDS = 0.01


def probe_controls(root: Path, work: Path) -> None:
    fixtures = root / "script/test/fixtures/persisted-network"
    py_compile.compile(str(root / "script/test/lib/persisted-network.py"), cfile=str(work / "driver.pyc"), doraise=True)
    spec = importlib.util.spec_from_file_location("pn_contract", root / "script/test/lib/persisted-network.py")
    driver = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = driver
    spec.loader.exec_module(driver)
    inventory = work / "inventory"
    (inventory / "state").mkdir(parents=True)
    (inventory / "state/image").write_bytes(b"native image" * 200000)
    (inventory / "state/link").symlink_to("image")
    (inventory / "state/db-wal").write_bytes(b"sidecar")
    assert driver.snapshot_validation(inventory) == driver.EGRESS.snapshot_validation(inventory)
    before = driver.snapshot_validation(inventory)
    with (inventory / "state/image").open("ab") as handle: handle.write(b"changed")
    assert driver.snapshot_validation(inventory) != before
    (work / "dotfiles").mkdir()
    target = work / "dotfiles/agent-vm.toml"
    target.write_bytes(b"# stand-in\n")
    for file in ("guest-pn4-write.sh", "guest-pn-probe.sh"):
        shutil.copy2(fixtures / file, work / file)
    shutil.copy2(root / "script/test/fixtures/egress-probe.sh", work / "egress-probe.sh")
    result = subprocess.run(["bash", "./guest-pn4-write.sh"], cwd=work, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0 and result.stdout == "PN4_WRITE_OK\n", result
    assert target.read_bytes() == b"# stand-in\n[network]\nallow_host = true\n"
    (work / "r").mkdir()
    (work / "r/marker").write_bytes(b"receipt marker")
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(work), **kwargs)
        def log_message(self, *_args):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        result = subprocess.run(["bash", "./guest-pn-probe.sh", str(port), "marker", "127.0.0.1"], cwd=work, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and "PN_REACHED marker" in result.stdout, result
    finally:
        server.shutdown(); server.server_close(); thread.join(5)
    # Hold a bound, non-listening socket: no other process can steal the closed-port control.
    with socket.socket() as closed:
        closed.bind(("127.0.0.1", 0))
        result = subprocess.run(["bash", "./guest-pn-probe.sh", str(closed.getsockname()[1]), "marker", "127.0.0.1"], cwd=work, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and "PN_DENIED marker" in result.stdout, result


def provenance_controls(root: Path, work: Path) -> None:
    # ---- Build-provenance checker: P1-P5 --------------------------------
    checker_path = root / "script/test/lib/build-provenance.py"
    spec = importlib.util.spec_from_file_location("build_provenance", checker_path)
    checker = importlib.util.module_from_spec(spec)
    sys.modules["build_provenance"] = checker  # dataclass __module__ resolution
    spec.loader.exec_module(checker)
    sha_a = "a" * 40
    sha_b = "b" * 40

    def accepts(text, expected, status):
        try:
            checker.assert_committed_build(
                checker.parse_version(text), expected_sha=expected, tracked_status=status)
            return True
        except ValueError:
            return False

    # P1 positive, P2 prefix lookalike, P3 false-clean, P5 untracked-only.
    assert accepts(f"agent-vm 0.3.4 ({sha_a})\n", sha_a, ""), "P1 must accept"
    full64 = "abcdef1" + "0" * 57
    other64 = full64[:-1] + "1"
    assert accepts(f"agent-vm 0.3.4 ({full64})\n", full64, ""), "P1 64-hex exact equality"
    assert not accepts(f"agent-vm 0.3.4 ({full64})\n", other64, ""), "P2 64-hex inequality"
    prefix_a = "abcdef1" + "0" * 33
    prefix_b = "abcdef1" + "1" * 33
    assert not accepts(f"agent-vm 0.3.4 ({prefix_a})\n", prefix_b, ""), "P2 prefix must reject"
    assert accepts(f"agent-vm 0.3.4 ({sha_a})\n", sha_a, ""), "P5 allows unrelated untracked files"
    for text, status, why in [
        (f"agent-vm 0.3.4 ({sha_a}, dirty)\n", "", "dirty binary"),
        (f"agent-vm 0.3.4 ({sha_a})\n", " M x\n", "dirty tracked source"),
        (f"agent-vm 0.3.4 ({sha_a}, state unknown)\n", "", "unknown state"),
        ("agent-vm 0.3.4 (unknown)\n", "", "unknown revision"),
        ("agent-vm 0.3.3\n", "", "legacy bare version"),
        (f"agent-vm 0.3.4 ({sha_a})", "", "missing final newline"),
        (f"agent-vm 0.3.4 ({sha_a})\n\n", "", "extra blank line"),
        (f"agent-vm 0.3.4 ({sha_a[:7]})\n", "", "short SHA"),
        (f"agent-vm 0.3.4 ({sha_a}) trailing\n", "", "trailing junk"),
    ]:
        assert not accepts(text, sha_a, status), f"P3/P4 must reject {why}"
    # The checker CLI against real files.
    version_file = work / "checker-version.txt"
    status_file = work / "checker-status.txt"
    version_file.write_text(f"agent-vm 0.3.4 ({sha_a})\n")
    status_file.write_text("")
    good = subprocess.run([sys.executable, str(checker_path), str(version_file), sha_a, str(status_file)],
                          capture_output=True, text=True)
    assert good.returncode == 0 and good.stdout.strip() == "provenance: clean binary matches source HEAD", good
    version_file.write_bytes(b"agent-vm 0.3.4 (" + sha_a.encode() + b")\r\n")
    bad = subprocess.run([sys.executable, str(checker_path), str(version_file), sha_a, str(status_file)],
                         capture_output=True, text=True)
    assert bad.returncode != 0 and bad.stderr.startswith("provenance: "), bad
    invalid = work / "checker-invalid.txt"
    invalid.write_bytes(b"agent-vm 0.3.4 (" + sha_a.encode() + b")\xff\n")
    bad = subprocess.run([sys.executable, str(checker_path), str(invalid), sha_a, str(status_file)],
                         capture_output=True, text=True)
    assert bad.returncode != 0 and bad.stderr.startswith("provenance: "), bad



def live_shell_controls(root: Path, work: Path) -> None:
    # ---- Live-shell matrix: P6-P10 --------------------------------------
    git_env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
                   GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")

    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_NAMESPACE"):
        git_env.pop(key, None)

    def git_repo(path, message):
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True, env=git_env)
        subprocess.run(["git", "config", "core.filemode", "true"], cwd=path, check=True, env=git_env)
        subprocess.run(["git", "add", "-A"], cwd=path, check=True, env=git_env)
        subprocess.run(["git", "commit", "-q", "--no-gpg-sign", "-m", message], cwd=path, check=True, env=git_env)
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=path, capture_output=True, text=True, env=git_env).stdout.strip()

    repo_a = work / "A"
    (repo_a / "script").mkdir(parents=True)
    shutil.copytree(root / "script/test", repo_a / "script/test",
                    ignore=shutil.ignore_patterns("__pycache__"))
    sha_a_full = git_repo(repo_a, "A")
    repo_b = work / "B"
    repo_b.mkdir()
    (repo_b / "b.txt").write_text("b\n")
    sha_b_full = git_repo(repo_b, "B")

    tools = work / "tools"
    tools.mkdir()
    events = work / "events.log"

    def write_tool(name, body):
        path = tools / name
        path.write_text(body)
        path.chmod(0o755)
        return path

    real_git = shutil.which("git")
    real_shasum = shutil.which("shasum")
    write_tool("git", '#!/bin/sh\nif [ "${PN_FAIL_GIT:-}" = 1 ]; then exit 17; fi\nexec "$REAL_GIT" "$@"\n')
    write_tool("shasum", '#!/bin/sh\ncase "${PN_FAIL_HASH:-}:$*" in\n'
                          '  binary:*bin-*|diff:*tree.diff) exit 19 ;;\nesac\nexec "$REAL_SHASUM" "$@"\n')
    write_tool("uname", '#!/bin/sh\ncase "${1:-}" in -s) echo Darwin ;; -m) echo arm64 ;; *) echo Darwin ;; esac\n')
    write_tool("pgrep", '#!/bin/sh\nexit 1\n')
    write_tool("mktemp", '#!/bin/sh\nout="$("$REAL_MKTEMP" "$@")" || exit $?\n'
                         'case "$out" in /tmp/avm-pn.*|/private/tmp/avm-pn.*)\n'
                         '  printf "allocated %s\\n" "$out" >> "$PN_EVENTS"\n'
                         '  grep -Fxq "provenance: clean binary matches source HEAD" "$AGENT_VM_PN_EVIDENCE/provenance-check.txt" 2>/dev/null || { echo "scratch allocated before provenance success" >&2; exit 66; }\n'
                         '  ;;\nesac\nprintf "%s\\n" "$out"\n')
    write_tool("python3", '#!/bin/sh\ncase "${1:-}" in\n'
                          '  */build-provenance.py) exec "$REAL_PYTHON" "$@" ;;\n'
                          '  */persisted-network.py) if [ "${PN_FAIL_STARTUP:-}" = 1 ]; then echo "persisted-network driver startup failed" >&2; exit 29; fi; shift; exec "$REAL_PYTHON" "$STUB_DRIVER" "$@" ;;\n'
                          '  *) exec "$REAL_PYTHON" "$@" ;;\nesac\n')
    stub = work / "stub-driver.py"
    stub.write_text(
        "import os, shutil, sys\n"
        "events = os.environ['PN_EVENTS']\n"
        "def note(line):\n"
        "    with open(events, 'a') as handle:\n"
        "        handle.write(line + '\\n')\n"
        "root, evidence = sys.argv[1], sys.argv[2]\n"
        "note('driver')\n"
        "assert os.path.isdir(root), 'scratch missing'\n"
        "receipt = ''\n"
        "try:\n    receipt = open(os.path.join(evidence, 'provenance-check.txt')).read()\nexcept OSError:\n    pass\n"
        "assert 'provenance: clean binary matches source HEAD' in receipt, 'receipt must precede scratch'\n"
        "if os.environ.get('STUB_CLEANUP_FAIL') == '1':\n    note('cleanup-failed')\n    sys.exit(24)\n"
        "shutil.rmtree(root)\n"
        "note('cleanup')\n"
        "sys.exit(int(os.environ.get('STUB_EXIT', '0')))\n"
    )

    def live_env(env_extra=None):
        env = dict(os.environ)
        env["PATH"] = f"{tools}:{os.environ['PATH']}"
        env["REAL_MKTEMP"] = shutil.which("mktemp")
        env["REAL_GIT"] = real_git
        env["REAL_SHASUM"] = real_shasum
        env["REAL_PYTHON"] = sys.executable
        env["STUB_DRIVER"] = str(stub)
        env["PN_EVENTS"] = str(events)
        env["AGENT_VM_LIVE_TEST_IMAGE"] = "fixture-image"
        for key in ("AGENT_VM_BUILD_PROVENANCE_STRICT", "AGENT_VM_GIT_SHA", "GITHUB_SHA"):
            env.pop(key, None)
        if env_extra:
            env.update(env_extra)
        return env

    run_counter = [0]

    def run_live(script_repo, binary_body, *, name, env_extra=None):
        run_counter[0] += 1
        events.write_text("")
        binary = work / f"bin-{name}-{run_counter[0]}"
        binary.write_text(binary_body)
        binary.chmod(0o755)
        evidence = work / f"evidence-{name}-{run_counter[0]}"
        evidence.mkdir()
        env = live_env(env_extra)
        env["AGENT_VM_BIN"] = str(binary)
        env["AGENT_VM_PN_EVIDENCE"] = str(evidence)
        proc = subprocess.run(
            ["bash", str(script_repo / "script/test/persisted-network-live.sh")],
            cwd=script_repo, env=env, capture_output=True, text=True, timeout=180)
        return proc, evidence, events.read_text()

    def clean_binary(sha):
        return f"#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha})\\n'\n"

    def allocations(text):
        return [line.split(" ", 1)[1] for line in text.splitlines() if line.startswith("allocated ")]

    def teardown_live(proc, measured, pidfile, *, on_before_removal=None):
        # Resolve the owned driver during teardown instead of trusting a single
        # pre-teardown snapshot. Readiness may never arrive and the fixture may
        # still be about to publish PN_PID, but the shell records the driver PID
        # inside the scratch at launch, so ownership holds by construction.
        owned_scratch = allocations(events.read_text())
        driver = measured
        if driver is None:
            driver = read_owned_pid(pidfile)
        if driver is None:
            for path in owned_scratch:
                driver = read_launch_pid(Path(path))
                if driver is not None:
                    break
        if driver is None and owned_scratch:
            # Fail closed: without an owned driver PID, driver absence cannot be
            # established, so scratch stays as evidence rather than being
            # deleted around a possibly-live driver.
            survivors = reap_owned_fixture(proc, None)
            if sys.exc_info()[0] is None:
                raise AssertionError(
                    f"live shell ownership unresolved; retained scratch: {owned_scratch}")
            return survivors
        survivors = reap_owned_fixture(proc, driver)
        if survivors:
            if sys.exc_info()[0] is None:
                raise AssertionError(f"live shell left owned survivors: {survivors}")
            return survivors
        # Actual removal boundary: scratch is deleted only once both the shell
        # and the owned driver are established absent. Prove that here, at the
        # boundary, rather than inferring it from snapshots taken around it. Skip
        # the proof when an assertion is already unwinding so cleanup cannot mask
        # the real failure with a boundary message.
        if on_before_removal is not None and sys.exc_info()[0] is None:
            on_before_removal(owned_scratch)
        # The absence proof above is the only licence to delete; route the
        # removal through the single seam so that invariant has one home.
        discard_owned_scratch(owned_scratch, driver_established_absent=not survivors,
                              shell_established_absent=proc.poll() is not None)
        return survivors

    def emergency_reap(proc, snapshot):
        """Last-resort cleanup that owns scratch only through the seam.

        Used by controls whose own tracking may never have run — if the shell
        dies before the readiness assertions, `snapshot` is still `None`. That
        is unknown ownership, not absence, so identity is first recovered from
        the launch record left in the owned scratch; if it stays unknown the
        seam refuses to delete and the scratch survives as evidence. Returns the
        recovered driver PID so the caller can assert its absence.
        """
        if proc.poll() is None:
            reap_owned_fixture(proc, None)
        owned = [Path(path) for path in allocations(events.read_text())]
        if snapshot is None:
            for path in owned:
                snapshot = read_launch_pid(path)
                if snapshot is not None:
                    break
        if snapshot is not None:
            signal_owned(snapshot, signal.SIGKILL)
            deadline = time.monotonic() + TEARDOWN_TIMEOUT_SECONDS
            while pid_alive(snapshot) and time.monotonic() < deadline:
                time.sleep(SIGNAL_POLL_INTERVAL_SECONDS)
        discard_owned_scratch(
            owned,
            driver_established_absent=snapshot is not None and not pid_alive(snapshot),
            shell_established_absent=proc.poll() is not None)
        return snapshot

    def rejected(name, *args, **kwargs):
        proc, evidence, log = run_live(repo_a, *args, name=name, **kwargs)
        ok = (proc.returncode != 0 and "driver" not in log.split()
              and allocations(log) == [] and (evidence / "provenance-check.txt").exists())
        assert ok, f"P6 {name}: rc={proc.returncode} log={log!r} stdout={proc.stdout[-400:]}"
        required = ["source.txt", "tree.diff", "tree.diff.sha256", "binary.sha256",
                    "harness.sha256", "image.txt", "binary-version.txt"]
        assert all((evidence / path).exists() for path in required), f"missing rejection manifest: {name}"
        assert "rebuild" in (evidence / "provenance-check.txt").read_text(), name
        return evidence

    # Oracle preflight owns a separate committed fixture; never change A's SHA/history.
    oracle_repo = work / "oracle-repo"
    (oracle_repo / "script").mkdir(parents=True)
    shutil.copytree(root / "script/test", oracle_repo / "script/test", ignore=shutil.ignore_patterns("__pycache__"))
    oracle_sha = git_repo(oracle_repo, "oracle positive")
    proc, _, log = run_live(oracle_repo, clean_binary(oracle_sha), name="oracle-positive")
    assert proc.returncode == 0 and "driver" in log.split(), "oracle provenance prerequisites"
    oracle_tsv = oracle_repo / "script/test/fixtures/persisted-network/expected-stderr.tsv"
    oracle_tsv.write_text("\n".join(line for line in oracle_tsv.read_text().splitlines() if not line.startswith("PN3\t")) + "\n")
    oracle_sha = git_repo(oracle_repo, "oracle missing row")
    proc, evidence, log = run_live(oracle_repo, clean_binary(oracle_sha), name="oracle-missing")
    assert proc.returncode != 0 and not allocations(log) and "driver" not in log.split(), "oracle preflight did not refuse before allocation"
    assert not (evidence / "provenance-check.txt").exists(), "oracle refusal reached provenance"
    for row in ("PN1", "PN2", "PN3", "PN4B", "PN5"):
        lookup = subprocess.run(["bash", "-c", 'source "$1"; pn_expected "$2"', "pn", str(oracle_repo / "script/test/lib/persisted-network.sh"), row], capture_output=True, timeout=10)
        assert (lookup.returncode != 0) == (row == "PN3"), row
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_a, env=git_env, text=True).strip() == sha_a_full, "oracle control changed A HEAD"

    # TERM the actual live shell: its trap must forward to the cleanup-owning PID.
    term_stub = work / "term-driver.py"
    signal_stub(term_stub)
    ready, receipt = work / "live-ready", work / "live-term"
    term_pid = work / "live-driver-term.pid"
    binary = work / "bin-term"
    binary.write_text(clean_binary(sha_a_full))
    binary.chmod(0o755)
    evidence = work / "evidence-term"
    evidence.mkdir()
    events.write_text("")
    env = live_env({"STUB_DRIVER": str(term_stub), "PN_READY": str(ready), "PN_TERM": str(receipt),
                    "PN_PID": str(term_pid), "PN_REMOVE_SCRATCH": "1"})
    env.update(AGENT_VM_BIN=str(binary), AGENT_VM_PN_EVIDENCE=str(evidence))
    with (work / "term-stdout").open("w") as stdout, (work / "term-stderr").open("w") as stderr:
        proc = subprocess.Popen(["bash", str(repo_a / "script/test/persisted-network-live.sh")], cwd=repo_a, env=env, stdout=stdout, stderr=stderr)
        measured = None
        try:
            wait_ready(proc, ready)
            measured = int(ready.read_text())
            proc.terminate()
            assert proc.wait(timeout=TEARDOWN_TIMEOUT_SECONDS) != 0, "live TERM unexpectedly succeeded"
            assert receipt.read_text() == str(measured), "live trap did not forward TERM to measured driver"
            owned = allocations(events.read_text())
            assert len(owned) == 1 and not os.path.exists(owned[0]), "live TERM did not clean owned scratch"
            print("live shell TERM PASS: forwarded signal and retained cleanup receipt")
        finally:
            # Resolve the owned driver during teardown from the shell's launch
            # record or the fixture's startup PID, even if readiness never came.
            teardown_live(proc, measured, term_pid)

    # Failure path: a driver that ignores TERM must not strand the live shell or
    # its scratch. The shell blocks in its trap, so teardown must escalate to
    # KILL and only then reclaim scratch; a survivor fails this control loudly.
    ignored_stub = work / "ignored-term-driver.py"
    signal_stub(ignored_stub, ignore_term=True)
    ignored_ready, ignored_receipt = work / "live-ready-ignored", work / "live-term-ignored"
    ignored_pid = work / "live-driver-ignored.pid"
    ignored_binary = work / "bin-term-ignored"
    ignored_binary.write_text(clean_binary(sha_a_full))
    ignored_binary.chmod(0o755)
    ignored_evidence = work / "evidence-term-ignored"
    ignored_evidence.mkdir()
    events.write_text("")
    ignored_env = live_env({"STUB_DRIVER": str(ignored_stub), "PN_READY": str(ignored_ready),
                            "PN_TERM": str(ignored_receipt), "PN_PID": str(ignored_pid),
                            "PN_REMOVE_SCRATCH": "1"})
    ignored_env.update(AGENT_VM_BIN=str(ignored_binary), AGENT_VM_PN_EVIDENCE=str(ignored_evidence))
    with (work / "term-ignored-stdout").open("w") as stdout, (work / "term-ignored-stderr").open("w") as stderr:
        proc = subprocess.Popen(["bash", str(repo_a / "script/test/persisted-network-live.sh")], cwd=repo_a, env=ignored_env, stdout=stdout, stderr=stderr)
        measured = None
        observed_timeout = False
        try:
            wait_ready(proc, ignored_ready)
            measured = int(ignored_ready.read_text())
            proc.terminate()
            try:
                proc.wait(timeout=TEARDOWN_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                observed_timeout = True
        finally:
            teardown_live(proc, measured, ignored_pid)
        assert observed_timeout, "ignored-TERM live shell exited on TERM"
        assert not pid_alive(measured), "ignored-TERM live driver survived teardown"
    print("ignored-TERM live-shell control PASS: KILL reaped driver without survivors")

    # Pre-readiness ownership: a driver that never publishes readiness and
    # ignores TERM must still be owned through its startup PID, so teardown
    # keeps scratch until both shell and driver are absent. The driver PID is
    # read only after readiness fails, proving it was captured independently.
    rf_stub = work / "readiness-fail-driver.py"
    signal_stub(rf_stub, ignore_term=True, publish_ready=False)
    rf_ready, rf_receipt = work / "live-ready-rf", work / "live-term-rf"
    rf_pid = work / "live-driver-rf.pid"
    rf_binary = work / "bin-term-rf"
    rf_binary.write_text(clean_binary(sha_a_full))
    rf_binary.chmod(0o755)
    rf_evidence = work / "evidence-term-rf"
    rf_evidence.mkdir()
    events.write_text("")
    rf_env = live_env({"STUB_DRIVER": str(rf_stub), "PN_READY": str(rf_ready),
                       "PN_TERM": str(rf_receipt), "PN_PID": str(rf_pid),
                       "PN_REMOVE_SCRATCH": "1"})
    rf_env.update(AGENT_VM_BIN=str(rf_binary), AGENT_VM_PN_EVIDENCE=str(rf_evidence))
    with (work / "term-rf-stdout").open("w") as stdout, (work / "term-rf-stderr").open("w") as stderr:
        proc = subprocess.Popen(["bash", str(repo_a / "script/test/persisted-network-live.sh")], cwd=repo_a, env=rf_env, stdout=stdout, stderr=stderr)
        measured = None

        def at_removal_boundary(owned):
            # Asserted where scratch is actually deleted, not before or after.
            assert proc.poll() is not None, \
                "readiness-failure control: scratch removal began with the shell alive"
            assert not pid_alive(measured), \
                "readiness-failure control: scratch removal began with the driver alive"
            assert all(os.path.isdir(path) for path in owned), \
                "readiness-failure control: scratch vanished before the removal boundary"

        try:
            try:
                wait_ready(proc, rf_ready)
            except AssertionError as error:
                assert str(error) == "signal fixture readiness timeout", error
            else:
                raise AssertionError("readiness-failure control: live driver unexpectedly became ready")
            measured = read_owned_pid(rf_pid)
            assert measured is not None, "readiness-failure control: driver PID was not published before readiness"
            assert pid_alive(measured), "readiness-failure control: driver was absent before teardown"
            owned = allocations(events.read_text())
            assert owned and all(os.path.isdir(path) for path in owned), \
                "readiness-failure control: scratch was removed while the driver was alive"
            # TERM resistance: an ignoring fixture must survive a bounded TERM
            # with scratch intact and no cooperating receipt. A cooperating
            # fixture exits and writes the receipt, failing the control loudly.
            signal_owned(measured, signal.SIGTERM)
            term_deadline = time.monotonic() + TEARDOWN_TIMEOUT_SECONDS
            while pid_alive(measured) and time.monotonic() < term_deadline:
                time.sleep(SIGNAL_POLL_INTERVAL_SECONDS)
            assert pid_alive(measured), "readiness-failure control: fixture cooperated with TERM"
            assert not rf_receipt.exists(), "readiness-failure control: fixture wrote a TERM receipt"
            assert all(os.path.isdir(path) for path in allocations(events.read_text())), \
                "readiness-failure control: scratch was removed while the driver survived TERM"
        finally:
            teardown_live(proc, measured, rf_pid, on_before_removal=at_removal_boundary)
        assert not pid_alive(measured), "readiness-failure control: driver survived teardown"
        assert all(not os.path.exists(path) for path in allocations(events.read_text())), \
            "readiness-failure control: scratch was not removed after absence"
    print("live readiness-failure + ignored-TERM control PASS: TERM survived and absence established before scratch removal")

    # Publication race: PN_PID publication is still pending when readiness fails,
    # so a pre-teardown PID snapshot would be None. Ownership must still resolve
    # from the shell's launch record, leave no owned survivor, and never delete
    # scratch while the driver is alive. The withheld `pid_gate` simulates a
    # publication delayed past the readiness failure without touching scheduling.
    race_gate = work / "publication-race.release"
    race_gate.unlink(missing_ok=True)
    race_stub = work / "publication-race-driver.py"
    signal_stub(race_stub, ignore_term=True, publish_ready=False, pid_gate=race_gate)
    race_ready, race_receipt = work / "live-ready-race", work / "live-term-race"
    race_pid = work / "live-driver-race.pid"
    race_binary = work / "bin-term-race"
    race_binary.write_text(clean_binary(sha_a_full))
    race_binary.chmod(0o755)
    race_evidence = work / "evidence-term-race"
    race_evidence.mkdir()
    events.write_text("")
    race_env = live_env({"STUB_DRIVER": str(race_stub), "PN_READY": str(race_ready),
                         "PN_TERM": str(race_receipt), "PN_PID": str(race_pid),
                         "PN_REMOVE_SCRATCH": "1"})
    race_env.update(AGENT_VM_BIN=str(race_binary), AGENT_VM_PN_EVIDENCE=str(race_evidence))
    with (work / "term-race-stdout").open("w") as stdout, (work / "term-race-stderr").open("w") as stderr:
        proc = subprocess.Popen(["bash", str(repo_a / "script/test/persisted-network-live.sh")], cwd=repo_a, env=race_env, stdout=stdout, stderr=stderr)
        launch_pid = None

        def race_removal_boundary(owned):
            assert proc.poll() is not None, \
                "publication-race control: scratch removal began with the shell alive"
            assert launch_pid is not None and not pid_alive(launch_pid), \
                "publication-race control: scratch removal began with the driver alive"
            assert all(os.path.isdir(path) for path in owned), \
                "publication-race control: scratch vanished before the removal boundary"

        try:
            try:
                wait_ready(proc, race_ready)
            except AssertionError as error:
                assert str(error) == "signal fixture readiness timeout", error
            else:
                raise AssertionError("publication-race control: live driver unexpectedly became ready")
            assert not race_pid.exists(), "publication-race control: PN_PID was published before readiness failed"
            owned = allocations(events.read_text())
            assert owned, "publication-race control: no owned scratch was allocated"
            launch_pid = read_launch_pid(Path(owned[0]))
            assert launch_pid is not None, "publication-race control: shell launch record was missing"
            assert pid_alive(launch_pid), "publication-race control: launch-record driver was absent"
            assert all(os.path.isdir(path) for path in owned), \
                "publication-race control: scratch was removed while the driver was alive"
        finally:
            # Hand teardown no snapshot at all: with PN_PID withheld it must still
            # refresh ownership from the shell's launch record, not the caller.
            teardown_live(proc, None, race_pid, on_before_removal=race_removal_boundary)
        assert launch_pid is not None and not pid_alive(launch_pid), \
            "publication-race control: driver survived teardown"
        assert all(not os.path.exists(path) for path in allocations(events.read_text())), \
            "publication-race control: scratch was not removed after absence"
    print("live publication-race + ignored-TERM control PASS: launch record owned and reaped the withheld driver")

    # Launch-to-handoff interruption: TERM lands after the shell has published its
    # launch record but before the scratch handoff. The shell must reap the driver
    # before touching that record or the scratch, so a TERM-ignoring driver cannot
    # be stranded once the shell is gone. A BASH_ENV DEBUG hook pauses the shell
    # exactly at the handoff line, making the window deterministic; the release is
    # never created, so only the shell's own TERM trap moves it.
    pause_record = work / "prehandoff.paused"
    pause_release = work / "prehandoff.release"
    pause_release.unlink(missing_ok=True)
    pause_hook = work / "prehandoff-pause.sh"
    pause_hook.write_text(
        'pn_prehandoff_pause() {\n'
        '    if [[ "$BASH_COMMAND" == "shell_owns_scratch=0" ]]; then\n'
        '        printf "%s" "$root" > "$PN_PAUSE_SCRATCH"\n'
        '        while [[ ! -e "$PN_PAUSE_RELEASE" ]]; do sleep "$PN_PAUSE_INTERVAL"; done\n'
        '    fi\n'
        '}\n'
        'trap pn_prehandoff_pause DEBUG\n')
    prehandoff_stub = work / "prehandoff-driver.py"
    signal_stub(prehandoff_stub, ignore_term=True, publish_ready=False)
    prehandoff_binary = work / "bin-prehandoff"
    prehandoff_binary.write_text(clean_binary(sha_a_full))
    prehandoff_binary.chmod(0o755)
    prehandoff_evidence = work / "evidence-prehandoff"
    prehandoff_evidence.mkdir()
    prehandoff_pid = work / "live-driver-prehandoff.pid"
    events.write_text("")
    prehandoff_env = live_env({"STUB_DRIVER": str(prehandoff_stub), "BASH_ENV": str(pause_hook),
                               "PN_PAUSE_SCRATCH": str(pause_record),
                               "PN_PAUSE_RELEASE": str(pause_release),
                               "PN_PAUSE_INTERVAL": str(SIGNAL_POLL_INTERVAL_SECONDS),
                               "PN_READY": str(work / "live-ready-prehandoff"),
                               "PN_TERM": str(work / "live-term-prehandoff"),
                               "PN_PID": str(prehandoff_pid),
                               "PN_REMOVE_SCRATCH": "1"})
    prehandoff_env.update(AGENT_VM_BIN=str(prehandoff_binary),
                          AGENT_VM_PN_EVIDENCE=str(prehandoff_evidence))
    with (work / "term-prehandoff-stdout").open("w") as stdout, \
         (work / "term-prehandoff-stderr").open("w") as stderr:
        proc = subprocess.Popen(["bash", str(repo_a / "script/test/persisted-network-live.sh")],
                                cwd=repo_a, env=prehandoff_env, stdout=stdout, stderr=stderr)
        launch_pid = None
        observed_timeout = False

        def prehandoff_removal_boundary(owned):
            assert proc.poll() is not None, \
                "pre-handoff control: scratch removal began with the shell alive"
            assert launch_pid is not None and not pid_alive(launch_pid), \
                "pre-handoff control: scratch removal began with the driver alive"
            assert all(os.path.isdir(path) for path in owned), \
                "pre-handoff control: scratch vanished before the removal boundary"

        try:
            # Wait for both the paused shell and the driver's own PID publication:
            # the fixture publishes PN_PID only after it registers SIG_IGN, so an
            # observed PID proves the driver will ignore the TERM we deliver.
            boundary_deadline = time.monotonic() + READINESS_DEADLINE_SECONDS
            while not (pause_record.exists() and prehandoff_pid.exists()) \
                    and time.monotonic() < boundary_deadline:
                time.sleep(SIGNAL_POLL_INTERVAL_SECONDS)
            assert pause_record.exists(), \
                "pre-handoff control: shell never reached the handoff boundary"
            assert prehandoff_pid.exists(), \
                "pre-handoff control: driver never registered TERM handling before handoff"
            scratch = Path(pause_record.read_text())
            launch_pid = read_launch_pid(scratch)
            published_pid = read_owned_pid(prehandoff_pid)
            assert launch_pid is not None, \
                "pre-handoff control: launch record was absent before handoff"
            assert launch_pid == published_pid, \
                "pre-handoff control: launch record and published PID disagreed"
            assert pid_alive(launch_pid), "pre-handoff control: driver was absent before handoff"
            proc.terminate()
            try:
                proc.wait(timeout=TEARDOWN_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                observed_timeout = True
            assert observed_timeout, \
                "pre-handoff control: shell exited without reaping the ignored-TERM driver"
            assert os.path.isdir(scratch) and (scratch / "driver.pid").exists(), \
                "pre-handoff control: shell removed identity or scratch while the driver lived"
            assert pid_alive(launch_pid), "pre-handoff control: driver was already absent"
        finally:
            teardown_live(proc, launch_pid, prehandoff_pid,
                          on_before_removal=prehandoff_removal_boundary)
        assert proc.poll() is not None, "pre-handoff control: shell survived teardown"
        assert launch_pid is not None and not pid_alive(launch_pid), \
            "pre-handoff control: driver survived teardown"
        assert all(not os.path.exists(path) for path in allocations(events.read_text())), \
            "pre-handoff control: scratch was not removed after absence"
    print("live launch-to-handoff + ignored-TERM control PASS: identity and scratch retained until driver absence")

    # Unresolved ownership fails closed. Withhold PN_PID *and* drop the shell's
    # launch record before teardown, so no owned driver PID can be established:
    # teardown must reap only the shell, keep the scratch as evidence, and raise
    # rather than delete scratch around a possibly-live owned driver.
    unresolved_gate = work / "unresolved-owner.release"
    unresolved_gate.unlink(missing_ok=True)
    unresolved_stub = work / "unresolved-owner-driver.py"
    signal_stub(unresolved_stub, ignore_term=True, publish_ready=False, pid_gate=unresolved_gate)
    unresolved_ready, unresolved_receipt = work / "live-ready-unresolved", work / "live-term-unresolved"
    unresolved_pid = work / "live-driver-unresolved.pid"
    unresolved_binary = work / "bin-term-unresolved"
    unresolved_binary.write_text(clean_binary(sha_a_full))
    unresolved_binary.chmod(0o755)
    unresolved_evidence = work / "evidence-term-unresolved"
    unresolved_evidence.mkdir()
    events.write_text("")
    unresolved_env = live_env({"STUB_DRIVER": str(unresolved_stub), "PN_READY": str(unresolved_ready),
                               "PN_TERM": str(unresolved_receipt), "PN_PID": str(unresolved_pid),
                               "PN_REMOVE_SCRATCH": "1"})
    unresolved_env.update(AGENT_VM_BIN=str(unresolved_binary), AGENT_VM_PN_EVIDENCE=str(unresolved_evidence))
    with (work / "term-unresolved-stdout").open("w") as stdout, (work / "term-unresolved-stderr").open("w") as stderr:
        proc = subprocess.Popen(["bash", str(repo_a / "script/test/persisted-network-live.sh")], cwd=repo_a, env=unresolved_env, stdout=stdout, stderr=stderr)
        orphan = None
        try:
            try:
                wait_ready(proc, unresolved_ready)
            except AssertionError as error:
                assert str(error) == "signal fixture readiness timeout", error
            else:
                raise AssertionError("unresolved-ownership control: live driver unexpectedly became ready")
            assert not unresolved_pid.exists(), "unresolved-ownership control: PN_PID was published"
            owned = allocations(events.read_text())
            assert owned, "unresolved-ownership control: no owned scratch was allocated"
            scratch = Path(owned[0])
            orphan = read_launch_pid(scratch)
            assert orphan is not None and pid_alive(orphan), \
                "unresolved-ownership control: launch record was absent"
            (scratch / "driver.pid").unlink()
            try:
                teardown_live(proc, None, unresolved_pid)
            except AssertionError as error:
                assert "ownership unresolved" in str(error), error
            else:
                raise AssertionError(
                    "unresolved-ownership control: teardown deleted scratch with ownership unresolved")
            assert pid_alive(orphan), "unresolved-ownership control: driver was not preserved as evidence"
            assert os.path.isdir(scratch), \
                "unresolved-ownership control: scratch was removed while ownership was unresolved"
        finally:
            # Ownership was deliberately withheld: recover the recorded driver
            # (or, if the shell died before it was captured, the launch record
            # in the owned scratch) and remove scratch only through the seam,
            # which refuses while absence is unproven.
            orphan = emergency_reap(proc, orphan)
        assert orphan is not None and not pid_alive(orphan), \
            "unresolved-ownership control: driver survived cleanup"
    print("unresolved-ownership control PASS: fail-closed teardown kept scratch and raised")

    # Failure before ownership capture. If the shell dies — here KILLed — after
    # recording its launch identity but before readiness, the control's own
    # snapshot never runs and `orphan` is still None when cleanup unwinds. A None
    # snapshot is unknown ownership, not absence: cleanup must recover the driver
    # from the launch record in the owned scratch, KILL a TERM-resistant driver,
    # and delete scratch only once it is absent. This is the adversarial
    # emergency-guard failure path as a first-class control.
    early_gate = work / "early-exit.release"
    early_gate.unlink(missing_ok=True)
    early_stub = work / "early-exit-driver.py"
    signal_stub(early_stub, ignore_term=True, publish_ready=False, pid_gate=early_gate)
    early_ready, early_receipt = work / "live-ready-early", work / "live-term-early"
    early_pid = work / "live-driver-early.pid"
    early_binary = work / "bin-term-early"
    early_binary.write_text(clean_binary(sha_a_full))
    early_binary.chmod(0o755)
    early_evidence = work / "evidence-term-early"
    early_evidence.mkdir()
    events.write_text("")
    early_env = live_env({"STUB_DRIVER": str(early_stub), "PN_READY": str(early_ready),
                          "PN_TERM": str(early_receipt), "PN_PID": str(early_pid),
                          "PN_REMOVE_SCRATCH": "1"})
    early_env.update(AGENT_VM_BIN=str(early_binary), AGENT_VM_PN_EVIDENCE=str(early_evidence))
    with (work / "term-early-stdout").open("w") as stdout, \
         (work / "term-early-stderr").open("w") as stderr:
        proc = subprocess.Popen(["bash", str(repo_a / "script/test/persisted-network-live.sh")],
                                cwd=repo_a, env=early_env, stdout=stdout, stderr=stderr)
        observed = None
        try:
            # Wait for the shell to record the driver identity, then release the
            # gate so the fixture publishes its PID after installing SIG_IGN:
            # that proves TERM resistance and lets this control learn the driver
            # independently. Deleting the published PID leaves the launch record
            # as the only identity cleanup can recover.
            scratch = None
            deadline = time.monotonic() + READINESS_DEADLINE_SECONDS
            while time.monotonic() < deadline:
                allocated = allocations(events.read_text())
                if allocated:
                    candidate = read_launch_pid(Path(allocated[0]))
                    if candidate is not None:
                        scratch, observed = Path(allocated[0]), candidate
                        break
                time.sleep(SIGNAL_POLL_INTERVAL_SECONDS)
            assert scratch is not None, \
                "failure-before-ownership control: shell never recorded its driver"
            early_gate.write_text("release")
            registration_deadline = time.monotonic() + READINESS_DEADLINE_SECONDS
            while not early_pid.exists() and time.monotonic() < registration_deadline:
                time.sleep(SIGNAL_POLL_INTERVAL_SECONDS)
            assert early_pid.exists(), \
                "failure-before-ownership control: fixture never registered TERM handling"
            assert int(early_pid.read_text()) == observed, \
                "failure-before-ownership control: launch record and published PID disagreed"
            assert pid_alive(observed), "failure-before-ownership control: driver was absent"
            early_pid.unlink()
            proc.kill()
            try:
                wait_ready(proc, early_ready)
            except AssertionError as error:
                assert str(error) == "signal fixture exited before readiness", error
            else:
                raise AssertionError(
                    "failure-before-ownership control: shell was KILLed but readiness arrived")
            # The bounded failure is not absence: identity and scratch survive it,
            # and the seam must refuse to delete while either is unproven.
            assert os.path.isdir(scratch) and (scratch / "driver.pid").exists(), \
                "failure-before-ownership control: shell death erased driver identity or scratch"
            assert pid_alive(observed), \
                "failure-before-ownership control: driver did not outlive the shell"
            for driver_absent, shell_absent in ((False, True), (True, False)):
                try:
                    discard_owned_scratch(allocations(events.read_text()),
                                          driver_established_absent=driver_absent,
                                          shell_established_absent=shell_absent)
                except AssertionError as error:
                    assert "ownership is unresolved" in str(error), error
                else:
                    raise AssertionError(
                        "failure-before-ownership control: seam removed scratch with "
                        f"driver_absent={driver_absent} shell_absent={shell_absent}")
            assert os.path.isdir(scratch) and (scratch / "driver.pid").exists(), \
                "failure-before-ownership control: seam removed scratch with unknown ownership"
        finally:
            # The control deliberately hands cleanup no snapshot, exactly as if the
            # shell had died before readiness: recovery must come from the scratch.
            recovered = emergency_reap(proc, None)
        assert recovered == observed and recovered is not None and not pid_alive(recovered), \
            "failure-before-ownership control: driver survived cleanup"
        assert all(not os.path.exists(path) for path in allocations(events.read_text())), \
            "failure-before-ownership control: scratch was not removed after absence"
    print("live failure-before-ownership control PASS: recovered identity and reaped before scratch removal")

    # P6: dirty/mismatched/unknown candidates and a dirty source.
    flipped = sha_a_full[:-1] + ("0" if sha_a_full[-1] != "0" else "1")
    rejected("mismatch-sha", clean_binary(flipped))
    rejected("dirty-binary", f"#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a_full}, dirty)\\n'\n")
    rejected("unknown-state", f"#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a_full}, state unknown)\\n'\n")
    rejected("unknown-revision", "#!/bin/sh\nprintf 'agent-vm 0.3.4 (unknown)\\n'\n")
    (repo_a / "script/test/README-dirt").write_text("dirt\n")
    subprocess.run(["git", "add", "script/test/README-dirt"], cwd=repo_a, check=True, env=git_env)
    rejected("dirty-source-content", clean_binary(sha_a_full))
    subprocess.run(["git", "reset", "-q", "--hard"], cwd=repo_a, check=True, env=git_env)
    (repo_a / "script/test/README-dirt").unlink(missing_ok=True)
    script_dirt = repo_a / "script/test/persisted-network-live.sh"
    script_dirt.chmod(script_dirt.stat().st_mode & ~0o111)
    rejected("dirty-source-mode", clean_binary(sha_a_full))
    script_dirt.chmod(script_dirt.stat().st_mode | 0o111)
    subprocess.run(["git", "reset", "-q", "--hard"], cwd=repo_a, check=True, env=git_env)

    # P7: a matching clean candidate reaches one harmless driver.
    ok_proc, ok_evidence, ok_log = run_live(repo_a, clean_binary(sha_a_full), name="accept")
    ok_allocs = allocations(ok_log)
    assert ok_proc.returncode == 0, f"P7 rc={ok_proc.returncode} {ok_proc.stdout[-400:]} {ok_proc.stderr[-400:]}"
    assert ok_log.split().count("driver") == 1 and ok_log.split().count("cleanup") == 1, ok_log
    assert len(ok_allocs) == 1 and not os.path.exists(ok_allocs[0]), ok_log
    assert (ok_evidence / "binary.sha256").exists() and (ok_evidence / "provenance-check.txt").exists(), "evidence retained"
    (repo_a / "script/test/untracked-ok").write_text("u\n")
    unt_proc, _, unt_log = run_live(repo_a, clean_binary(sha_a_full), name="accept-untracked")
    assert unt_proc.returncode == 0 and len(allocations(unt_log)) == 1, unt_log
    (repo_a / "script/test/untracked-ok").unlink()

    # P8: driver status propagation and cleanup semantics.
    exit23, _, log23 = run_live(repo_a, clean_binary(sha_a_full), name="exit23",
                                env_extra={"STUB_EXIT": "23"})
    assert exit23.returncode == 23, f"P8 expected 23, got {exit23.returncode}"
    assert log23.split().count("driver") == 1 and "cleanup" in log23.split()
    assert allocations(log23) and not os.path.exists(allocations(log23)[0]), log23
    cleanfail, _, logcf = run_live(repo_a, clean_binary(sha_a_full), name="cleanfail",
                                   env_extra={"STUB_CLEANUP_FAIL": "1"})
    assert cleanfail.returncode == 24, f"P8 expected 24, got {cleanfail.returncode}"
    assert "cleanup-failed" in logcf, logcf
    cleanfail_scratch = allocations(logcf)
    assert len(cleanfail_scratch) == 1 and os.path.isdir(cleanfail_scratch[0]), \
        "failed cleanup must preserve owned scratch"
    # The shell only exits after `wait "$driver"`, so the status-24 return proves
    # the driver is gone; confirm identity is absent, not merely unreadable.
    cleanfail_driver = read_launch_pid(Path(cleanfail_scratch[0]))
    assert cleanfail_driver is not None and not pid_alive(cleanfail_driver), \
        "failed cleanup control: driver identity absent after the shell returned"
    discard_owned_scratch(cleanfail_scratch, driver_established_absent=True,
                          shell_established_absent=True)

    # No cleanup-owning driver exists on exec/startup or canonicalization failure.
    bash_env = work / "fail-scratch-cd.sh"
    bash_env.write_text('cd() { case "${1:-}" in /tmp/avm-pn.*|/private/tmp/avm-pn.*) '
                        'echo "scratch canonicalization failed" >&2; return 33 ;; '
                        '*) builtin cd "$@" ;; esac; }\n')
    for name, extra, status, diagnostic in [
        ("canonicalization-failure", {"BASH_ENV": str(bash_env)}, 33, "scratch canonicalization failed"),
        ("startup-failure", {"PN_FAIL_STARTUP": "1"}, 29, "driver startup failed"),
    ]:
        proc, _, log = run_live(repo_a, clean_binary(sha_a_full), name=name, env_extra=extra)
        owned = allocations(log)
        try:
            assert proc.returncode == status and diagnostic in proc.stderr, (name, proc)
            assert len(owned) == 1 and not os.path.exists(owned[0]), (name, log, proc.stderr)
            assert not {"driver", "cleanup", "cleanup-failed"}.intersection(log.split()), (name, log)
            print(f"P8 {name} PASS: status {status}, scratch removed, no driver/cleanup")
        finally:
            # Baseline regressions must not leave test-owned empty scratch
            # behind. These exec/startup paths never launch a driver, so driver
            # and shell absence hold; reclaim only empty scratch through the
            # seam so a regression that left driver state still fails loudly.
            discard_owned_scratch(owned, driver_established_absent=True,
                                  shell_established_absent=True, empty_only=True)

    # P9: inherited Git routing must not select checkout B.
    routing = {"GIT_DIR": str(repo_b / ".git"), "GIT_WORK_TREE": str(repo_b),
               "GIT_INDEX_FILE": str(repo_b / ".git/index"),
               "GIT_COMMON_DIR": str(repo_b / ".git"), "GIT_NAMESPACE": "other"}
    b_proc, b_evidence, b_log = run_live(repo_a, clean_binary(sha_b_full), name="routed-b", env_extra=routing)
    assert b_proc.returncode != 0 and allocations(b_log) == [] and "driver" not in b_log.split(), b_log
    assert f"commit: {sha_a_full}" in (b_evidence / "source.txt").read_text(), "must record A"
    a_proc, _, a_log = run_live(repo_a, clean_binary(sha_a_full), name="routed-a", env_extra=routing)
    assert a_proc.returncode == 0 and len(allocations(a_log)) == 1, f"P9 routed A must accept: {a_log}"
    # Wrong top level: the harness source lives in an unversioned subdirectory.
    repo_c = work / "C"
    (repo_c / "sub/script").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo_c, check=True, env=git_env)
    (repo_c / "outer.txt").write_text("outer\n")
    shutil.copytree(root / "script/test", repo_c / "sub/script/test",
                    ignore=shutil.ignore_patterns("__pycache__"))
    c_proc, c_evidence, c_log = run_live(repo_c / "sub", clean_binary(sha_a_full), name="wrong-root")
    assert c_proc.returncode != 0 and allocations(c_log) == [] and "driver" not in c_log.split(), c_log

    assert (c_evidence / "provenance-check.txt").exists(), "root rejection receipt"
    assert "not yet validated" in (c_evidence / "source.txt").read_text(), "root identity not trusted"
    for path in ["binary.sha256", "harness.sha256", "image.txt"]:
        assert (c_evidence / path).exists(), f"root rejection lost {path}"

    # Fallible preflight controls: rejection manifests, no scratch or driver.
    for name, extra, body in [
        ("git-failure", {"PN_FAIL_GIT": "1"}, clean_binary(sha_a_full)),
        ("binary-hash-failure", {"PN_FAIL_HASH": "binary"}, clean_binary(sha_a_full)),
        ("diff-hash-failure", {"PN_FAIL_HASH": "diff"}, clean_binary(sha_a_full)),
        ("version-failure", {}, "#!/bin/sh\nprintf partial; exit 9\n"),
    ]:
        proc, evidence, log = run_live(repo_a, body, name=name, env_extra=extra)
        assert proc.returncode != 0 and allocations(log) == [] and "driver" not in log.split(), name
        receipt = (evidence / "provenance-check.txt").read_text()
        assert "provenance:" in receipt and "rebuild" in receipt, name
        assert (evidence / "source.txt").exists() and (evidence / "image.txt").exists(), name
        if name == "version-failure":
            assert (evidence / "binary-version.txt").read_bytes() == b"partial", name
            assert all((evidence / path).exists() for path in
                       ["tree.diff", "tree.diff.sha256", "binary.sha256", "harness.sha256"]), name
        if name == "diff-hash-failure":
            assert (evidence / "tree.diff").exists() and (evidence / "binary.sha256").exists(), name

    # P10: the candidate's exact stdout bytes are preserved and rejected.
    def byte_case(name, body, expected_bytes):
        proc, evidence, log = run_live(repo_a, body, name=name)
        saved = (evidence / "binary-version.txt").read_bytes()
        assert proc.returncode != 0 and allocations(log) == [] and "driver" not in log.split(), f"P10 {name}: {log}"
        assert saved == expected_bytes, f"P10 {name}: saved {saved!r} != {expected_bytes!r}"

    byte_case("blank-lines", f"#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a_full})\\n\\n\\n'\n",
              f"agent-vm 0.3.4 ({sha_a_full})\n\n\n".encode())
    byte_case("second-line", f"#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a_full})\\nnoise\\n'\n",
              f"agent-vm 0.3.4 ({sha_a_full})\nnoise\n".encode())
    byte_case("no-final-lf", f"#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a_full})'\n",
              f"agent-vm 0.3.4 ({sha_a_full})".encode())
    byte_case("invalid-utf8", f"#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a_full})\\377\\n'\n",
              f"agent-vm 0.3.4 ({sha_a_full})".encode() + b"\xff\n")
    partial = f"agent-vm 0.3.4 ({sha_a_full[:20]}"
    proc, evidence, log = run_live(repo_a, f"#!/bin/sh\nprintf '{partial}'; exit 9\n", name="partial-exit")
    assert proc.returncode != 0 and allocations(log) == [] and "driver" not in log.split(), proc.stdout[-200:]
    assert (evidence / "binary-version.txt").read_bytes() == partial.encode(), "partial stdout preserved"


def load_driver(root: Path):
    spec = importlib.util.spec_from_file_location("pn_contract_driver", root / "script/test/lib/persisted-network.py")
    driver = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = driver
    spec.loader.exec_module(driver)
    return driver


def pid_alive(pid: int) -> bool:
    """Liveness of a PID this test measured. A reaped PID reports not alive."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_owned_pid(path: Path):
    """PID the fixture publishes at startup, before readiness; None if unwritten."""
    try:
        return int(path.read_text())
    except (OSError, ValueError):
        return None


def read_launch_pid(root: Path):
    """Driver PID the live shell records beside the scratch it hands over."""
    return read_owned_pid(root / "driver.pid")


def owned_alive(proc, pid: int) -> bool:
    # A Popen must be polled so its own exit status is reaped; a measured PID
    # that is not the Popen is only observable through the kernel.
    return proc.poll() is None if pid == proc.pid else pid_alive(pid)


def signal_owned(pid: int, sig: int) -> None:
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        pass  # Already exited: a dead-PID race is not a teardown error.


def await_owned_absent(proc, measured, deadline: float) -> None:
    if proc.poll() is None:
        try:
            proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            pass
    if measured is not None and measured != proc.pid:
        while pid_alive(measured) and time.monotonic() < deadline:
            time.sleep(SIGNAL_POLL_INTERVAL_SECONDS)


def reap_owned_fixture(proc, measured):
    """Bounded TERM -> KILL teardown of exactly the fixture this test launched.

    Signalling only the owned Popen and the measured PID keeps unrelated
    processes out of reach. Timeouts never raise, so cleanup cannot mask an
    assertion already in flight; any PID still alive after the KILL grace is
    returned so the caller can fail loudly instead of logging a survivor.
    """
    pids = [proc.pid]
    if measured is not None and measured != proc.pid:
        pids.append(measured)
    for pid in pids:
        if owned_alive(proc, pid):
            signal_owned(pid, signal.SIGTERM)
    await_owned_absent(proc, measured, time.monotonic() + TEARDOWN_TIMEOUT_SECONDS)
    for pid in pids:
        if owned_alive(proc, pid):
            signal_owned(pid, signal.SIGKILL)
    await_owned_absent(proc, measured, time.monotonic() + TEARDOWN_TIMEOUT_SECONDS)
    return [pid for pid in pids if owned_alive(proc, pid)]


def discard_owned_scratch(paths, *, driver_established_absent: bool,
                          shell_established_absent: bool, empty_only: bool = False) -> None:
    """The single seam through which this harness deletes owned scratch.

    Removing owned scratch is only safe once the driver it was allocated for has
    been established absent (and, for a live-shell control, the shell too). Every
    harness removal path routes through here so that invariant has one home:
    unknown ownership — a launch record that could not be read, an `orphan` left
    as `None` before the readiness assertions ran — is not absence, and the
    scratch is retained as evidence instead. Refusal is loud when no assertion is
    already unwinding, so an unresolved fixture is reported rather than silently
    leaked; when one is in flight the scratch is still kept but cleanup cannot
    mask the real failure. `empty_only` reclaims a scratch known to hold no
    driver state with `rmdir` rather than `rmtree`, so a regression that left
    driver state behind keeps failing loudly instead of being erased.
    """
    if not (driver_established_absent and shell_established_absent):
        if sys.exc_info()[0] is None:
            raise AssertionError(
                "refusing to remove owned scratch while ownership is unresolved; "
                f"retained as evidence: {[str(Path(path)) for path in paths]}")
        return
    for path in paths:
        if empty_only:
            if os.path.isdir(path):
                os.rmdir(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)


def wait_ready(proc, ready: Path) -> None:
    deadline = time.monotonic() + READINESS_DEADLINE_SECONDS
    while not ready.exists():
        assert proc.poll() is None, "signal fixture exited before readiness"
        assert time.monotonic() < deadline, "signal fixture readiness timeout"
        time.sleep(SIGNAL_POLL_INTERVAL_SECONDS)


def signal_stub(path: Path, *, ignore_term: bool = False, publish_ready: bool = True,
                pid_gate: Path | None = None) -> None:
    # Absolute interpreter avoids recursion when this fixture itself is named python3.
    # The owned PID is published before readiness so teardown can act on it even
    # when readiness never arrives; readiness is only a proof the driver started.
    # Publication happens *after* the TERM registration, so an observed owned PID
    # guarantees the handler (or SIG_IGN) is already installed. With pid_gate the
    # publication waits for that file instead, also after registration, so a
    # control can hold PN_PID past a readiness failure while the fixture stays
    # TERM-resistant.
    registration = ("signal.signal(signal.SIGTERM, signal.SIG_IGN)" if ignore_term
                    else "signal.signal(signal.SIGTERM, term)")
    lines = ["import os, signal, sys, shutil"]
    if pid_gate is not None:
        lines.append("import time")
    lines += ['from pathlib import Path',
              'ready = Path(os.environ["PN_READY"])',
              'receipt = Path(os.environ["PN_TERM"])']
    lines += ['def term(signum, frame):',
              '    receipt.write_text(str(os.getpid()))',
              '    if os.environ.get("PN_REMOVE_SCRATCH") == "1":',
              '        shutil.rmtree(sys.argv[1])',
              '    sys.exit(143)',
              registration]
    if pid_gate is None:
        lines += ['owned_pid = os.environ.get("PN_PID")',
                  'if owned_pid:',
                  '    Path(owned_pid).write_text(str(os.getpid()))']
    if pid_gate is not None:
        lines += ['owned_pid = os.environ.get("PN_PID")',
                  'if owned_pid:',
                  f'    while not Path({str(pid_gate)!r}).exists():',
                  f'        time.sleep({SIGNAL_POLL_INTERVAL_SECONDS})',
                  '    Path(owned_pid).write_text(str(os.getpid()))']
    if publish_ready:
        lines += ['ready.with_suffix(".pending").write_text(str(os.getpid()))',
                  'ready.with_suffix(".pending").replace(ready)']
    lines += ['while True:', '    signal.pause()']
    path.write_text(f"#!{sys.executable}\n" + "\n".join(lines) + "\n")
    path.chmod(0o755)


class SentinelAccepted(AssertionError):
    """Only this semantic failure is a hard-coded-lookup negative-control kill."""


def helper_controls(root: Path, work: Path) -> None:
    mirror = work / "lookup"
    (mirror / "script").mkdir(parents=True)
    shutil.copytree(root / "script/test", mirror / "script/test", ignore=shutil.ignore_patterns("__pycache__"))
    helper = mirror / "script/test/lib/persisted-network.sh"
    tsv = mirror / "script/test/fixtures/persisted-network/expected-stderr.tsv"
    original = tsv.read_text()
    rows = {}
    for line in original.splitlines():
        if line and not line.startswith("#"):
            row, text = line.split("\t")
            rows.setdefault(row, []).append(text)
    driver = load_driver(mirror)
    for row, texts in rows.items():
        result = subprocess.run(["bash", "-c", 'source "$1"; pn_expected "$2"', "pn", str(helper), row], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and result.stdout == "".join(text + "\n" for text in texts), row
        assert driver.shell_helper("pn_expected", row) == result.stdout, row
        fixed_log = "\n".join(texts)
        driver.require_shared_stderr_oracle(row, fixed_log, row)
        for omitted in range(len(texts)):
            try:
                driver.require_shared_stderr_oracle(row, "\n".join(text for i, text in enumerate(texts) if i != omitted), row)
            except AssertionError as error:
                assert texts[omitted] in str(error), row
            else:
                raise AssertionError(f"{row}: missing-substring control accepted")

        sentinel = f"PN_SENTINEL_{row}"
        updated = texts.copy()
        updated[0] = sentinel
        tsv.write_text(original.replace(f"{row}\t{texts[0]}", f"{row}\t{sentinel}"))

        def sentinel_control():
            try:
                driver.require_shared_stderr_oracle(row, fixed_log, row)
            except AssertionError as error:
                assert sentinel in str(error), f"{row}: sentinel not named: {error}"
            else:
                raise SentinelAccepted(f"{row}: sentinel control accepted unchanged log")

        try:
            sentinel_control()
            driver.require_shared_stderr_oracle(row, "\n".join(updated), row)
            real_helper = driver.shell_helper
            driver.shell_helper = lambda name, value: "\n".join(rows[value]) + "\n" if name == "pn_expected" else real_helper(name, value)
            try:
                sentinel_control()
            except SentinelAccepted:
                print(f"{row} hard-coded lookup negative control PASS: semantic acceptance failure")
            else:
                raise AssertionError(f"{row}: hard-coded negative control survived")
            finally:
                driver.shell_helper = real_helper
            sentinel_control()
        finally:
            tsv.write_text(original)
    driver.require_shared_stderr_oracle("unchecked", "", None)
    unknown = subprocess.run(["bash", "-c", 'source "$1"; pn_expected absent', "pn", str(helper)], capture_output=True, timeout=10)
    assert unknown.returncode != 0, "unknown shell row accepted"
    try:
        driver.require_shared_stderr_oracle("unknown", "", "absent")
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError("unknown consumer row accepted")

    tools = work / "tools"
    tools.mkdir()
    signal_stub(tools / "python3")
    env = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}")

    def pid_control():
        ready, receipt = work / "ready", work / "term"
        ready.unlink(missing_ok=True)
        receipt.unlink(missing_ok=True)
        proc = subprocess.Popen(["bash", "-c", 'source "$1"; pn_launch unused', "pn", str(helper)], env=dict(env, PN_READY=str(ready), PN_TERM=str(receipt)))
        measured = None
        try:
            wait_ready(proc, ready)
            measured = int(ready.read_text())
            assert proc.pid == measured, "pn_launch PID ownership mismatch"
            proc.terminate()
            assert proc.wait(timeout=TEARDOWN_TIMEOUT_SECONDS) != 0 and receipt.read_text() == str(measured), "pn_launch TERM cleanup missing"
        finally:
            survivors = reap_owned_fixture(proc, measured)
            if survivors and sys.exc_info()[0] is None:
                raise AssertionError(f"pn_launch fixture survived teardown: {survivors}")

    pid_control()
    source = helper.read_text()
    helper.write_text(source.replace("exec python3", "python3"))
    try:
        try:
            pid_control()
        except AssertionError as error:
            assert str(error) == "pn_launch PID ownership mismatch", error
            print("no-exec negative control PASS: PID ownership mismatch")
        else:
            raise AssertionError("no-exec negative control survived")
    finally:
        helper.write_text(source)
    pid_control()

    def write_python_stub(body: str) -> None:
        stub = tools / "python3"
        stub.write_text(f"#!{sys.executable}\n{body}\n")
        stub.chmod(0o755)

    def dead_fixture_control(name: str, body: str, expected_error: str) -> None:
        write_python_stub(body)
        try:
            ready, receipt = work / f"ready-{name}", work / f"term-{name}"
            ready.unlink(missing_ok=True)
            proc = subprocess.Popen(["bash", "-c", 'source "$1"; pn_launch unused', "pn", str(helper)],
                                    env=dict(env, PN_READY=str(ready), PN_TERM=str(receipt)))
            measured = None
            try:
                try:
                    wait_ready(proc, ready)
                except AssertionError as error:
                    assert expected_error in str(error), (name, error)
                else:
                    raise AssertionError(f"{name}: wait_ready accepted a bad fixture")
            finally:
                survivors = reap_owned_fixture(proc, measured)
            assert not survivors and proc.poll() is not None, f"{name}: survivors {survivors}"
            print(f"{name} control PASS: bounded wait reported and teardown reaped the owned fixture")
        finally:
            signal_stub(tools / "python3")

    # Exit before readiness: a dead fixture is reported, not waited out.
    dead_fixture_control("exit-before-readiness", "import sys\nsys.exit(0)",
                         "signal fixture exited before readiness")
    # Readiness timeout: a live fixture that never signals is still bounded.
    dead_fixture_control("readiness-timeout", "import signal\nwhile True:\n    signal.pause()",
                         "signal fixture readiness timeout")

    # Ignored TERM: the bounded wait must time out, then KILL must reap the
    # owned fixture; a survivor fails the control loudly instead of logging.
    signal_stub(tools / "python3", ignore_term=True)
    try:
        ready, receipt = work / "ready-ignored", work / "term-ignored"
        ready.unlink(missing_ok=True)
        receipt.unlink(missing_ok=True)
        proc = subprocess.Popen(["bash", "-c", 'source "$1"; pn_launch unused', "pn", str(helper)],
                                env=dict(env, PN_READY=str(ready), PN_TERM=str(receipt)))
        measured = None
        observed_timeout = False
        try:
            wait_ready(proc, ready)
            measured = int(ready.read_text())
            assert proc.pid == measured, "ignored-TERM fixture PID ownership mismatch"
            proc.terminate()
            try:
                proc.wait(timeout=TEARDOWN_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                observed_timeout = True
        finally:
            survivors = reap_owned_fixture(proc, measured)
        assert observed_timeout, "ignored-TERM helper fixture exited on TERM"
        assert not survivors and proc.poll() is not None and not pid_alive(measured), \
            f"ignored-TERM helper left owned survivors {survivors}"
        print("ignored-TERM helper control PASS: KILL reaped the owned fixture")
    finally:
        signal_stub(tools / "python3")

    # Dead-PID race: reaping an already-exited owned fixture is a no-op.
    finished = subprocess.Popen(["true"])
    finished.wait()
    assert reap_owned_fixture(finished, finished.pid) == [], "reaped PID reported a survivor"
    print("already-exited PID control PASS: teardown treated the dead PID as absent")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="pn-contract-") as tmp:
        work = Path(tmp)
        for name in ("persisted-network-contract.py", "persisted-network.py", "build-provenance.py"):
            py_compile.compile(str(ROOT / "script/test/lib" / name), cfile=str(work / (name + "c")), doraise=True)
        for control in (probe_controls, provenance_controls, helper_controls, live_shell_controls):
            scratch = work / control.__name__
            scratch.mkdir()
            control(ROOT, scratch)
    print("persisted network host-only controls PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
