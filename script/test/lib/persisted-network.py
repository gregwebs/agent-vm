#!/usr/bin/env python3
"""Serial native PN rows; boot-free companion exercises the probe separately."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("pn_egress", ROOT / "script/test/lib/egress-fixtures.py")
EGRESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EGRESS
SPEC.loader.exec_module(EGRESS)
HELPER = ROOT / "script/test/lib/persisted-network.sh"
FIXTURES = ROOT / "script/test/fixtures/persisted-network"


def shell_helper(name, value):
    return subprocess.check_output(["bash", "-c", 'source "$1"; "$2" "$3"', "pn", str(HELPER), name, str(value)], text=True, timeout=10)


def require_shared_stderr_oracle(row: str, text: str, oracle: str | None) -> None:
    if oracle:
        for substring in shell_helper("pn_expected", oracle).splitlines():
            if substring not in text:
                raise AssertionError(f"{row}: missing shared stderr oracle {substring!r}")


def snapshot_validation(work):
    # Native caches can contain large disk images; inventory hashing must not
    # allocate a whole image. Keep the validation helper's sidecar convention.
    result = {}
    for directory in ("home", "config", "state", "proj"):
        for path in sorted((work / directory).rglob("*")):
            if path.name.endswith(("-shm", "-wal", "-journal")):
                continue
            meta = path.lstat()
            value = ""
            if path.is_symlink():
                value = os.readlink(path)
            elif path.is_file():
                digest = hashlib.sha256()
                with path.open("rb") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
                value = digest.hexdigest()
            result[str(path.relative_to(work))] = [meta.st_mode, meta.st_size, value]
    return result


def interrupted(signum, _frame):
    raise InterruptedError(f"signal {signum}")


def main():
    root, evidence = map(lambda x: Path(x).resolve(), sys.argv[1:3])
    binary, image = sys.argv[3:5]
    works = []
    fixture = None
    http_log = evidence / "http.log"
    errors = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    try:
        # No SO_REUSEPORT: a busy fixture port must fail before a denial counts.
        with socket.socket() as check:
            check.bind(("127.0.0.1", 18090))
        www = root / "www/r"
        www.mkdir(parents=True)
        # http_get requests /r/ID and requires exact 'receipt ID' bytes.
        # /r/marker is the marker file, not a second unbounded probe implementation.
        (www / "marker").write_bytes(b"receipt marker")
        with http_log.open("wb") as log:
            server = subprocess.Popen([sys.executable, "-m", "http.server", "--bind", "127.0.0.1", "18090", "--directory", str(www.parent)], stdout=log, stderr=log)
        token = EGRESS.process_identity(server.pid)
        if token is None:
            raise RuntimeError("fixture identity unavailable")
        fixture = (server, {"pid": server.pid, "start": token})
        (evidence / "fixture.identity.json").write_text(json.dumps(fixture[1], indent=2))
        deadline = time.monotonic() + 5
        while True:
            if server.poll() is not None:
                raise RuntimeError("http.server exited before readiness")
            try:
                with socket.create_connection(("127.0.0.1", 18090), timeout=0.5):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("http.server not ready in 5s")
                time.sleep(0.05)

        def fresh(name):
            work = root / name
            shell_helper("pn_fresh_state", work)
            launches = []
            works.append((work, launches))
            project = work / "proj"
            for target in ["egress-probe.sh", "persisted-network/guest-pn-probe.sh", "persisted-network/guest-pn4-write.sh"]:
                shutil.copy2(ROOT / "script/test/fixtures" / target, project / Path(target).name)
            return work, project, launches

        def config(work, text):
            file = work / "home/.config/agent-vm/config.toml"
            file.write_text(text)
            file.chmod(0o600)
            return file

        def launch(row, work, project, launches, flags=(), guest="probe", expected="reach", oracle=None):
            offset = http_log.stat().st_size
            before = snapshot_validation(work)
            state_before = sorted(str(p.relative_to(work / "state")) for p in (work / "state").rglob("*"))
            (evidence / f"{row}-before.json").write_text(json.dumps({"http_offset": offset, "snapshot": before, "state": state_before}, indent=2))
            env = EGRESS.base_environment(work)
            env.update(AGENT_VM_BIN=binary, AGENT_VM_LIVE_TEST_IMAGE=image)
            snippet = "echo GUEST_EXECUTED; bash ./guest-pn4-write.sh" if guest == "write" else "echo GUEST_EXECUTED; bash ./guest-pn-probe.sh 18090 marker"
            argv = (binary, "--no-git", "--image", image, *flags, "shell", "bash", "-c", snippet)
            command = EGRESS.Command(row, "native", "shell", "validation-only" if expected == "refuse" else "guest", env, argv, str(project), 300, 10)
            owned = EGRESS.OwnedLaunch(work, command, row)
            launches.append(owned)
            status = owned.run()
            text = owned.log.read_text(errors="replace")
            if status in (124, 130, 143) or owned.errors:
                raise RuntimeError(f"{row}: timeout/interrupt/observation error: {status} {owned.errors}")
            require_shared_stderr_oracle(row, text, oracle)
            if server.poll() is not None:
                raise RuntimeError(f"{row}: host fixture died during launch")
            delta = http_log.read_bytes()[offset:]
            count = delta.count(b"GET /r/marker ")
            if expected == "refuse":
                assert status != 0 and "GUEST_EXECUTED" not in text and "PN_REACHED" not in text
                assert count == 0
                project_hash = hashlib.sha256(os.fsencode(project.resolve())).hexdigest()[:12]
                assert not (work / "state" / project_hash).exists()
                assert snapshot_validation(work) == before
            else:
                assert status == 0, f"{row}: launch exited {status}"
                if guest == "write":
                    assert "PN4_WRITE_OK" in text
                else:
                    assert ("PN_REACHED marker" if expected == "reach" else "PN_DENIED marker") in text
                    assert count == (1 if expected == "reach" else 0)
            # Record deltas before cleanup's admin operations.
            (evidence / f"{row}-after.json").write_text(json.dumps({"http_requests": count, "snapshot": snapshot_validation(work), "status": status}, indent=2))
            cleanup_errors = EGRESS.cleanup_launch(owned)
            if cleanup_errors:
                raise RuntimeError(f"{row}: cleanup {cleanup_errors}")
            with (evidence / "summary.tsv").open("a") as summary:
                summary.write(f"{row}\tPASS\n")
            print(f"PASS {row}", flush=True)

        for row, expected, saved, flags in [("PN1", "deny", False, ()), ("PN2", "reach", True, ()), ("PN3", "deny", True, ("--allow-host=false",))]:
            work, project, launches = fresh(row)
            file = config(work, (FIXTURES / "user-allow-host.toml").read_text()) if saved else None
            before = file.read_bytes() if file else None
            launch(row, work, project, launches, flags, expected=expected, oracle=row)
            if file:
                assert file.read_bytes() == before
        work, p1, launches = fresh("PN4")
        p2 = work / "p2"
        p2.mkdir()
        for file in ("egress-probe.sh", "guest-pn-probe.sh"):
            shutil.copy2(p1 / file, p2 / file)
        target = p1 / "dotfiles/agent-vm.toml"
        target.parent.mkdir()
        target.write_text("# tools/image dotfile without authority\n")
        target.chmod(0o600)
        file = work / "home/.config/agent-vm/config.toml"
        file.symlink_to(target)
        launch("PN4-A", work, p1, launches, guest="write")
        assert target.read_text().endswith("[network]\nallow_host = true\n")
        launch("PN4-B", work, p2, launches, expected="refuse", oracle="PN4B")
        file.unlink()
        shutil.copy2(target, file)
        file.chmod(0o600)
        launch("PN4c", work, p2, launches)
        work, _, launches = fresh("PN5")
        config(work, (FIXTURES / "user-allow-host.toml").read_text())
        launch("PN5", work, work / "home", launches, expected="refuse", oracle="PN5")
    except (AssertionError, OSError, RuntimeError, InterruptedError, subprocess.SubprocessError) as error:
        errors.append(str(error) or repr(error))
    finally:
        for index, (work, launches) in enumerate(works):
            errors.extend(EGRESS.cleanup_run(work, binary, launches, fixture=fixture if index == 0 else None))
        if not works and fixture:
            server, identity = fixture
            EGRESS.signal_identity(identity, signal.SIGTERM)
            try:
                server.wait(timeout=2)
            except subprocess.TimeoutExpired:
                EGRESS.signal_identity(identity, signal.SIGKILL)
                server.wait(timeout=2)
        if fixture:
            identity = fixture[1]
            try:
                absent = EGRESS.process_identity(identity["pid"]) is None
                (evidence / "fixture.cleaned.json").write_text(json.dumps({"identity": identity, "absent": absent}, indent=2))
                if not absent:
                    errors.append("host fixture remains after run cleanup")
            except (OSError, RuntimeError) as error:
                errors.append(f"host fixture absence not established: {error}")
        # Retain receipts/logs even when a row fails, never snapshot them as policy state.
        for work, _ in works:
            dest = evidence / work.name
            dest.mkdir(exist_ok=True)
            for file in work.glob("*"):
                if file.is_file():
                    shutil.copy2(file, dest / file.name)
        (evidence / "errors.json").write_text(json.dumps(errors, indent=2))
        if not errors:
            shutil.rmtree(root)
        else:
            print(f"Owned scratch retained after failure: {root}", file=sys.stderr)
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
