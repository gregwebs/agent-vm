#!/usr/bin/env python3
"""Boot-free controls for the released-image launch helper.

No VM, no network, no release assets: prove that a timed-out launch and a
parent interruption (Ctrl-C and SIGTERM) stop the whole owned process group --
including a TERM-resistant child and grandchild -- that invalid bounds cannot
spawn a child, and that a normal launch returns the child's status. Run from
ci-contracts.sh (normal mode). Uses no bytecode cache.

The interruption cases spawn this same file as a `--driver` subprocess and
signal the parent (not the new-session child), reproducing the leak: a new
session does not receive the terminal's Ctrl-C / SIGTERM.
"""

import ast
import contextlib
import importlib.util
import io
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True

HERE = pathlib.Path(__file__).resolve().parent
HELPER_PATH = HERE / "released-image-launch.py"

# The child spawns a grandchild in the same group; both ignore SIGTERM, so the
# helper must escalate to SIGKILL to stop them.
SCENARIO = """
import os, signal, subprocess, sys, time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
grandchild = subprocess.Popen(
    [sys.executable, "-c",
     "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(300)"]
)
with open(sys.argv[1], "w") as fh:
    fh.write(f"{os.getpid()} {grandchild.pid} {os.getpgrp()} {os.getsid(0)}\\n")
time.sleep(300)
"""


def load_helper():
    spec = importlib.util.spec_from_file_location("released_image_launch", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def wait_dead(pid, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not alive(pid):
            return True
        time.sleep(0.05)
    return not alive(pid)


def wait_for(predicate, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def parse_pids(pidfile):
    if not pidfile.exists():
        return []
    return [int(value) for value in pidfile.read_text().split()]


def assert_stopped(failures, label, pids):
    if len(pids) != 4:
        failures.append(f"{label}: scenario did not record child/grandchild pids: {pids}")
        return
    child, grandchild, pgrp, sid = pids
    if not (child == pgrp == sid):
        failures.append(
            f"{label}: child not an owned group leader: pid={child} pgrp={pgrp} sid={sid}"
        )
    if not wait_dead(child, 5):
        failures.append(f"{label}: child {child} survived")
    if not wait_dead(grandchild, 5):
        failures.append(f"{label}: grandchild {grandchild} survived")


def _driver(scenario, pidfile):
    """Run the helper under a long timeout so the test can interrupt it."""
    helper = load_helper()
    try:
        helper.run_in_owned_group(
            [sys.executable, str(scenario), str(pidfile)],
            env=dict(os.environ),
            cwd=None,
            timeout=3600,
            grace=1.0,
        )
    except KeyboardInterrupt:
        return 130
    except helper.LaunchInterrupted as exc:
        return 128 + exc.signum
    return 0


def interruption_case(failures, label, signum, expected_rc, scenario, tmp):
    pidfile = pathlib.Path(tmp) / f"{label}.pids"
    driver = subprocess.Popen(
        [
            sys.executable,
            "-B",
            str(pathlib.Path(__file__).resolve()),
            "--driver",
            str(scenario),
            str(pidfile),
        ],
        env=dict(os.environ),
    )
    try:
        if not wait_for(pidfile.exists, 15):
            failures.append(f"{label}: driver never launched its owned child")
            return
        pids = parse_pids(pidfile)
        os.kill(driver.pid, signum)
        try:
            rc = driver.wait(timeout=30)
        except subprocess.TimeoutExpired:
            failures.append(f"{label}: driver did not exit after signal {signum}")
            driver.kill()
            driver.wait()
            return
        if rc != expected_rc:
            failures.append(f"{label}: driver exit {rc}, expected {expected_rc}")
        assert_stopped(failures, label, pids)
    finally:
        if driver.poll() is None:
            driver.kill()
            driver.wait()


def main():
    helper = load_helper()
    failures = []

    # Syntax guard for the helper itself: parse, do not import-and-run as a
    # script, and never write a __pycache__ into the tree.
    ast.parse(HELPER_PATH.read_text())

    with tempfile.TemporaryDirectory(prefix="av265-launch-test.") as tmp:
        tmpdir = pathlib.Path(tmp)
        scenario = tmpdir / "scenario.py"
        scenario.write_text(SCENARIO)
        env = dict(os.environ)

        # 1) A normal launch returns the child's status.
        status = helper.run_in_owned_group(
            [sys.executable, "-c", "import sys; sys.exit(7)"],
            env=env,
            cwd=None,
            timeout=30,
            grace=2,
        )
        if status != 7:
            failures.append(f"normal launch status {status!r}, expected 7")

        # 2) A timed-out launch stops the whole owned group, including the
        #    TERM-resistant child and grandchild.
        pidfile = tmpdir / "timeout.pids"
        try:
            helper.run_in_owned_group(
                [sys.executable, str(scenario), str(pidfile)],
                env=env,
                cwd=None,
                timeout=0.5,
                grace=1.0,
            )
            failures.append("timed-out launch returned instead of raising")
        except helper.LaunchTimedOut:
            pass
        except Exception as exc:  # noqa: BLE001 - report any unexpected failure
            failures.append(f"timed-out launch raised {exc!r}")
        assert_stopped(failures, "timeout", parse_pids(pidfile))

        # 3) Invalid bounds are rejected before any child is spawned.
        marker = tmpdir / "invalid-bound.marker"
        write_marker = [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('x')"]
        for bad in (float("nan"), float("inf"), 0, -1):
            for kw in ("timeout", "grace"):
                if marker.exists():
                    marker.unlink()
                bounds = {"timeout": 30, "grace": 2}
                bounds[kw] = bad
                try:
                    helper.run_in_owned_group(
                        write_marker, env=env, cwd=None, **bounds
                    )
                    failures.append(f"bound {kw}={bad!r} accepted")
                except ValueError:
                    pass
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"bound {kw}={bad!r} raised {exc!r}")
                if marker.exists():
                    failures.append(f"bound {kw}={bad!r} spawned a child")

        # 3b) `main` rejects an invalid bound with status 2, before spawning.
        if marker.exists():
            marker.unlink()
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                helper.main(
                    [
                        "--root", str(tmpdir / "r"),
                        "--shim", str(tmpdir / "shim"),
                        "--log", str(tmpdir / "log"),
                        "--binary", sys.executable,
                        "--timeout", "nan",
                        "--", "-c", f"open({str(marker)!r}, 'w').write('x')",
                    ]
                )
            failures.append("main accepted a non-finite timeout")
        except SystemExit as exc:
            if exc.code != 2:
                failures.append(f"main invalid-bound exit {exc.code}, expected 2")
        if marker.exists():
            failures.append("main with an invalid bound spawned a child")

        # 4) macOS returns EPERM (not ESRCH) for killpg to a group whose leader
        #    is an unreaped zombie with no live members. A bounded timeout must
        #    not turn that empty group into a supervisor failure; a genuinely
        #    live group must still be signalled.
        zombie = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.exit(0)"], start_new_session=True
        )
        time.sleep(0.5)
        try:
            helper._signal_group(zombie.pid, signal.SIGKILL)
        except Exception as exc:  # noqa: BLE001 - any raise is a regression
            failures.append(f"zombie-leader empty group raised {exc!r}")
        finally:
            zombie.wait()
        live = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(300)"], start_new_session=True
        )
        helper._signal_group(live.pid, signal.SIGKILL)
        try:
            live.wait(timeout=5)
        except subprocess.TimeoutExpired:
            failures.append("live owned group survived SIGKILL")
            live.kill()
            live.wait()

        # 5) Parent interruption cleans up the owned group: Ctrl-C (SIGINT) and
        #    SIGTERM, with resistant descendants.
        interruption_case(
            failures, "sigint", signal.SIGINT, 130, scenario, tmp
        )
        interruption_case(
            failures, "sigterm", signal.SIGTERM, 143, scenario, tmp
        )

    for failure in failures:
        print(f"released-image-launch-test: FAIL: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("released-image launch timeout/interruption/group controls passed")
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "--driver":
        sys.exit(_driver(sys.argv[2], sys.argv[3]))
    sys.exit(main())
