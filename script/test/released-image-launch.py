#!/usr/bin/env python3
"""Launch the installed released-image candidate as an owned, bounded process.

Why this exists: `subprocess.run(timeout=...)` kills and waits only for the
direct child. On the installed npm route that child is Node, which spawns the
native launcher; a timeout could leave the native process -- and the VM it owns
-- alive and mutating private test state after the harness exits. So the
candidate runs in its own session/process group, and the whole owned group is
signalled (TERM, a bounded grace, then KILL) and reaped on timeout *and* on
parent interruption (Ctrl-C / SIGTERM), because a new-session child does not get
the terminal's signal.

Only the process group this helper created is signalled -- never an unrelated
host process. The timeout/grace bounds are validated as finite and positive
before the child is spawned, so a NaN/infinity/nonpositive bound cannot disable
termination. A timeout exit is mapped to status 124.

This is a narrow test-launch helper, not a release/evidence framework. It is
covered boot-free by script/test/released-image-launch-test.py.
"""

import argparse
import math
import os
import signal
import subprocess
import sys

# Match the historical `subprocess.run(timeout=...)` -> 124 mapping so callers
# keep treating a timeout as a bounded failure rather than a signal death.
TIMEOUT_EXIT = 124


class LaunchTimedOut(Exception):
    """The launched group overran the timeout and was terminated."""


class LaunchInterrupted(Exception):
    """The parent was interrupted; the owned group was terminated."""

    def __init__(self, signum):
        super().__init__(f"interrupted by signal {signum}")
        self.signum = signum


def _validate_bound(name, value):
    """Reject a bound that cannot terminate: non-finite or non-positive."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{name} must be a number, got {value!r}")
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be finite and positive, got {value!r}")
    return float(value)


def _signal_group(pgid, sig):
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        # The whole group already exited between calls; nothing to signal.
        pass


def _terminate_group(proc, grace):
    """TERM the owned group, then KILL it if the direct child survives grace.

    The KILL is unconditional once the child is gone so a TERM-ignoring
    grandchild cannot outlive the bounded launch either.
    """
    pgid = proc.pid  # start_new_session makes the child the group leader
    _signal_group(pgid, signal.SIGTERM)
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        _signal_group(pgid, signal.SIGKILL)
        proc.wait()
        return
    _signal_group(pgid, signal.SIGKILL)


def _cleanup_group(proc, grace):
    """Terminate the owned group with SIGTERM/SIGINT temporarily ignored.

    A signal arriving during cleanup must not recurse into cleanup or cut the
    bounded TERM/KILL escalation short, so both handlers are ignored for the
    duration and restored afterwards.
    """
    previous = {}
    for sig in (signal.SIGTERM, signal.SIGINT):
        previous[sig] = signal.signal(sig, signal.SIG_IGN)
    try:
        _terminate_group(proc, grace)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def run_in_owned_group(argv, *, env, cwd, timeout, grace):
    """Run argv in a fresh session; on timeout/interruption kill the group.

    Returns the child's exit status. Raises LaunchTimedOut after the owned group
    is terminated and reaped, and LaunchInterrupted if the parent is interrupted
    (SIGTERM), so the caller never returns while a descendant is still live in
    the group this helper created. `timeout` and `grace` are validated before
    any child is spawned.
    """
    timeout = _validate_bound("timeout", timeout)
    grace = _validate_bound("grace", grace)

    state = {"proc": None, "cleaned": False}

    def cleanup():
        # Serialize cleanup and never signal an already-reaped group id (it could
        # have been reused by an unrelated process).
        proc = state["proc"]
        if proc is None or state["cleaned"]:
            return
        state["cleaned"] = True
        _cleanup_group(proc, grace)

    def on_signal(signum, _frame):
        cleanup()
        raise LaunchInterrupted(signum)

    previous = signal.signal(signal.SIGTERM, on_signal)
    try:
        proc = subprocess.Popen(argv, env=env, cwd=cwd, start_new_session=True)
        state["proc"] = proc
        try:
            status = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            cleanup()
            raise LaunchTimedOut from None
        finally:
            # Once reaped, a late signal must not signal a reused group id.
            if proc.poll() is not None:
                state["cleaned"] = True
        return status
    except KeyboardInterrupt:
        # Ctrl-C goes to this parent, not to the new-session candidate.
        cleanup()
        raise
    finally:
        signal.signal(signal.SIGTERM, previous)


def build_environment(root, shim, log):
    """The isolated environment for one installed-candidate launch."""
    return {
        "HOME": root + "/home",
        "XDG_CONFIG_HOME": root + "/config",
        "AGENT_VM_STATE_DIR": root + "/state",
        "AGENT_VM_SHARE_MSB_CACHE": "0",
        "PATH": shim + ":/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "BUILDER_LOG": log,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="per-route private state root")
    parser.add_argument("--shim", required=True, help="decoy PATH prefix")
    parser.add_argument("--log", required=True, help="builder-decoy provenance log")
    parser.add_argument("--binary", required=True, help="installed candidate path")
    parser.add_argument(
        "--interpreter",
        default="",
        help="vetted absolute Node interpreter for an npm dispatcher candidate",
    )
    parser.add_argument("--timeout", type=float, default=900.0)
    parser.add_argument("--grace", type=float, default=10.0)
    parser.add_argument("args", nargs=argparse.REMAINDER)
    opts = parser.parse_args(argv)

    args = list(opts.args)
    if args and args[0] == "--":
        args = args[1:]
    env = build_environment(opts.root, opts.shim, opts.log)
    # The only override environment tested is explicit, not inherited.
    if args and args[0].startswith("IMAGE_ENV="):
        env["AGENT_VM_IMAGE_TAG"] = args.pop(0).split("=", 1)[1]
    if opts.interpreter:
        command = [opts.interpreter, opts.binary, *args]
    else:
        command = [opts.binary, *args]

    try:
        status = run_in_owned_group(
            command, env=env, cwd=None, timeout=opts.timeout, grace=opts.grace
        )
    except ValueError as exc:
        parser.error(str(exc))  # exit 2 before any child is spawned
    except LaunchTimedOut:
        return TIMEOUT_EXIT
    except LaunchInterrupted as exc:
        return 128 + exc.signum
    return status if status is not None else 1


if __name__ == "__main__":
    sys.exit(main())
