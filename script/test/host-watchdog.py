#!/usr/bin/env python3
"""Run a command under a wall-clock watchdog.

macOS ships no guaranteed ``timeout`` utility, so host harnesses use this to
bound an individual ``docker buildx build`` or probe container. The command runs
in its own session/process group, so on timeout the WHOLE group is signalled
(SIGTERM, then SIGKILL): no build, container client or daemon-side helper is
orphaned, and the harness's own cleanup traps still run on the SIGTERM.

The escalation does NOT depend on the group leader exiting: a grandchild that
ignores SIGTERM (or is reparented) survives a leader-only wait, so the group is
polled until it is actually empty and then SIGKILLed. An inherited SIGINT,
SIGTERM or SIGHUP is forwarded to the child group before the watchdog exits.

Usage: host-watchdog.py SECONDS COMMAND [ARG...]

Exit status mirrors coreutils ``timeout``: the command's own status, the
signal-derived 128+N when the command is killed by a signal, or 124 when the
watchdog itself fired.
"""

import os
import signal
import subprocess
import sys
import time

TERM_GRACE_SECONDS = 10
# How often to re-check whether any process in the child group is still alive.
POLL_SECONDS = 0.05


def main(argv):
    if len(argv) < 3:
        sys.stderr.write("usage: host-watchdog.py SECONDS COMMAND [ARG...]\n")
        return 2
    try:
        seconds = float(argv[1])
    except ValueError:
        sys.stderr.write("host-watchdog: not a number of seconds: %r\n" % (argv[1],))
        return 2
    if seconds <= 0:
        sys.stderr.write("host-watchdog: seconds must be positive: %r\n" % (argv[1],))
        return 2

    command = argv[2:]
    try:
        process = subprocess.Popen(command, start_new_session=True)
    except OSError as error:
        sys.stderr.write("host-watchdog: cannot run %r: %s\n" % (command[0], error))
        return 127

    handlers = {}

    def forward(signum, _frame):
        sys.stderr.write(
            "host-watchdog: received %s; killing process group\n"
            % _signal_name(signum)
        )
        _terminate(process)
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            handlers[signum] = signal.signal(signum, forward)
        except (ValueError, OSError, AttributeError):
            pass

    try:
        try:
            status = process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            sys.stderr.write(
                "host-watchdog: command timed out after %gs; killing process group\n"
                % (seconds,)
            )
            _terminate(process)
            return 124
    finally:
        for signum, previous in handlers.items():
            try:
                signal.signal(signum, previous)
            except (ValueError, OSError):
                pass

    # Mirror a shell: a signal-terminated child reports 128 + signal number.
    return status if status >= 0 else 128 - status


def _signal_name(signum):
    try:
        return signal.Signals(signum).name
    except ValueError:
        return "signal %d" % signum


def _signal_group(pid, signum):
    try:
        os.killpg(pid, signum)
    except ProcessLookupError:
        return False
    except PermissionError:
        return False
    return True


def _group_alive(pid):
    """True while any process remains in the child's process group."""
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _group_empty(process, grace):
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        # Reap the leader if it has exited so its zombie does not keep the
        # group looking alive.
        process.poll()
        if not _group_alive(process.pid):
            return True
        time.sleep(POLL_SECONDS)
    process.poll()
    return not _group_alive(process.pid)


def _terminate(process):
    """SIGTERM the child's process group, escalating to SIGKILL after a grace.

    The escalation runs even when the group leader has already exited: the
    group, not the leader, is what must be observed as empty.
    """
    _signal_group(process.pid, signal.SIGTERM)
    if _group_empty(process, TERM_GRACE_SECONDS):
        return
    _signal_group(process.pid, signal.SIGKILL)
    _group_empty(process, TERM_GRACE_SECONDS)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
