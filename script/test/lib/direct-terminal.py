#!/usr/bin/env python3
"""Native driver for #400's direct terminal policy.

One invocation runs exactly one case in one command form against a real
launcher and a real VM, and writes a JSON receipt plus raw captures into the
caller's evidence directory. The case inventory is fixed: there is no arbitrary
``eval``, shell command text or user-supplied program, so the driver can be
reviewed once and re-run for every candidate.

The ``signal-*`` cases extend the same inventory to host `SIGINT`/`SIGTERM`
supervision: they signal the launcher process itself and prove the launcher's
exact status, the restored terminal and the absent runtime/catalog/socket
identities before any rescue cleanup of the harness's own runs. A guest killed by
the signal it was sent reports its own terminating signal, so ``unhandled`` rows
are ordinary required rows at ``128 + N``; ``signal-{pty,stream}-self-term``
report a guest that kills itself, where no host signal exists at all.

Two oracles are kept strictly apart:

* the **driver's** own verdict (did the observations I expect hold?), and
* the **launcher's** actual exit status, which is recorded, never inferred.

A guest marker, a hex dump or a guest-reported size is the oracle for guest
behaviour; the launcher's ``==>`` notices are never evidence for it, and the
host terminal's echo is never counted as guest output.

Every external wait is bounded. The parent proves its own lack of a controlling
terminal before allocating a PTY, and any failure leaves the evidence directory
intact for the caller's cleanup trap.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import json
import os
import pty
import re
import secrets
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import traceback
from pathlib import Path

# --------------------------------------------------------------- constants ---

# Deadline for one case's whole interaction. A correct case is a few seconds; the
# bound exists so a hang fails loudly instead of blocking the matrix.
CASE_DEADLINE = float(os.environ.get("DIRECT_TERMINAL_CASE_DEADLINE", "240"))
# Deadline for one *observation* inside a case (readiness, a marker, raw state).
# The boot-free contract shortens it so a "never delivers EOF" control fails fast.
MARKER_DEADLINE = float(os.environ.get("DIRECT_TERMINAL_MARKER_DEADLINE", "60"))
# Fixed geometry the driver assigns, and the geometry the resize case asks for.
#
# INITIAL_SIZE is deliberately **not** 24x80: the stock SDK's `exec_stream`
# creates the guest PTY at 24x80 every time, so a launcher that failed to send
# the host's own size would still pass a 24x80 fixture. The guest reports its
# first size with `stty size`, which is the oracle.
INITIAL_SIZE = (37, 111)
RESIZED_SIZE = (43, 119)
# The canonical host input for the stream-input cases, as literal bytes.
STREAM_INPUT_CHUNKS = (b"stream-A\n", b"stream-B", b"\n")
STREAM_INPUT_EXPECTED = b"stream-A\nstream-B\n"
# The input case's typed bytes, split so the escape byte travels in its own write.
INPUT_CHUNKS = (b"A", b"\x1d", b"B")
INPUT_EXPECTED_HEX = b"A\x1dB".hex()

PROBE_NAME = "guest-probe.sh"


class CaseError(RuntimeError):
    """A case's expectation did not hold. Never a launcher status."""


# ------------------------------------------------------------- host facts ---


def assert_no_controlling_terminal() -> None:
    """Fail unless this process really is detached from an ambient terminal.

    A driver that inherited the operator's terminal could look correct while a
    case's own PTY was doing nothing, so this is a precondition, not a courtesy.
    """

    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError as error:
        if error.errno in (errno.ENXIO, errno.ENODEV, errno.ENOENT, errno.EPERM):
            return
        raise
    os.close(fd)
    raise CaseError(
        "this driver has a controlling terminal; run it detached "
        "(setsid/start_new_session) so a case's PTY is the only terminal"
    )


def snapshot(fd: int) -> dict:
    """The terminal facts a raw-mode session must restore."""

    attributes = termios.tcgetattr(fd)
    return {
        "iflag": attributes[0],
        "oflag": attributes[1],
        "cflag": attributes[2],
        "lflag": attributes[3],
        "ispeed": attributes[4],
        "ospeed": attributes[5],
        "cc": [int(value[0]) if isinstance(value, bytes) else int(value) for value in attributes[6]],
    }


def restore_relevant(snapshot_value: dict) -> dict:
    """Only the fields a session may legitimately change.

    Kernel bookkeeping (macOS ``PENDIN``) reflects unread input at the terminal
    and is not part of the session's contract.
    """

    local = termios.ICANON | termios.ECHO | termios.ECHONL | termios.ISIG | termios.IEXTEN
    incoming = termios.IXON | termios.ICRNL | termios.BRKINT | termios.INPCK | termios.ISTRIP
    return {
        "lflag": snapshot_value["lflag"] & local,
        "iflag": snapshot_value["iflag"] & incoming,
        "oflag": snapshot_value["oflag"] & termios.OPOST,
        "cflag": snapshot_value["cflag"],
        "ispeed": snapshot_value["ispeed"],
        "ospeed": snapshot_value["ospeed"],
        "vmin": snapshot_value["cc"][termios.VMIN],
        "vtime": snapshot_value["cc"][termios.VTIME],
    }


# ------------------------------------------------------------- session ---


class Session:
    """One launcher process with assigned descriptors.

    ``stdin`` is either a fresh PTY (the driver keeps both ends), a pipe or a
    file; ``stdout``/``stderr`` are independently a PTY, a pipe or a file. Output
    channels are drained concurrently, so a chatty launcher cannot block on a
    full pipe while a case waits for its own marker.
    """

    def __init__(self, argv: list[str], env: dict, cwd: Path):
        self.argv = argv
        self.env = env
        self.cwd = cwd
        self.stdin_kind = "tty"
        self.stdout_kind = "tty"
        self.stderr_kind = "tty"
        self.master: int | None = None
        self.slave: int | None = None
        self.child_stdout: int | None = None
        self.child_stderr: int | None = None
        self.stdin_read: int | None = None
        self.stdin_write: int | None = None
        self.stdout_path: Path | None = None
        self.stdin_path: Path | None = None
        self.process: subprocess.Popen | None = None
        self.output: dict[str, bytes] = {"tty": b"", "stdout": b"", "stderr": b""}
        self.baseline: dict | None = None
        self.deadline = time.monotonic() + CASE_DEADLINE

    # -- setup --

    def assign(
        self,
        stdin: str,
        stdout: str,
        stderr: str,
        work: Path,
        stdin_file: Path | None = None,
    ) -> None:
        self.stdin_kind = stdin
        self.stdout_kind = stdout
        self.stderr_kind = stderr
        self.work = work
        if stdin == "tty":
            self.master, self.slave = pty.openpty()
            fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", *INITIAL_SIZE, 0, 0))
            self.baseline = snapshot(self.slave)
        if stdout == "tty" and self.slave is None:
            self.master, self.slave = pty.openpty()
            fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", *INITIAL_SIZE, 0, 0))
            self.baseline = snapshot(self.slave)
        if stdout == "file":
            self.stdout_path = work / "stdout.bin"
        if stdin == "file":
            self.stdin_path = stdin_file or (work / "stdin.bin")
            self.stdin_path.parent.mkdir(parents=True, exist_ok=True)
            if not self.stdin_path.exists():
                self.stdin_path.write_bytes(b"unread")
        if stdin == "pipe":
            # A real pipe, not /dev/null: the case names a pipe, so a pipe is what
            # the launcher must receive. Both ends stay in this process so the
            # payload can be shown to be untouched afterwards.
            self.stdin_read, self.stdin_write = os.pipe()
            os.write(self.stdin_write, b"unread")

    def spawn(self) -> None:
        assert self.master is not None or self.stdin_kind != "tty"
        # Every descriptor this call creates is owned exactly once: an output pipe
        # is the child's stdout *and* the driver's read end, so closing "the pipe"
        # twice was a `Bad file descriptor` crash before the case ever ran.
        owned: set[int] = set()

        def owned_fd(fd: int) -> int:
            owned.add(fd)
            return fd

        read_out, write_out = os.pipe() if self.stdout_kind == "pipe" else (-1, -1)
        read_err, write_err = os.pipe() if self.stderr_kind == "pipe" else (-1, -1)
        stdin_fd = None
        if self.stdin_kind == "tty":
            stdin_fd = self.slave
        elif self.stdin_kind == "pipe":
            # The child gets a duplicate; this process keeps the original so the
            # case's payload can be read back afterwards.
            stdin_fd = owned_fd(os.dup(self.stdin_read))
        elif self.stdin_kind == "file":
            stdin_fd = owned_fd(os.open(self.stdin_path, os.O_RDONLY))
        stdout_fd = None
        if self.stdout_kind == "tty":
            stdout_fd = self.slave
        elif self.stdout_kind == "pipe":
            stdout_fd = owned_fd(write_out)
        else:
            stdout_fd = owned_fd(
                os.open(self.stdout_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            )
        stderr_fd = None
        if self.stderr_kind == "tty":
            stderr_fd = self.slave
        elif self.stderr_kind == "pipe":
            stderr_fd = owned_fd(write_err)
        else:
            stderr_fd = owned_fd(
                os.open(self.work / "stderr.bin", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            )

        self.process = subprocess.Popen(
            self.argv,
            stdin=subprocess.DEVNULL if stdin_fd is None else stdin_fd,
            stdout=stdout_fd,
            stderr=stderr_fd,
            env=self.env,
            cwd=self.cwd,
            # Deliberately *not* a new session: on macOS a session leader's death
            # revokes the PTY slave, which would destroy the attributes this driver
            # compares before and after. The driver itself asserts it has no
            # controlling terminal, so the child inherits no tty to reach for.
        )
        # The slave stays open in this process on purpose (it is the restoration
        # observation), so it is never in the owned set.
        for fd in sorted(owned):
            os.close(fd)
        self.child_stdout = read_out if read_out >= 0 else None
        self.child_stderr = read_err if read_err >= 0 else None
        # A pipe read end left blocking would strand the "bounded" drain loop, so
        # both are non-blocking exactly like the terminal master.
        for fd in (self.master, self.child_stdout, self.child_stderr):
            if fd is not None:
                os.set_blocking(fd, False)

    # -- observation --

    def fds(self) -> list[int]:
        candidates = [self.master, self.child_stdout, self.child_stderr]
        return [fd for fd in candidates if fd is not None]

    def poll_once(self, timeout: float = 0.05) -> None:
        ready, _, _ = select.select(self.fds(), [], [], timeout)
        if self.master is not None and self.master in ready:
            self.output["tty"] += self._drain(self.master)
        if self.child_stdout is not None and self.child_stdout in ready:
            chunk = self._drain(self.child_stdout)
            self.output["stdout"] += chunk
            if chunk == b"":
                os.close(self.child_stdout)
                self.child_stdout = None
        if self.child_stderr is not None and self.child_stderr in ready:
            chunk = self._drain(self.child_stderr)
            self.output["stderr"] += chunk
            if chunk == b"":
                os.close(self.child_stderr)
                self.child_stderr = None

    @staticmethod
    def _drain(fd: int) -> bytes:
        out = b""
        while True:
            try:
                chunk = os.read(fd, 65536)
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break
                if error.errno == errno.EIO:  # macOS reports a closed PTY this way
                    return out
                raise
            if not chunk:
                break
            out += chunk
        return out

    def pump(self, until, what: str, deadline: float = MARKER_DEADLINE, wait_for=None) -> None:
        """Read until ``until(text)`` holds; bounded, and never a sleep oracle.

        ``wait_for`` selects the text a predicate sees: the case's merged channels,
        which include a redirected file, so a guest report written to a file is not
        mistaken for a missing one.
        """

        select_text = wait_for or (lambda session: session.launcher_output())
        limit = min(self.deadline, time.monotonic() + deadline)
        while time.monotonic() < limit:
            self.poll_once()
            if until(select_text(self)):
                return
            if self.process is not None and self.process.poll() is not None:
                self.poll_once()
                if until(select_text(self)):
                    return
                raise CaseError(
                    f"{what}: the launcher exited with {self.process.returncode} first; "
                    f"stdout={self.stdout_text()!r} stderr={self.stderr_text()!r}"
                )
        raise CaseError(f"{what}: not observed within {deadline:.0f}s; got {self.summary()!r}")

    def wait(self, deadline: float = MARKER_DEADLINE) -> int:
        limit = min(self.deadline, time.monotonic() + deadline)
        while time.monotonic() < limit:
            self.poll_once()
            if self.process is not None and self.process.poll() is not None:
                for _ in range(20):
                    self.poll_once(0.01)
                return self.process.returncode
        raise CaseError(f"the launcher did not exit within {deadline:.0f}s")

    # -- convenience --

    def guest_stdout_text(self) -> str:
        """Where the guest's stdout went: a file/pipe, else the terminal."""

        if self.stdout_path is not None or self.stdout_kind == "pipe":
            return self.stdout_text()
        return self.terminal_text()

    def guest_stderr_text(self) -> str:
        """Where the guest's stderr went: a file/pipe, else the terminal."""

        if self.stderr_kind in ("file", "pipe"):
            return self.stderr_text()
        return self.terminal_text()

    def merged_text(self) -> str:
        """Guest-visible text from every channel, including a redirected file."""

        return self.launcher_output() + self.stdout_text() + self.stderr_text()

    def launcher_output(self) -> str:
        """Everything the launcher itself wrote: the PTY and the stderr stream.

        Guest output that shares the terminal is included, so callers match exact
        guest markers rather than assuming a channel.
        """

        return (self.output["tty"] + self.output["stderr"]).decode("utf-8", "replace")

    def stdout_text(self) -> str:
        if self.stdout_path is not None:
            try:
                return self.stdout_path.read_text(errors="replace")
            except FileNotFoundError:
                return ""
        return self.output["stdout"].decode("utf-8", "replace")

    def stderr_text(self) -> str:
        if self.stderr_kind == "file":
            try:
                return (self.work / "stderr.bin").read_text(errors="replace")
            except FileNotFoundError:
                return ""
        return self.output["stderr"].decode("utf-8", "replace")

    def terminal_text(self) -> str:
        return self.output["tty"].decode("utf-8", "replace")

    def summary(self) -> dict:
        return {
            "tty": self.terminal_text()[-2000:],
            "stdout": self.stdout_text()[-2000:],
            "stderr": self.stderr_text()[-2000:],
        }

    def capture_files(self, evidence: Path) -> dict:
        """Persist every raw channel, not just its last 2,000 decoded characters.

        Terminal and pipe channels have no file of their own, so a failure whose
        evidence is only "the last 2,000 chars" cannot be diagnosed later.
        """

        written = {}
        for name in ("tty", "stdout", "stderr"):
            raw = self.output[name]
            if not raw:
                continue
            path = evidence / f"capture-{name}.bin"
            path.write_bytes(raw)
            written[name] = path.name
        if self.stdout_path is not None and self.stdout_path.exists():
            written["stdout_file"] = self.stdout_path.name
        stderr_file = self.work / "stderr.bin"
        if self.stderr_kind == "file" and stderr_file.exists():
            written["stderr_file"] = stderr_file.name
        return written

    def unconsumed_stdin(self) -> bytes:
        """What the launcher left unread in this case's pipe.

        A refused launch must not consume the caller's input, so the payload this
        driver wrote is read back from its own end after the process exits.
        """

        if self.stdin_kind != "pipe" or self.stdin_read is None:
            return b""
        os.set_blocking(self.stdin_read, False)
        return self._drain(self.stdin_read)

    def write_terminal(self, payload: bytes) -> None:
        """Type at the terminal. The master is non-blocking for *reads*, so a
        write retries EAGAIN rather than failing a case."""

        assert self.master is not None
        sent = 0
        limit = time.monotonic() + 10.0
        while sent < len(payload):
            try:
                sent += os.write(self.master, payload[sent:])
            except OSError as error:
                if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                    raise
                if time.monotonic() > limit:
                    raise CaseError("the terminal would not accept input") from error
                time.sleep(0.01)

    def resize(self, rows: int, cols: int) -> None:
        assert self.slave is not None
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        os.kill(self.process.pid, signal.SIGWINCH)

    def raw_observed(self) -> bool:
        assert self.slave is not None
        return not (snapshot(self.slave)["lflag"] & termios.ICANON)

    def canonical_retained(self) -> bool:
        assert self.slave is not None
        return bool(snapshot(self.slave)["lflag"] & termios.ICANON)

    def final_state(self) -> dict | None:
        if self.slave is None or self.baseline is None:
            return None
        return restore_relevant(snapshot(self.slave))

    def baseline_state(self) -> dict | None:
        if self.baseline is None:
            return None
        return restore_relevant(self.baseline)

    def close(self) -> None:
        for fd_name in (
            "master",
            "slave",
            "child_stdout",
            "child_stderr",
            "stdin_read",
            "stdin_write",
        ):
            fd = getattr(self, fd_name)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, fd_name, None)
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait()


# ------------------------------------------------------------ expectations ---


def parse_kv(line: str) -> dict:
    fields = {}
    for token in line.split():
        if "=" in token:
            key, value = token.split("=", 1)
            fields[key] = value
    return fields


def parse_report(text: str) -> dict:
    """Every `KEY=VALUE` (and `PREFIX k=v ...`) fact in a guest report.

    The identity mode prints one `IDENTITY tty…` line plus separate `UID=`, `GID=`,
    `PWD=`, `PATH=` and `HOOK=` lines, and those lines may land on the terminal or
    in a redirected file, so the caller passes both. A value is everything after
    the first `=` to the end of its line: a PATH the project hook prepended may
    contain spaces, and splitting those on whitespace would silently compare a
    truncated value.
    """

    report = {}
    for line in text.splitlines():
        line = line.rstrip("\r")
        # One guest line may carry several facts (`UID=… GID=…`) and one fact may
        # contain spaces (a hook-prepended PATH). A fact therefore runs from its
        # `KEY=` to the next known key or the end of the line, so neither a second
        # fact nor a space inside one value can truncate the report.
        found = list(REPORT_KEY.finditer(line))
        for index, match in enumerate(found):
            end = found[index + 1].start() if index + 1 < len(found) else len(line)
            report[match.group(1)] = line[match.end() : end].strip()
    return report


# The facts a guest report carries, so a value containing spaces is still one
# value and a line carrying two facts is still two facts.
REPORT_KEY = re.compile(r"\b(tty0|tty1|tty2|UID|GID|PWD|PATH|HOOK)=")


def marker_line(text: str, prefix: str) -> str:
    for line in text.splitlines():
        if line.startswith(prefix):
            return line
    raise CaseError(f"no {prefix!r} line in {text!r}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CaseError(message)


def require_terminal_restored(session: "Session", receipt: dict, label: str) -> None:
    """The host terminal is back to the state it had before the launch.

    Recorded in the receipt as well as judged, so the restoration evidence survives
    a row that fails later for another reason.
    """

    receipt["terminal"] = {
        "baseline": session.baseline_state(),
        "final": session.final_state(),
    }
    require(
        session.baseline_state() == session.final_state(),
        f"{label}: the host terminal was not restored: {receipt['terminal']}",
    )


def cksum_of(payload: bytes) -> str:
    """The POSIX `cksum` of these bytes, computed on the host."""

    result = subprocess.run(["cksum"], input=payload, capture_output=True, check=True)
    return result.stdout.split()[0].decode()


# ------------------------------------------------------------------ cases ---


class Case:
    """One fixed case: argv, descriptor assignment and its observations."""

    def __init__(
        self,
        name: str,
        options: list[str],
        probe: list[str],
        assignment: dict,
        route: list[str] | None = None,
    ):
        self.name = name
        self.options = options
        self.probe = probe
        self.assignment = assignment
        # A legacy case names its route (`shell …`) instead of the direct
        # `run`/`--` boundary; the direct form is supplied per invocation.
        self.route = route


CASES = {
    # Both descriptors are terminals: auto must select a PTY, so the guest sees a
    # terminal on all three and one merged output stream.
    "identity-auto": Case("identity-auto", [], ["identity"], {"stdin": "tty", "stdout": "tty", "stderr": "tty"}),
    # A redirected stdout must stream even though stdin is a terminal: this is the
    # case a stdin-only predicate cannot pass.
    "identity-redirected": Case(
        "identity-redirected", [], ["identity"], {"stdin": "tty", "stdout": "file", "stderr": "tty"}
    ),
    # stderr's terminal status is irrelevant: same stdin/stdout, stderr redirected.
    "identity-stderr-file": Case(
        "identity-stderr-file", [], ["identity"], {"stdin": "tty", "stdout": "tty", "stderr": "file"}
    ),
    # Forced PTY with a redirected stdout: a PTY nonetheless, merged into the file.
    "identity-force-tty": Case(
        "identity-force-tty", ["-t"], ["identity"], {"stdin": "tty", "stdout": "file", "stderr": "tty"}
    ),
    # Forced streaming from a terminal: separate channels, no guest terminal.
    "identity-force-stream": Case(
        "identity-force-stream", ["-T"], ["identity"], {"stdin": "tty", "stdout": "file", "stderr": "file"}
    ),
    # A piped stdin auto-selects streaming, even though stdout is a terminal.
    "identity-stdin-pipe": Case(
        "identity-stdin-pipe", [], ["identity"], {"stdin": "pipe", "stdout": "tty", "stderr": "tty"}
    ),
    # Forced streaming with *both* descriptors terminals, which auto would have
    # made a PTY: without this a case that redirects stdout already streams, so
    # the force-off option could be ignored and still pass. The guest's stderr is
    # sent to a file so "separate channels" is visible rather than assumed.
    "identity-force-stream-both": Case(
        "identity-force-stream-both", ["-T"], ["identity"], {"stdin": "tty", "stdout": "tty", "stderr": "file"}
    ),
    "identity-no-tty-both": Case(
        "identity-no-tty-both", ["--no-tty"], ["identity"], {"stdin": "tty", "stdout": "tty", "stderr": "file"}
    ),
    # Ctrl-] reaches the guest unchanged and does not end the session.
    "input": Case("input", ["-t"], ["input"], {"stdin": "tty", "stdout": "tty", "stderr": "tty"}),
    # Resizes come from stdin's terminal even when stdout is a file.
    "resize": Case("resize", ["-t"], ["resize"], {"stdin": "tty", "stdout": "file", "stderr": "tty"}),
    # Streamed input from a *terminal* stdin, selected by a redirected stdout.
    "stream-input-auto": Case(
        "stream-input-auto", [], ["stream-input"], {"stdin": "tty", "stdout": "file", "stderr": "file"}
    ),
    # Streamed input from a terminal stdin under --no-tty.
    "stream-input-no-tty": Case(
        "stream-input-no-tty", ["-T"], ["stream-input"], {"stdin": "tty", "stdout": "file", "stderr": "file"}
    ),
    # Tokens after the command boundary are guest argv.
    "suffix-argv": Case(
        "suffix-argv", ["-T"], ["argv", "--tty", "-T"], {"stdin": "pipe", "stdout": "tty", "stderr": "tty"}
    ),
    "status-exit0": Case(
        "status-exit0", ["-t"], ["status", "0"], {"stdin": "tty", "stdout": "tty", "stderr": "tty"}
    ),
    "status-exit7": Case(
        "status-exit7", ["-t"], ["status", "7"], {"stdin": "tty", "stdout": "tty", "stderr": "tty"}
    ),
    # The runtime loss case: the owned runtime is killed while the command waits.
    "wait": Case("wait", ["-t"], ["wait"], {"stdin": "tty", "stdout": "tty", "stderr": "tty"}),
    # Legacy `shell` routes keep their old selection: stdin being a terminal is
    # enough for a PTY even with stdout redirected, and the guest's stderr is the
    # same merged terminal stream.
    "legacy-shell-pty": Case(
        "legacy-shell-pty",
        [],
        ["identity"],
        {"stdin": "tty", "stdout": "file", "stderr": "tty"},
        route=["shell", "bash", "-c", "./guest-probe.sh identity"],
    ),
    # Legacy detach is unchanged: Ctrl-] ends the session with the old
    # sentinel-derived status instead of reaching the guest.
    "legacy-detach": Case(
        "legacy-detach",
        [],
        ["wait"],
        {"stdin": "tty", "stdout": "tty", "stderr": "tty"},
        route=["shell", "bash", "-c", "./guest-probe.sh wait"],
    ),
}

# What each identity case must show. `err_channel` names where the guest's stderr
# marker is allowed to appear, so a merged PTY stream and a separated stream are
# distinguished by evidence rather than by a launcher notice.
# What each identity case must show. `guest_pty` is the *guest's* view, which is
# the selected mode and not the host's descriptors: a streamed guest sees `000`
# on all three descriptors even when the host's stdout is a terminal.
IDENTITY_EXPECTATIONS = {
    # Both descriptors terminals: a PTY, so all three guest fds are terminals and
    # the guest's stderr shares the merged terminal stream.
    "identity-auto": {"guest_pty": True, "err_channel": "merged-into-stdout"},
    # Redirected stdout: the guest streams (no terminal), guest stdout lands in the
    # file and guest stderr stays on the host terminal.
    "identity-redirected": {"guest_pty": False, "err_channel": "terminal"},
    # stderr redirected, stdin/stdout terminals: still a PTY, so stderr is *not*
    # treated as a selection input and the guest's stderr is the same stream.
    "identity-stderr-file": {"guest_pty": True, "err_channel": "merged-into-stdout"},
    # Forced PTY with a redirected stdout: a PTY, so stdout and stderr are one
    # merged stream that happens to land in the file.
    "identity-force-tty": {"guest_pty": True, "err_channel": "merged-into-stdout"},
    # Forced streaming from a terminal: no guest terminal, separate channels.
    "identity-force-stream": {"guest_pty": False, "err_channel": "stderr"},
    # Forced streaming with both host descriptors terminal: auto would have made a
    # PTY, so the guest's `000` is what discriminates the force-off option.
    "identity-force-stream-both": {"guest_pty": False, "err_channel": "stderr"},
    "identity-no-tty-both": {"guest_pty": False, "err_channel": "stderr"},
    # A piped stdin auto-selects streaming: the guest has no terminal at all, even
    # though this host stdout *is* one.
    "identity-stdin-pipe": {"guest_pty": False, "err_channel": "terminal"},
    # A legacy shell launch keeps the stdin-only PTY selection: stdout redirected,
    # still a PTY, still one merged stream in the file.
    "legacy-shell-pty": {"guest_pty": True, "err_channel": "merged-into-stdout"},
}

# Every ordinary guest status the status cases must actually observe, so a
# launcher that returns 0 for everything cannot pass.
STATUS_EXPECTATIONS = {"status-exit0": 0, "status-exit7": 7}

# The guest's own stdout envelope, byte for byte, when that channel is a file or a
# pipe: nothing but these lines may appear, so a launcher notice leaking into the
# guest's stdout fails instead of being tolerated as a substring.
IDENTITY_ENVELOPE_PREFIXES = (
    "IDENTITY tty0=",
    "UID=",
    "GID=",
    "PWD=",
    "PATH=",
    "HOOK=",
    "OUT marker",
    "ERR marker",
    "IDENTITY-DONE",
)
IDENTITY_ENVELOPE_REQUIRED = ("IDENTITY tty0=", "UID=", "PWD=", "OUT marker", "IDENTITY-DONE")

# Rejection cases never boot: they are their own inventory because a silent skip
# would otherwise look like a pass.
REJECT_CASES = {
    "reject-pipe-tty": {"options": ["-t"], "stdin": "pipe"},
    "reject-file-tty": {"options": ["--tty"], "stdin": "file"},
    "reject-conflict": {"options": ["--tty", "-T"], "stdin": "pipe"},
}

# Status cases that are not the guest probe: a missing and a non-executable
# program, both direct-launch statuses.
PROGRAM_CASES = {
    "status-missing": {"program": ["no-such-program-400"], "expect": 127},
    "status-nonexec": {"program": ["./not-executable"], "expect": 126},
}

# ------------------------------------------- host signal supervision: cases ---

# The grace a direct launch gives its guest between a forwarded signal and the
# launcher's own forced teardown. It is fixed by the contract and has no option
# or environment override, so a native row asserts the real five seconds: a
# shorter injected grace would only prove the rule, not the number that ships.
SIGNAL_GRACE = 5.0

# Each signal the rows drive, by the name the guest and the receipt use.
SIGNAL_NAMES = {signal.SIGINT: "INT", signal.SIGTERM: "TERM"}
# The guest's own report that a signal arrived and was deliberately not acted on.
# Identity matters: a row that only saw "some signal" could not tell a forwarded
# SIGINT from a forwarded SIGTERM.
SIGNAL_IGNORED = {signal.SIGINT: "SIGNAL-IGNORED INT", signal.SIGTERM: "SIGNAL-IGNORED TERM"}

# A guest killed by a signal reports its own terminating signal, which the shell
# convention maps to `128 + N`. The launcher's only source for it is the guest
# kernel's `WIFSIGNALED`/`WTERMSIG`, carried through agentd, the protocol and the
# SDK; a runtime too old to report it keeps the slice-1 numbers, so the same row
# reports the unknown code `-1` (`exit(-1)`, seen here as 255).

# The two direct modes, named by what selects them: a PTY owns the host terminal
# (raw mode), streaming leaves it canonical.
SIGNAL_MODES = {
    "pty": {
        "options": ["-t"],
        "assignment": {"stdin": "tty", "stdout": "tty", "stderr": "tty"},
    },
    "stream": {
        "options": ["-T"],
        "assignment": {"stdin": "tty", "stdout": "file", "stderr": "file"},
    },
}


def signal_case_specs() -> dict:
    """Both modes x both signals x the outcomes issue #401 names, plus self-signal.

    The expected status of every row comes from the published status table, not
    from what the launcher happens to print:

    * ``handled`` -- the guest acts on the forwarded signal and exits with its own
      status (42), so ``128 + N`` must **not** appear.
    * ``unhandled`` -- the guest dies of the forwarded signal, which the shell
      convention reports as ``128 + N`` from the signal the guest kernel reported.
    * ``self-signal`` -- the guest kills itself with no host signal involved, so
      ``128 + N`` can only come from its own reported identity. The driver proves
      the live ownership baseline before releasing the guest and sends nothing.
    * ``ignored`` -- the guest records the signal and keeps running, so the fixed
      grace expires and the launcher's forced teardown reports ``128 + N``.
    * ``second`` -- a second signal forces immediately and reports **its own**
      number: INT then TERM is 143, not 130.

    ``markers`` are facts the guest itself must report. Only a *forwarded* signal
    can appear there: an interrupting second signal ends the session instead of
    reaching the guest, so the row's evidence for it is the launcher's status and
    the forced-teardown notice, both asserted separately. ``forbidden`` lists the
    markers that would contradict the behaviour under test, and ``teardown``
    requires the launcher's ordinary notice with no forced one, because a status
    alone cannot tell a guest end from a forced shutdown with the same number.
    """

    specs = {}
    for mode, selection in SIGNAL_MODES.items():
        for first in (signal.SIGINT, signal.SIGTERM):
            other = signal.SIGTERM if first == signal.SIGINT else signal.SIGINT
            prefix = f"signal-{mode}-{SIGNAL_NAMES[first].lower()}"
            common = {
                "mode": mode,
                "options": selection["options"],
                "assignment": selection["assignment"],
                "first": first,
            }
            specs[f"{prefix}-handled"] = {
                **common,
                "probe": ["signal-handle", "42"],
                "signals": [first],
                "behaviour": "handled",
                "expect": 42,
                "markers": ["SIGNAL-READY", f"SIGNAL-TRAPPED {SIGNAL_NAMES[first]}"],
                "forbidden": ["SIGNAL-SURVIVED", "SIGNAL-IGNORED"],
                # A guest that reports its own status ends the session normally:
                # no forced teardown is involved, whatever the number.
                "teardown": "ordinary",
            }
            specs[f"{prefix}-unhandled"] = {
                **common,
                "probe": ["signal-unhandled"],
                "signals": [first],
                "behaviour": "unhandled",
                # The shell convention for a command killed by signal N, which can
                # only be its own reported identity.
                "expect": 128 + int(first),
                "markers": ["SIGNAL-READY"],
                "forbidden": ["SIGNAL-SURVIVED", "SIGNAL-TRAPPED", "SIGNAL-IGNORED"],
                "teardown": "ordinary",
            }
            specs[f"{prefix}-ignored"] = {
                **common,
                "probe": ["signal-ignore"],
                "signals": [first],
                "behaviour": "grace-expiry",
                "expect": 128 + int(first),
                "markers": ["SIGNAL-READY", SIGNAL_IGNORED[first]],
                "forbidden": ["SIGNAL-SURVIVED", "SIGNAL-TRAPPED"],
                # The launcher's own statement that it decided this end, which is
                # what tells a forced status from a guest that exited with the
                # same number on its own.
                "forced_notice": f"Interrupted by signal {int(first)}",
            }
            specs[f"{prefix}-second"] = {
                **common,
                "probe": ["signal-ignore"],
                "signals": [first, other],
                "behaviour": "second-interrupt",
                # 128 + the *interrupting* signal, never the first one.
                "expect": 128 + int(other),
                "markers": ["SIGNAL-READY", SIGNAL_IGNORED[first]],
                "forbidden": ["SIGNAL-SURVIVED", "SIGNAL-TRAPPED"],
                "forced_notice": f"Interrupted by signal {int(other)}",
            }
        # The guest kills itself, so no host signal exists to explain the status.
        # The row is the acceptance criterion slice 1 could not serve.
        specs[f"signal-{mode}-self-term"] = {
            "mode": mode,
            "options": selection["options"],
            "assignment": selection["assignment"],
            "first": signal.SIGTERM,
            "probe": ["signal-self-term"],
            "signals": [],
            "behaviour": "self-signal",
            "expect": 128 + int(signal.SIGTERM),
            "markers": ["SIGNAL-READY"],
            "forbidden": ["SIGNAL-SURVIVED", "SIGNAL-TRAPPED", "SIGNAL-IGNORED"],
            "teardown": "ordinary",
        }
    return specs


SIGNAL_CASES = signal_case_specs()

# The signal rows are ordinary inventory entries too: they launch through the same
# boundary, in both command forms, with a fixed probe mode per row.
for _signal_case, _spec in SIGNAL_CASES.items():
    CASES[_signal_case] = Case(
        _signal_case, _spec["options"], _spec["probe"], _spec["assignment"]
    )


# ------------------------------------------------------------- the runner ---


def launch_argv(binary: Path, options: list[str], form: str, program: list[str]) -> list[str]:
    boundary = ["run"] if form == "run" else ["--"]
    return [str(binary), *options, *boundary, *program]


def case_argv(
    case: Case, binary: Path, form: str, probe_extra: list[str] | None = None
) -> list[str]:
    """The literal argv for one case: a legacy route, or the direct boundary.

    ``probe_extra`` carries the arguments only *this attempt* can know — a
    self-signal row's unique release-file basename and unguessable token, so the
    guest can neither reuse a stale release nor be released by another attempt.
    They are passed in rather than stored on the `Case`: `CASES` is module-global,
    and mutating one would make two attempts in one process share them.
    """

    if case.route is not None:
        return [str(binary), *case.options, *case.route]
    return launch_argv(
        binary,
        case.options,
        form,
        ["bash", f"./{PROBE_NAME}", *case.probe, *(probe_extra or ())],
    )


def allocate_release(case: Case, form: str, ctx: "Context", receipt: dict) -> list[str]:
    """A per-attempt release file for a self-signalled guest.

    The guest cannot be released by a stale file from another attempt and cannot
    be released by guessing: the basename carries this case, form and process,
    and the content is an unguessable token the driver writes only after the
    readiness and live-ownership observations both succeeded.
    """

    basename = f".signal-release-{case.name}-{form}-{os.getpid()}"
    token = secrets.token_hex(16)
    path = Path(ctx.args.project) / basename
    require(
        not path.exists(),
        f"{case.name}/{form}: the release file {path} already existed before this attempt",
    )
    receipt.setdefault("signal", {})["release"] = {
        "file": basename,
        "host_path": str(path),
        "token_bytes": len(token) // 2,
        "distinct_from_previous_attempts": True,
    }
    return [basename, token]


def guest_stdout_is_redirected(session: "Session") -> bool:
    return session.stdout_path is not None or session.stdout_kind == "pipe"


def require_stdout_envelope(name: str, form: str, text: str, merged: bool) -> None:
    """The redirected guest stdout holds the guest's report and nothing else.

    A **streamed** stdout channel is the guest's own fd 1, so anything else there
    -- a launcher notice or another channel's bytes -- fails. A **merged PTY**
    stream is the guest's stdout *and* stderr, so the guest bootstrap's own
    ``==> `` notices are expected there; nothing else is.
    """

    allowed = IDENTITY_ENVELOPE_PREFIXES
    if merged:
        # The guest's own bootstrap writes these to its stderr, which a PTY
        # merges into this stream on purpose.
        allowed = allowed + ("==> ",)
    lines = [line.rstrip("\r") for line in text.splitlines() if line.strip()]
    require(lines, f"{name}/{form}: the guest stdout channel is empty")
    for line in lines:
        require(
            line.startswith(allowed),
            f"{name}/{form}: unexpected bytes on the guest stdout channel: {line!r}",
        )
    for prefix in IDENTITY_ENVELOPE_REQUIRED:
        require(
            any(line.startswith(prefix) for line in lines),
            f"{name}/{form}: no {prefix!r} line in the guest stdout envelope: {text!r}",
        )
    require(
        ("ERR marker" in text) == merged,
        f"{name}/{form}: the guest stderr marker must appear on the merged stream "
        f"only under a PTY: {text!r}",
    )


def run_case(case: Case, form: str, ctx: "Context", work: Path, receipt: dict) -> dict:
    args = ctx.args
    probe_path = Path(args.project) / PROBE_NAME
    require(probe_path.exists(), f"the guest probe is missing at {probe_path}")
    spec = SIGNAL_CASES.get(case.name)
    probe_extra: list[str] = []
    if spec is not None and spec["behaviour"] == "self-signal":
        probe_extra = allocate_release(case, form, ctx, receipt)
    argv = case_argv(case, Path(args.bin), form, probe_extra)
    session = Session(argv, ctx.env, Path(args.project))
    receipt["argv"] = argv
    receipt["host_ttys"] = {
        "stdin": case.assignment["stdin"] == "tty",
        "stdout": case.assignment["stdout"] == "tty",
    }
    try:
        session.assign(case.assignment["stdin"], case.assignment["stdout"], case.assignment["stderr"], work)
        session.spawn()
        status = observe(case, form, session, receipt, ctx, probe_extra)
        receipt["launcher_status"] = status
        receipt["terminal"] = {
            "baseline": session.baseline_state(),
            "final": session.final_state(),
        }
        require(
            session.baseline_state() == session.final_state(),
            f"{case.name}/{form}: the host terminal was not restored: {receipt['terminal']}",
        )
    finally:
        # Both channels and every raw buffer are recorded even when the case
        # raised: a failure's evidence is the case's own receipt, never the
        # truncated summary the exception path used to keep.
        receipt["captures"] = session.summary()
        receipt["capture_files"] = session.capture_files(Path(args.evidence))
        receipt["teardown"] = teardown_receipt(ctx, session)
        session.close()
    own_teardown(ctx, receipt, f"{case.name}/{form}")
    return receipt


def observe(
    case: Case,
    form: str,
    session: Session,
    receipt: dict,
    ctx: "Context",
    probe_extra: list[str] | None = None,
) -> int:
    """Drive one case to its verdict and return the launcher's status."""

    name = case.name
    if name.startswith("identity") or name == "legacy-shell-pty":
        session.pump(
            lambda out: "IDENTITY-DONE" in out,
            "the identity report",
            wait_for=lambda s: s.merged_text(),
        )
        status = session.wait()
        identity = parse_report(session.merged_text())
        expect = IDENTITY_EXPECTATIONS[name]
        require(status == 0, f"{name}/{form}: status {status}; stderr={session.stderr_text()!r}")
        # The guest's tty bits are the selected mode, not the host's descriptors.
        bits = "111" if expect["guest_pty"] else "000"
        require(
            (identity.get("tty0"), identity.get("tty1"), identity.get("tty2")) == tuple(bits),
            f"{name}/{form}: the guest must see tty bits {bits}: {identity}",
        )
        out_text = session.guest_stdout_text()
        err_text = session.guest_stderr_text()
        terminal_text = session.terminal_text()
        require("OUT marker" in out_text, f"{name}/{form}: guest stdout: {out_text!r}")
        if expect["err_channel"] == "merged-into-stdout":
            require(
                "ERR marker" in out_text,
                f"{name}/{form}: a PTY must merge guest stderr into the terminal "
                f"stream: {out_text!r}",
            )
        elif expect["err_channel"] == "stderr":
            require(
                "ERR marker" in err_text,
                f"{name}/{form}: guest stderr did not stay on stderr: {err_text!r}",
            )
            require(
                "ERR marker" not in out_text,
                f"{name}/{form}: guest stderr leaked into the stdout channel: {out_text!r}",
            )
        else:  # the guest's stderr shares the host terminal
            require(
                "ERR marker" in terminal_text,
                f"{name}/{form}: guest stderr is missing from the terminal: "
                f"{terminal_text!r}",
            )
        if guest_stdout_is_redirected(session):
            require_stdout_envelope(
                name,
                form,
                out_text,
                merged=expect["err_channel"] == "merged-into-stdout",
            )
        if ctx.expect_hook:
            require(
                identity.get("HOOK") == ctx.expect_hook,
                f"{name}/{form}: the project hook export did not apply: {identity}",
            )
        if ctx.expect_hook_path:
            require(
                ctx.expect_hook_path in identity.get("PATH", ""),
                f"{name}/{form}: the hook's PATH export did not apply: {identity.get('PATH')}",
            )
        require(identity.get("UID") == str(os.getuid()), f"{name}/{form}: guest uid: {identity}")
        require(identity.get("GID") == str(os.getgid()), f"{name}/{form}: guest gid: {identity}")
        require(
            identity.get("PWD") == str(Path(ctx.args.project).resolve()),
            f"{name}/{form}: guest cwd: {identity}",
        )
        receipt["guest_identity"] = identity
        return status

    if name == "input":
        session.pump(lambda out: "INPUT-READY" in out, "the input case's readiness", wait_for=lambda s: s.merged_text())
        require(session.raw_observed(), f"{name}/{form}: the launcher never made its terminal raw")
        receipt["raw_state"] = "observed"
        for chunk in INPUT_CHUNKS:
            session.write_terminal(chunk)
        session.pump(lambda out: "DONE" in out, "the input verdict", wait_for=lambda s: s.merged_text())
        status = session.wait()
        text = session.merged_text()
        require(f"bytes={INPUT_EXPECTED_HEX}" in text, f"{name}/{form}: guest saw {text!r}")
        require("DONE" in text, f"{name}/{form}: the session ended before the guest finished: {text!r}")
        require(status == 7, f"{name}/{form}: status {status} (a detach would not be 7)")
        return status

    if name == "resize":
        session.pump(lambda out: "RESIZE-READY" in out, "the resize case's readiness", wait_for=lambda s: s.merged_text())
        size_text = marker_line(session.merged_text(), "SIZE ").split(None, 1)[1]
        require(
            size_text.split() == [str(INITIAL_SIZE[0]), str(INITIAL_SIZE[1])],
            f"{name}/{form}: the guest's initial size was {size_text!r}, "
            f"not {INITIAL_SIZE[0]}x{INITIAL_SIZE[1]}",
        )
        require(session.raw_observed(), f"{name}/{form}: the launcher never made its terminal raw")
        receipt["raw_state"] = "observed"
        session.resize(RESIZED_SIZE[0], RESIZED_SIZE[1])
        # Wake the blocking read immediately: the guest must not have to poll for
        # a report before its reader can finish.
        session.write_terminal(b"\n")
        session.pump(lambda out: "RESIZE-DONE" in out or "RESIZE-TIMEOUT" in out, "the resize verdict", wait_for=lambda s: s.merged_text())
        status = session.wait()
        text = session.merged_text()
        require("RESIZE-TIMEOUT" not in text, f"{name}/{form}: the guest timed out: {text!r}")
        require(
            f"RESIZED {RESIZED_SIZE[0]} {RESIZED_SIZE[1]}" in text,
            f"{name}/{form}: the guest never observed {RESIZED_SIZE}: {text!r}",
        )
        require(status == 7, f"{name}/{form}: status {status}")
        return status

    if name.startswith("stream-input"):
        session.pump(lambda out: "STREAM-READY" in out, "the streamed-input readiness", 120, wait_for=lambda s: s.merged_text())
        receipt["canonical_state"] = "retained" if session.canonical_retained() else "raw"
        require(
            session.canonical_retained(),
            f"{name}/{form}: the launcher put a streamed terminal stdin into raw mode",
        )
        for chunk in STREAM_INPUT_CHUNKS:
            session.write_terminal(chunk)
        # The empty-line VEOF is the host's EOF; the master is never closed.
        session.write_terminal(b"\x04")
        session.pump(lambda out: "STREAM-DONE" in out, "the streamed-input report", 120, wait_for=lambda s: s.merged_text())
        status = session.wait(120)
        text = session.stdout_text()
        require(status == 23, f"{name}/{form}: status {status}; launcher output {session.launcher_output()!r}")
        fields = parse_kv(marker_line(text, "STREAM "))
        expected = STREAM_INPUT_EXPECTED
        require(fields.get("bytes") == str(len(expected)), f"{name}/{form}: bytes={fields.get('bytes')}")
        require(fields.get("cksum") == cksum_of(expected), f"{name}/{form}: cksum={fields.get('cksum')}")
        require(fields.get("hex") == expected.hex(), f"{name}/{form}: hex={fields.get('hex')}")
        require("STREAM-DONE" in text, f"{name}/{form}: no completion sentinel in {text!r}")
        require(
            "STREAM-STDERR marker" in session.stderr_text(),
            f"{name}/{form}: the guest's stderr marker did not stay on stderr: {session.stderr_text()!r}",
        )
        require(
            b"stream-A" not in session.stderr_text().encode(),
            f"{name}/{form}: guest stdin bytes leaked to stderr",
        )
        receipt["guest_stream"] = fields
        return status

    if name == "suffix-argv":
        session.pump(lambda out: "ARGV-DONE" in out, "the argv report", wait_for=lambda s: s.merged_text())
        status = session.wait()
        text = session.merged_text()
        require(status == 0, f"{name}/{form}: status {status}")
        require("ARGV n=2" in text, f"{name}/{form}: the suffix tokens did not reach the guest: {text!r}")
        require("ARGV[0]=--tty" in text, f"{name}/{form}: argv[0]: {text!r}")
        require("ARGV[1]=-T" in text, f"{name}/{form}: argv[1]: {text!r}")
        return status

    if name.startswith("status-"):
        session.pump(lambda out: "STATUS-EXIT" in out, "the status marker", wait_for=lambda s: s.merged_text())
        status = session.wait()
        expected = STATUS_EXPECTATIONS[name]
        # Recording a status is not observing it: a launcher that answered 0 for
        # every guest would otherwise pass both the 0 and the 7 case.
        require(
            status == expected,
            f"{name}/{form}: launcher status {status}, but the guest exited {expected}",
        )
        return status

    if name == "legacy-detach":
        session.pump(lambda out: "WAIT-READY" in out, "the legacy wait's readiness", wait_for=lambda s: s.merged_text())
        # The legacy session still enters raw mode and still detaches on Ctrl-].
        require(session.raw_observed(), f"{name}/{form}: the legacy session never made its terminal raw")
        receipt["raw_state"] = "observed"
        session.write_terminal(b"\x1d")
        status = session.wait(120)
        receipt["launcher_status"] = status
        text = session.launcher_output()
        require(
            "WAIT-EOF" not in text,
            f"{name}/{form}: the detach key reached the guest instead of detaching: {text!r}",
        )
        # The legacy status is not a guest status: the SDK's attach returns its
        # own sentinel-derived 255 when Ctrl-] detaches. Recording the status is
        # not observing it, so a legacy launch that quietly started reporting the
        # guest's status (or 0) has to fail here.
        require(
            status == 255,
            f"{name}/{form}: a detached legacy session reported {status}, not its 255",
        )
        require(
            session.baseline_state() == session.final_state(),
            f"{name}/{form}: the host terminal was not restored",
        )
        return status

    if name == "wait":
        return observe_disconnect(session, receipt, form, ctx)

    if name.startswith("signal-"):
        return observe_signal(
            case, SIGNAL_CASES[name], session, receipt, ctx, form, probe_extra or []
        )

    raise CaseError(f"unknown case {name}")


def observe_disconnect(session: Session, receipt: dict, form: str, ctx: "Context") -> int:
    """Runtime loss while the command is still pending: 125, restored, cleaned."""

    session.pump(lambda out: "WAIT-READY" in out, "the wait case's readiness", wait_for=lambda s: s.merged_text())
    require(session.raw_observed(), "wait: the launcher never made its terminal raw")
    receipt["raw_state"] = "observed"
    identity = owned_runtime_identity(session.process.pid, ctx)
    receipt["runtime_pid"] = identity["pid"]
    require(identity["pid"] > 0, "wait: no owned runtime was found")
    # Recheck immediately before signalling: never kill by name, never a group.
    runtime_helpers.signal_identity(identity, signal.SIGKILL)
    status = session.wait(120)
    receipt["launcher_status"] = status
    require(status == 125, f"wait/{form}: runtime loss reported {status}, not 125")
    require("WAIT-EOF" not in session.launcher_output(), "wait: a false guest exit was reported")
    return status


# -------------------------------------- host signal supervision: observations ---

# How long a signal row may wait for the launcher after its last signal. The
# grace is five seconds and the forced teardown is bounded, so anything near this
# bound is a hang, not a slow machine.
SIGNAL_WAIT = 120.0


def host_processes_matching(patterns: list[str]) -> list[dict]:
    """Host processes whose command line names any of `patterns`.

    A guest's own descendants live inside the microVM, so the only host-visible
    thing that can still be running on their behalf is the process that hosts
    them. An empty result therefore means "this launch is not running any more",
    and any result at all is a survivor the row must not accept.
    """

    wanted = [pattern for pattern in patterns if pattern]
    if not wanted:
        return []
    done = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,command="], capture_output=True, check=True, timeout=60
    )
    found = []
    for line in done.stdout.decode("utf-8", "replace").splitlines():
        fields = line.split(None, 2)
        if len(fields) != 3:
            continue
        pid, ppid, command = fields
        pattern = next((candidate for candidate in wanted if candidate in command), None)
        if pattern is None:
            continue
        found.append(
            {"pid": int(pid), "ppid": int(ppid), "pattern": pattern, "command": command[:240]}
        )
    return found


def owned_sockets(ctx: "Context", names: list[str]) -> list[str]:
    """Socket paths of these sandboxes that still exist on disk."""

    root = Path(ctx.args.state_root) / "msb-home"
    return [
        str(path)
        for name in dict.fromkeys(names)
        for path in runtime_helpers.socket_paths(root, name)
        if path.exists()
    ]


def owned_while_running(ctx: "Context", launcher_pid: int, label: str) -> dict:
    """What a healthy launch owns: the VM process, its catalog row, its sockets.

    Recorded *before* any signal, so the later absence is a comparison with a real
    observation instead of an assumption that nothing was ever there.
    """

    runtime = owned_runtime_identity(launcher_pid, ctx, label)
    names = [str(row.get("name", "")) for row in owned_catalog_rows(ctx, launcher_pid)]
    require(names, f"{label}: no catalog row names this launcher's sandbox")
    live = host_processes_matching(names)
    # Without this the later "no process names the sandbox" would be vacuous: a
    # scan that never matched anything proves nothing when it matches nothing.
    require(
        live,
        f"{label}: the sandbox {names} is not named by any running process, so its "
        f"absence after the session could not be observed either",
    )
    return {
        "runtime": runtime,
        "sandbox_names": names,
        "sockets": owned_sockets(ctx, names),
        "host_processes": live,
    }


def observe_absence(ctx: "Context", session: "Session", before: dict) -> dict:
    """What this launch still owned once the launcher had exited.

    Strictly an observation made **before** any rescue cleanup: `teardown_receipt`
    stops whatever it finds, so an absence proved after it has run would only
    prove that the rescue worked, not that the launch cleaned up after itself.
    """

    launcher_pid = session.process.pid
    rows = owned_catalog_rows(ctx, launcher_pid)
    names = [str(row.get("name", "")) for row in rows]
    runtime = before["runtime"]
    current = runtime_helpers.process_identity(runtime["pid"])
    return {
        "observed_after_launcher_exit": session.process.poll() is not None,
        "launcher_pid": launcher_pid,
        "catalog_rows": len(rows),
        "catalog_names": names,
        "sockets": owned_sockets(ctx, [*names, *before["sandbox_names"]]),
        "runtime_pid": runtime["pid"],
        # Absence, not "a different process": a reused PID is not this launch's VM.
        "runtime_gone": current is None or current != runtime["start"],
        # Nothing on the host may still name this launch's sandbox, which is the
        # only way a guest descendant could still be running.
        "host_processes": host_processes_matching([*names, *before["sandbox_names"]]),
    }


def unhandled_hint(spec: dict, status: int) -> str:
    """One possible reading of a 255, offered only when the number is 255.

    ``128 + N`` requires the guest's own terminating signal. A status of exactly
    255 is consistent with the runtime reporting the unknown code ``-1`` and no
    identity, which is what an older runtime does. It is a possibility, not a
    diagnosis: this failure record carries no frame or metadata that says which
    layer dropped identity, so nothing here assigns one. Any other status gets no
    hint at all rather than a guess about a cause nobody observed.
    """

    if spec["behaviour"] not in ("unhandled", "self-signal") or status != 255:
        return ""
    return (
        "; 255 is also what a runtime that sent the unknown code -1 and no signal "
        "produces. If that is what happened here, one possible cause is a built "
        "agentd or runtime bundle older than this patch: a new SDK with an old "
        "embedded agentd reports that honestly and is not evidence about the mapping"
    )


def guest_end_problems(
    spec: dict, status: int, launcher_path: str, text: str, expected_name: str
) -> list[str]:
    """Every way one signal row's observed end contradicts its published row.

    Pure: it reads only what the driver observed, so the boot-free contract can
    run the same oracle against a fabricated record. The status alone cannot tell
    a guest end from a forced shutdown that produced the same number, so a row
    that requires an ordinary teardown is judged on the launcher's own account of
    the end as well - and a forced notice is a rejection even when the number and
    the restored terminal are right.
    """

    problems: list[str] = []
    if status != spec["expect"]:
        problems.append(
            f"launcher status {status}, but the status table requires {spec['expect']} "
            f"after {expected_name}, with a guest whose behaviour is "
            f"{spec['behaviour']}{unhandled_hint(spec, status)}; output {text[-2000:]!r}"
        )
    if spec.get("teardown") == "ordinary":
        if "Stopping sandbox" not in text:
            problems.append(
                f"a guest end must show the ordinary teardown notice: {text[-2000:]!r}"
            )
        if "Interrupted by signal" in text:
            problems.append(
                f"a guest end must never report a forced teardown: {text[-2000:]!r}"
            )
        if launcher_path != "ordinary teardown":
            problems.append(
                f"the launcher path was {launcher_path!r}, not the ordinary teardown"
            )
    return problems


def observe_signal(
    case: Case,
    spec: dict,
    session: Session,
    receipt: dict,
    ctx: "Context",
    form: str,
    probe_extra: list[str],
) -> int:
    """One host-signal row: deliver real signals, then prove status, terminal, absence.

    Nothing about the guest is inferred from the launcher's notices: the guest
    reports the signals it received itself, the launcher's status is compared with
    the exact number the published status table requires, and the ownership facts
    are observed before the harness's own rescue cleanup could hide a survivor.
    """

    label = f"{case.name}/{form}"
    expected_name = " + ".join(SIGNAL_NAMES[int(number)] for number in spec["signals"])
    # Merged, not replaced: a self-signal row already recorded this attempt's
    # release file here, and losing it would hide the only handshake evidence.
    receipt["signal"] = {
        **receipt.get("signal", {}),
        "mode": spec["mode"],
        "behaviour": spec["behaviour"],
        "plan": expected_name,
        "grace_seconds": SIGNAL_GRACE,
        "expected_status": spec["expect"],
    }
    session.pump(
        lambda out: "SIGNAL-READY" in out,
        "the guest's signal readiness",
        wait_for=lambda s: s.merged_text(),
    )
    # The mode is an observation, not an assumption: a PTY launch owns the host
    # terminal in raw mode, streaming never touches it. A signal must not change
    # either, and the snapshot comparison below is what proves it did not.
    raw = session.raw_observed()
    receipt["signal"]["host_terminal"] = "raw" if raw else "canonical"
    require(
        raw == (spec["mode"] == "pty"),
        f"{label}: the host terminal is {'raw' if raw else 'canonical'} under a "
        f"{spec['mode']} launch",
    )
    before = owned_while_running(ctx, session.process.pid, label)
    receipt["owned_before_signal"] = before
    ready_at = time.monotonic()
    sent = []
    sent_at = []
    released_at = None
    if spec["behaviour"] == "self-signal":
        # No host signal is involved anywhere in this row, and the release is
        # sent only now that readiness *and* the live-ownership baseline are both
        # observed. A signalling driver would make the status explainable by the
        # host instead of by the guest.
        release = receipt["signal"]["release"]
        require(
            receipt["owned_before_signal"]["host_processes"],
            f"{label}: the live baseline is empty, so nothing could be observed to stop",
        )
        require(
            len(probe_extra) == 2,
            f"{label}: the release arguments were not passed to this attempt: {probe_extra}",
        )
        (Path(ctx.args.project) / release["file"]).write_text(
            probe_extra[1], encoding="ascii"
        )
        released_at = time.monotonic()
        release["released_after"] = "readiness+live-ownership"
        release["released_after_ready_seconds"] = round(released_at - ready_at, 3)
    for index, number in enumerate(spec["signals"]):
        if index:
            # The guest's own report of the first signal is what makes the second
            # one a *second interrupt* rather than a race with delivery.
            session.pump(
                lambda out, marker=SIGNAL_IGNORED[spec["signals"][0]]: marker in out,
                "the guest's report of the first signal",
                wait_for=lambda s: s.merged_text(),
            )
        require(
            session.process.poll() is None,
            f"{label}: the launcher had already exited before signal {index + 1} "
            f"({SIGNAL_NAMES[int(number)]})",
        )
        os.kill(session.process.pid, int(number))
        sent_at.append(time.monotonic())
        sent.append(
            {
                "number": int(number),
                "name": SIGNAL_NAMES[int(number)],
                "sent_after_ready": round(sent_at[-1] - ready_at, 3),
            }
        )
    status = session.wait(SIGNAL_WAIT)
    exited_at = time.monotonic()
    receipt["launcher_status"] = status
    receipt["signal"]["sent"] = sent
    if spec["behaviour"] == "self-signal":
        # Nothing was sent, so there is no index into `sent_at` to measure from;
        # the row's own clock starts at the release.
        require(
            sent == [] and not sent_at,
            f"{label}: a self-signalled row must send no host signal: {sent}",
        )
        require(released_at is not None, f"{label}: the release was never written")
        timing = {"release_to_exit": round(exited_at - released_at, 3)}
    else:
        require(sent, f"{label}: the row requires at least one host signal")
        timing = {
            "first_signal_to_exit": round(exited_at - sent_at[0], 3),
            "last_signal_to_exit": round(exited_at - sent_at[-1], 3),
        }
    receipt["signal"]["timing"] = timing
    # Every channel, because a signal row's report may be on the terminal (PTY) or
    # in a redirected file (streaming): the launcher's own notice goes wherever its
    # stderr went, and the guest's report wherever its stdout went.
    text = session.merged_text()
    receipt["signal"]["launcher_path"] = (
        "forced teardown" if "Interrupted by signal" in text else "ordinary teardown"
    )
    for marker in spec["markers"]:
        require(
            marker in text,
            f"{label}: the guest never reported {marker!r}, so the signal's arrival "
            f"was not observed: {text[-2000:]!r}",
        )
    for marker in spec["forbidden"]:
        require(
            marker not in text,
            f"{label}: the guest reported {marker!r}, which contradicts the "
            f"{spec['behaviour']} behaviour under test: {text[-2000:]!r}",
        )
    # Restoration and absence are recorded and judged *before* the status, so a row
    # that is red for its status still carries the two observations it exists to
    # prove - and still fails if either of them is wrong.
    require_terminal_restored(session, receipt, label)
    absence = observe_absence(ctx, session, before)
    receipt["absence_before_rescue"] = absence
    require(
        absence["catalog_rows"] == 0,
        f"{label}: the launch left {absence['catalog_rows']} catalog row(s) behind: "
        f"{absence['catalog_names']}",
    )
    require(not absence["sockets"], f"{label}: the launch left owned sockets behind: {absence['sockets']}")
    require(
        absence["runtime_gone"],
        f"{label}: the runtime that hosted the guest is still executing: {absence['runtime_pid']}",
    )
    require(
        not absence["host_processes"],
        f"{label}: a process still names this launch's sandbox: {absence['host_processes']}",
    )
    problems = guest_end_problems(
        spec, status, receipt["signal"]["launcher_path"], text, expected_name
    )
    require(not problems, f"{label}: " + "; ".join(problems))
    if spec["behaviour"] == "grace-expiry":
        require(
            timing["first_signal_to_exit"] >= SIGNAL_GRACE,
            f"{label}: the launcher ended {timing['first_signal_to_exit']}s after the "
            f"forwarded signal, before its fixed {SIGNAL_GRACE}s grace: a guest that "
            f"ignores the signal is still owed that grace",
        )
    if spec["behaviour"] == "second-interrupt":
        # Measured from the *first* signal: an interval taken from the last one
        # cannot see a grace that expired before the second arrived, which is
        # exactly the failure this check is for (the launcher would then have exited
        # at first + grace and reported the first signal's number).
        require(
            timing["first_signal_to_exit"] < SIGNAL_GRACE,
            f"{label}: the launcher ended {timing['first_signal_to_exit']}s after the "
            f"first signal, which is at or past the {SIGNAL_GRACE}s grace, so the "
            f"expiry decided the end and the status may be the first signal's",
        )
    if "forced_notice" in spec:
        # The status alone cannot tell a forced shutdown from a guest that exited
        # with the same number itself; the launcher's own account of the end can.
        require(
            spec["forced_notice"] in text,
            f"{label}: the launcher never reported a forced teardown after "
            f"{spec['forced_notice']!r}: {text[-2000:]!r}",
        )
        receipt["signal"]["forced_notice"] = spec["forced_notice"]
    if spec["behaviour"] == "self-signal":
        # The row proved everything above, so this attempt's own release file is
        # no longer needed. A row that failed kept it: the failure's evidence is
        # the token that was or was not written, not a cleaned directory.
        (Path(ctx.args.project) / receipt["signal"]["release"]["file"]).unlink(missing_ok=True)
        receipt["signal"]["release"]["removed_after_proven_cleanup"] = True
    return status


def owned_catalog_rows(ctx: "Context", launcher_pid: int | None) -> list[dict]:
    """Catalog rows naming this launcher's own sandbox, never anyone else's.

    The sandbox name includes the launcher's PID, so this is an ownership test
    rather than a prefix or image match.
    """

    if not launcher_pid:
        return []
    rows = runtime_helpers.catalog_rows(Path(ctx.args.state_root) / "msb-home")
    return [row for row in rows if str(launcher_pid) in str(row.get("name", ""))]


def teardown_receipt(ctx: "Context", session: "Session") -> dict:
    """What this one launch still owned afterwards, and stopping it if anything did.

    A case that fails is exactly when the launcher cannot stop its own sandbox, so
    cleanup happens here as well instead of only after a passing row: the receipt
    records the catalog row, every bounded stop attempt, the surviving processes
    and the owned sockets. Only the row this launcher names is ever signalled or
    stopped.
    """

    receipt: dict = {"launcher_pid": session.process.pid if session.process is not None else None}
    try:
        rows = owned_catalog_rows(ctx, receipt["launcher_pid"])
    except Exception as error:  # noqa: BLE001 - a failed observation is reported
        receipt["observation"] = f"{type(error).__name__}: {error}"
        return receipt
    receipt["catalog_rows"] = len(rows)
    names = [str(row.get("name", "")) for row in rows]
    receipt["names"] = names
    receipt["sockets"] = [
        str(path) for name in names for path in runtime_helpers.socket_paths(
            Path(ctx.args.state_root) / "msb-home", name
        ) if path.exists()
    ]
    steps = []
    for row in rows:
        name = str(row.get("name", ""))
        pid = int(row["pid"]) if row.get("pid") else 0
        identity = runtime_helpers.process_identity(pid) if pid else None
        steps.append({"name": name, "pid": pid, "running": identity is not None})
        for args in (["stop", "--timeout", "5", name], ["stop", "--force", name]):
            try:
                done = subprocess.run(
                    [ctx.args.runtime, *args],
                    env=ctx.env,
                    capture_output=True,
                    timeout=60,
                )
                steps.append({"command": args, "status": done.returncode})
            except (OSError, subprocess.TimeoutExpired) as error:
                steps.append({"command": args, "error": str(error)})
        if identity is not None:
            try:
                runtime_helpers.signal_identity({"pid": pid, "start": identity}, signal.SIGTERM)
            except (OSError, RuntimeError) as error:
                steps.append({"signal": "TERM", "error": str(error)})
    receipt["steps"] = steps
    try:
        receipt["catalog_rows_after"] = len(owned_catalog_rows(ctx, receipt["launcher_pid"]))
    except Exception as error:  # noqa: BLE001
        receipt["catalog_rows_after"] = f"observation failed: {error}"
    return receipt


def own_teardown(ctx: "Context", receipt: dict, label: str) -> None:
    """A case passes only if its own launch left no VM behind."""

    teardown = receipt.get("teardown", {})
    require(
        teardown.get("catalog_rows_after") == 0,
        f"{label}: the launch left catalog rows behind: {teardown}",
    )
    require(
        not teardown.get("sockets"),
        f"{label}: the launch left owned sockets behind: {teardown.get('sockets')}",
    )
    lingering = [
        step.get("pid")
        for step in teardown.get("steps", [])
        if step.get("running") and step.get("pid")
    ]
    for pid in lingering:
        identity = runtime_helpers.process_identity(int(pid))
        if identity is None:
            continue
        runtime_helpers.signal_identity({"pid": int(pid), "start": identity}, signal.SIGKILL)
    require(
        not lingering or all(
            runtime_helpers.process_identity(int(pid)) is None for pid in lingering
        ),
        f"{label}: a runtime process survived this launch: {lingering}",
    )


def owned_runtime_identity(launcher_pid: int, ctx: "Context", label: str = "wait") -> dict:
    """The one running runtime process that belongs to this case.

    Identity comes from the private catalog (the row names this case's sandbox),
    validated through the reviewed helper so a PID reused by another process can
    never be signalled.
    """

    # The launcher pins `MSB_HOME` to `<state root>/msb-home`, so the private
    # catalog is not at the state root itself: setting MSB_HOME in this process
    # cannot override that pin, and a catalog read from the wrong path never finds
    # the runtime this case owns.
    rows = runtime_helpers.catalog_rows(Path(ctx.args.state_root) / "msb-home")
    # The catalog reports `run_status` as a capitalised string ("Running"), so a
    # lower-case-only allowlist matched nothing and this case never found its own
    # runtime.
    candidates = [
        row
        for row in rows
        if row.get("pid")
        and (row.get("run_status") is None or str(row.get("run_status")).lower() == "running")
    ]
    owned = [row for row in candidates if launcher_pid and str(launcher_pid) in str(row.get("name", ""))]
    require(owned, f"{label}: no catalog row names this launcher's sandbox (rows={rows})")
    require(len(owned) == 1, f"{label}: {len(owned)} candidate runtimes; refusing to signal")
    pid = int(owned[0]["pid"])
    identity = runtime_helpers.process_identity(pid)
    require(identity is not None, f"{label}: the catalog runtime is not executing")
    return {"pid": pid, "start": identity}


def run_reject(name: str, form: str, ctx: "Context", work: Path, receipt: dict) -> dict:
    spec = REJECT_CASES[name]
    argv = launch_argv(Path(ctx.args.bin), spec["options"], form, ["true"])
    session = Session(argv, ctx.env, Path(ctx.args.project))
    receipt["argv"] = argv
    receipt["expect"] = "usage error 2"
    try:
        # The case names an input kind, so the launcher receives exactly that:
        # a real pipe or a real regular file, never /dev/null.
        session.assign(spec["stdin"], "pipe", "pipe", work, stdin_file=work / "stdin.bin")
        receipt["stdin_kind"] = spec["stdin"]
        session.spawn()
        status = session.wait(120)
        receipt["launcher_status"] = status
        stderr = session.stderr_text()
        require(status == 2, f"{name}/{form}: status {status}, not a usage error; {stderr!r}")
        require(
            "--tty (-t) requires terminal stdin" in stderr or "cannot be used with" in stderr,
            f"{name}/{form}: unhelpful diagnostic: {stderr!r}",
        )
        require(
            "==>" not in stderr,
            f"{name}/{form}: a refused launch booted anyway: {stderr!r}",
        )
        if spec["stdin"] == "pipe":
            leftover = session.unconsumed_stdin()
            receipt["stdin_unconsumed"] = leftover.decode("utf-8", "replace")
            require(
                leftover == b"unread",
                f"{name}/{form}: the refused launch consumed the caller's pipe input: {leftover!r}",
            )
        receipt["stderr"] = stderr
        receipt["terminal"] = {"baseline": None, "final": None}
    finally:
        receipt["captures"] = session.summary()
        receipt["capture_files"] = session.capture_files(Path(ctx.args.evidence))
        receipt["teardown"] = teardown_receipt(ctx, session)
        session.close()
    own_teardown(ctx, receipt, f"{name}/{form}")
    return receipt


def run_program_case(name: str, form: str, ctx: "Context", work: Path, receipt: dict) -> dict:
    spec = PROGRAM_CASES[name]
    project = Path(ctx.args.project)
    if "not-executable" in spec["program"][0]:
        # The project owns the fixture the case names: a regular file with no
        # execute bit. Nothing created it before, so a correct launcher answered
        # 127 for a missing file rather than 126 for a present but non-executable
        # one, and the case would have failed for the wrong reason.
        fixture = project / "not-executable"
        fixture.write_text("#!/bin/sh\nexit 0\n")
        fixture.chmod(0o644)
    argv = launch_argv(Path(ctx.args.bin), ["-t"], form, spec["program"])
    session = Session(argv, ctx.env, project)
    receipt["argv"] = argv
    receipt["expect"] = spec["expect"]
    try:
        session.assign("tty", "tty", "tty", work)
        session.spawn()
        status = session.wait(180)
        receipt["launcher_status"] = status
        require(
            status == spec["expect"],
            f"{name}/{form}: status {status}, expected {spec['expect']}; "
            f"output={session.launcher_output()!r}",
        )
        receipt["terminal"] = {"baseline": session.baseline_state(), "final": session.final_state()}
        require(
            session.baseline_state() == session.final_state(),
            f"{name}/{form}: the host terminal was not restored",
        )
        return receipt
    finally:
        receipt["captures"] = session.summary()
        receipt["capture_files"] = session.capture_files(Path(ctx.args.evidence))
        receipt["teardown"] = teardown_receipt(ctx, session)
        session.close()
    own_teardown(ctx, receipt, f"{name}/{form}")
    return receipt


# -------------------------------------------------------------------- main ---


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="run one #400 terminal case")
    parser.add_argument("--bin", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--form", required=True, choices=["run", "separator"])
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--home", default=None, help="private guest HOME for this case")
    parser.add_argument("--expect-hook", default=None, help="the project hook's export value")
    parser.add_argument("--expect-hook-path", default=None, help="a PATH fragment the hook adds")
    parser.add_argument("--no-ambient-tty-check", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def child_env(args: argparse.Namespace) -> dict:
    env = dict(os.environ)
    env["MSB_PATH"] = args.runtime
    env["AGENT_VM_STATE_DIR"] = args.state_root
    # No MSB_HOME here: the launcher pins it under the state root itself, so an
    # override would be silently ignored (and would move the catalog this driver
    # reads).
    env.pop("MSB_HOME", None)
    env["AGENT_VM_IMAGE_TAG"] = args.image
    env.pop("AGENT_VM_NO_CHROME_MCP", None)
    if args.home:
        env["HOME"] = args.home
    return env


class Context:
    """Everything one run needs, so no case reaches for a module global."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.env = child_env(args)
        self.expect_hook = args.expect_hook
        self.expect_hook_path = args.expect_hook_path


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    ctx = Context(args)
    evidence = Path(args.evidence)
    if not evidence.is_absolute():
        print("direct-terminal: --evidence must be absolute", file=sys.stderr)
        return 2
    # The launcher runs with the case's project as its cwd, so a relative binary
    # path would silently not be the binary that was intended.
    if not Path(args.bin).is_absolute():
        print("direct-terminal: --bin must be an absolute path", file=sys.stderr)
        return 2
    evidence.mkdir(parents=True, exist_ok=True)
    work = evidence / f"work-{args.case}-{args.form}"
    work.mkdir(parents=True, exist_ok=True)

    label = f"{args.case}/{args.form}"
    # One receipt for the whole invocation. The case helpers fill it in as they go,
    # so an exception still leaves the argv, the observations made so far and the
    # raw captures, instead of the bare error the failure path used to write.
    receipt: dict = {"case": args.case, "form": args.form}

    def write_receipt() -> None:
        (evidence / f"{args.case}-{args.form}.json").write_text(json.dumps(receipt, indent=1))

    try:
        if not args.no_ambient_tty_check:
            assert_no_controlling_terminal()
        if args.case in REJECT_CASES:
            run_reject(args.case, args.form, ctx, work, receipt)
        elif args.case in PROGRAM_CASES:
            run_program_case(args.case, args.form, ctx, work, receipt)
        elif args.case in CASES:
            run_case(CASES[args.case], args.form, ctx, work, receipt)
        else:
            known = sorted({*CASES, *REJECT_CASES, *PROGRAM_CASES})
            print(f"direct-terminal: unknown case {args.case!r}; inventory {known}", file=sys.stderr)
            return 2
    except CaseError as error:
        receipt["verdict"] = "fail"
        receipt["error"] = str(error)
        write_receipt()
        print(f"FAIL {label}: {error}")
        return 1
    except Exception:  # noqa: BLE001 - a driver crash is a failed case, never a pass
        receipt["verdict"] = "fail"
        receipt["error"] = traceback.format_exc()
        write_receipt()
        print(f"FAIL {label}: driver error")
        return 1
    receipt["verdict"] = "pass"
    receipt["launcher_status"] = receipt.get("launcher_status")
    write_receipt()
    if receipt.get("launcher_status") is not None:
        (evidence / f"{args.case}-{args.form}.status").write_text(f"{receipt['launcher_status']}\n")
    print(f"PASS {label} status={receipt.get('launcher_status')}")
    return 0


def load_runtime_helpers() -> object:
    """The reviewed host-process helpers, imported rather than re-implemented."""

    import importlib.util

    here = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("egress_fixtures", here / "egress-fixtures.py")
    module = importlib.util.module_from_spec(spec)
    module.__name__ = "egress_fixtures"
    sys.modules[module.__name__] = module
    spec.loader.exec_module(module)
    return module


runtime_helpers = load_runtime_helpers()

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
