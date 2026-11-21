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

sys.dont_write_bytecode = True

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

# ------------------------------------------------- the access prompt (#501 s3) --

# The prompt is found by its own text, never by a launcher notice: this line is
# drawn by the takeover frame itself, so its presence is the takeover's evidence.
PROMPT_TITLE = "the sandbox refused a network request"
# The question's own instruction row. Answering is a line now: the operator types a
# letter (or its word) on the input row and presses Enter, so the launcher draws no
# "ready" state — the row below is the question's evidence and its input row follows.
PROMPT_INSTRUCTION = "Type one of the below letters and press enter:"
# The host restore of the plan's §5.7, byte for byte, as `screen::host_restore`
# builds it. A forced or lost end must contain it exactly once and end with it
# (the rows that check it send launcher notices to a file, so the terminal stream
# ends at the restore).
HOST_RESTORE = (
    "\x18\x1b[0m\x1b[<u\x1b[?6l\x1b[r\x1b[?1049l"
    "\x1b[?1003l\x1b[?1002l\x1b[?1001l\x1b[?1000l\x1b[?9l"
    "\x1b[?1004l\x1b[?2004l\x1b[?2026l\x1b(B\x1b)B\x0f\x1b[0m"
)
# A `refuse` probe prints this many held lines; the deny row requires every one,
# in order and exactly once, after the leave.
PROMPT_LINE_COUNT = 60
# How soon after the guest's *refusal* a prompt must appear. AC1 says 1 s with the
# writer's queue empty; the stall row is allowed the plan's 1.5 s because its
# readiness marker precedes the refusal it has to observe.
#
# Measured from the guest's `CONNECT rc=` line, not from `REFUSE-READY`: readiness
# precedes the guest's own spawn (`timeout` + `bash` + the `/dev/tcp` open) by up
# to ~0.1 s, and the *decision* to take over waits for the refusal to reach the
# feed. The runtime wakes that follower on the append itself (microsandbox #126),
# so ingestion is milliseconds; its 2 s fallback poll is a net for a notification
# that never arrived, and a row that lands on the net fails this bound instead of
# silently measuring it. Both intervals are recorded (`appeared_seconds`,
# `refused_seconds`, `after_refusal_seconds`), so a launcher that really is slow
# is distinguishable from a slow log; only the interval this slice owns is
# asserted.
PROMPT_APPEARS_WITHIN = 1.0
PROMPT_STALL_WITHIN = 1.5


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
        env: dict | None = None,
    ):
        self.name = name
        self.options = options
        self.probe = probe
        self.assignment = assignment
        # Per-case environment overrides: the prompt's setting and TERM are the
        # case's facts, not the operator's.
        self.env = env or {}
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

# ------------------------------------- the access prompt: the eleven rows -------

# One row per acceptance criterion the plan assigns to the driver (§10.4). Each
# names its probe mode, what the driver answers, and what it must observe. The
# `access` field is the post-launch check against the launcher's own command, and
# `"none"` means the row proves an absence instead (no allowance, or no prompt).
#
# `stderr: "file"` on the forced and runtime-loss rows is deliberate: it keeps the
# launcher's own notices off the terminal stream, so "the output ends with the host
# restore" is a statement about the terminal and not about where a notice landed.
PROMPT_CASES = {
    # AC1: a refused TCP connect prompts within 1 s; `d` restores; the guest
    # continues; `access` still lists the refusal.
    "prompt-deny": {
        "probe": ["refuse"],
        "answer": b"d",
        "expect": 0,
        "lines": True,
        "access": "refusal",
    },
    # AC2: `s` grants a session allowance, applied with revision >= 2.
    "prompt-session": {
        # A public address: refused by default deny, reachable after the allowance.
        "probe": ["refuse", "1.1.1.1", "443", "1"],
        "answer": b"s",
        "expect": 0,
        "lines": True,
        "retry_succeeds": True,
        "access": "session-applied",
    },
    # AC3: the #491 case offers only `p`, labelled from the next launch, and only
    # the record is written.
    "prompt-project-next": {
        "probe": ["refuse-dns"],
        "answer": b"p",
        "expect": 0,
        "access": "project-record-only",
        "offer": "project-only",
        "result_says": "next launch",
    },
    # AC4: a key typed before the guard, later `ss` in one write, then `d`: no
    # allowance, and the guest's stdin is empty.
    "prompt-guard": {
        "probe": ["refuse"],
        "answer": b"d",
        "expect": 0,
        "guard": True,
        "access": "no-allowance",
        "probe_stdin": True,
    },
    # AC3's other arm: the full offer's `p` applies now and records, which `s` does
    # not.
    "prompt-project": {
        "probe": ["refuse", "1.1.1.1", "443", "1"],
        "answer": b"p",
        "expect": 0,
        "lines": True,
        "retry_succeeds": True,
        "access": "project-applied",
    },
    # AC12: a CLI `access allow` closes the shown prompt without a key, and a prompt
    # `p` typed while that grant is in flight must never write a project record.
    "prompt-answered-elsewhere": {
        "probe": ["refuse"],
        "answer": None,
        "expect": 0,
        "answered_elsewhere": True,
        "race_key": b"p",
        # AC12's original wording assumes the CLI answered first. R19 is first-answer-
        # wins, and the prompt's `p` is typed while the CLI runs (Popen), so either
        # surface can win; the row asserts the specified invariant and records which
        # one did (round 4).
        "access": "first-answer-wins",
    },
    # AC7's alternate-screen half: the leave used DECRC, the final size is the
    # host's, and the guest was asked to redraw.
    "prompt-alt-screen": {
        "probe": ["alt"],
        "answer": b"d",
        "expect": 0,
        "alt": True,
    },
    # AC8: after a stalled sequence, CAN then the prompt, by 1.5 s.
    "prompt-stall": {
        "probe": ["stall"],
        "answer": b"d",
        "expect": 0,
        "stall": True,
        "access": "refusal",
    },
    # AC13's guest-exit half: unanswered, the guest's own exit ends it, with the
    # leave before its held output and its own status.
    "prompt-exit": {
        "probe": ["exit-during"],
        "answer": None,
        "expect": 7,
        "exit": True,
    },
    # AC13's forced half: two external SIGINTs, the host restore exactly once, the
    # forced status — on both screens.
    "prompt-forced": {
        # The guest ignores INT/TERM: the first signal is forwarded, the second must
        # force the launcher (F2). A guest killed by the first is a guest exit.
        "probe": ["refuse", "203.0.113.10", "443", "0", "ignore"],
        "answer": None,
        "expect": 128 + int(signal.SIGINT),
        "forced": True,
        "stderr": "file",
    },
    "prompt-forced-alt": {
        "probe": ["alt", "ignore"],
        "answer": None,
        "expect": 128 + int(signal.SIGINT),
        "forced": True,
        "stderr": "file",
    },
    # AC13's runtime-loss half: the owned runtime is killed while the question is
    # up; 125, the host restore exactly once — on both screens.
    "prompt-runtime-loss": {
        "probe": ["refuse"],
        "answer": None,
        "expect": 125,
        "runtime_loss": True,
        "stderr": "file",
    },
    "prompt-runtime-loss-alt": {
        "probe": ["alt"],
        "answer": None,
        "expect": 125,
        "runtime_loss": True,
        "stderr": "file",
    },
    # AC9, in its three shapes: the setting off, TERM=dumb, and `-t` with stdout
    # redirected. No prompt bytes; the hint appears exactly once.
    "prompt-off-env": {
        "probe": ["refuse"],
        "answer": None,
        "expect": 0,
        "off": True,
        "env": {"AGENT_VM_NO_ACCESS_PROMPT": "1"},
    },
    "prompt-off-dumb": {
        "probe": ["refuse"],
        "answer": None,
        "expect": 0,
        "off": True,
        "env": {"TERM": "dumb"},
    },
    "prompt-off-redirect": {
        "probe": ["refuse"],
        "answer": None,
        "expect": 0,
        "off": True,
        "options": ["-t"],
        "stdout": "file",
    },
}

# Every prompt row's assignment: the launcher needs a terminal on both stdin and
# stdout, and the prompt's own eligibility checks they are the same one.
for _prompt_name, _prompt_spec in PROMPT_CASES.items():
    _assignment = {"stdin": "tty", "stdout": "tty", "stderr": "tty"}
    _assignment["stdout"] = _prompt_spec.get("stdout", "tty")
    _assignment["stderr"] = _prompt_spec.get("stderr", "tty")
    CASES[_prompt_name] = Case(
        _prompt_name,
        _prompt_spec.get("options", []),
        _prompt_spec["probe"],
        _assignment,
        env=_prompt_spec.get("env"),
    )


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
    session = Session(argv, {**ctx.env, **case.env}, Path(args.project))
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
    if name in PROMPT_CASES:
        return observe_prompt(case, form, session, receipt, ctx)
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


# ------------------------------------- the access prompt: observation helpers ---


def access_command(ctx: "Context", *arguments: str) -> subprocess.CompletedProcess:
    """`agent-vm access …` under the case's own state root and project.

    The prompt's grants are the same command's business, so the row asks the
    launcher's own CLI rather than reading the log format here.
    """

    return subprocess.run(
        [ctx.args.bin, "access", *arguments],
        env=ctx.env,
        cwd=ctx.args.project,
        capture_output=True,
        text=True,
        timeout=120,
    )


def access_output(ctx: "Context", *arguments: str) -> str:
    done = access_command(ctx, *arguments)
    return done.stdout + done.stderr


def allowance_rows(table: str, destination: str) -> list[dict]:
    """Rows of `access allowances` whose DESTINATION cell names `destination`.

    The table's columns are SCOPE, DESTINATION, RECORDED, SESSION, STATUS; a row's
    first cell is its scope, which is what distinguishes a record from a live session
    allowance.
    """

    rows = []
    for line in table.splitlines():
        if destination not in line or line.lstrip().startswith("SCOPE"):
            continue
        fields = line.split()
        if not fields or fields[0] not in ("session", "project"):
            continue
        rows.append(
            {
                "scope": fields[0],
                "status": " ".join(fields[1:]),
            }
        )
    return rows


def prompt_destination(spec: dict) -> str:
    """The destination a prompt case's refusal names, spelled as `access` spells it.

    The inventory passes its own trigger target (`refuse 1.1.1.1 443 1`) so a
    session or project allowance can be retried against a reachable address; the
    #491 case's trigger is a DNS name. A table lookup keyed on one hard-coded
    array made every other case search for a row that could never exist.
    """

    probe = spec["probe"]
    if probe[0] == "refuse-dns":
        return "blocked.example"
    return probe[1] if len(probe) > 1 else "203.0.113.10"


def allowance_destination(table: str, needle: str) -> str | None:
    """The `access allowances` DESTINATION cell of the row naming `needle`.

    `access revoke` takes the destination *as agent-vm records it*
    (`tcp://[1.1.1.1/32]:443`), which is not the probe's argument, so the cell is
    read back rather than reconstructed.
    """

    for line in table.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0] not in ("session", "project"):
            continue
        if needle in fields[1]:
            return fields[1]
    return None


def refusal_id(ctx: "Context", destination: str) -> str | None:
    """The 8-hex ID of the *live* session's refusal row naming `destination`.

    The project's refusal log outlives a launch and every case of a row shares one
    project, so matching the destination alone can return an *ended* session's row
    — and `access allow` on that row fails ("has ended"), which the answered-
    elsewhere row then reported as a product failure. The refusals table's SESSION
    cell is a *label* (`access_cmd::label`: "running", "running (no control
    socket)", "not responding", "ended", "ended (unclean)"), never an id, so the
    live row is the one whose label is not an ended one; the prompt's own text
    names the session id, but the table does not print it.
    """

    for line in access_output(ctx).splitlines():
        if destination not in line or "ended" in line:
            continue
        match = re.match(r"\s*([0-9a-f]{8})\b", line)
        if match:
            return match.group(1)
    return None


def question_is_drawn(text: str) -> bool:
    """Whether the prompt's question is the latest frame drawn.

    The accumulated text keeps every frame, so `PROMPT_TITLE in text` stays true
    after the leave. The instruction row is drawn by the takeover itself and again
    by every redraw, so the latest one being present (and no leave after it) means
    the line is on screen and can be typed.
    """

    drawn = text.rfind(PROMPT_INSTRUCTION)
    return drawn >= 0 and drawn > text.rfind("\x1b[?1049l")


def cpr_reply(text: str) -> bytes:
    """The terminal's answer to the prompt's cursor-position request.

    The request names the input row and the column just past the typed line, so the
    reply is read off the move rather than assumed: a reply that names another
    position is host input, not a confirmation.
    """

    moves = re.findall(r"\x1b\[(\d+);(\d+)H(?=(?:(?!\x1b\[\d+;\d+H).)*\x1b\[6n)", text, re.S)
    require(moves, "the prompt asked for a position it never moved to")
    row, col = moves[-1]
    return f"\x1b[{row};{col}R".encode()


class PromptDriver:
    """How many cursor-position requests have been answered, and when the last was.

    The count must outlive one `pump_prompt` call: a caller that re-pumps would
    otherwise answer the same request again on every pass (H13). `limit` is the
    launcher's own shape: one request per takeover, so exactly one reply is ever
    written (H15) — extra replies are host input, and a driver that keeps answering
    keeps a session busy with them.
    """

    def __init__(self, limit: int = 1) -> None:
        self.answered = 0
        self.limit = limit


def pump_prompt(
    session: "Session",
    predicate,
    what: str,
    driver: "PromptDriver",
    deadline: float = MARKER_DEADLINE,
) -> str:
    """Read until `predicate` holds, answering the prompt's position requests once.

    A real terminal answers `CSI 6 n`; without an answer the launcher falls back to its
    1 s margin, which would make every visibility assertion weaker than the product's
    own. But this must never answer a request that was already answered: every call
    site shares the case's one `PromptDriver`, whose count is read here **once, above
    the polling loop** — re-initialising it per iteration wrote one reply every 10 ms
    for as long as the predicate took, and those replies are host input the question
    would have to clear (H16).
    """

    limit = min(session.deadline, time.monotonic() + deadline)
    answered = driver.answered
    while time.monotonic() < limit:
        session.poll_once()
        text = session.launcher_output()
        requests = text.count("\x1b[6n")
        # One terminal, one request, one reply: `limit` is 1 for every case.
        while answered < requests and answered < driver.limit:
            if session.process is not None and session.process.poll() is not None:
                break
            session.write_terminal(cpr_reply(text))
            answered += 1
            driver.answered = answered
        if predicate(text):
            return text
        time.sleep(0.01)
    raise CaseError(f"{what}: not observed within {deadline:.0f}s")


#: How long the prompt ignores input after the question becomes readable
#: (`access_prompt::relay::SETTLE_MS`): the tail of typing aimed at the guest must not
#: arrive as an answer, so a driver waits it out exactly as a person reading the
#: question does.
SETTLE_SECONDS = 0.5
#: What a driver waits before typing: the settle window plus room for the last read.
SETTLE_MARGIN = 0.25


def settle() -> None:
    """Wait out the prompt's settle window."""

    time.sleep(SETTLE_SECONDS + SETTLE_MARGIN)


def wait_for_question(session: "Session", label: str, driver: "PromptDriver") -> str:
    """Pump until the question is drawn, answering its one cursor-position request.

    Leaves the question *answerable*: the settle window has passed, so the next
    keystroke is the operator's.
    """

    pump_prompt(session, question_is_drawn, f"{label}: the question", driver=driver)
    settle()
    return session.launcher_output()


def submit(session: "Session", answer: bytes) -> None:
    """Type the answer one byte at a time, then press Enter.

    The line may only be assembled from single-byte reads (a paste, or a burst that
    arrives as one read, clears it), so every letter is its own write, as a person's
    keystrokes are — and a word like `session` is typed the same way.
    """

    for byte in answer:
        session.write_terminal(bytes([byte]))
        time.sleep(0.05)
    session.write_terminal(b"\r")


def held_lines_after(text: str, start: int) -> list[int]:
    """Every `LINE n` the guest printed after `start`, in order."""

    return [int(match.group(1)) for match in re.finditer(r"LINE (\d+)", text[start:])]


def require_modes_reapplied(text: str, leave_at: int, first_line_at: int, label: str) -> None:
    """The guest's modes come back after the leave, in §5.6's order."""

    window = text[leave_at:first_line_at]
    for sequence, position in (("\x1b(0", "the line-drawing designation"), ("\x1b[?1002h", "button-event mouse"), ("\x1b[?2004h", "bracketed paste")):
        require(
            sequence in window,
            f"{label}: the leave did not re-apply {position}: {window!r}",
        )
    require(
        window.index("\x1b(0") < window.index("\x1b[?1002h") < window.index("\x1b[?2004h"),
        f"{label}: the modes were re-applied out of order: {window!r}",
    )


def observe_prompt(case: Case, form: str, session: "Session", receipt: dict, ctx: "Context") -> int:
    """One prompt row: drive the question, answer it, and check the whole aftermath."""

    spec = PROMPT_CASES[case.name]
    label = f"{case.name}/{form}"
    # AC1's latency bound is *recorded* here and fails the case at the end, after
    # every other check has run. A gate at this point hid all the other acceptance
    # criteria's evidence on a real boot, where the refusal→prompt interval is
    # bimodal (see `PROMPT_APPEARS_WITHIN`). The case still fails; it just fails
    # with its whole receipt instead of only the timing line.
    deferred: list[str] = []
    receipt["prompt"] = {"probe": spec["probe"], "answer": None if spec["answer"] is None else spec["answer"].decode()}
    # One driver for the whole case: every pump below shares it, so no call site can
    # write a reply the launcher did not ask for (H16).
    driver = PromptDriver(limit=1)
    session.pump(
        lambda out: "REFUSE-READY" in out,
        "the prompt probe's readiness",
        wait_for=lambda s: s.merged_text(),
    )
    if spec.get("off"):
        # AC9: no prompt bytes anywhere, and the hint exactly once. The probe holds the
        # session open until released, so the observation is on a live session.
        # The guest's stdout may be a file (`prompt-off-redirect`), so the hold
        # marker is read from every channel, not only the launcher's terminal.
        session.pump(
            lambda out: "HOLD-READY" in out,
            f"{label}: the guest's hold",
            wait_for=lambda s: s.merged_text(),
        )
        session.write_terminal(b" ")
        session.pump(
            lambda out: "REFUSE-DONE" in out,
            "the guest's completion",
            wait_for=lambda s: s.merged_text(),
        )
        status = session.wait()
        terminal = session.launcher_output()
        require(
            PROMPT_TITLE not in terminal,
            f"{label}: a prompt was drawn with it off: {terminal[-800:]!r}",
        )
        require(
            PROMPT_TITLE not in session.guest_stdout_text(),
            f"{label}: a prompt was drawn into the guest's stdout: {session.guest_stdout_text()[-800:]!r}",
        )
        hint = "The sandbox refused a guest network request"
        require(
            terminal.count(hint) == 1,
            f"{label}: the hint must appear exactly once on stderr, saw "
            f"{terminal.count(hint)}: {terminal[-800:]!r}",
        )
        require(status == spec["expect"], f"{label}: status {status}; {terminal[-800:]!r}")
        return status

    # From the guest's readiness; both halves are recorded so the launcher's own
    # share is separable from the guest's spawn and the runtime's log ingestion.
    started = time.monotonic()
    connect_at: list[float] = []

    def until_prompt(text: str) -> bool:
        if not connect_at and "CONNECT rc=" in text:
            connect_at.append(time.monotonic())
        return PROMPT_TITLE in text

    pump_prompt(session, until_prompt, f"{label}: the prompt", driver)
    appeared_at = time.monotonic()
    receipt["prompt"]["appeared_seconds"] = round(appeared_at - started, 3)
    if connect_at:
        receipt["prompt"]["refused_seconds"] = round(connect_at[0] - started, 3)
        receipt["prompt"]["after_refusal_seconds"] = round(appeared_at - connect_at[0], 3)
    # AC1's latency bound applies to every prompt row, not only the stalled one: a
    # row that took ten seconds to appear would otherwise pass. The measured
    # interval is the refusal's own (see `PROMPT_APPEARS_WITHIN`); the stall row's
    # prompt precedes the guest's report of its refused connect, so there the bound
    # stays on the total.
    bound = PROMPT_STALL_WITHIN if spec.get("stall") else PROMPT_APPEARS_WITHIN
    measured = receipt["prompt"].get("after_refusal_seconds")
    if measured is None:
        measured = receipt["prompt"]["appeared_seconds"]
        receipt["prompt"]["prompt_before_refusal_report"] = True
    if measured <= bound:
        receipt["prompt"]["latency_within_bound"] = True
    else:
        receipt["prompt"]["latency_within_bound"] = False
        deferred.append(
            f"AC1 latency: {measured}s after the guest's refusal "
            f"({receipt['prompt']['appeared_seconds']}s after its readiness), "
            f"not within {bound}s"
        )
    session_id = re.search(r"session ([0-9a-f]{8})\b", session.launcher_output())
    if session_id:
        receipt["prompt"]["session"] = session_id.group(1)
    if spec.get("stall"):
        text = session.launcher_output()
        can_at = text.find("\x18")
        enter_at = text.find("\x1b[?1049h")
        require(
            0 <= can_at < enter_at,
            f"{label}: a stalled sequence must be cancelled with CAN before the "
            f"enter frame (can={can_at}, enter={enter_at}): {text[-800:]!r}",
        )
    if spec.get("offer") == "project-only":
        text = pump_prompt(
            session, question_is_drawn, f"{label}: the question", driver
        )
        require("from the next launch" in text, f"{label}: the #491 offer is missing: {text[-800:]!r}")
        require(
            "  s session  allow for" not in text,
            f"{label}: `s` was offered for a destination only a record can admit: {text[-800:]!r}",
        )
    if spec.get("guard"):
        # A letter typed at the guest before the question appeared must not answer it;
        # a burst that arrives as one read clears the line; then a deliberate `d` and
        # Enter. Nothing may reach the guest and nothing may be granted.
        session.write_terminal(b"s")
        wait_for_question(session, label, driver)
        session.write_terminal(b"ss")
        submit(session, b"d")
    elif spec.get("answered_elsewhere"):
        wait_for_question(session, label, driver)
        if not ctx.standin:
            identifier = refusal_id(ctx, prompt_destination(spec))
            require(identifier, f"{label}: no refusal row names the destination, so the CLI cannot answer")
            receipt["prompt"]["answered_elsewhere_id"] = identifier
            if not spec.get("race_key"):
                done = access_command(ctx, "allow", identifier)
                receipt["prompt"]["answered_elsewhere_status"] = done.returncode
                require(
                    done.returncode == 0,
                    f"{label}: `access allow {identifier}` failed ({done.returncode}): {done.stdout}{done.stderr}",
                )
            if spec.get("race_key"):
                # AC12's race: a `p` aimed at the question *while the CLI's session
                # grant is still running*. The prompt's conditional grant must find the
                # destination answered under the handler's lock and write no record.
                # (The old code sent the key only after `access_command` returned, so
                # the lock never decided anything: M12/C-F4.)
                racing = subprocess.Popen(
                    [ctx.args.bin, "access", "allow", identifier],
                    env=ctx.env,
                    cwd=ctx.args.project,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                submit(session, spec["race_key"])
                receipt["prompt"]["race_key"] = spec["race_key"].decode()
                try:
                    out, err = racing.communicate(timeout=120)
                except subprocess.TimeoutExpired:
                    racing.kill()
                    out, err = racing.communicate()
                receipt["prompt"]["race_status"] = racing.returncode
                require(
                    racing.returncode == 0,
                    f"{label}: the racing `access allow {identifier}` failed "
                    f"({racing.returncode}): {out}{err}",
                )
    elif spec.get("forced"):
        wait_for_question(session, label, driver)
        os.kill(session.process.pid, signal.SIGINT)
        time.sleep(0.3)
        os.kill(session.process.pid, signal.SIGINT)
    elif spec.get("runtime_loss"):
        wait_for_question(session, label, driver)
        identity = owned_runtime_identity(session.process.pid, ctx, label)
        receipt["prompt"]["runtime_pid"] = identity["pid"]
        runtime_helpers.signal_identity(identity, signal.SIGKILL)
    elif spec["answer"] is not None:
        wait_for_question(session, label, driver)
        submit(session, spec["answer"])
    # else: the guest ends the session by itself while the question is up.

    # The `access`/`access allowances` check runs **while the session is live**: a
    # session allowance exists only in a running session, and the row used to check
    # after the launcher had exited, so a correct build failed (finding 15, AC2).
    if spec.get("access") is not None or spec.get("result_says"):
        pump_prompt(
            session, lambda out: "\x1b[?1049l" in out, f"{label}: the leave", driver
        )
        # A session-scope allowance exists only in a running session, and the probe
        # holds itself open for exactly this check (M12/C-F4).
        live_access = spec.get("access") in (
            "session-applied",
            "session-applied-no-record",
            "project-applied",
            "project-record-only",
        )
        if live_access:
            pump_prompt(
                session, lambda out: "HOLD-READY" in out, f"{label}: the live hold", driver
            )
        require_access(case, form, ctx, receipt, spec)
        if live_access:
            session.write_terminal(b" ")
    elif (
        spec["probe"][0] in ("refuse", "refuse-dns", "alt")
        and not spec.get("forced")
        and not spec.get("runtime_loss")
    ):
        # This row holds the probe open for a live check it does not run (the
        # alternate-screen and stall rows): release it so the row does not wait for the
        # probe's own 15 s timeout.
        pump_prompt(
            session, lambda out: "HOLD-READY" in out, f"{label}: the guest's hold", driver
        )
        session.write_terminal(b" ")
    status = session.wait(120)
    receipt["launcher_status"] = status
    text = session.launcher_output()
    if spec.get("result_says"):
        require(
            spec["result_says"] in text,
            f"{label}: the result sentence must say {spec['result_says']!r}: {text[-1200:]!r}",
        )
    require(
        status == spec["expect"],
        f"{label}: launcher status {status}, expected {spec['expect']}; "
        f"terminal tail {text[-1200:]!r}",
    )

    if spec.get("forced") or spec.get("runtime_loss"):
        # The terminal stream ends at the host restore, and only one copy of it.
        require(
            text.count(HOST_RESTORE) == 1,
            f"{label}: the host restore must appear exactly once, saw "
            f"{text.count(HOST_RESTORE)}: {text[-1200:]!r}",
        )
        require(
            text.rstrip().endswith(HOST_RESTORE),
            f"{label}: the terminal output must end with the host restore: {text[-1200:]!r}",
        )
    if spec.get("alt"):
        require(
            "\x1b8" in text,
            f"{label}: an alternate-screen guest is restored with DECRC: {text[-1200:]!r}",
        )
        require(
            "\x1b[?1049l" not in text,
            f"{label}: ?1049l would drop the guest to the main screen: {text[-1200:]!r}",
        )
        leave_at = text.rfind("\x1b8")
        sizes = [tuple(int(value) for value in match.groups()) for match in re.finditer(r"SIZE (\d+) (\d+)", text)]
        final_report = re.search(r"SIZE-FINAL (\d+) (\d+)", text)
        receipt["prompt"]["sizes"] = sizes
        receipt["prompt"]["final_size_report"] = (
            (int(final_report.group(1)), int(final_report.group(2))) if final_report else None
        )
        after = [match for match in re.finditer(r"SIZE (\d+) (\d+)", text[leave_at:])] if leave_at >= 0 else []
        require(
            after,
            f"{label}: the guest never saw a size change after the leave, so it was not "
            f"asked to redraw (sizes={sizes}, "
            f"final={receipt['prompt']['final_size_report']}): {text[-1200:]!r}",
        )
        final = (int(after[-1].group(1)), int(after[-1].group(2)))
        require(
            final == INITIAL_SIZE,
            f"{label}: the guest's final size is {final}, not the host's {INITIAL_SIZE}",
        )
    if spec.get("lines"):
        require("\x1b[?1049l" in text, f"{label}: no leave frame: {text[-1200:]!r}")
        leave_at = text.rfind("\x1b[?1049l")
        require(
            "\x1b[?6h" in text[:leave_at],
            f"{label}: origin mode must be re-set before the screen restore: {text[-1200:]!r}",
        )
        # AC6/R8: every LINE the guest wrote arrives exactly once and in order, and
        # none is written while the takeover holds the terminal. Which lines the
        # takeover actually *held* depends on how long the refusal took to reach
        # the feed — the runtime's ingestion poll allows up to 2 s, during which the
        # guest legitimately keeps writing to a terminal no takeover owns — so the
        # split point is recorded, not assumed to be zero (a real boot on
        # 2026-11-15 had lines 0-37 forwarded before the takeover).
        written = held_lines_after(text, 0)
        require(
            written == list(range(PROMPT_LINE_COUNT)),
            f"{label}: the guest's lines must arrive once each and in order; "
            f"saw {written[:8]}…{written[-4:] if len(written) > 8 else ''}",
        )
        enter_at = text.rfind("\x1b[?1049h", 0, leave_at)
        in_takeover = [
            int(match.group(1))
            for match in re.finditer(r"LINE (\d+)", text[max(enter_at, 0) : leave_at])
        ]
        require(
            not in_takeover,
            f"{label}: guest output was written during the takeover, not held: "
            f"{in_takeover[:8]}",
        )
        numbers = held_lines_after(text, leave_at)
        require(
            numbers,
            f"{label}: no held line was released after the leave: {text[-800:]!r}",
        )
        first_line_at = text.index(f"LINE {numbers[0]}", leave_at)
        require_modes_reapplied(text, leave_at, first_line_at, label)
        # No prompt byte may follow the leave: a redraw written after it would be
        # drawn over the guest.
        after_leave = text[leave_at:]
        require(
            PROMPT_INSTRUCTION not in after_leave and PROMPT_TITLE not in after_leave,
            f"{label}: a prompt frame was written after the leave: {after_leave[-800:]!r}",
        )
        receipt["prompt"]["held_lines"] = len(numbers)
    # The probe's own report of its refused connect. A takeover now starts within
    # milliseconds of the refusal (microsandbox #126 wakes the runtime's log
    # follower on the append instead of its 2 s poll), so the report is usually
    # written while the takeover holds the guest's output — the rows that end with
    # a leave flush it, and the forced-end and runtime-loss rows, which never
    # flush a hold, lose it. Those rows prove the refusal by the prompt's own text,
    # which they already assert, and record whether the report survived.
    connect = re.search(r"CONNECT rc=(\d+)", text)
    if spec.get("forced") or spec.get("runtime_loss"):
        receipt["prompt"]["connect_report"] = None if connect is None else connect.group(1)
    else:
        require(connect, f"{label}: the probe never reported its connection result: {text[-1200:]!r}")
        require(
            connect.group(1) != "0",
            f"{label}: the refused connection succeeded (rc=0), so this row is not a refusal",
        )
    if spec.get("exit"):
        require(
            "EXIT-DURING-DONE" in text,
            f"{label}: the guest's own completion is missing: {text[-1200:]!r}",
        )
        leave_at = text.rfind("\x1b[?1049l")
        require(
            leave_at >= 0 and leave_at < text.rindex("EXIT-DURING-DONE"),
            f"{label}: the prompt's leave must precede the guest's held output: {text[-1200:]!r}",
        )
        # AC14: 300 numbered KiB blocks, each once and in order, all after the leave.
        blocks = [int(match.group(1)) for match in re.finditer(r"BLOCK (\d+)", text)]
        require(
            blocks == list(range(300)),
            f"{label}: the held payload must be complete and in order after the leave; "
            f"saw {len(blocks)} blocks{blocks[:4]}…",
        )
        receipt["prompt"]["held_blocks"] = len(blocks)
    if spec.get("retry_succeeds"):
        # AC2: after the answer, the same connect succeeds without a restart.
        retry = re.search(r"RETRY rc=(\d+)", text)
        require(retry, f"{label}: the probe never reported its retry: {text[-1200:]!r}")
        require(
            retry.group(1) == "0",
            f"{label}: the guest's retry after the allowance failed (rc={retry.group(1)})",
        )
        receipt["prompt"]["retry"] = "succeeded"
    if spec.get("probe_stdin"):
        # AC4's claim is that no *prompt input* reaches the guest. The launcher's
        # own cursor-position reply is not a key: it is written to the terminal
        # after the enter frame and may be read back after the takeover ends — a
        # stated restore limit ("a paste or reply split across a takeover's start
        # or end ... the rest reaches the guest"). On a real boot the driver's own
        # reply did reach the guest (`1b5b31343b3352`), so the drain is required to
        # be nothing but CPR replies, which excludes every answer byte and a lone
        # Esc/CR/LF too.
        drained = re.search(r"STDIN ([0-9a-f]*)", text)
        require(drained, f"{label}: the probe never reported its stdin: {text[-1200:]!r}")
        raw = bytes.fromhex(drained.group(1)) if drained.group(1) else b""
        require(
            re.fullmatch(rb"(?:\x1b\[\d+;\d+R)*", raw) is not None,
            f"{label}: prompt input reached the guest: {drained.group(1)!r}",
        )
        receipt["prompt"]["guest_stdin"] = drained.group(1)
    if deferred:
        # Everything above has been checked and recorded; the case's verdict is
        # still a failure, and `deferred` is what makes it one.
        raise CaseError(f"{label}: " + "; ".join(deferred))
    return status


def require_access(case: Case, form: str, ctx: "Context", receipt: dict, spec: dict) -> None:
    """The post-launch check against the launcher's own `access` command."""

    label = f"{case.name}/{form}"
    expected = spec.get("access")
    if expected is None:
        return
    if ctx.standin:
        # A boot-free control drives a stand-in, which has no session, no refusal
        # log and no allowance store. The control's claim is about the driver's
        # byte oracle, so the CLI check is recorded as skipped, not faked.
        receipt["prompt"]["access"] = "skipped: boot-free control (a stand-in is not the launcher)"
        return
    destination = prompt_destination(spec)
    try:
        _check_access(ctx, receipt, label, expected, destination, spec)
    finally:
        # The project is shared by both forms of a row and by its later cases, and a
        # project record outlives the launch: one left behind suppresses the next
        # launch's refusal entirely ("the prompt: not observed"). The checks above
        # are the evidence; this only leaves the project as it was found.
        canonical = allowance_destination(access_output(ctx, "allowances"), destination)
        if canonical:
            done = access_command(ctx, "revoke", "--project", canonical)
            receipt["prompt"]["revoked_after_check"] = {
                "destination": canonical,
                "status": done.returncode,
            }


def _check_access(
    ctx: "Context", receipt: dict, label: str, expected: str, destination: str, spec: dict
) -> None:
    if expected == "refusal":
        table = access_output(ctx)
        require(destination in table, f"{label}: `access` does not list the refusal: {table!r}")
        receipt["prompt"]["access"] = "listed"
    elif expected == "session-applied":
        table = access_output(ctx, "allowances")
        require(destination in table, f"{label}: `access allowances` never names the destination: {table!r}")
        require(
            "applied" in table.lower(),
            f"{label}: the session allowance is not applied: {table!r}",
        )
        revisions = [int(value) for value in re.findall(r"rev(?:ision)? (\d+)", table, re.IGNORECASE)]
        require(
            any(revision >= 2 for revision in revisions),
            f"{label}: no confirmed revision >= 2 in `access allowances`: {table!r}",
        )
        receipt["prompt"]["access"] = "session-applied"
    elif expected in ("project-record", "project-record-only"):
        # AC3: the record exists; "only" additionally requires that it was not
        # applied to this session (the #491 case's label promises exactly that).
        table = access_output(ctx, "allowances")
        rows = allowance_rows(table, destination)
        require(rows, f"{label}: `access allowances` never names the record: {table!r}")
        require(
            any(row["scope"] == "project" for row in rows),
            f"{label}: no project record names {destination}: {table!r}",
        )
        if expected == "project-record-only":
            # An *applied* project allowance also has PROJECT scope, so scope alone
            # cannot tell the two apart (M12/C-F4). The status can: an applied entry
            # reads `applied (rev N)` (access_cmd.rs:377), a record this session did not
            # adopt reads `not confirmed for this session` (:425).
            require(
                all(row["scope"] != "session" for row in rows),
                f"{label}: a session allowance was applied although only a record was "
                f"offered: {table!r}",
            )
            require(
                all("applied (rev" not in row["status"] for row in rows),
                f"{label}: the project allowance was applied to this session, although "
                f"the offer promised only a record for the next launch: {table!r}",
            )
        receipt["prompt"]["access"] = expected
    elif expected == "project-applied":
        table = access_output(ctx, "allowances")
        rows = allowance_rows(table, destination)
        require(rows, f"{label}: `access allowances` never names the allowance: {table!r}")
        require(
            any(row["scope"] == "project" for row in rows),
            f"{label}: no project record was written: {table!r}",
        )
        require(
            any(row["scope"] == "session" for row in rows)
            or any("applied" in row["status"].lower() for row in rows),
            f"{label}: the project allowance was not applied to this session: {table!r}",
        )
        receipt["prompt"]["access"] = "project-applied"
    elif expected == "first-answer-wins":
        # R19/R21: the prompt's grant is conditional under the handler's lock, so a
        # destination the CLI already answered is reported as answered elsewhere and
        # never promoted. The prompt's `p` is typed while the CLI runs, so *either*
        # surface may win — the row records which and asserts the invariant (AC12's
        # "never writes a project record" holds when the CLI wins; round 4).
        table = access_output(ctx, "allowances")
        rows = allowance_rows(table, destination)
        require(rows, f"{label}: `access allowances` never names the allowance: {table!r}")
        session_won = any(row["scope"] == "session" for row in rows)
        project_won = any(row["scope"] == "project" for row in rows)
        require(
            session_won or project_won,
            f"{label}: neither surface's allowance is listed: {table!r}",
        )
        if session_won:
            require(
                not project_won,
                f"{label}: the CLI answered first, so a prompt `p` must not have "
                f"written a project record: {table!r}",
            )
        receipt["prompt"]["access"] = "first-answer-wins"
        receipt["prompt"]["race_winner"] = "prompt" if project_won else "cli"
    elif expected == "no-allowance":
        table = access_output(ctx, "allowances")
        require(
            destination not in table,
            f"{label}: an allowance was granted for a question that was never answered: {table!r}",
        )
        receipt["prompt"]["access"] = "no-allowance"
    else:  # pragma: no cover - the inventory is fixed
        raise CaseError(f"{label}: unknown access expectation {expected!r}")



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
    parser.add_argument(
        "--standin",
        action="store_true",
        help="boot-free control: the launcher is a stand-in, so `access` checks are skipped",
    )
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
    # #501 slice 3: the prompt is pinned on (or off) by the case, never by the
    # operator's environment, and TERM is pinned unless a case is *about* TERM.
    env["TERM"] = "xterm-256color"
    env.pop("AGENT_VM_NO_ACCESS_PROMPT", None)
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
        self.standin = args.standin


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
