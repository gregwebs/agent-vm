#!/usr/bin/env python3
"""A launcher stand-in for the #400 boot-free driver controls.

It accepts a real launcher's argv (`[launch options] run|-- PROGRAM ARG...`),
consumes the launch options and the command-boundary token exactly as a launcher
does, and then plays the *plumbing* a launcher provides: the host terminal's
canonical (or raw, for a terminal-input case) bytes forwarded into the guest's
stdin pipe, EOF at the host's own end-of-file, and the guest's stdout/stderr left
on their inherited descriptors.

`STANDIN_MODE` selects a deliberately broken variant so the driver's oracles can
be shown to reject it. This file is never part of a launch; it exists only to
prove that the driver and the guest probe distinguish a correct session from a
broken one without a VM, a runtime or an image.
"""

from __future__ import annotations

import os
import re
import select
import signal
import subprocess
import sys
import termios
import time

MODE = os.environ.get("STANDIN_MODE", "ok")

# The prompt controls (#501 slice 3). A stand-in that plays a *correct* prompt must
# satisfy the driver's oracle; the broken variants must not. These frames are a
# control's own minimal rendition — the product's frames come from
# `access_prompt::screen` and are checked by the tmux oracle — so nothing here
# claims to be the launcher's byte stream.
PROMPT_ENTER = (
    b"\x1b[?1049h"
    b"\x1b[?1003l\x1b[?1002l\x1b[?1001l\x1b[?1000l\x1b[?9l"
    b"\x1b[?2004l\x1b[?6l\x1b[>0u\x1b[0m\x1b(B\x0f"
    b"\x1b[H\x1b[2J"
    b"\x1b[2;1H\x1b[2Kagent-vm: the sandbox refused a network request from the guest"
    b"\x1b[4;1H\x1b[2K  tcp 203.0.113.10:443"
    b"\x1b[7;1H\x1b[2KHow should this request be treated?"
    b"\x1b[8;1H\x1b[2KType one of the below letters and press enter:"
    b"\x1b[9;1H\x1b[2K_"
    b"\x1b[11;1H\x1b[2K  d deny     keep refusing (also Enter or Esc)"
    b"\x1b[9;1H\x1b[6n"
)
# The input row after a key stroke: the letter, then the cursor's `_`.
def prompt_input(typed: bytes) -> bytes:
    return b"\x1b[9;1H\x1b[2K" + typed + b"_"
PROMPT_LEAVE = (
    b"\x1b[0m\x1b[H\x1b[2J\x1b[<u\x1b[?6h\x1b[?1049l"
)
# What the guest's modes must get back (the `refuse` probe's prelude).
PROMPT_MODES_BACK = b"\x1b(0\x1b[?1002h\x1b[?2004h"
# A redraw the product would never write after the leave: a broken variant's tell.
PROMPT_REDRAW_AFTER_LEAVE = b"\x1b[8;1H\x1b[2KType one of the below letters and press enter:"


def die(message: str) -> None:
    print(f"standin: {message}", file=sys.stderr)
    raise SystemExit(64)


def split_argv(argv: list[str]) -> tuple[str, list[str]]:
    """Consume launch options and the route token; return (probe mode, program)."""

    index = 0
    while index < len(argv):
        if argv[index] in ("run", "--"):
            index += 1
            break
        index += 1
    program = argv[index:]
    if not program:
        die("no program after the command boundary")
    mode = ""
    if program[0].endswith("bash") and len(program) > 1 and program[1].endswith("guest-probe.sh"):
        mode = program[2] if len(program) > 2 else ""
    return mode, program


def save_attributes(fd: int):
    return termios.tcgetattr(fd)


def restore_attributes(fd: int, attributes) -> None:
    termios.tcsetattr(fd, termios.TCSANOW, attributes)


def set_raw(fd: int) -> None:
    """What a launcher does to its terminal before forwarding raw input."""

    attributes = termios.tcgetattr(fd)
    raw = list(attributes)
    raw[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG | termios.IEXTEN)
    raw[6] = list(attributes[6])
    raw[6][termios.VMIN] = 1
    raw[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, raw)


def forward(sink, *, truncate: int | None = None, hold: bool = False, mangle: bool = False) -> None:
    """Copy host input into the guest's stdin pipe, byte for byte."""

    copied = 0
    while truncate is None or copied < truncate:
        readable, _, _ = select.select([0], [], [], 30.0)
        if not readable:
            die("the host terminal never delivered input")
        chunk = os.read(0, 4096)
        if not chunk:
            break
        if mangle:
            chunk = chunk.replace(b"\x1d", b"A")
        if truncate is not None:
            remaining = truncate - copied
            if remaining <= 0:
                break
            chunk = chunk[:remaining]
        copied += len(chunk)
        sink.write(chunk)
        sink.flush()
    if hold:
        # Everything forwarded, but the guest's stdin is never closed: the
        # consumer stays open, so no EOF can arrive. Longer than any control's
        # deadline, so the deadline — not this sleep — decides the verdict.
        time.sleep(20)
        sink.close()
        return
    sink.close()


def read_answer_line(prefix: bytes = b"") -> bytes:
    """Read the typed answer up to its Enter, as a launcher's line reader does."""

    seen = prefix
    deadline = time.monotonic() + 30.0
    while b"\r" not in seen and b"\n" not in seen:
        readable, _, _ = select.select([0], [], [], max(0.0, deadline - time.monotonic()))
        if not readable:
            die("the driver never answered")
        seen += os.read(0, 64)
    return seen


def play_prompt_cadence(program: list[str]) -> int:
    """Play the *launcher's* answer cadence, to exercise the driver's own rules.

    The real launcher sends one cursor-position request and treats any later reply as
    input. A stand-in that accepted any read as the key (the plain `prompt-ok` mode)
    cannot catch a driver that answers repeatedly; this mode can (H15). The answer
    itself is a typed line: a letter (or its word) and then Enter, and every byte the
    driver sent before the answer is kept, because a letter can arrive while this mode
    is still counting replies.
    """

    attributes = save_attributes(0)
    set_raw(0)
    process = subprocess.Popen(program, stdout=subprocess.PIPE)
    try:
        assert process.stdout is not None
        head = b""
        while b"REFUSE-READY" not in head:
            chunk = process.stdout.read(1)
            if not chunk:
                die("the probe ended before its readiness")
            head += chunk
            os.write(1, head)
        os.write(1, PROMPT_ENTER)
        # The launcher's reply cadence: it answered the one request it sent. A driver
        # that answers a request twice (H16: a pump without the shared driver
        # re-initialises its count) sends the second reply at once, and this mode then
        # leaves the question unanswered — that is the class it exists to catch.
        # Count *replies*, not reads: the terminal may coalesce several writes into one
        # read, and a driver that answers twice must still be caught.
        pending = b""
        replies = 0
        window = time.monotonic() + 1.0
        while replies == 0 and time.monotonic() < window:
            readable, _, _ = select.select([0], [], [], 0.05)
            if not readable:
                continue
            raw = os.read(0, 4096)
            pending += raw
            replies += len(re.findall(rb"\x1b\[\d+;\d+R", raw))
            os.write(1, prompt_input(b""))
        # A second reply to the same request arrives immediately; give it its moment.
        settle = time.monotonic() + 0.2
        while time.monotonic() < settle:
            readable, _, _ = select.select([0], [], [], 0.02)
            if not readable:
                continue
            raw = os.read(0, 4096)
            pending += raw
            replies += len(re.findall(rb"\x1b\[\d+;\d+R", raw))
        if replies != 1:
            # Zero replies (no driver) or more than one (a driver answering twice): leave
            # the question unanswered, as a real launcher's question would time out.
            os.write(1, PROMPT_LEAVE)
            held = b""
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                held += chunk
            os.write(1, held)
            return process.wait()
        # Now the answer: a letter (or its word), then Enter.
        line = read_answer_line(pending)
        typed = re.sub(rb"\x1b\[\d+;\d+R", b"", line)
        os.write(1, prompt_input(typed.rstrip(b"\r\n")))
        os.write(1, PROMPT_LEAVE)
        if MODE != "prompt-no-modes":
            os.write(1, PROMPT_MODES_BACK)
        held = b""
        while True:
            chunk = process.stdout.read(4096)
            if not chunk:
                break
            held += chunk
        os.write(1, held)
        return process.wait()
    finally:
        restore_attributes(0, attributes)


def play_prompt(program: list[str]) -> int:
    """Play a launcher's takeover over a real `refuse` probe.

    The probe's own prelude and readiness go straight to the terminal (the guest
    set its modes before the question existed); everything it writes while the
    question is up is held, then released after the leave, in order.
    """

    attributes = save_attributes(0)
    set_raw(0)
    process = subprocess.Popen(program, stdout=subprocess.PIPE)
    try:
        assert process.stdout is not None
        head = b""
        # The prelude and REFUSE-READY arrive first and go out untouched.
        while b"REFUSE-READY" not in head:
            chunk = process.stdout.read(1)
            if not chunk:
                die("the probe ended before its readiness")
            head += chunk
            os.write(1, head)
        os.write(1, PROMPT_ENTER)
        time.sleep(0.3)
        # Wait for the answer line, which the driver types at the terminal.
        line = read_answer_line()
        os.write(1, prompt_input(line.rstrip(b"\r\n")))
        os.write(1, PROMPT_LEAVE)
        if MODE != "prompt-no-modes":
            os.write(1, PROMPT_MODES_BACK)
        held = b""
        while True:
            chunk = process.stdout.read(4096)
            if not chunk:
                break
            held += chunk
        if MODE == "prompt-drop-line":
            # One held line never reaches the terminal: the ordering oracle must
            # notice the gap.
            held = re.sub(rb"LINE 17\r?\n", b"", held, count=1)
        os.write(1, held)
        if MODE == "prompt-redraw-after-leave":
            time.sleep(0.1)
            os.write(1, PROMPT_REDRAW_AFTER_LEAVE)
        return process.wait()
    finally:
        restore_attributes(0, attributes)


def main(argv: list[str]) -> int:
    probe_mode, program = split_argv(argv)
    if MODE == "prompt-cadence" and probe_mode == "refuse":
        return play_prompt_cadence(program)
    if MODE.startswith("prompt") and probe_mode == "refuse":
        return play_prompt(program)
    if MODE == "early-exit":
        # A launcher that dies before any readiness barrier.
        return 0
    if MODE == "raw-leftover":
        set_raw(0)
        return subprocess.run(program).returncode
    if MODE == "no-winch":
        # A launcher that never forwards a resize to the guest. It still takes the
        # terminal raw and restores it, because only the notification is broken.
        attributes = save_attributes(0)
        set_raw(0)
        try:
            return subprocess.run(program).returncode
        finally:
            restore_attributes(0, attributes)
    if probe_mode in ("resize", "wait"):
        # A PTY launch: raw host terminal, a guest process on that terminal, and the
        # launcher relays the resize it receives (the driver signals the launcher,
        # not the guest) and restores the terminal on the way out.
        attributes = save_attributes(0)
        set_raw(0)
        process = subprocess.Popen(program)

        def relay(_signum, _frame):
            process.send_signal(signal.SIGWINCH)

        signal.signal(signal.SIGWINCH, relay)
        try:
            return process.wait()
        finally:
            restore_attributes(0, attributes)
    if probe_mode == "input" and MODE != "mangle-input":
        # A terminal-input case keeps the host terminal: the guest needs it for
        # its own raw mode, exactly as a real PTY launch provides it. The launcher
        # restores what it changed on the way out.
        attributes = save_attributes(0)
        set_raw(0)
        try:
            return subprocess.run(program).returncode
        finally:
            restore_attributes(0, attributes)
    if probe_mode in ("stream-input", "input"):
        # A terminal-input case keeps the host terminal raw while it forwards; the
        # launcher restores exactly what it changed on the way out.
        attributes = save_attributes(0) if probe_mode == "input" else None
        if attributes is not None:
            set_raw(0)
        try:
            reader, writer = os.pipe()
            process = subprocess.Popen(program, stdin=reader)
            os.close(reader)
            sink = os.fdopen(writer, "wb", buffering=0)
            if probe_mode == "stream-input":
                forward(
                    sink,
                    truncate=15 if MODE == "stream-truncated" else None,
                    hold=MODE == "stream-no-eof",
                )
            else:
                # The input case consumes exactly three bytes, so the relay stops
                # when they have been forwarded instead of waiting for an EOF the
                # driver never sends (it keeps the terminal open).
                forward(sink, truncate=3, mangle=MODE == "mangle-input")
            sink.close()
            return process.wait()
        finally:
            if attributes is not None:
                restore_attributes(0, attributes)
    return subprocess.run(program).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
