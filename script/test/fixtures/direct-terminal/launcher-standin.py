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
import select
import signal
import subprocess
import sys
import termios
import time

MODE = os.environ.get("STANDIN_MODE", "ok")


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


def main(argv: list[str]) -> int:
    probe_mode, program = split_argv(argv)
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
