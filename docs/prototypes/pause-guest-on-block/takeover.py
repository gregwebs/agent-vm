#!/usr/bin/env python3
"""PROTOTYPE (throwaway): take over the terminal to ask about a (fake) block.

Runs COMMAND in a pty and relays it, as the agent-vm launcher relays the guest.
On a fake block it:
  1. holds guest output at a safe byte boundary (never mid escape sequence or
     mid UTF-8 character) and stops forwarding keystrokes; with --pause-vm it
     also freezes the session's msb (SIGSTOP);
  2. draws a prompt on the alternate screen, discarding typed-ahead keys;
  3. restores the terminal modes the guest had set, releases held output and,
     if the guest was on the alternate screen, nudges the pty size so it redraws.
Nothing is granted: answers go to /tmp/PROTOTYPE-494-takeover-<uid>.log.

usage: python3 -I takeover.py [--every N] [--pause-vm] -- COMMAND [ARGS...]
Fake block on demand: kill -USR1 $(cat /tmp/PROTOTYPE-494-takeover-$(id -u).pid)
"""
import fcntl, json, os, pty, select, signal, struct, subprocess, sys, termios, time, tty

LOG, PIDFILE = (f"/tmp/PROTOTYPE-494-takeover-{os.getuid()}.{x}" for x in ("log", "pid"))
FAKE = ["registry.npmjs.org:443", "pypi.org:443", "telemetry.example.com:443"]
QUIET_S = 0.7            # keys count only after this long with no typing
NOTIFY_S, TIMEOUT_S = 5, 60   # unanswered: notify, then deny
# guest-set DEC private modes we change while prompting and must put back
RESTORE = ["1000", "1002", "1003", "1006", "1015", "2004", "1004"]


class VT:
    """Just enough of a VT parser to know when a cut is safe and which modes are on."""
    def __init__(self):
        self.st, self.csi, self.utf, self.modes = "G", b"", 0, {}

    def safe(self):
        return self.st == "G" and self.utf == 0

    def alt(self):
        return any(self.modes.get(m) for m in ("1049", "1047", "47"))

    def feed(self, data):
        for b in data:
            st = self.st
            if st == "G":
                if b == 0x1B: self.st = "E"
                elif b >= 0xF0: self.utf = 3
                elif b >= 0xE0: self.utf = 2
                elif b >= 0xC0: self.utf = 1
                elif 0x80 <= b < 0xC0 and self.utf: self.utf -= 1
                else: self.utf = 0
            elif st == "E":
                self.st = {0x5B: "C", 0x5D: "O", 0x50: "S", 0x58: "S", 0x5E: "S", 0x5F: "S"}.get(
                    b, "I" if 0x20 <= b <= 0x2F else "G")
                self.csi = b""
            elif st == "I":
                if not 0x20 <= b <= 0x2F: self.st = "G"
            elif st == "C":
                if 0x40 <= b <= 0x7E:
                    if self.csi.startswith(b"?") and b in (0x68, 0x6C):
                        for n in self.csi[1:].split(b";"):
                            self.modes[n.decode(errors="replace")] = b == 0x68
                    self.st = "G"
                elif b in (0x18, 0x1A): self.st = "G"
                else: self.csi += bytes([b])
            elif st in ("O", "S"):
                if b == 0x07 and st == "O": self.st = "G"
                elif b == 0x1B: self.st = st + "E"
            else:  # OE / SE: ESC inside a string ends it (ST is ESC \)
                self.st = "G"


def winsize(fd):
    return struct.unpack("HHHH", fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0" * 8))


def set_winsize(fd, rows, cols):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def session_msbs(root):
    """msb processes of agent-vm launchers at or under pid `root`."""
    rows = [l.split(None, 2) for l in subprocess.run(
        ["ps", "-A", "-o", "pid=,ppid=,command="], capture_output=True, text=True).stdout.splitlines()]
    kids, tree = {}, {root}
    for r in rows:
        if len(r) == 3: kids.setdefault(int(r[1]), []).append(int(r[0]))
    todo = [root]
    while todo:
        for k in kids.get(todo.pop(), []): tree.add(k); todo.append(k)
    out = []
    for r in rows:
        if len(r) == 3 and "msb machine --name agent-vm-" in r[2]:
            launcher = r[2].split("--name ", 1)[1].split()[0].rsplit("-", 1)[-1]
            if launcher.isdigit() and int(launcher) in tree: out.append(int(r[0]))
    return out


def main():
    a = sys.argv[1:]
    every = pause_vm = None
    while a and a[0] != "--":
        if a[0] == "--every": every = float(a[1]); a = a[2:]
        elif a[0] == "--pause-vm": pause_vm = True; a = a[1:]
        else: sys.exit(__doc__)
    cmd = a[1:]
    if not cmd: sys.exit(__doc__)

    rows, cols, _, _ = winsize(0)
    pid, master = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
    set_winsize(master, rows, cols)
    with open(PIDFILE, "w") as f: f.write(str(os.getpid()))
    saved = termios.tcgetattr(0)
    tty.setraw(0)

    vt, held, pending, asked = VT(), b"", [], set()
    nxt = [time.monotonic() + every if every else None, 0]

    def fake_block(*_):
        dest = FAKE[nxt[1] % len(FAKE)]; nxt[1] += 1
        if dest not in asked: pending.append(dest)
    signal.signal(signal.SIGUSR1, fake_block)
    signal.signal(signal.SIGWINCH, lambda *_: set_winsize(master, *winsize(0)[:2]))

    def out(s):
        os.write(1, s.encode() if isinstance(s, str) else s)

    def prompt(dest):
        frozen = session_msbs(pid) if pause_vm else []
        for m in frozen: os.kill(m, signal.SIGSTOP)
        t0, was_alt = time.monotonic(), vt.alt()
        out(("" if was_alt else "\x1b[?1049h")
            + "".join(f"\x1b[?{m}l" for m in RESTORE) + "\x1b[0m\x1b[?25h\x1b[H\x1b[2J")
        more = f"  (+{len(pending)} more waiting)" if pending else ""
        out("\r\n  \x1b[1;7m agent-vm \x1b[0m  the sandbox blocked a network request\r\n\r\n"
            f"    destination  \x1b[1m{dest}\x1b[0m  (name supplied by the guest, not verified){more}\r\n"
            f"    session      {pid}{'   VM paused' if frozen else '   guest output held'}\r\n\r\n"
            "    [s] allow for this session   [p] allow for this project\r\n"
            "    [d] deny (Enter, Esc)        [n] deny, don't ask again this session\r\n\r\n"
            "    The request has already failed; retry it after allowing.\r\n\r\n")
        termios.tcflush(0, termios.TCIFLUSH)
        answer, last_key, ready, notified = None, t0, None, False
        while answer is None:
            now = time.monotonic()
            if (now - last_key >= QUIET_S) != ready:
                ready = now - last_key >= QUIET_S
                out("\r\x1b[2K    " + ("\x1b[32mready for your answer\x1b[0m" if ready
                                         else "\x1b[33mstop typing to answer...\x1b[0m"))
            if not notified and now - t0 >= NOTIFY_S:
                notified = True  # PROTOTYPE: the real launcher posts the host notification here
                out("\x1b[s\x1b[1;60H(notification sent)\x1b[u")
            if now - t0 >= TIMEOUT_S:
                answer = "deny-timeout"; break
            r, _, _ = select.select([0], [], [], 0.1)
            if not r: continue
            chunk = os.read(0, 1024)
            if not ready or len(chunk) != 1:
                last_key = time.monotonic(); continue  # still typing, or pasted: never an answer
            answer = {b"s": "session", b"p": "project", b"d": "deny", b"\r": "deny",
                      b"\x1b": "deny", b"n": "deny-and-stop-asking"}.get(chunk)
        if answer == "deny-and-stop-asking": asked.add(dest)
        out(f"\r\n    recorded: {answer}  (PROTOTYPE: nothing granted)\r\n"); time.sleep(0.6)
        out("\x1b[0m\x1b[H\x1b[2J" + ("" if was_alt else "\x1b[?1049l")
            + "".join(f"\x1b[?{m}h" for m in RESTORE if vt.modes.get(m))
            + ("\x1b[?25l" if vt.modes.get("25") is False else ""))
        for m in frozen: os.kill(m, signal.SIGCONT)
        with open(LOG, "a") as f:
            f.write(json.dumps({"dest": dest, "answer": answer, "notified": notified, "seconds": round(time.monotonic() - t0, 1),
                                "guest_alt_screen": was_alt, "vm_paused": bool(frozen)}) + "\n")
        if was_alt:  # we drew over the guest's screen: make it repaint
            r_, c_ = winsize(0)[:2]
            set_winsize(master, max(r_ - 1, 1), c_); time.sleep(0.05); set_winsize(master, r_, c_)

    try:
        unsafe_since = None
        while True:
            if nxt[0] and time.monotonic() >= nxt[0]:
                fake_block(); nxt[0] = time.monotonic() + every
            if pending:
                if vt.safe() or (unsafe_since and time.monotonic() - unsafe_since > 0.5):
                    if not vt.safe(): out(b"\x18"); vt.st = "G"   # CAN aborts a stalled sequence
                    unsafe_since = None
                    prompt(pending.pop(0))
                    if every: nxt[0] = time.monotonic() + every
                    if held: vt.feed(held); out(held); held = b""
                    continue
                unsafe_since = unsafe_since or time.monotonic()
            try:
                r, _, _ = select.select([0, master], [], [], 0.1)
            except InterruptedError:
                continue
            if master in r:
                try: data = os.read(master, 4096)
                except OSError: break
                if not data: break
                if pending:  # forward only up to the first safe boundary, hold the rest
                    i = 0
                    while i < len(data) and not vt.safe(): vt.feed(data[i:i + 1]); i += 1
                    out(data[:i]); held += data[i:]
                else:
                    vt.feed(data); out(data)
            if 0 in r and not pending:
                os.write(master, os.read(0, 1024))
    finally:
        termios.tcsetattr(0, termios.TCSAFLUSH, saved)
        os.unlink(PIDFILE)
    _, status = os.waitpid(pid, 0)
    sys.exit(os.waitstatus_to_exitcode(status))


if __name__ == "__main__":
    main()
