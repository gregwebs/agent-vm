#!/usr/bin/env python3
"""PROTOTYPE, throwaway: "Try host OS notifications for sandbox blocks".

Replays fake sandbox block events through a per-session coalescer into host OS
notifications. Wording and grouping live here so both platforms share them.

  python3 proto.py single|flood|kinds|mixed|two-sessions|repl [--backend mac|linux|console]
      [--interval SECONDS] [--updates passive|active] [--linger SECONDS]
      [--terminal terminal|ghostty|wezterm|alacritty|linux]

Events are fake stand-ins: no structured block feed exists yet. State is written
to /tmp/PROTOTYPE-agent-vm-blocks (wipe me) only so blocks.py can show it.
"""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import threading
import time

PROTO = "/tmp/PROTOTYPE-agent-vm-blocks"
HERE = os.path.dirname(os.path.abspath(__file__))
APP_BIN = os.path.join(HERE, "build/AgentVMBlocks.app/Contents/MacOS/AgentVMBlocks")


def label(dest, port):
    return f"{dest}:{port}" if port and port != 443 else dest


def wording(s):
    """(title, subtitle, body) for one session's notification."""
    blocks = s["blocks"]  # (kind, dest) -> count, insertion ordered
    sub = f'{s["project"]} · session {s["label"]}'
    keys = list(blocks)
    if len(keys) == 1:
        kind, dest = keys[0]
        n = blocks[keys[0]]
        times = f" ({n}×)" if n > 1 else ""
        if kind == "network":
            return (f"Blocked: {dest}{times}", sub,
                    "Network access denied. Click to review; you can allow it for this session or project.")
        if kind == "locked":
            return (f"Blocked by policy: {dest}{times}", sub,
                    "Administrator or platform policy. It can't be allowed from agent-vm.")
        return (f"Refused: {dest}{times}", sub,
                "Credential or GitHub repository restriction, not a network block. Click to see why.")
    top = sorted(blocks.items(), key=lambda kv: -kv[1])[:3]
    parts = [d + (f" ({n}×)" if n > 1 else "") for (_, d), n in top]
    more = len(keys) - len(top)
    approvable = sum(1 for k, _ in keys if k == "network")
    tail = f"{approvable} can be allowed. Click to review." if approvable else "None can be allowed here. Click to review."
    return (f"{len(keys)} blocked in {s['project']}", sub,
            " · ".join(parts) + (f" · +{more} more" if more > 0 else "") + "\n" + tail)


class MacBackend:
    def __init__(self):
        if not os.path.exists(APP_BIN):
            sys.exit(f"missing {APP_BIN}; run mac/build.sh first")
        self.p = subprocess.Popen([APP_BIN, "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            print(f"  [app] {line.rstrip()}")

    def post(self, n):
        self.p.stdin.write(json.dumps({"op": "post", **n}) + "\n")
        self.p.stdin.flush()

    def close(self):
        try:
            self.p.stdin.write('{"op":"quit"}\n')
            self.p.stdin.flush()
        except BrokenPipeError:
            pass


class LinuxBackend:
    """Untested: notify-send with --replace-id, and a --wait child per notification for the click."""

    def __init__(self):
        if not shutil.which("notify-send"):
            sys.exit("notify-send not found")
        self.ids, self.waiters = {}, {}

    def post(self, n):
        sid = n["session"]
        if sid in self.waiters:
            self.waiters.pop(sid).terminate()
        cmd = ["notify-send", "--app-name=agent-vm", "--print-id", "--wait",
               "--urgency=" + ("low" if n["passive"] else "normal"),
               "--action=default=Show blocks", n["title"], n["subtitle"] + "\n" + n["body"]]
        if sid in self.ids:
            cmd.insert(1, f"--replace-id={self.ids[sid]}")
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        self.waiters[sid] = p

        def wait():
            first = p.stdout.readline().strip()
            if first.isdigit():
                self.ids[sid] = first
            for line in p.stdout:
                print(f"  [notify-send] {sid}: {line.strip()}")
                if line.strip() == "default":
                    subprocess.Popen(["/bin/sh", os.path.join(HERE, "open-terminal.sh"), sid])
        threading.Thread(target=wait, daemon=True).start()

    def close(self):
        pass


class ConsoleBackend:
    def post(self, n):
        pass

    def close(self):
        pass


class Coalescer:
    """One notification per session. The first block, and each new destination, gets an
    active banner (at most once per interval); repeats only update the count passively."""

    def __init__(self, backend, interval, updates):
        self.backend, self.interval, self.updates = backend, interval, updates
        self.sessions, self.lock = {}, threading.Lock()
        threading.Thread(target=self._tick, daemon=True).start()

    def event(self, ev):
        with open(f'{PROTO}/{ev["session"]}.jsonl', "a") as f:
            f.write(json.dumps({**ev, "time": time.strftime("%H:%M:%S")}) + "\n")
        with self.lock:
            s = self.sessions.setdefault(ev["session"], {
                "project": ev["project"], "session": ev["session"], "label": ev["session"].rsplit("-", 1)[-1],
                "blocks": {}, "dirty": False, "new_dest": False, "last": 0.0, "posts": 0})
            key = (ev["kind"], label(ev["dest"], ev.get("port")))
            s["new_dest"] |= key not in s["blocks"]
            s["blocks"][key] = s["blocks"].get(key, 0) + 1
            s["dirty"] = True
            if s["posts"] == 0:
                self._flush(s)

    def _tick(self):
        while True:
            time.sleep(0.25)
            with self.lock:
                for s in self.sessions.values():
                    if s["dirty"] and time.monotonic() - s["last"] >= self.interval:
                        self._flush(s)

    def _flush(self, s):
        title, sub, body = wording(s)
        passive = s["posts"] > 0 and not s["new_dest"] and self.updates == "passive"
        n = {"id": f'agent-vm.{s["session"]}', "thread": f'agent-vm.{s["project"]}', "session": s["session"],
             "title": title, "subtitle": sub, "body": body, "passive": passive, "sound": False}
        s.update(dirty=False, new_dest=False, last=time.monotonic(), posts=s["posts"] + 1)
        total = sum(s["blocks"].values())
        print(f'{time.strftime("%H:%M:%S")} post #{s["posts"]} {"passive" if passive else "ACTIVE "} '
              f'{n["id"]} ({total} events)\n    {title}\n    {sub}\n    ' + body.replace("\n", "\n    "))
        self.backend.post(n)


def ev(project, pid, kind, dest, port=443, transport="tcp", source="sni"):
    return {"project": project, "session": f"agent-vm-{abs(hash(project)) % 16**6:06x}-{pid}",
            "kind": kind, "dest": dest, "port": port, "transport": transport, "source": source}


def scenario(name, c):
    def at(delay, e):
        time.sleep(delay)
        c.event(e)

    if name == "single":
        at(0, ev("myapp", 4242, "network", "registry.npmjs.org", source="dns"))
    elif name == "flood":
        # npm retries hard; two more destinations appear part-way through
        start = time.monotonic()
        i = 0
        while time.monotonic() - start < 20:
            at(0.2, ev("myapp", 4242, "network", "registry.npmjs.org", source="dns"))
            i += 1
            if i == 25:
                c.event(ev("myapp", 4242, "network", "pypi.org", source="dns"))
            if i == 50:
                c.event(ev("myapp", 4242, "network", "203.0.113.5", port=8443, source="ip"))
    elif name == "kinds":
        at(0, ev("myapp", 4242, "network", "registry.npmjs.org", source="dns"))
        at(4, ev("infra", 5151, "locked", "169.254.169.254", port=80, source="ip"))
        at(4, ev("website", 6262, "credential", "push to acme/private-repo", port=None, source="github"))
    elif name == "mixed":
        at(0, ev("myapp", 4242, "network", "registry.npmjs.org", source="dns"))
        at(2, ev("myapp", 4242, "locked", "169.254.169.254", port=80, source="ip"))
        at(2, ev("myapp", 4242, "credential", "push to acme/private-repo", port=None, source="github"))
        at(2, ev("myapp", 4242, "network", "pypi.org", source="dns"))
    elif name == "two-sessions":
        at(0, ev("myapp", 4242, "network", "registry.npmjs.org", source="dns"))
        at(1, ev("myapp", 4343, "network", "github.com", source="dns"))
        at(1, ev("website", 6262, "network", "fonts.googleapis.com", source="dns"))
        for _ in range(10):
            at(0.3, ev("myapp", 4242, "network", "registry.npmjs.org", source="dns"))
    elif name == "repl":
        print("commands: n HOST | l HOST | c TEXT | s PID | p PROJECT | q")
        project, pid = "myapp", 4242
        for line in sys.stdin:
            cmd, _, arg = line.strip().partition(" ")
            kinds = {"n": "network", "l": "locked", "c": "credential"}
            if cmd in kinds and arg:
                c.event(ev(project, pid, kinds[cmd], arg, port=None if cmd == "c" else 443))
            elif cmd == "s" and arg.isdigit():
                pid = int(arg)
            elif cmd == "p" and arg:
                project = arg
            elif cmd == "q":
                break


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=["single", "flood", "kinds", "mixed", "two-sessions", "repl"])
    ap.add_argument("--backend", default="mac" if platform.system() == "Darwin" else "linux",
                    choices=["mac", "linux", "console"])
    ap.add_argument("--interval", type=float, default=3.0)
    ap.add_argument("--updates", default="passive", choices=["passive", "active"])
    ap.add_argument("--linger", type=float, default=90.0, help="seconds to stay up for clicks")
    ap.add_argument("--terminal", default="terminal", choices=["terminal", "ghostty", "wezterm", "alacritty", "linux"],
                    help="what a click opens")
    a = ap.parse_args()
    shutil.rmtree(PROTO, ignore_errors=True)
    os.makedirs(PROTO, mode=0o700)
    with open(f"{PROTO}/terminal", "w") as f:
        f.write(a.terminal)
    backend = {"mac": MacBackend, "linux": LinuxBackend, "console": ConsoleBackend}[a.backend]()
    c = Coalescer(backend, a.interval, a.updates)
    try:
        time.sleep(0.5)
        scenario(a.scenario, c)
        if a.scenario != "repl":
            time.sleep(a.interval + 0.5)
            print(f"\nclick a notification within {a.linger:.0f}s (Ctrl-C to stop)")
            time.sleep(a.linger)
    except KeyboardInterrupt:
        pass
    backend.close()


if __name__ == "__main__":
    main()
