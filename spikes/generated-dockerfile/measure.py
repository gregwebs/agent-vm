#!/usr/bin/env python3
"""SPIKE (throwaway) -- measure the rebuild cascade of the generated shapes.

Builds each shape twice: once with a fresh baseline version (populates cache)
and once with one middle tool's version bumped. The second build's buildkit
progress is parsed to show which tool steps re-ran.

Variants:
  linear            -- one stage, tools appended (today's chain, one file)
  multistage        -- independent tool stages + linear merge
  multistage+link   -- independent tool stages + `COPY --link` merge
  prefix+link       -- disjoint /opt/tool-<name> roots + `COPY --link` merge
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = "codex,opencode,claude,copilot"
BASE = "debian:13-slim"
BUMP = "opencode"
STEP = re.compile(r"^#(\d+)\s+(?:\[([^\]]+)\]\s+)?(.*)$")


def gen(outdir: Path, extra: list[str]) -> None:
    subprocess.run(
        [sys.executable, str(HERE / "generate.py"), "--fixture", "--tools", TOOLS,
         "--out", str(outdir), *extra],
        check=True,
    )


def build(dockerfile: Path, context: Path, tool: str, version: str) -> str:
    cmd = [
        "docker", "buildx", "build",
        "--progress=plain",
        "-f", str(dockerfile),
        "--build-arg", f"BASE_IMAGE={BASE}",
        "--build-arg", f"AGENT_VERSION_{tool.upper()}={version}",
        str(context),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        raise SystemExit(f"build failed: {dockerfile}")
    return proc.stderr


def rows(progress: str) -> list[dict]:
    labels: dict[str, str] = {}
    cmds: dict[str, str] = {}
    status: dict[str, str] = {}
    for line in progress.splitlines():
        m = STEP.match(line)
        if not m:
            continue
        jid, label, rest = m.group(1), m.group(2), m.group(3)
        if label:
            labels[jid] = label
            cmds[jid] = rest
        head = rest.split(maxsplit=1)[0] if rest else ""
        if head == "CACHED":
            status[jid] = "CACHED"
        elif head == "DONE":
            status.setdefault(jid, "RAN")
    return [
        {"label": label, "cmd": cmds.get(jid, ""), "status": status.get(jid, "?")}
        for jid, label in labels.items()
    ]


def tool_of(cmd: str) -> str | None:
    m = re.search(r"FIXTURE_TOOL=(\w+)", cmd)
    return m.group(1) if m else None


def measure(variant: str, dockerfile: Path, context: Path, nonce: str) -> dict:
    # Per-variant version tokens: the tool stage commands are identical across
    # variants, so a shared token would let one variant's bumped stage serve
    # another's from buildkit's shared cache.
    build(dockerfile, context, BUMP, f"{variant}-baseline-{nonce}")
    parsed = rows(build(dockerfile, context, BUMP, f"{variant}-bumped-{nonce}"))
    ran_tools = sorted({t for r in parsed if r["status"] == "RAN" and (t := tool_of(r["cmd"]))})
    ran_stages = sorted(
        {r["label"].split()[0] for r in parsed
         if r["status"] == "RAN" and r["label"].startswith(("tool_", "merged"))
         and not r["cmd"].startswith("FROM")}
    )
    ran_steps = [
        r for r in parsed
        if r["status"] == "RAN" and r["label"] != "internal" and not r["cmd"].startswith("FROM")
    ]
    print(f"\n=== {variant}: rebuilt after bumping {BUMP} ===")
    print(f"  build steps re-run : {len(ran_steps)}")
    if ran_stages:
        print(f"  stages re-run      : {', '.join(ran_stages)}")
    for r in ran_steps:
        t = tool_of(r["cmd"])
        print(f"    - [{r['label']}] {t or r['cmd'][:66]}")
    return {"tools": ran_tools, "steps": len(ran_steps), "stages": ran_stages}


def main() -> None:
    nonce = str(time.time_ns())
    print(f"base={BASE}  bump={BUMP}  (baseline -> bumped, nonce={nonce})")
    gen(HERE / "out-fixture", [])
    gen(HERE / "out-fixture-link", ["--link"])
    gen(HERE / "out-fixture-prefix", ["--prefix", "--link"])

    variants = [
        ("linear", HERE / "out-fixture" / "linear.Dockerfile", HERE / "out-fixture"),
        ("multistage", HERE / "out-fixture" / "multistage.Dockerfile", HERE / "out-fixture"),
        ("multistage+link", HERE / "out-fixture-link" / "multistage.Dockerfile", HERE / "out-fixture-link"),
        ("prefix+link", HERE / "out-fixture-prefix" / "multistage.Dockerfile", HERE / "out-fixture-prefix"),
    ]
    results = {name: measure(name, df, ctx, nonce) for name, df, ctx in variants}

    print("\n=== verdict ===")
    for name, r in results.items():
        tools = ", ".join(r["tools"]) or "(none)"
        print(f"  {name:<16} re-ran {len(r['tools'])} tool(s) / {r['steps']} step(s): {tools}")


if __name__ == "__main__":
    main()
