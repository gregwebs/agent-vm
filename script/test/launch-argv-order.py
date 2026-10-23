#!/usr/bin/env python3
"""Boot-free contract for the `agent-vm [launch options] <tool>` argv order (issue #358).

Two independent checks, both runnable without a VM:

1. A tracked-file sweep: no tracked shell caller invokes a tool verb followed by a
   launch option, and no user-facing doc shows `agent-vm … <tool> --<launch option>`.
   This is the class of miss (profiling/measure_variants.sh) that the manual
   migration sweep found only by reading, so it is pinned here instead.

2. A behavioural check of `profiling/measure_variants.sh`'s `create()` helper: run
   the real function body against an argv-recording stub and assert `--memory <mem>`
   precedes the `shell` verb. The earlier old order silently measured the wrong
   memory, so the order is asserted, not just that the helper runs.

Known blind spots (documented, not silently ignored): a verb held in a shell/py
variable (`"$TOOL" --mount`) cannot be seen by a literal-token sweep; the shell
sweep is line-oriented, so a launch option on a `\\`-continued line is missed; the
doc sweep deliberately excludes `docs/adr/` (historical records) and lines that
show the wrong form as a counter-example.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

LAUNCH_OPTIONS = [
    "--memory",
    "--cpus",
    "--no-git",
    "--repo",
    "--allow-missing-credentials",
    "--mount",
    "--publish",
    "--auto-publish",
    "--allow-egress",
    "--allow-internet-egress",
    "--allow-lan",
    "--allow-host",
    "--image",
    "--root",
]
TOOL_VERBS = ["shell", "dsh", "pi", "codex", "opencode", "claude", "copilot"]

# A whole token, not a substring: `pi` must not match inside `platform.claude.com`.
TOOL_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(" + "|".join(TOOL_VERBS) + r")(?![A-Za-z0-9_.-])"
)
LAUNCH_RE = re.compile(
    r"(?<![A-Za-z0-9-])(" + "|".join(re.escape(o) for o in LAUNCH_OPTIONS) + r")(?![A-Za-z0-9-])"
)
# One rendered command, not two spanning a backtick: an interpolation token may
# not itself contain a backtick, so the migration note's two examples stay separate.
DOC_RE = re.compile(
    r"agent-vm\s+(?:[^\s`]+\s+)*(" + "|".join(TOOL_VERBS) + r")\s+("
    + "|".join(re.escape(o) for o in LAUNCH_OPTIONS)
    + r")(?![A-Za-z0-9-])"
)


def tracked_files(*suffixes: str) -> list[str]:
    listed = subprocess.check_output(["git", "-C", str(REPO_ROOT), "ls-files"], text=True)
    return [f for f in listed.splitlines() if f.endswith(suffixes)]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def sweep_tracked_callers() -> None:
    """Check 1: no tracked shell caller or user-facing doc uses the old order."""
    hits: list[str] = []
    for path in tracked_files(".sh"):
        for lineno, line in enumerate(
            (REPO_ROOT / path).read_text(errors="replace").splitlines(), 1
        ):
            for tool in TOOL_RE.finditer(line):
                for launch in LAUNCH_RE.finditer(line):
                    if launch.start() > tool.end():
                        hits.append(f"{path}:{lineno}: `{tool.group(1)} … {launch.group(1)}`")
    for path in tracked_files(".md"):
        if path.startswith("docs/adr/"):
            continue  # Historical records: ADRs describe the grammar they replaced.
        for lineno, line in enumerate(
            (REPO_ROOT / path).read_text(errors="replace").splitlines(), 1
        ):
            for match in DOC_RE.finditer(line):
                # USAGE.md's migration note deliberately prints the wrong form after
                # "not"; that counter-example is the one allowed occurrence.
                if "not" in line[max(0, match.start() - 6) : match.start()].lower():
                    continue
                hits.append(f"{path}:{lineno}: `{match.group(0)}`")
    if hits:
        fail(
            "old launch-option order found (launch options go BEFORE the verb):\n  "
            + "\n  ".join(hits)
        )


def create_body() -> str:
    """The literal `create()` function body from the profiling script."""
    source = (REPO_ROOT / "profiling/measure_variants.sh").read_text()
    match = re.search(r"^create\(\) \{.*?\}\s*$", source, re.S | re.M)
    if match is None:
        # A silent rename would drop this contract's coverage, so it is a failure.
        fail("could not find create() in profiling/measure_variants.sh")
    return match.group(0)


def check_measure_variants_create_argv() -> None:
    """Check 2: `create <mem>` puts `--memory <mem>` before the `shell` verb."""
    body = create_body()
    for mem in ("1", "4"):
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "stub-agent-vm"
            argv_out = Path(tmp) / "argv"
            stub.write_text(
                "#!/bin/sh\n"
                'printf "%s\\n" "$@" > "$ARGV_OUT"\n'
                'echo "[profile] create:  0.123s"\n'
            )
            stub.chmod(0o755)
            script = f"{body}\nAGENTVM={stub!s} ARGV_OUT={argv_out!s} create {mem} >/dev/null\n"
            subprocess.run(["bash", "-c", script], check=True)
            got = argv_out.read_text().splitlines()
            want = ["--memory", mem, "shell", "true"]
            if got != want:
                fail(
                    f"`create {mem}` launched with argv {got}, expected {want}"
                    " (--memory must precede the shell verb)"
                )


def main() -> None:
    sweep_tracked_callers()
    check_measure_variants_create_argv()
    print("launch-argv-order: OK (no old-order caller; create() puts --memory before shell)")


if __name__ == "__main__":
    main()
