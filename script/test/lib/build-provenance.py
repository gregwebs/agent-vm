#!/usr/bin/env python3
"""Assert a persisted-network candidate was built from the tracked source (#335).

Standalone host checker: standard library only, no import of the native driver
or its fixtures. `persisted-network-live.sh` runs it before any native activity,
so a stale or dirty candidate is rejected before a VM starts.

The binary's self-report is build metadata, not authenticity. It is accepted
only when it names one known full commit, self-reports clean, AND the caller's
independently measured tracked status is empty. A `dirty` or `unknown` label
fails closed, and a bare legacy version fails closed.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass

_FULL_ID = r"[0-9a-f]{40}|[0-9a-f]{64}"
_VERSION = re.compile(
    rf"agent-vm (?P<release>\S+) "
    rf"\((?P<revision>{_FULL_ID}|unknown)(?:, (?P<label>dirty|state unknown))?\)\n"
)


@dataclass(frozen=True)
class ReportedBuild:
    revision: str | None
    state: str  # "clean" | "dirty" | "unknown"


def parse_version(text: str) -> ReportedBuild:
    """Parse one newline-terminated version line; raise ValueError otherwise."""
    match = _VERSION.fullmatch(text)
    if match is None:
        raise ValueError("not one agent-vm version line")
    revision = match.group("revision")
    label = match.group("label")
    if revision == "unknown":
        state = "dirty" if label == "dirty" else "unknown"
        return ReportedBuild(revision=None, state=state)
    if label is None:
        state = "clean"
    elif label == "dirty":
        state = "dirty"
    else:
        state = "unknown"
    return ReportedBuild(revision=revision, state=state)


def assert_committed_build(
    build: ReportedBuild, *, expected_sha: str, tracked_status: str
) -> None:
    """Fail closed unless the candidate is a known, clean, exact match."""
    if build.revision is None:
        raise ValueError("the binary does not name a commit")
    if build.revision != expected_sha.strip().lower():
        raise ValueError("the binary commit does not match source HEAD")
    if build.state != "clean":
        raise ValueError(f"the binary reports state {build.state}")
    if tracked_status != "":
        raise ValueError("the tracked source tree is dirty")


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            "usage: build-provenance.py VERSION_FILE EXPECTED_FULL_SHA TRACKED_STATUS_FILE",
            file=sys.stderr,
        )
        return 2
    _, version_path, expected_sha, status_path = argv
    try:
        with open(version_path, "rb") as handle:
            version_text = handle.read().decode("utf-8")
        with open(status_path, "rb") as handle:
            tracked_status = handle.read().decode("utf-8")
    except (OSError, UnicodeError) as error:
        print(f"provenance: cannot read evidence ({error.__class__.__name__})", file=sys.stderr)
        return 1
    try:
        build = parse_version(version_text)
        assert_committed_build(
            build, expected_sha=expected_sha, tracked_status=tracked_status
        )
    except ValueError as error:
        print(f"provenance: {error}", file=sys.stderr)
        return 1
    print("provenance: clean binary matches source HEAD")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
