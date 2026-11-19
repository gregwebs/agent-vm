#!/usr/bin/env python3
"""Select the one test executable Cargo built for the `agent-vm` binary target.

The Phase 0 protocol must never pick a stale or unrelated executable. Cargo's JSON output is
the only source: it names the artifact, its profile and its target, and the selected path must
resolve strictly inside the isolated `CARGO_TARGET_DIR`.

Usage: cpu-commitment-select.py <cargo.jsonl> <isolated-target-dir>

Exit codes: 0 selected, 1 selector failure, 2 invocation misuse.
"""

import json
import pathlib
import sys

TARGET_NAME = "agent-vm"


def fail(reason):
    print(f"select: {reason}", file=sys.stderr)
    return 1


def select(rows_path, target_dir):
    rows_path = pathlib.Path(rows_path)
    try:
        rows = [
            json.loads(line)
            for line in rows_path.read_text().splitlines()
            if line.strip()
        ]
    except (OSError, json.JSONDecodeError) as error:
        return fail(f"cannot read Cargo JSON {rows_path}: {error}")
    finished = [row for row in rows if row.get("reason") == "build-finished"]
    if not finished:
        return fail(f"{rows_path} has no build-finished record")
    if not all(row.get("success") is True for row in finished):
        return fail(f"{rows_path} reports a failed build")
    artifacts = [
        row
        for row in rows
        if row.get("reason") == "compiler-artifact"
        and row.get("target", {}).get("name") == TARGET_NAME
        and "bin" in row.get("target", {}).get("kind", [])
        and row.get("profile", {}).get("test") is True
        and row.get("executable")
    ]
    if len(artifacts) != 1:
        return fail(f"expected exactly one {TARGET_NAME} test artifact, got {len(artifacts)}")
    executable = pathlib.Path(artifacts[0]["executable"])
    try:
        resolved = executable.resolve(strict=True)
    except OSError as error:
        return fail(f"the artifact {executable} does not resolve: {error}")
    try:
        root = pathlib.Path(target_dir).resolve(strict=True)
    except OSError as error:
        return fail(f"the isolated target directory {target_dir} does not resolve: {error}")
    try:
        resolved.relative_to(root)
    except ValueError:
        return fail(f"the artifact {resolved} is outside the isolated target dir {root}")
    if not resolved.is_file():
        return fail(f"the artifact {resolved} is not a regular file")
    print(resolved)
    return 0


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    return select(argv[1], argv[2])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
