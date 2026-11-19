#!/usr/bin/env python3
"""Write and verify the Phase 0 runtime provenance manifest (plan P0-A/P0-F).

The manifest is the attestation the native harness and the wrapper both check:

* the canonical `MSB_PATH` and `MSB_LIBKRUNFW_PATH` were explicitly selected,
* both files' SHA-256 match what the isolated build produced,
* the pinned agent and vendor commits are recorded,
* the clean-from-source firmware rebuild is labelled UNPROVEN (operator-accepted level).

Usage:
  cpu-commitment-manifest.py write <evidence-dir> <msb> <firmware> <agent-sha> <vendor-sha>
  cpu-commitment-manifest.py verify <evidence-dir> <msb> <firmware>

Exit codes: 0 ok, 2 misuse, 3 missing/mismatched provenance (INCONCLUSIVE).
"""

import hashlib
import json
import pathlib
import sys

MANIFEST = "runtime-manifest.json"
REQUIRED = (
    "msb_path",
    "msb_sha256",
    "firmware_path",
    "firmware_sha256",
    "agent_sha",
    "vendor_sha",
    "clean_firmware_rebuild",
)


def sha256(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def write(evidence, msb, firmware, agent_sha, vendor_sha):
    evidence = pathlib.Path(evidence)
    manifest = {
        "msb_path": str(pathlib.Path(msb).resolve(strict=True)),
        "msb_sha256": sha256(msb),
        "firmware_path": str(pathlib.Path(firmware).resolve(strict=True)),
        "firmware_sha256": sha256(firmware),
        "agent_sha": agent_sha,
        "vendor_sha": vendor_sha,
        "clean_firmware_rebuild": "UNPROVEN",
    }
    (evidence / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def verify(evidence, msb, firmware):
    path = pathlib.Path(evidence) / MANIFEST
    try:
        manifest = json.loads(path.read_text())
    except OSError as error:
        return report(f"the manifest {path} is unreadable: {error}")
    except json.JSONDecodeError as error:
        return report(f"the manifest {path} is malformed: {error}")
    missing = [key for key in REQUIRED if not manifest.get(key)]
    if missing:
        return report(f"the manifest is missing {', '.join(missing)}")
    if manifest["clean_firmware_rebuild"] != "UNPROVEN":
        return report("the manifest must state clean-from-source firmware rebuild UNPROVEN")
    for label, path_value, declared_path, declared_hash in (
        ("MSB_PATH", msb, manifest["msb_path"], manifest["msb_sha256"]),
        (
            "MSB_LIBKRUNFW_PATH",
            firmware,
            manifest["firmware_path"],
            manifest["firmware_sha256"],
        ),
    ):
        try:
            actual_path = pathlib.Path(path_value).resolve(strict=True)
            declared = pathlib.Path(declared_path).resolve(strict=True)
        except OSError as error:
            return report(f"{label} path cannot be resolved: {error}")
        if actual_path != declared:
            return report(f"{label} {actual_path} != manifest {declared}")
        actual = sha256(actual_path)
        if actual != declared_hash.lower():
            return report(f"{label} sha256 {actual} != manifest {declared_hash}")
    print("manifest: ok")
    return 0


def report(reason):
    print(f"manifest: INCONCLUSIVE: {reason}", file=sys.stderr)
    return 3


def main(argv):
    if len(argv) == 5 and argv[1] == "verify":
        return verify(argv[2], argv[3], argv[4])
    if len(argv) == 7 and argv[1] == "write":
        write(argv[2], argv[3], argv[4], argv[5], argv[6])
        return 0
    print(__doc__.strip().splitlines()[-1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
