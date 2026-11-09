#!/usr/bin/env python3
"""Validate the source identities that compose the agent-vm runtime."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tomllib

# What each Cargo root must resolve every cohort crate to: the release and the
# registry checksum of that release, recorded per lock. Most of the cohort ships
# as a unit at the runtime's release version; `arch_gen`, `cpuid` and `smbios`
# are published on their own cadence, so the outer workspace resolves 0.1.45
# while the vendored lock still pins 0.1.42 — two official crates.io releases of
# the fork. Only the outer workspace may be ahead, which a per-crate set of
# accepted versions could not express: it accepted either version in either lock.
#
# The checksums are recorded here, not merely compared between the locks. A
# checksum that only had to be non-empty would tie the artifact of a crate whose
# two locks disagree on version to no published release at all, since
# `compare_locks` can only compare a release both roots resolve.
#
# A bump must edit these rows deliberately: both rows for a crate that moves in
# both locks, one row for a crate that moves in one. That friction is the point —
# a lock cannot follow a vendored update on its own, and the review sees the old
# and new artifact of each root side by side. `compare_locks` then re-reads the
# two rows against each other, so a release recorded with two checksums is a
# failure rather than two independent truths.
ROOT_PINS: dict[str, tuple[str, str]] = {
    "msb_krun": ("0.1.42", "9cc8c72e61d6342ed8f381f049e5659c3c3c7a2d589eb2407f4abecc5aa633f2"),
    "msb_krun_arch": ("0.1.42", "ac38ac5290daf53011289f0b3420ce69e577db101b39fa4ac8c73869635dc9e1"),
    "msb_krun_arch_gen": ("0.1.45", "bc601bbe7784c2858abd909a4ef7afa79f9f4d5d941e2e21fedb5ca0d4ad46b2"),
    "msb_krun_cpuid": ("0.1.45", "2692ad93a9f3da926d50d5f21e83984fa4fe2345727394da41a4b484e8c7935e"),
    "msb_krun_devices": ("0.1.42", "a030aa4be892ea9b2215c2828d2ce02d77d4b02133f0af6dc842bae5a802ed87"),
    "msb_krun_hvf": ("0.1.42", "b7eafee262ce993bafc612abb3dd6582c102f0f462f15fb22159bf04184dc908"),
    "msb_krun_kernel": ("0.1.42", "51ad8e40e3fe51a18effce0245e099c318e8302e851e7917eef296d46bbe143d"),
    "msb_krun_polly": ("0.1.42", "fad6d7aae45e030546e31349f1c8fe2d257223b95360f84ca80b6bc0ef232f22"),
    "msb_krun_smbios": ("0.1.45", "9a86f61e2babd56b34a1a09fbcd5991b8299f93066b6af897f62b520085f3312"),
    "msb_krun_utils": ("0.1.42", "4b4ecd659171dc62624ff73007f5abdf4fffaf48131ef00fed1ea3d164fb2e6f"),
    "msb_krun_vmm": ("0.1.42", "284e283d6f1b5e5496afe615c6a4912e41b8b0210d40b1e7d4e0647a59ed6175"),
}
NESTED_PINS: dict[str, tuple[str, str]] = {
    "msb_krun": ("0.1.42", "9cc8c72e61d6342ed8f381f049e5659c3c3c7a2d589eb2407f4abecc5aa633f2"),
    "msb_krun_arch": ("0.1.42", "ac38ac5290daf53011289f0b3420ce69e577db101b39fa4ac8c73869635dc9e1"),
    "msb_krun_arch_gen": ("0.1.42", "372c943ecdd64cc741630ff76a4763aad41732f62dba368be0f530b83373ec85"),
    "msb_krun_cpuid": ("0.1.42", "ef38e1dc441567a43111aceade3837b7111d29c1f8c1ca6dd5f4ff82e92b6824"),
    "msb_krun_devices": ("0.1.42", "a030aa4be892ea9b2215c2828d2ce02d77d4b02133f0af6dc842bae5a802ed87"),
    "msb_krun_hvf": ("0.1.42", "b7eafee262ce993bafc612abb3dd6582c102f0f462f15fb22159bf04184dc908"),
    "msb_krun_kernel": ("0.1.42", "51ad8e40e3fe51a18effce0245e099c318e8302e851e7917eef296d46bbe143d"),
    "msb_krun_polly": ("0.1.42", "fad6d7aae45e030546e31349f1c8fe2d257223b95360f84ca80b6bc0ef232f22"),
    "msb_krun_smbios": ("0.1.42", "fdd434257469b722d2920d179a5a927b09e795c95035eca01674c5033bf83caa"),
    "msb_krun_utils": ("0.1.42", "4b4ecd659171dc62624ff73007f5abdf4fffaf48131ef00fed1ea3d164fb2e6f"),
    "msb_krun_vmm": ("0.1.42", "284e283d6f1b5e5496afe615c6a4912e41b8b0210d40b1e7d4e0647a59ed6175"),
}
COHORT = frozenset(ROOT_PINS)
FIRMWARE_VERSION = "5.6.1"
FIRMWARE_ABI = "5"
REGISTRY_PREFIX = "registry+https://github.com/rust-lang/crates.io-index"


def fail(message: str) -> None:
    raise ValueError(message)


def load_toml(path: pathlib.Path) -> dict:
    with path.open("rb") as stream:
        return tomllib.load(stream)


def cohort_packages(
    lock_path: pathlib.Path, pins: dict[str, tuple[str, str]]
) -> dict[str, tuple[str, str, str]]:
    """What `lock_path` resolves, held to the pins of its own Cargo root."""
    packages = load_toml(lock_path).get("package", [])
    selected: dict[str, tuple[str, str, str]] = {}
    unused = load_toml(lock_path).get("patch", {}).get("unused", [])
    for package in unused:
        if package.get("name") in COHORT:
            fail(f"{lock_path}: unused patch override for {package['name']}")
    for package in packages:
        name = package.get("name")
        if isinstance(name, str) and (name == "msb_krun" or name.startswith("msb_krun_")) and name not in COHORT:
            fail(f"{lock_path}: unexpected msb_krun cohort package {name}")
        if name not in COHORT:
            continue
        version = package.get("version", "")
        source = package.get("source", "")
        checksum = package.get("checksum", "")
        if name in selected:
            fail(f"{lock_path}: duplicate cohort package {name}")
        expected_version, expected_checksum = pins[name]
        if version != expected_version:
            fail(f"{lock_path}: {name} is {version}, expected {expected_version}")
        if not source.startswith(REGISTRY_PREFIX):
            fail(f"{lock_path}: {name} has non-registry source {source!r}")
        if checksum != expected_checksum:
            fail(
                f"{lock_path}: {name} {version} has checksum {checksum!r}, expected "
                f"{expected_checksum}"
            )
        selected[name] = (version, source, checksum)
    if set(selected) != COHORT:
        fail(f"{lock_path}: cohort mismatch; missing={sorted(COHORT - set(selected))}, extra={sorted(set(selected) - COHORT)}")
    return selected


def compare_locks(
    root: dict[str, tuple[str, str, str]], nested: dict[str, tuple[str, str, str]]
) -> None:
    """Check that both Cargo roots resolve each cohort crate to the same release.

    Two roots that land on one release must agree on its checksum, which is what
    proves they read the same published artifact. Only a crate the pin tables put
    at different releases may differ here: `cohort_packages` has already held
    each lock to the version and checksum of its own row, so a differing version
    is one the pins record.

    The per-lock checksums already hold each lock to its own artifact, so the
    checksum comparison here is a second, independent reading rather than the
    only one: it is what catches a release recorded twice with two checksums, and
    it is the only check that compares the two source strings beyond the registry
    prefix each is checked against.
    """
    for name, (root_version, root_source, root_checksum) in root.items():
        nested_version, nested_source, nested_checksum = nested[name]
        if root_version != nested_version:
            continue
        if (root_source, root_checksum) != (nested_source, nested_checksum):
            fail(f"root and nested Cargo locks disagree on {name} source/checksum")


def check_manifest(path: pathlib.Path) -> None:
    manifest = load_toml(path)
    for table_name, table in manifest.get("patch", {}).items():
        if not isinstance(table, dict):
            continue
        names = set(table)
        overlap = names & COHORT
        if overlap:
            fail(f"{path}: patch.{table_name} overrides cohort crate(s): {', '.join(sorted(overlap))}")


def check_metadata(path: pathlib.Path, pins: dict[str, tuple[str, str]]) -> None:
    """`cargo metadata` for one root, held to the same pins as its lock."""
    metadata = json.loads(path.read_text())
    selected: dict[str, tuple[str, str]] = {}
    for package in metadata.get("packages", []):
        name = package.get("name")
        if isinstance(name, str) and (name == "msb_krun" or name.startswith("msb_krun_")) and name not in COHORT:
            fail(f"{path}: unexpected msb_krun cohort package {name}")
        if name not in COHORT:
            continue
        if name in selected:
            fail(f"{path}: cargo metadata has duplicate cohort package {name}")
        selected[name] = (package.get("version", ""), package.get("source") or "")
    if set(selected) != COHORT:
        fail(f"{path}: metadata cohort mismatch; missing={sorted(COHORT - set(selected))}, extra={sorted(set(selected) - COHORT)}")
    for name, (version, source) in selected.items():
        expected_version, _ = pins[name]
        if version != expected_version or not source.startswith(REGISTRY_PREFIX):
            fail(
                f"{path}: {name} is {version} from {source!r}; expected registry "
                f"{expected_version}"
            )


def check_firmware(args: argparse.Namespace) -> None:
    if args.gitlink_mode != "160000":
        fail(f"firmware gitlink mode is {args.gitlink_mode!r}, expected '160000'")
    if args.gitlink == "":
        fail("firmware gitlink is empty")
    if args.firmware_head == "":
        fail("firmware recursive submodule is not initialized; run git submodule update --init --recursive")
    if args.firmware_head != args.gitlink:
        fail(f"firmware checkout HEAD is {args.firmware_head}, expected gitlink {args.gitlink}")
    if args.firmware_dirty:
        fail("firmware source is dirty (tracked modifications or non-ignored untracked files)")
    constants = pathlib.Path(args.constants).read_text()
    if f'LIBKRUNFW_VERSION: &str = "{FIRMWARE_VERSION}"' not in constants:
        fail(f"firmware version constant is not {FIRMWARE_VERSION}")
    if f'LIBKRUNFW_ABI: &str = "{FIRMWARE_ABI}"' not in constants:
        fail(f"firmware ABI constant is not {FIRMWARE_ABI}")
    firmware = pathlib.Path(args.firmware_dir)
    cmdline_patch = firmware / "patches/0031-msb-krunfw-increase-kernel-command-line-size.patch"
    x86_config = firmware / "config-libkrunfw_x86_64"
    if "COMMAND_LINE_SIZE\t16384" not in cmdline_patch.read_text():
        fail("pinned firmware lacks the 16 KiB command-line patch")
    config = x86_config.read_text()
    required = ("CONFIG_KVM=y", "CONFIG_KVM_INTEL=y", "CONFIG_KVM_AMD=y", "CONFIG_POSIX_MQUEUE=y", "CONFIG_BRIDGE=y", "CONFIG_NF_TABLES=y")
    missing = [symbol for symbol in required if symbol not in config]
    if missing:
        fail(f"pinned firmware lacks required x86 config: {', '.join(missing)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root-lock", required=True, type=pathlib.Path)
    parser.add_argument("--nested-lock", required=True, type=pathlib.Path)
    parser.add_argument("--root-manifest", required=True, type=pathlib.Path)
    parser.add_argument("--nested-manifest", required=True, type=pathlib.Path)
    parser.add_argument("--constants", required=True, type=pathlib.Path)
    parser.add_argument("--firmware-dir", required=True)
    parser.add_argument("--gitlink", required=True)
    parser.add_argument("--gitlink-mode", required=True)
    parser.add_argument("--firmware-head", required=True)
    parser.add_argument("--firmware-dirty", action="store_true")
    parser.add_argument("--root-metadata", type=pathlib.Path)
    parser.add_argument("--nested-metadata", type=pathlib.Path)
    args = parser.parse_args()
    try:
        root = cohort_packages(args.root_lock, ROOT_PINS)
        nested = cohort_packages(args.nested_lock, NESTED_PINS)
        compare_locks(root, nested)
        check_manifest(args.root_manifest)
        check_manifest(args.nested_manifest)
        check_firmware(args)
        if args.root_metadata or args.nested_metadata:
            if not (args.root_metadata and args.nested_metadata):
                fail("both cargo metadata files are required in full mode")
            check_metadata(args.root_metadata, ROOT_PINS)
            check_metadata(args.nested_metadata, NESTED_PINS)
    except (OSError, tomllib.TOMLDecodeError, json.JSONDecodeError, ValueError) as error:
        print(f"runtime provenance: FAIL: {error}", file=sys.stderr)
        sys.exit(1)
    root_versions = "/".join(sorted({version for version, _ in ROOT_PINS.values()}))
    nested_versions = "/".join(sorted({version for version, _ in NESTED_PINS.values()}))
    print(
        f"runtime provenance: per-lock registry pins, root {root_versions} / nested "
        f"{nested_versions}; firmware {args.gitlink[:12]} version {FIRMWARE_VERSION} ABI {FIRMWARE_ABI}"
    )


if __name__ == "__main__":
    main()
