#!/usr/bin/env python3
"""Validate the source identities that compose the agent-vm runtime."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tomllib

# The version(s) each cohort crate may resolve to, checked per crate rather than
# as one number, and `COHORT` derived from it so the set and the pins cannot
# drift apart. Most of the cohort ships as a unit at the runtime's release
# version; `arch_gen`, `cpuid` and `smbios` are published on their own cadence,
# so the outer workspace resolves 0.1.45 while the vendored lock still pins
# 0.1.42 — two official crates.io releases of the fork. Naming the accepted set
# per crate keeps a lock from drifting to an unpublished or edited crate, which
# a single version string could not express once the halves legitimately differ.
VERSIONS: dict[str, frozenset[str]] = {
    "msb_krun": frozenset(("0.1.42",)),
    "msb_krun_arch": frozenset(("0.1.42",)),
    "msb_krun_arch_gen": frozenset(("0.1.42", "0.1.45")),
    "msb_krun_cpuid": frozenset(("0.1.42", "0.1.45")),
    "msb_krun_devices": frozenset(("0.1.42",)),
    "msb_krun_hvf": frozenset(("0.1.42",)),
    "msb_krun_kernel": frozenset(("0.1.42",)),
    "msb_krun_polly": frozenset(("0.1.42",)),
    "msb_krun_smbios": frozenset(("0.1.42", "0.1.45")),
    "msb_krun_utils": frozenset(("0.1.42",)),
    "msb_krun_vmm": frozenset(("0.1.42",)),
}
COHORT = frozenset(VERSIONS)
FIRMWARE_VERSION = "5.6.1"
FIRMWARE_ABI = "5"
REGISTRY_PREFIX = "registry+https://github.com/rust-lang/crates.io-index"


def fail(message: str) -> None:
    raise ValueError(message)


def load_toml(path: pathlib.Path) -> dict:
    with path.open("rb") as stream:
        return tomllib.load(stream)


def cohort_packages(lock_path: pathlib.Path) -> dict[str, tuple[str, str, str]]:
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
        if version not in VERSIONS[name]:
            expected = " or ".join(sorted(VERSIONS[name]))
            fail(f"{lock_path}: {name} is {version}, expected {expected}")
        if not source.startswith(REGISTRY_PREFIX):
            fail(f"{lock_path}: {name} has non-registry source {source!r}")
        if not checksum:
            fail(f"{lock_path}: {name} has no registry checksum")
        selected[name] = (version, source, checksum)
    if set(selected) != COHORT:
        fail(f"{lock_path}: cohort mismatch; missing={sorted(COHORT - set(selected))}, extra={sorted(set(selected) - COHORT)}")
    return selected


def compare_locks(
    root: dict[str, tuple[str, str, str]], nested: dict[str, tuple[str, str, str]]
) -> None:
    """Check that both Cargo roots resolve each cohort crate to the same release.

    Two roots that land on one release must agree on its checksum, which is what
    proves they read the same published artifact. Only a crate with several
    accepted releases may differ in version: `cohort_packages` has already
    narrowed each lock to `VERSIONS[name]`, so a differing version is one the map
    accepts.
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


def check_metadata(path: pathlib.Path) -> None:
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
        expected = " or ".join(sorted(VERSIONS[name]))
        if version not in VERSIONS[name] or not source.startswith(REGISTRY_PREFIX):
            fail(f"{path}: {name} is {version} from {source!r}; expected registry {expected}")


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
        root = cohort_packages(args.root_lock)
        nested = cohort_packages(args.nested_lock)
        compare_locks(root, nested)
        check_manifest(args.root_manifest)
        check_manifest(args.nested_manifest)
        check_firmware(args)
        if args.root_metadata or args.nested_metadata:
            if not (args.root_metadata and args.nested_metadata):
                fail("both cargo metadata files are required in full mode")
            check_metadata(args.root_metadata)
            check_metadata(args.nested_metadata)
    except (OSError, tomllib.TOMLDecodeError, json.JSONDecodeError, ValueError) as error:
        print(f"runtime provenance: FAIL: {error}", file=sys.stderr)
        sys.exit(1)
    pins = "/".join(sorted({version for versions in VERSIONS.values() for version in versions}))
    print(f"runtime provenance: root+nested registry cohort {pins}; checksums equal where the version is; firmware {args.gitlink[:12]} version {FIRMWARE_VERSION} ABI {FIRMWARE_ABI}")


if __name__ == "__main__":
    main()
