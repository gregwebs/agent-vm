#!/usr/bin/env python3
"""Serial native config-mounts rows (#394 / ADR-0046, #397 / ADR-0048).

Boot-free fake-`msb` assertions are not native enforcement evidence and are
never counted here: every row below boots the digest-pinned image through the
real candidate and reads what the guest printed.

The launch mechanics, process-group ownership, identity receipts, bounded
cleanup and private cache/approval environment are the persisted-network
harness's, imported rather than copied (`egress-fixtures.py`,
`persisted-network.sh::pn_fresh_state`). Only the rows are new.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("cm_egress", ROOT / "script/test/lib/egress-fixtures.py")
EGRESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EGRESS
SPEC.loader.exec_module(EGRESS)
HELPER = ROOT / "script/test/lib/persisted-network.sh"
PROBE = ROOT / "script/test/fixtures/config-mounts/guest-cm-probe.sh"
LAUNCH_OPTIONS = ("--no-git",)


def shell_helper(name, value):
    return subprocess.check_output(
        ["bash", "-c", 'source "$1"; "$2" "$3"', "cm", str(HELPER), name, str(value)],
        text=True, timeout=10)


def snapshot_validation(work):
    """The persisted-network shape: mode, size and content digest per path."""
    result = {}
    for directory in ("home", "config", "state", "proj"):
        for path in sorted((work / directory).rglob("*")):
            if path.name.endswith(("-shm", "-wal", "-journal")):
                continue
            meta = path.lstat()
            value = ""
            if path.is_symlink():
                value = os.readlink(path)
            elif path.is_file():
                digest = hashlib.sha256()
                with path.open("rb") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
                value = digest.hexdigest()
            result[str(path.relative_to(work))] = [meta.st_mode, meta.st_size, value]
    return result


def tree_digest(path):
    """One digest over a directory's names and contents, for the ro oracle."""
    digest = hashlib.sha256()
    for entry in sorted(path.rglob("*")):
        digest.update(str(entry.relative_to(path)).encode() + b"\0")
        if entry.is_symlink():
            digest.update(b"link\0" + os.readlink(entry).encode())
        elif entry.is_file():
            digest.update(entry.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def marker(path):
    return path.read_text() if path.is_file() else "absent"


def fork_identity(work):
    """Every published fork's directory name and manifest digest, sorted.

    Read after a launch's cleanup proved absence. The comparison is the point:
    selecting a set, nesting it or renaming it must not create a second copy or
    reseed this one, which would change both values.
    """
    identity = []
    for manifest in sorted((work / "state").glob("*.mounts/forks/*/manifest.json")):
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        identity.append([manifest.parent.name, digest])
    return identity


# The named-mount-set document (#397). Declared only, it selects nothing; with
# `mounts = ["all-set"]` prepended it selects the three leaves, and a repeated
# reference inside `all-set` must change nothing.
SETS_TABLE = """[mount_sets]
all-set = ["ro-set", "rw-set", "fork-set", "ro-set"]
ro-set = ["~/cm/ro:/cm/ro:ro"]
rw-set = ["~/cm/rw:/cm/rw:rw"]
fork-set = ["~/cm/fork:/cm/fork:fork"]
"""
SETS_DEFAULT = 'mounts = ["all-set"]\n'


def interrupted(signum, _frame):
    raise InterruptedError(f"signal {signum}")


def main():
    if len(sys.argv) != 6:
        raise SystemExit("usage: config-mounts.py ROOT EVIDENCE BINARY IMAGE MSB_PATH")
    root, evidence = map(lambda x: Path(x).resolve(), sys.argv[1:3])
    binary, image, msb = sys.argv[3:6]
    work = root / "cm"
    launches = []
    errors = []
    rows = []
    summary = evidence / "summary.tsv"
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)

    def record(row, expected, actual):
        passed = expected == actual
        rows.append((row, expected, actual, passed))
        with summary.open("a") as handle:
            handle.write(f"{row}\t{expected}\t{actual}\t{'PASS' if passed else 'FAIL'}\n")
        print(f"{'PASS' if passed else 'FAIL'} {row}: expected {expected!r} actual {actual!r}", flush=True)
        if not passed:
            raise AssertionError(f"{row}: expected {expected!r}, got {actual!r}")

    def guest_line(text, prefix):
        for line in text.splitlines():
            if line.startswith(prefix):
                return line
        return "<missing>"

    try:
        shell_helper("pn_fresh_state", work)
        project = work / "proj"
        home = work / "home"
        for name, seed in (("ro", "seed-ro"), ("rw", "seed-rw"), ("fork", "seed-fork")):
            source = home / "cm" / name
            source.mkdir(parents=True)
            (source / "marker").write_text(seed)
        (project / "project-marker").write_text("project\n")
        shutil.copy2(PROBE, project / PROBE.name)
        config = home / ".config/agent-vm/config.toml"
        config.write_text('mounts = ["~/cm/ro:/cm/ro:ro", "~/cm/rw:/cm/rw:rw", "~/cm/fork:/cm/fork:fork"]\n')
        config.chmod(0o600)
        rw_marker = home / "cm/rw/marker"
        fork_marker = home / "cm/fork/marker"
        ro_tree = tree_digest(home / "cm/ro")

        # The runtime is named explicitly (resolution rung 1) and the environment
        # is built from scratch, so no inherited MSB_* variable can redirect it.
        env = EGRESS.base_environment(work)
        env["MSB_PATH"] = msb

        def launch(row, phase, flags=()):
            before = snapshot_validation(work)
            (evidence / f"{row}-before.json").write_text(
                json.dumps({"snapshot": before, "fixtures": {
                    "ro": ro_tree, "rw": marker(rw_marker), "fork": marker(fork_marker)}}, indent=2))
            argv = (binary, *LAUNCH_OPTIONS, "--image", image, *flags, "shell", "bash", "-c",
                    f"bash ./{PROBE.name} {phase}")
            command = EGRESS.Command(row, "native", "shell", "guest", env, argv, str(project), 300, 10)
            owned = EGRESS.OwnedLaunch(work, command, row)
            launches.append(owned)
            (evidence / f"{row}-command.json").write_text(json.dumps(command.plan(), indent=2))
            status = owned.run()
            text = owned.log.read_text(errors="replace")
            if status in (124, 130, 143) or owned.errors:
                raise RuntimeError(f"{row}: timeout/interrupt/observation error: {status} {owned.errors}")
            if status != 0:
                raise RuntimeError(f"{row}: launch exited {status}: {text[-2000:]}")
            (evidence / f"{row}-after.json").write_text(json.dumps({
                "snapshot": snapshot_validation(work), "status": status,
                "guest": [line for line in text.splitlines() if line.startswith("CM-")]}, indent=2))
            return text

        def cleanup(owned, row):
            # Fixtures are never touched while a VM that holds them may exist.
            problems = EGRESS.cleanup_launch(owned)
            if problems:
                raise RuntimeError(f"{row}: cleanup {problems}")

        # ---- L1: ro, rw and fork under the default selection ----------------
        l1 = launch("L1", "all")
        record("CM-N1", "CM-N1 read=seed-ro write=denied", guest_line(l1, "CM-N1"))
        record("CM-N2", "CM-N2 wrote", guest_line(l1, "CM-N2"))
        record("CM-N3a", "CM-N3a read=seed-fork wrote", guest_line(l1, "CM-N3a"))
        if "==> Config mounts: 3 from" not in l1:
            raise AssertionError("L1: the selected notice did not name the three declarations")
        # Host oracles, read only after the launch's cleanup proved absence.
        # The expected value is the retained pre-launch observation, so the row
        # compares two measurements rather than asserting a constant twice.
        cleanup(launches[0], "L1")
        record("CM-N1-host", ro_tree, tree_digest(home / "cm/ro"))
        record("CM-N2-host", "guest-rw", marker(rw_marker))
        record("CM-N3a-host", "seed-fork", marker(fork_marker))

        # The launch's own first pin is the approval record: a fresh private HOME
        # has no store, so an absent record means this launch was not what it says.
        pins = home / ".config/agent-vm/image-pins.json"
        if not pins.is_file():
            raise RuntimeError("L1: no image-pins.json; the digest-pinned acquisition left no approval")
        shutil.copy2(pins, evidence / "image-pins.json")
        document = json.loads(pins.read_text())
        requested = image.rsplit("@", 1)[-1]
        recorded = " ".join(
            f"{pin.get('reference', '')} {pin.get('manifest_digest', '')}" for pin in document.get("pins", []))
        if requested not in recorded:
            raise RuntimeError(
                f"image-pins.json does not name the requested digest {requested}: {recorded!r}")
        if len(document.get("pins", [])) != 1:
            raise RuntimeError(f"image-pins.json has {len(document.get('pins', []))} pins, expected 1")

        # ---- the host changes its own seed between launches -----------------
        fork_marker.write_text("host-later")

        # ---- L2: the fork keeps the guest's own write -----------------------
        l2 = launch("L2", "n3b")
        record("CM-N3b", "CM-N3b read=guest-fork", guest_line(l2, "CM-N3b"))
        cleanup(launches[1], "L2")
        record("CM-N3b-host", "host-later", marker(fork_marker))

        # ---- L3: the opt-out removes every config mount ----------------------
        l3 = launch("L3", "n4", ("--no-config-mounts",))
        record("CM-N4", "CM-N4 ro=absent rw=absent fork=absent project=present", guest_line(l3, "CM-N4"))
        if "==> Config mounts: skipped 3 from" not in l3:
            raise AssertionError("CM-N4: the skipped notice did not name the three declarations")
        cleanup(launches[2], "L3")

        # ---- L4: an equivalent --mount reuses the config fork ----------------
        # The opt-out is what proves the config entry did not supply it.
        l4 = launch("L4", "n5", ("--no-config-mounts", "--mount", f"{home}/cm/fork:/cm/fork:fork"))
        record("CM-N5", "CM-N5 read=guest-fork", guest_line(l4, "CM-N5"))
        cleanup(launches[3], "L4")

        # ---- named mount sets (#397) ---------------------------------------
        # Every config rewrite below happens only after the previous launch's
        # cleanup proved absence, and each launch's command line and config bytes
        # are retained beside its before/after receipts.
        absent_line = "CM-S ro=absent rw=absent fork=absent project=present"
        access_line = ("CM-S access ro=seed-ro ro-write=denied rw=wrote fork=guest-fork "
                       "project=present")
        fork_before = fork_identity(work)

        def write_config(row, body):
            config.write_text(body)
            config.chmod(0o600)
            shutil.copy2(config, evidence / f"{row}-config.toml")

        # S1: definitions alone must mount nothing.
        write_config("S1", SETS_TABLE)
        s1 = launch("S1", "sets-absent")
        record("CM-S1", absent_line, guest_line(s1, "CM-S"))
        cleanup(launches[4], "S1")

        # S2: the defaults select the set's three leaves.
        write_config("S2", SETS_DEFAULT + SETS_TABLE)
        s2 = launch("S2", "sets")
        record("CM-S2", access_line, guest_line(s2, "CM-S"))
        cleanup(launches[5], "S2")
        if "==> Reusing fork" not in s2 or "Initialized fork" in s2:
            raise AssertionError("CM-S2: the set-selected fork was not reused")

        # S3: the opt-out removes all three again, project still visible.
        s3 = launch("S3", "sets-absent", ("--no-config-mounts",))
        record("CM-S3", absent_line, guest_line(s3, "CM-S"))
        cleanup(launches[6], "S3")

        # S4: the opt-out plus an explicit name grants exactly S2's access.
        s4 = launch("S4", "sets", ("--no-config-mounts", "--mount", "all-set"))
        record("CM-S4", access_line, guest_line(s4, "CM-S"))
        cleanup(launches[7], "S4")
        if "==> Reusing fork" not in s4 or "Initialized fork" in s4:
            raise AssertionError("CM-S4: the explicitly selected set reseeded the fork")

        # Host oracles, read only after the last launch's cleanup proved absence.
        record("CM-S-host-ro", ro_tree, tree_digest(home / "cm/ro"))
        record("CM-S-host-rw", "set-rw", marker(rw_marker))
        record("CM-S-host-fork", "host-later", marker(fork_marker))
        record("CM-S-host-fork-identity", fork_before, fork_identity(work))
    except (AssertionError, OSError, RuntimeError, InterruptedError, subprocess.SubprocessError) as error:
        errors.append(str(error) or repr(error))
    finally:
        errors.extend(EGRESS.cleanup_run(work, binary, launches))
        # Receipts and logs survive even when a row fails; never snapshot host
        # policy state into the evidence instead of the launch's own files.
        for file in sorted(work.glob("*")):
            if file.is_file():
                shutil.copy2(file, evidence / file.name)
        (evidence / "errors.json").write_text(json.dumps(errors, indent=2))
        failed = [row for row in rows if not row[3]]
        (evidence / "totals.json").write_text(json.dumps({
            "rows": len(rows), "passed": len(rows) - len(failed),
            "failed": [row[0] for row in failed]}, indent=2))
        if not errors:
            shutil.rmtree(root)
        else:
            print(f"Owned scratch retained after failure: {root}", file=sys.stderr)
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
