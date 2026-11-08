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
import re
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
GM_PROBE = ROOT / "script/test/fixtures/config-mounts/guest-gm-probe.sh"
LAUNCH_OPTIONS = ("--no-git",)


def shell_helper(name, value):
    return subprocess.check_output(
        ["bash", "-c", 'source "$1"; "$2" "$3"', "cm", str(HELPER), name, str(value)],
        text=True, timeout=10)


def snapshot_validation(work):
    """The persisted-network shape: mode, size and content digest per path."""
    result = {}
    for directory in ("home", "config", "state", "proj", "gm"):
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


def guest_line(text, prefix):
    """The one line a probe rendered for `prefix`, or `<missing>`.

    Module level rather than a closure: `run_gm_group` compares guest output, and
    `--dispatch-check` drives it without `main()`'s locals.
    """
    for line in text.splitlines():
        if line.startswith(prefix):
            return line
    return "<missing>"


def marker(path):
    return path.read_text() if path.is_file() else "absent"


def gm_git(home, cwd, *args):
    """Run `git` for the GM fixture with an environment built from scratch.

    Never inherits `GIT_*`: a `GIT_DIR`, `GIT_COMMON_DIR`, `GIT_INDEX_FILE` or
    `GIT_CONFIG_COUNT`/`GIT_CONFIG_PARAMETERS` in the caller's environment would
    redirect Git despite `-C` and change the `.git` shape every GM row is about.
    Global and system config are pinned to `/dev/null` so a developer's
    `worktree.useRelativePaths` cannot rewrite the pointer either.
    """
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }
    return subprocess.run(
        ["git", "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false",
         "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=always", *args],
        cwd=str(cwd), env=env, check=True, capture_output=True, text=True, timeout=60)


def build_gm_fixture(work):
    """One real linked worktree, and the paths the GM rows drive.

    Everything happens before any baseline snapshot: the repo-local identity,
    signing and hook policy are written with `git config` *before* the first
    commit, so the fixture commits without whatever the host or the image says.
    The guest probe is copied into the worktree, so the project bind carries it.
    """
    home = work / "home"
    main = work / "gm" / "main"
    worktree = work / "gm" / "wt"
    main.mkdir(parents=True)
    worktree.mkdir(parents=True)
    gm_git(home, main, "init", "-q")
    for key, value in (("user.name", "gm"), ("user.email", "gm@example.invalid"),
                       ("commit.gpgsign", "false"), ("tag.gpgsign", "false"),
                       ("core.hooksPath", "/dev/null")):
        gm_git(home, main, "config", key, value)
    (main / "tracked.txt").write_text("seed\n")
    gm_git(home, main, "add", "tracked.txt")
    gm_git(home, main, "commit", "-q", "-m", "seed")
    gm_git(home, main, "worktree", "add", "-q", str(worktree), "-b", "gm")
    shutil.copy2(GM_PROBE, worktree / GM_PROBE.name)
    return {
        "home": home,
        "main": main,
        "worktree": worktree,
        # The common directory, canonical: this is the guest path the automatic
        # bind must reproduce exactly.
        "common": (main / ".git").resolve(),
        "probe": worktree / GM_PROBE.name,
        "tracked": worktree / "tracked.txt",
    }


def gm_branch_oid(gm):
    """The fixture's `gm` branch object id, or `<absent>`."""
    try:
        out = gm_git(gm["home"], gm["main"], "rev-parse", "gm")
    except subprocess.CalledProcessError:
        return "<absent>"
    return out.stdout.strip()


def _gm_rev_parse(gm, revision):
    """One revision as text, or `<absent>` — never an exception in a row."""
    try:
        return gm_git(gm["home"], gm["main"], "rev-parse", revision).stdout.strip()
    except subprocess.CalledProcessError:
        return "<absent>"


def _gm_show(gm, oid, name):
    """`name` at `oid`, or `<absent>`."""
    try:
        return gm_git(gm["home"], gm["main"], "show", f"{oid}:{name}").stdout
    except subprocess.CalledProcessError:
        return "<absent>"


def _gm_has_object(gm, oid):
    """Whether the host repository can read `oid` — the "host sees the object" oracle."""
    try:
        gm_git(gm["home"], gm["main"], "cat-file", "-e", oid)
    except subprocess.CalledProcessError:
        return False
    return True


def gm_tree_digest(gm):
    return tree_digest(gm["common"])


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


def pi_fork_identity(work):
    """The **Pi lineage's** fork identity: directory name and manifest digest.

    Filtered by the declaration's guest destination rather than asserting the
    whole run holds one fork: the #394/#397 rows publish their own `/cm/fork`
    fork in the same state root, and rewriting those rows to make this one pass
    would destroy their evidence. Within the Pi lineage there is exactly one.
    """
    identity = []
    for manifest in sorted((work / "state").glob("*.mounts/forks/*/manifest.json")):
        document = json.loads(manifest.read_text())
        if not str(document.get("guest", "")).endswith("/.pi"):
            continue
        identity.append([manifest.parent.name, hashlib.sha256(manifest.read_bytes()).hexdigest()])
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


# The tool-mount topology (#396). Every synthetic tool executes `bash` with the
# probe as its argument vector, so these rows test catalog *selection* — never an
# image's installed Pi version or login state — and the probe itself is the guest
# program. `pi` is the only tool allowed a `:fork`, and it is the only one whose
# definition references others.
PROBE_ARGS = 'args = ["./guest-cm-probe.sh"]\n'
AGENT_SET = (
    "[mount_sets]\n"
    'agent = ["~/cm-tool/agent:/cm/tool/agent:rw", '
    '"~/cm-tool/agent/skills:/cm/tool/agent/skills:ro", '
    '"~/cm-tool/readonly:/cm/tool/readonly:ro"]\n'
)
TOOL_DEFAULT = 'mounts = ["~/cm-tool/default:/cm/tool/default:ro"]\n'
SHELL_OWN = 'mounts = ["~/cm-tool/shell-own:/cm/tool/shell-own:ro"]\n'


def tool(name, *, tools, mounts=None):
    body = f'[[tools]]\nname = "{name}"\ncommand = "bash"\n{PROBE_ARGS}tools = {tools}\n'
    return body + (f"mounts = {mounts}\n" if mounts else "")


def shell_tool(*, tools_line, mounts_line):
    return (
        '[[tools]]\nname = "shell"\ncommand = "bash"\nargs = ["-O", "histappend"]\n'
        f"interactive_shell = true\n{tools_line}{mounts_line}"
    )


# Pi's own list is the fork only: `agent` reaches a Pi launch *through* `tools`,
# so a run that dropped the mount edges could not still produce CM-T3's agent
# topology.
TOOLS_BASE = (
    tool("pi", tools='["claude", "codex"]', mounts='["~/.pi:fork"]')
    + tool("claude", tools="[]", mounts='["agent"]')
    + tool("codex", tools="[]", mounts='["agent"]')
    + tool("bridge", tools='["pi"]')
    + tool("plain", tools="[]")
)
# The wildcard shell (T5): `tools` omitted on purpose, which is what makes it
# deliberately broad — it inherits every same-tier tool's mounts.
TOOLS_WILDCARD_SHELL = AGENT_SET + TOOLS_BASE + shell_tool(
    tools_line="", mounts_line=SHELL_OWN)
# T6: the same shell with inheritance switched off, plus a user-wide default.
TOOLS_EMPTY_SHELL = (
    TOOL_DEFAULT + AGENT_SET + TOOLS_BASE
    + shell_tool(tools_line="tools = []\n", mounts_line=SHELL_OWN))
# T7: no declared shell at all, so the built-in fallback runs; the custom catalog
# and the user-wide default stay.
TOOLS_FALLBACK_SHELL = TOOL_DEFAULT + AGENT_SET + TOOLS_BASE
# T8-T10: a *wildcard* declared shell (no `tools` line), so the opt-out has a
# non-empty inherited facet to suppress on the shell route too: with `tools = []`
# the inherited list is empty before the opt-out can act on it.
TOOLS_OPTOUT = TOOL_DEFAULT + AGENT_SET + TOOLS_BASE + shell_tool(
    tools_line="", mounts_line=SHELL_OWN)
# A tool named exactly like the set `agent`. Its own leaf and its own `persist`
# link are the independently observable provisioning facts that make "selecting a
# set provisions no tool" discriminating: a launch of this tool shows both, and
# `--mount agent` must show neither.
TOOLS_SAME_NAME_TOOL = (
    '[[tools]]\nname = "agent"\ncommand = "bash"\n' + PROBE_ARGS
    + 'tools = []\npersist = ["agent-tool-state"]\n'
    + 'mounts = ["~/cm-tool/agent-tool:/cm/tool/agent-tool:ro"]\n'
)
# T9/T9-control: the same-named tool is *not* in T8's catalog, because the
# wildcard shell there inherits every same-tier tool's `persist` and would create
# the link T9 has to find absent.
TOOLS_SET_NAME = TOOLS_OPTOUT + TOOLS_SAME_NAME_TOOL
# T11: the same Pi declaration reached as a top-level default and through a
# nested set, so the *route* is the only difference between the two launches.
TOOLS_DEFAULT_FORK = (
    'mounts = ["~/.pi:fork"]\n'
    + tool("pi", tools='["claude", "codex"]', mounts="[]")
    + tool("claude", tools="[]")
    + tool("codex", tools="[]")
)
TOOLS_NESTED_SET = (
    "[mount_sets]\nouter = [\"inner\"]\ninner = [\"~/.pi:fork\"]\n"
    + tool("pi", tools='["claude", "codex"]', mounts='["outer"]')
    + tool("claude", tools="[]")
    + tool("codex", tools="[]")
)


def interrupted(signum, _frame):
    raise InterruptedError(f"signal {signum}")


BLOCKED_NOTE = "BLOCKED: guest image has no git"
# Every GM row, in order. `GM-N3` has no host oracle: "absent" is a guest-only
# observation (the host path is there by definition), which the host-only controls
# state rather than imitate.
GM_ROWS = ("GM-N1", "GM-N1-host", "GM-N2", "GM-N2-host", "GM-N3", "GM-N4", "GM-N4-host")


class Rows:
    """The evidence receipt: one line per assertion, and a status never inferred
    from silence.

    `BLOCKED` is the third status because a native row that could not run must
    read as neither of the other two: `PASS` would be a claim nothing measured
    (CONTRIBUTING.md: never a pass) and `FAIL` would report the product for a
    missing thing in the image. A blocked row is therefore not counted in
    `passed`, and `totals()` lists it apart from `failed`.

    A class rather than a closure so the decision is reachable without a VM: the
    contract script runs `--self-check`, which drives this receipt and the GM-N2
    host oracle over observations that never touch an image.
    """

    def __init__(self, summary, quiet=False):
        self.summary = Path(summary)
        self.quiet = quiet
        self.rows = []

    def record(self, row, expected, actual, blocked=False):
        passed = expected == actual and not blocked
        status = "BLOCKED" if blocked else ("PASS" if passed else "FAIL")
        self.rows.append((row, expected, actual, passed, blocked))
        with self.summary.open("a") as handle:
            handle.write(f"{row}\t{expected}\t{actual}\t{status}\n")
        if not self.quiet:
            print(f"{status} {row}: expected {expected!r} actual {actual!r}", flush=True)
        if not passed and not blocked:
            raise AssertionError(f"{row}: expected {expected!r}, got {actual!r}")

    def blocked(self, row):
        self.record(row, BLOCKED_NOTE, BLOCKED_NOTE, blocked=True)

    def totals(self):
        return {
            "rows": len(self.rows),
            "passed": sum(1 for _, _, _, passed, _ in self.rows if passed),
            "blocked": [row for row, _, _, _, blocked in self.rows if blocked],
            "failed": [row for row, _, _, passed, blocked in self.rows
                       if not passed and not blocked],
        }


def gm_commit_row(guest_line):
    """The GM-N2 row: the probe committed, so its line carries a full object id."""
    match = re.fullmatch(r"GM-N2 commit=([0-9a-f]{40})", guest_line)
    expected = "GM-N2 commit=<40-hex object id>"
    return expected, (expected if match else guest_line), (match.group(1) if match else None)


# The guest path of the second, explicitly writable route GM-N4 compares against.
GM_ALIAS = "/gm-alt"


class GmHost:
    """The GM rows' host-side oracle: everything measured on the host repository
    after a launch's cleanup proved the VM absent.

    A class so the row logic can be driven without a VM (`--dispatch-check`): the
    launch seam is replaced there, the oracle is not, because the oracle is the
    half a faked launch must not be able to satisfy.
    """

    def __init__(self, gm):
        self.gm = gm

    def common_path(self):
        return self.gm["common"]

    def common_tree(self):
        return gm_tree_digest(self.gm)

    def branch(self):
        return gm_branch_oid(self.gm)

    def parent_of(self, oid):
        return _gm_rev_parse(self.gm, f"{oid}^")

    def file_at(self, oid, name):
        return _gm_show(self.gm, oid, name)

    def has_object(self, oid):
        return _gm_has_object(self.gm, oid)

    def probe(self):
        return marker(self.gm["common"] / "objects/gm-probe")


def run_gm_group(launch, cleanup, host, record, record_blocked, baseline):
    """The GM rows' control flow (#535), with every side effect injected.

    `launch(row, phase, flags=(), extra=())` returns what the guest printed,
    `cleanup(row)` tears that launch down, and `host` is a [`GmHost`]-shaped
    oracle. The launch half is injected so `--dispatch-check` can drive *this*
    dispatch without a VM: the blocked-versus-measured branch and the commit
    oracle are where this group regressed before, not the rows themselves.

    Returns `"blocked"` or `"measured"`, which is what the caller prints.
    """
    text = launch("GM-N1", "ro")
    missing = "GM-MISSING" in text
    cleanup("GM-N1")
    if missing:
        # No `git` in the image: no GM phase can say anything. Every row and its
        # host oracle is BLOCKED — recorded, counted apart from `passed`, and never
        # dressed up as a pass. The remaining launches are skipped because each
        # would measure the same absence.
        for row in GM_ROWS:
            record_blocked(row)
        return "blocked"

    record("GM-N1", "GM-N1 log=seed diff=tracked.txt write=denied add=denied",
           guest_line(text, "GM-N1"))
    if "==> Git metadata: linked worktree, read-only" not in text:
        raise AssertionError("GM-N1: the read-only notice did not print")
    record("GM-N1-host", {"common-tree": baseline["common-tree"], "probe": "absent"},
           {"common-tree": host.common_tree(), "probe": host.probe()})

    # GM-N2: `--git-mount=rw` lets the guest commit, and the host sees the ref, the
    # parent and the guest's edit.
    text = launch("GM-N2", "rw", flags=("--git-mount=rw",))
    expected, actual, oid = gm_commit_row(guest_line(text, "GM-N2"))
    record("GM-N2", expected, actual)
    if oid is None:
        raise AssertionError(f"GM-N2: the guest did not commit: {actual!r}")
    cleanup("GM-N2")
    expected, actual = gm_n2_host_row(oid, baseline["branch"], {
        "branch": host.branch(),
        "parent": host.parent_of(oid),
        "tracked": host.file_at(oid, "tracked.txt"),
        "object": "present" if host.has_object(oid) else "absent",
    })
    record("GM-N2-host", expected, actual)

    # GM-N3: `--git-mount=off` binds nothing, so the host path is absent.
    text = launch("GM-N3", "off", flags=("--git-mount=off",))
    record("GM-N3", "GM-N3 absent", guest_line(text, "GM-N3"))
    if "==> Git metadata:" in text:
        raise AssertionError("GM-N3: `off` printed a Git metadata notice")
    cleanup("GM-N3")

    # GM-N4: in ONE launch the same relative write is denied through the automatic
    # read-only bind and allowed through an explicit `:rw` alias. Recorded as "ro
    # is not repository-wide protection", never as an enforcement failure (spec
    # Testing Decisions).
    text = launch("GM-N4", "control",
                  extra=("--mount", f"{host.common_path()}:{GM_ALIAS}:rw"))
    record("GM-N4", "GM-N4 automatic=denied alias=allowed", guest_line(text, "GM-N4"))
    cleanup("GM-N4")
    record("GM-N4-host", "gm-probe\n", host.probe())
    return "measured"


def gm_n2_host_row(oid, baseline, observed):
    """The GM-N2-host oracle: the guest's commit is the branch tip, it **moved**
    the branch off the baseline, it descends from the baseline, and it carries the
    edit the guest made.

    Comparing the branch with the object id the guest reported is not enough on
    its own — that pair says nothing about the branch having moved, and nothing
    about what the commit contains.
    """
    expected = {"branch": oid, "moved": True, "parent": baseline,
                "tracked": "guest-commit", "object": "present"}
    actual = {
        "branch": observed["branch"],
        "moved": observed["branch"] != baseline,
        "parent": observed["parent"],
        "tracked": "guest-commit" if "guest-commit" in observed["tracked"] else "absent",
        "object": observed["object"],
    }
    return expected, actual


def main():
    if len(sys.argv) != 6:
        raise SystemExit("usage: config-mounts.py ROOT EVIDENCE BINARY IMAGE MSB_PATH")
    root, evidence = map(lambda x: Path(x).resolve(), sys.argv[1:3])
    binary, image, msb = sys.argv[3:6]
    work = root / "cm"
    launches = []
    errors = []
    summary = evidence / "summary.tsv"
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)

    receipt = Rows(summary)
    record = receipt.record
    record_blocked = receipt.blocked


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

        def run_row(row, argv, tool_name="shell", cwd=None):
            before = snapshot_validation(work)
            (evidence / f"{row}-before.json").write_text(
                json.dumps({"snapshot": before, "fixtures": {
                    "ro": ro_tree, "rw": marker(rw_marker), "fork": marker(fork_marker)}}, indent=2))
            command = EGRESS.Command(
                row, "native", tool_name, "guest", env, argv, str(cwd or project), 300, 10)
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
                "guest": [line for line in text.splitlines()
                          if line.startswith(("CM-", "GM-"))]}, indent=2))
            return text

        def launch(row, phase, flags=()):
            """A #394/#397 row: the historical explicit `bash -c` argv, unchanged."""
            return run_row(row, (binary, *LAUNCH_OPTIONS, "--image", image, *flags, "shell",
                                 "bash", "-c", f"bash ./{PROBE.name} {phase}"))

        def launch_script_shell(row, phase, flags=()):
            """A #396 declared/fallback shell row.

            The phase is a separate argv token and the product itself builds
            interactive bash's `-c` argument from it (`run::inner_argv` →
            `shell::guest_script_word`) — no Python-side quoting — so these rows
            exercise the shipped shell route rather than a copy of it.
            """
            return run_row(row, (binary, *LAUNCH_OPTIONS, "--image", image, *flags, "shell",
                                 "bash", f"./{PROBE.name}", phase))

        def launch_tool(row, phase, verb, flags=()):
            """A #396 tool row: the synthetic tool's own command and args run the probe."""
            return run_row(row, (binary, *LAUNCH_OPTIONS, "--image", image, *flags, verb, phase),
                           verb)

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

        # ---- tool mounts (#396) ---------------------------------------------
        # A topology of its own, over the same owned scratch: an agent parent
        # with a read-only child, a second read-only directory, a declared
        # shell's own leaf and a user-wide default. Every source, sentinel and
        # protected file is unmistakable — the operator's real config, real Pi
        # home and real credentials are never read or written.
        tool = home / "cm-tool"
        for name, seed in (
            ("agent", "agent-seed"),
            ("agent/skills", "skills-seed"),
            ("readonly", "readonly-seed"),
            ("shell-own", "shell-own"),
            ("default", "default"),
            ("agent-tool", "agent-tool-seed"),
        ):
            (tool / name).mkdir(parents=True, exist_ok=True)
            (tool / name / "marker").write_text(seed)
        pi_source = home / ".pi"
        (pi_source / "agent").mkdir(parents=True, exist_ok=True)
        (pi_source / "marker").write_text("pi-seed")
        (pi_source / "agent/auth.json").write_text('{"synthetic": "pi-auth-sentinel-396"}')
        (pi_source / "agent/models.json").write_text('{"synthetic": "pi-models-sentinel-396"}')
        tool_ro = {name: tree_digest(tool / name)
                   for name in ("agent/skills", "readonly", "agent-tool")}
        protected = {
            name: hashlib.sha256((pi_source / "agent" / name).read_bytes()).hexdigest()
            for name in ("auth.json", "models.json")
        }

        def write_tool_config(row, body):
            config.write_text(body)
            config.chmod(0o600)
            shutil.copy2(config, evidence / f"{row}-config.toml")

        def ro_now():
            return {name: tree_digest(tool / name)
                    for name in ("agent/skills", "readonly", "agent-tool")}

        def protected_now():
            digests = {
                name: hashlib.sha256((pi_source / "agent" / name).read_bytes()).hexdigest()
                for name in ("auth.json", "models.json")
            }
            return "unchanged" if digests == protected else "changed"

        # T1..T5 share this catalog: a wildcard shell, per-tool sets and the Pi
        # fork, which is what makes each row a *selection* difference.
        write_tool_config("T1", TOOLS_WILDCARD_SHELL)

        t1 = launch_tool("T1", "tool-plain", "plain")
        record("CM-T1",
               "CM-T1 agent=absent skills=absent readonly=absent pi=absent project=present",
               guest_line(t1, "CM-T1"))
        if "==> Config mounts:" in t1:
            raise AssertionError("CM-T1: the plain tool selected no mount, so no notice is due")
        cleanup(launches[-1], "T1")
        # The generic `.pi` guest-home link exists without the fork; what must be
        # absent is a Pi-lineage fork in the state root.
        record("CM-T1-host", [], pi_fork_identity(work))

        t2 = launch_tool("T2", "tool-claude", "claude")
        record("CM-T2",
               "CM-T2 agent=agent-seed agent-write=wrote skills=skills-seed skills-write=denied "
               "readonly=readonly-seed readonly-write=denied pi=absent",
               guest_line(t2, "CM-T2"))
        cleanup(launches[-1], "T2")
        record("CM-T2-host",
               {"parent-write": "claude-note", "ro": tool_ro},
               {"parent-write": marker(tool / "agent/new"), "ro": ro_now()})

        t3 = launch_tool("T3", "tool-pi", "pi")
        record("CM-T3",
               "CM-T3 agent=agent-seed skills=skills-seed readonly=readonly-seed pi=pi-seed "
               "pi-write=wrote auth=absent models=absent guest-file=wrote",
               guest_line(t3, "CM-T3"))
        cleanup(launches[-1], "T3")
        identity = pi_fork_identity(work)
        record("CM-T3-host",
               {"pi-source": "pi-seed", "protected": "unchanged", "guest-only": "absent",
                "parent-write": "claude-note"},
               {"pi-source": marker(pi_source / "marker"), "protected": protected_now(),
                "guest-only": "present" if (pi_source / "guest-only").exists() else "absent",
                "parent-write": marker(tool / "agent/new")})
        record("CM-T3-host-identity", 1, len(identity))

        # The host changes its own source between launches: the fork must not
        # follow, and must not be reseeded.
        (pi_source / "marker").write_text("pi-host-later")
        t4 = launch_tool("T4", "tool-bridge", "bridge")
        record("CM-T4", "CM-T4 pi=pi-guest guest-file=present", guest_line(t4, "CM-T4"))
        cleanup(launches[-1], "T4")
        if "==> Reusing fork" not in t4 or "Initialized fork" in t4:
            raise AssertionError("CM-T4: the inherited Pi fork was not reused")
        record("CM-T4-host",
               {"identity": identity, "pi-source": "pi-host-later"},
               {"identity": pi_fork_identity(work), "pi-source": marker(pi_source / "marker")})

        t5 = launch_script_shell("T5", "tool-shell")
        record("CM-T5",
               "CM-T5 agent=agent-seed skills=skills-seed ro-write=denied pi=pi-guest "
               "project=present",
               guest_line(t5, "CM-T5"))
        cleanup(launches[-1], "T5")
        record("CM-T5-host", {"ro": tool_ro, "pi-source": "pi-host-later"},
               {"ro": ro_now(), "pi-source": marker(pi_source / "marker")})

        # T6: the declared shell switches inheritance off; its own leaf and the
        # user-wide default survive, both read-only.
        write_tool_config("T6", TOOLS_EMPTY_SHELL)
        t6 = launch_script_shell("T6", "tool-shell-own")
        record("CM-T6",
               "CM-T6 agent=absent skills=absent readonly=absent pi=absent shell-own=shell-own "
               "shell-own-write=denied default=default default-write=denied",
               guest_line(t6, "CM-T6"))
        cleanup(launches[-1], "T6")
        record("CM-T6-host",
               {"shell-own": "shell-own", "default": "default"},
               {"shell-own": marker(tool / "shell-own/marker"),
                "default": marker(tool / "default/marker")})

        # T7: with no declared shell the built-in fallback runs in its own scope.
        write_tool_config("T7", TOOLS_FALLBACK_SHELL)
        t7 = launch_script_shell("T7", "tool-shell-fallback")
        record("CM-T7",
               "CM-T7 agent=absent skills=absent pi=absent shell-own=absent default=default "
               "default-write=denied project=present",
               guest_line(t7, "CM-T7"))
        cleanup(launches[-1], "T7")

        # T8: the automatic opt-out removes defaults, the shell's own leaf and
        # every inherited facet, on both a tool launch and the declared shell.
        write_tool_config("T8", TOOLS_OPTOUT)
        for row, verb in (("T8-pi", "pi"), ("T8-shell", "shell")):
            text = (launch_tool(row, "tool-optout", verb, ("--no-config-mounts",))
                    if verb != "shell"
                    else launch_script_shell(row, "tool-optout", ("--no-config-mounts",)))
            record(f"CM-T8-{verb}",
                   "CM-T8 agent=absent skills=absent readonly=absent pi=absent "
                   "shell-own=absent default=absent project=present",
                   guest_line(text, "CM-T8"))
            if "==> Config mounts: skipped" not in text:
                raise AssertionError(f"{row}: the opt-out left no skipped notice")
            cleanup(launches[-1], row)

        # T9: the explicit set returns exactly the agent topology, including the
        # separate read-only leaf; selecting a set named like a tool provisions no
        # tool, judged by that tool's own `persist` link (its mount is suppressed by
        # the opt-out either way, so the link is the observable this launch can see).
        write_tool_config("T9", TOOLS_SET_NAME)
        t9 = launch_tool("T9", "tool-set-explicit", "pi",
                         ("--no-config-mounts", "--mount", "agent"))
        record("CM-T9",
               "CM-T9 agent=agent-seed agent-write=wrote skills=skills-seed ro-write=denied "
               "readonly=readonly-seed readonly-write=denied pi=absent default=absent "
               "agent-tool=absent agent-tool-state=absent",
               guest_line(t9, "CM-T9"))
        cleanup(launches[-1], "T9")
        record("CM-T9-host", {"ro": tool_ro, "parent-write": "explicit-note"},
               {"ro": ro_now(), "parent-write": marker(tool / "agent/new")})

        # T9-control: the positive control for both observables. The same-named
        # tool *is* this launch, so its own leaf and its persist link both appear;
        # their absence in CM-T9 is then a measurement rather than a blind spot.
        t9c = launch_tool("T9-control", "tool-agent-name", "agent")
        record("CM-T9-control",
               "CM-T9-control agent-tool=agent-tool-seed agent-tool-state=present",
               guest_line(t9c, "CM-T9-control"))
        cleanup(launches[-1], "T9-control")

        # T10: the equivalent explicit fork declaration reuses the inherited
        # Pi fork even though the automatic sources are suppressed.
        t10 = launch_tool("T10", "tool-pi-explicit", "pi",
                          ("--no-config-mounts", "--mount", f"{pi_source}:{pi_source}:fork"))
        record("CM-T10", "CM-T10 pi=pi-guest guest-file=present agent=absent",
               guest_line(t10, "CM-T10"))
        cleanup(launches[-1], "T10")
        if "==> Reusing fork" not in t10 or "Initialized fork" in t10:
            raise AssertionError("T10: the explicit Pi fork was not reused")
        record("CM-T10-host", {"identity": identity, "pi-source": "pi-host-later"},
               {"identity": pi_fork_identity(work), "pi-source": marker(pi_source / "marker")})

        # T11: the same declaration as a top-level default, then through a nested
        # set — the route is the only difference, so no reseed and no new identity.
        for row, document in (("T11-default", TOOLS_DEFAULT_FORK),
                              ("T11-set", TOOLS_NESTED_SET)):
            write_tool_config(row, document)
            text = launch_tool(row, "tool-fork", "pi")
            record(f"CM-T11-{row.split('-', 1)[1]}",
                   "CM-T11 pi=pi-guest guest-file=present agent=absent",
                   guest_line(text, "CM-T11"))
            cleanup(launches[-1], row)
            if "==> Reusing fork" not in text or "Initialized fork" in text:
                raise AssertionError(f"{row}: the fork was reseeded")
            record(f"CM-T11-host-{row.split('-', 1)[1]}",
                   {"identity": identity, "pi-source": "pi-host-later"},
                   {"identity": pi_fork_identity(work),
                    "pi-source": marker(pi_source / "marker")})

        # ---- the automatic Git metadata rows (#535, ADR-0062) --------------
        # A real linked worktree, built by `git` before any baseline snapshot.
        # Every row also carries `LAUNCH_OPTIONS` (`--no-git`), so the whole
        # group proves independence from the GitHub-credential flag. The rows
        # themselves live in `run_gm_group`, which is what `--dispatch-check`
        # drives without a VM.
        gm = build_gm_fixture(work)
        gm_before = {"common-tree": gm_tree_digest(gm), "branch": gm_branch_oid(gm)}
        (evidence / "gm-before.json").write_text(json.dumps(gm_before, indent=2))

        def launch_gm(row, phase, flags=(), extra=()):
            argv = [binary, *LAUNCH_OPTIONS, *flags, "--image", image, *extra, "shell",
                    "bash", f"./{GM_PROBE.name}", phase, str(gm["common"])]
            if phase == "control":
                argv.append(GM_ALIAS)
            return run_row(row, tuple(argv), cwd=gm["worktree"])

        def cleanup_gm(row):
            cleanup(launches[-1], row)

        if run_gm_group(launch_gm, cleanup_gm, GmHost(gm),
                        record, record_blocked, gm_before) == "blocked":
            print(f"BLOCKED (guest image has no git): {', '.join(GM_ROWS)}", file=sys.stderr)

        # The read-only trees are the last thing measured: every row that had a
        # chance to write them is finished and its VM proven absent.
        record("CM-T-host-ro", tool_ro, ro_now())
        record("CM-T-host-protected", "unchanged", protected_now())
        record("CM-T-host-fork-identity", identity, pi_fork_identity(work))
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
        (evidence / "totals.json").write_text(json.dumps(receipt.totals(), indent=2))
        if not errors:
            shutil.rmtree(root)
        else:
            print(f"Owned scratch retained after failure: {root}", file=sys.stderr)
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


class FakeSeam:
    """A boot-free stand-in for `(launch, cleanup)`: canned guest output, recorded
    calls.

    Only the launch half is faked. The host oracle stays real, because a row that
    a fake launch can satisfy is exactly the row that cannot detect a faked
    commit.
    """

    def __init__(self, replies):
        self.replies = replies
        self.launched = []
        self.cleaned = []

    def launch(self, row, phase, flags=(), extra=()):
        self.launched.append((row, phase, flags, extra))
        reply = self.replies.get(phase)
        return reply() if callable(reply) else (reply or "")

    def cleanup(self, row):
        self.cleaned.append(row)


GM_RO_ROW = ("GM-N1 log=seed diff=tracked.txt write=denied add=denied\n"
             "==> Git metadata: linked worktree, read-only\n")


def gm_dispatch_check():
    """Boot-free: the GM group's **real dispatch** over fake launches (#535 M4).

    The two regressions this group had are driven end to end here, in the shape
    the review asked for: a `GM-MISSING` image blocks every row after one launch,
    and a guest line that names an object without committing makes GM-N2-host
    FAIL. The positive control really commits, so the oracle is shown to accept a
    good one rather than only to reject bad ones.
    """
    import tempfile

    failures = []

    def check(name, expected, actual):
        if expected != actual:
            failures.append(f"{name}: expected {expected!r}, got {actual!r}")

    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch) / "work"
        (work / "home").mkdir(parents=True)
        gm = build_gm_fixture(work)
        host = GmHost(gm)
        baseline = {"common-tree": host.common_tree(), "branch": host.branch()}

        # (a) No `git` in the image: one launch, seven BLOCKED rows, nothing passed,
        #     and no cleanup or launch after it.
        seam = FakeSeam({"ro": "GM-MISSING guest image has no git\n"})
        receipt = Rows(Path(scratch) / "blocked.tsv", quiet=True)
        check("(a) dispatch outcome", "blocked",
              run_gm_group(seam.launch, seam.cleanup, host,
                           receipt.record, receipt.blocked, baseline))
        check("(a) launches", [("GM-N1", "ro", (), ())], seam.launched)
        check("(a) cleanups", ["GM-N1"], seam.cleaned)
        check("(a) totals", {"rows": 7, "passed": 0, "blocked": list(GM_ROWS),
                            "failed": []}, receipt.totals())
        statuses = [line.rsplit("\t", 1)[1]
                    for line in (Path(scratch) / "blocked.tsv").read_text().splitlines()]
        check("(a) receipt statuses", ["BLOCKED"] * len(GM_ROWS), statuses)

        # (b) The guest prints the *seed* object id without committing: the shape
        #     passes, and the host oracle must catch it.
        seed = baseline["branch"]
        seam = FakeSeam({"ro": GM_RO_ROW, "rw": f"GM-N2 commit={seed}\n"})
        receipt = Rows(Path(scratch) / "unmoved.tsv", quiet=True)
        try:
            run_gm_group(seam.launch, seam.cleanup, host,
                         receipt.record, receipt.blocked, baseline)
        except AssertionError as error:
            check("(b) the failing row", True, str(error).startswith("GM-N2-host: "))
        else:
            failures.append("(b) a commit line naming the seed object passed the oracle")
        check("(b) totals", {"rows": 4, "passed": 3, "blocked": [],
                            "failed": ["GM-N2-host"]}, receipt.totals())

        # (c) The positive control: the launch really commits, and the oracle
        #     accepts it.
        def real_commit():
            gm["tracked"].write_text("seed\nguest-commit\n")
            gm_git(gm["home"], gm["worktree"], "add", "tracked.txt")
            gm_git(gm["home"], gm["worktree"], "commit", "-q", "-m", "gm-probe")
            oid = gm_git(gm["home"], gm["main"], "rev-parse", "gm").stdout.strip()
            return f"GM-N2 commit={oid}\n"

        def control_writes():
            (gm["common"] / "objects/gm-probe").write_text("gm-probe\n")
            return "GM-N4 automatic=denied alias=allowed\n"

        seam = FakeSeam({"ro": GM_RO_ROW, "rw": real_commit,
                         "off": "GM-N3 absent\n", "control": control_writes})
        receipt = Rows(Path(scratch) / "committed.tsv", quiet=True)
        check("(c) dispatch outcome", "measured",
              run_gm_group(seam.launch, seam.cleanup, host,
                           receipt.record, receipt.blocked, baseline))
        check("(c) totals", {"rows": 7, "passed": 7, "blocked": [], "failed": []},
              receipt.totals())
        check("(c) cleanups", ["GM-N1", "GM-N2", "GM-N3", "GM-N4"], seam.cleaned)

    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("GM dispatch check passed (GM-MISSING blocks all seven rows after one launch; "
          "a commit line naming the seed object fails GM-N2-host; a real commit passes)")
    return 0


def self_check():
    """Boot-free checks of the GM row logic (#535).

    The native rows are the only place these decisions run, so the decisions
    themselves are exercised here, without a VM: a missing `git` in the image must
    produce BLOCKED receipts that count as neither pass nor failure, and the GM-N2
    commit oracle must reject the three ways a commit can be wrong while the row
    still looks like a pass — an unmoved branch, a commit off the old tip, and a
    commit without the guest's edit.
    """
    import tempfile

    failures = []

    def check(name, expected, actual):
        if expected != actual:
            failures.append(f"{name}: expected {expected!r}, got {actual!r}")

    with tempfile.TemporaryDirectory() as scratch:
        summary = Path(scratch) / "summary.tsv"
        receipt = Rows(summary, quiet=True)
        receipt.record("R-pass", "same", "same")
        receipt.blocked("R-blocked")
        receipt.record("R-other-blocked", BLOCKED_NOTE, BLOCKED_NOTE, blocked=True)
        try:
            receipt.record("R-fail", "same", "different")
        except AssertionError:
            pass
        else:
            failures.append("a failing row did not raise")
        # A result that arrives while the row is blocked is still blocked: the
        # receipt may never be turned into a pass by what the row happened to say.
        receipt.record("R-blocked-with-output", "anything", "anything", blocked=True)
        check("totals", {"rows": 5, "passed": 1,
                         "blocked": ["R-blocked", "R-other-blocked", "R-blocked-with-output"],
                         "failed": ["R-fail"]}, receipt.totals())
        statuses = [line.rsplit("\t", 1)[1] for line in summary.read_text().splitlines()]
        check("summary statuses", ["PASS", "BLOCKED", "BLOCKED", "FAIL", "BLOCKED"], statuses)

    # The GM-N2 oracle, over the four observations it must tell apart.
    baseline = "a" * 40
    guest_commit = "b" * 40
    good = {"branch": guest_commit, "parent": baseline,
            "tracked": "seed\nguest-change\nguest-commit\n", "object": "present"}
    expected, actual = gm_n2_host_row(guest_commit, baseline, good)
    check("the good commit", expected, actual)
    for name, change in (
        ("unmoved branch", {"branch": baseline}),
        ("wrong parent", {"parent": "c" * 40}),
        ("no guest edit", {"tracked": "seed\n"}),
        ("no object", {"object": "absent"}),
    ):
        expected, actual = gm_n2_host_row(guest_commit, baseline, {**good, **change})
        if expected == actual:
            failures.append(f"the GM-N2 oracle accepted a commit with {name}")

    # A guest line that is not a full object id is not a commit.
    check("a refused commit",
          "GM-N2 commit=refused",
          gm_commit_row("GM-N2 commit=refused")[1])
    check("a real commit line",
          "GM-N2 commit=<40-hex object id>",
          gm_commit_row(f"GM-N2 commit={guest_commit}")[1])

    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("GM row logic self-check passed (BLOCKED is not a pass; the commit oracle "
          "rejects an unmoved branch, a wrong parent, a missing edit and a missing object)")
    return 0


if __name__ == "__main__":
    mode = sys.argv[1:]
    if mode == ["--self-check"]:
        raise SystemExit(self_check())
    if mode == ["--dispatch-check"]:
        raise SystemExit(gm_dispatch_check())
    raise SystemExit(main())
