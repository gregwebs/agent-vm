#!/usr/bin/env bash
# Contract for the build-identity probe (issue #335, controls B1-B19).
#
# Every fixture is an owned miniature Cargo workspace whose package sits two
# levels below a real Git repository, exactly like the shipped layout. The
# **actual** `crates/agent-vm/build.rs` is copied in, so Cargo fingerprints and
# Git discovery are exercised for real, not mocked. All Git mutations happen
# only inside these owned temporary directories.
#
# The runner inspects Cargo's parsed `run-build-script` fingerprint paths, not
# just emitted stdout, and records whether the probe and launcher rustc reran.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
repo="$(cd -- "${BASH_SOURCE[0]%/*}/../.." && pwd -P)"
channel="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$repo/rust-toolchain.toml")"
[[ -n "$channel" ]] || { echo 'cannot read the toolchain channel' >&2; exit 1; }
if [[ -n "${AGENT_VM_BUILD_PROVENANCE_STRICT:-}" ]]; then
    echo 'run this contract with AGENT_VM_BUILD_PROVENANCE_STRICT unset' >&2
    exit 1
fi
export AGENT_VM_BUILD_RS="$repo/crates/agent-vm/build.rs"
export AGENT_VM_FIXTURE_TOOLCHAIN="$channel"

python3 - "$repo" <<'PY'
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(sys.argv[1])
BUILD_RS = Path(os.environ["AGENT_VM_BUILD_RS"])
TOOLCHAIN = os.environ["AGENT_VM_FIXTURE_TOOLCHAIN"]
FALLBACK_DEPENDENCY = "build.rs/agent-vm-provenance-always-rerun"
CARGO = shutil.which("cargo")
assert CARGO, "cargo must be on PATH"
RUSTC = shutil.which("rustc")
assert RUSTC, "rustc must be on PATH"

PASSES = []
FAILURES = []
LOG_DIR = None
RUN_NUMBER = 0


def check(case, condition, detail=""):
    if condition:
        PASSES.append(case)
        print(f"PASS {case}")
    else:
        FAILURES.append((case, detail))
        print(f"FAIL {case}: {detail}")
    return bool(condition)


def base_env():
    # Deliberately rebuilt from scratch so no inherited SHA override, strict
    # flag or Git routing leaks in. `GIT_CONFIG_GLOBAL=/dev/null` keeps the
    # operator's global config and credential helpers out of every fixture.
    return {
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", "/tmp"),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        "RUSTUP_TOOLCHAIN": TOOLCHAIN,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_NAME": "fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_TERMINAL_PROMPT": "0",
    }


def run(command, *, cwd, env=None, check_=True, timeout=600):
    proc = subprocess.run(
        command, cwd=str(cwd), env=env or base_env(), capture_output=True,
        text=True, timeout=timeout,
    )
    global RUN_NUMBER
    if LOG_DIR is not None and command[0] == CARGO:
        RUN_NUMBER += 1
        (LOG_DIR / f"cargo-{RUN_NUMBER:04}.log").write_text(proc.stdout + proc.stderr)
    if check_ and proc.returncode != 0:
        raise RuntimeError(
            f"{' '.join(command)} failed ({proc.returncode}): {proc.stderr[-2000:]}"
        )
    return proc


def git(root, *args, env=None, check_=True):
    return run(
        ["git", "--no-optional-locks", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=always", *args],
        cwd=root, env=env, check_=check_,
    )


def head(root, env=None):
    return git(root, "rev-parse", "HEAD", env=env).stdout.strip()


def rebuild_events(log):
    script = len(re.findall(r"Running `.*build-script-build`", log))
    rustc = len(re.findall(r"Running `.*--crate-name agent_vm ", log))
    return script, rustc


def provenance_diagnostics(proc):
    # Only the probe's own fixed messages, never Cargo's verbose command line
    # (which echoes watched env values and would defeat a no-echo assertion).
    return "\n".join(
        line for line in (proc.stdout + proc.stderr).splitlines() if "build provenance:" in line
    )


class Fixture:
    def __init__(self, root, *, git_init=True):
        self.root = Path(root)
        self.pkg = self.root / "crates" / "agent-vm"
        (self.pkg / "src").mkdir(parents=True, exist_ok=True)
        (self.pkg / "Cargo.toml").write_text(
            '[package]\nname = "agent-vm"\nversion = "0.0.1"\nedition = "2024"\n\n'
            "[workspace]\n"
        )
        (self.pkg / "src/main.rs").write_text(
            'fn main() { println!("{}", concat!("agent-vm ", '
            'env!("AGENT_VM_BUILD_VERSION"))); }\n'
        )
        shutil.copyfile(BUILD_RS, self.pkg / "build.rs")
        (self.root / ".gitignore").write_text("target/\n")
        self.target = self.root / "target"
        if git_init:
            git(self.root, "init", "-q", "-b", "main")
            git(self.root, "config", "core.filemode", "true")

    def commit(self, message="c"):
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "--no-gpg-sign", "-m", message)

    def build(self, extra=None, target=None, args=("build",), check_=True):
        env = base_env()
        env["CARGO_TARGET_DIR"] = str(target or self.target)
        if extra:
            env.update(extra)
        return run(
            [CARGO, *args, "--offline", "-vv", "--manifest-path", str(self.pkg / "Cargo.toml")],
            cwd=self.root, env=env, check_=check_,
        )

    def version(self, target=None):
        binary = (target or self.target) / "debug/agent-vm"
        return run([str(binary), "--version"], cwd=self.root).stdout

    def fingerprint_paths(self, target=None):
        paths = set()
        target = target or self.target
        for jf in (target / "debug/.fingerprint").glob("*/*.json"):
            try:
                data = json.loads(jf.read_text())
            except (OSError, ValueError):
                continue
            for entry in data.get("local", []):
                rerun = entry.get("RerunIfChanged")
                if isinstance(rerun, dict):
                    paths.update(rerun.get("paths", []))
        return paths


def expect(sha, *, dirty=False, state_unknown=False, unknown=False):
    if unknown:
        return "agent-vm 0.0.1 (unknown, dirty)\n" if dirty else "agent-vm 0.0.1 (unknown)\n"
    if state_unknown:
        return f"agent-vm 0.0.1 ({sha}, state unknown)\n"
    suffix = ", dirty" if dirty else ""
    return f"agent-vm 0.0.1 ({sha}{suffix})\n"


def assert_fresh(fx, case, target=None, extra=None):
    before = len(fx.fingerprint_paths(target))
    proc = fx.build(extra, target=target)
    script, rustc = rebuild_events(proc.stdout + proc.stderr)
    check(case, script == 0 and rustc == 0,
          f"expected a no-op fresh build, got probe={script} rustc={rustc} (fingerprint paths={before})")


def case_b1(work):
    fx = Fixture(work / "b1")
    fx.commit()
    sha = head(fx.root)
    fx.build()
    check("B1 clean local repository", fx.version() == expect(sha), fx.version().strip())


def case_b2(work):
    fx = Fixture(work / "b2")
    (fx.root / "notes.txt").write_text("one\n")
    fx.commit()
    sha = head(fx.root)
    fx.build()
    check("B2 baseline clean", fx.version() == expect(sha), fx.version().strip())
    (fx.root / "notes.txt").write_text("two\n")
    fx.build()
    check("B2 unstaged tracked edit is dirty", fx.version() == expect(sha, dirty=True), fx.version().strip())
    git(fx.root, "add", "notes.txt")
    fx.build()
    check("B2 staged tracked edit is dirty", fx.version() == expect(sha, dirty=True), fx.version().strip())
    git(fx.root, "reset", "-q")
    (fx.root / "notes.txt").unlink()
    fx.build()
    check("B2 tracked deletion is dirty", fx.version() == expect(sha, dirty=True), fx.version().strip())


def case_b3(work):
    fx = Fixture(work / "b3")
    (fx.root / ".gitignore").write_text("ignored/\n")
    (fx.root / "tracked.txt").write_text("x\n")
    fx.commit()
    sha = head(fx.root)
    fx.build()
    (fx.root / "untracked.txt").write_text("u\n")
    (fx.root / "ignored").mkdir()
    (fx.root / "ignored" / "thing").write_text("i\n")
    fx.build()
    check("B3 untracked and ignored files stay clean", fx.version() == expect(sha), fx.version().strip())


def case_b4(work):
    fx = Fixture(work / "b4")
    fx.commit()
    sha_a = head(fx.root)
    fx.build()
    check("B4 baseline A", fx.version() == expect(sha_a), fx.version().strip())
    git(fx.root, "checkout", "-q", "-b", "x")
    git(fx.root, "commit", "-q", "--no-gpg-sign", "--allow-empty", "-m", "b")
    sha_b = head(fx.root)
    fx.build()
    check("B4 empty commit B changes identity", fx.version() == expect(sha_b), fx.version().strip())
    git(fx.root, "checkout", "-q", "main")
    fx.build()
    check("B4 branch switch back to A", fx.version() == expect(sha_a), fx.version().strip())
    git(fx.root, "checkout", "-q", "--detach", "x")
    fx.build()
    check("B4 detached at B", fx.version() == expect(sha_b), fx.version().strip())


def case_b5(work):
    fx = Fixture(work / "b5")
    fx.commit()
    sha = head(fx.root)
    fx.build()
    check("B5 baseline clean", fx.version() == expect(sha), fx.version().strip())
    git(fx.root, "pack-refs", "--all")
    fx.build()
    check("B5 first packing keeps HEAD", fx.version() == expect(sha), fx.version().strip())
    assert_fresh(fx, "B5 fresh after first packing")
    # Recreate a loose terminal before observing no-prune and prune separately.
    git(fx.root, "commit", "-q", "--no-gpg-sign", "--allow-empty", "-m", "loose")
    sha2 = head(fx.root)
    fx.build()
    check("B5 packed terminal to new loose commit", fx.version() == expect(sha2), fx.version().strip())
    assert_fresh(fx, "B5 fresh after new loose commit")
    loose = fx.root / ".git/refs/heads/main"
    git(fx.root, "pack-refs", "--all", "--no-prune")
    fx.build()
    check("B5 no-prune retains loose ref and correct HEAD", loose.exists() and fx.version() == expect(sha2))
    assert_fresh(fx, "B5 fresh after no-prune")
    git(fx.root, "pack-refs", "--all", "--prune")
    proc = fx.build()
    check("B5 prune independently invalidates and removes loose ref",
          not loose.exists() and rebuild_events(proc.stdout + proc.stderr) != (0, 0)
          and fx.version() == expect(sha2))
    assert_fresh(fx, "B5 fresh after prune")
    git(fx.root, "pack-refs", "--all")
    fx.build()
    check("B5 repeated packing keeps HEAD", fx.version() == expect(sha2), fx.version().strip())
    assert_fresh(fx, "B5 fresh after repeated packing")
    linked = work / "b5-linked"
    git(fx.root, "worktree", "add", "-q", "-b", "linked", str(linked))
    wt = Fixture(linked, git_init=False)
    wt.build()
    check("B5 real linked worktree clean", (linked / ".git").is_file() and wt.version() == expect(sha2))
    git(linked, "commit", "-q", "--no-gpg-sign", "--allow-empty", "-m", "linked commit")
    wt.build()
    check("B5 linked worktree commit invalidates", wt.version() == expect(head(linked)))
    assert_fresh(wt, "B5 linked worktree unchanged fresh")


def case_b6(work):
    fx = Fixture(work / "b6")
    (fx.root / "outside.txt").write_text("base\n")
    fx.commit()
    sha = head(fx.root)
    fx.build()
    (fx.root / "outside.txt").write_text("edited\n")
    fx.build()
    check("B6 non-crate tracked edit is dirty", fx.version() == expect(sha, dirty=True), fx.version().strip())
    (fx.root / "outside.txt").write_text("base\n")
    fx.build()
    check("B6 revert is clean again", fx.version() == expect(sha), fx.version().strip())
    (fx.root / "outside.txt").unlink()
    fx.build()
    check("B6 deletion is dirty", fx.version() == expect(sha, dirty=True), fx.version().strip())
    git(fx.root, "add", "-A")
    git(fx.root, "commit", "-q", "--no-gpg-sign", "-m", "delete")
    sha2 = head(fx.root)
    fx.build()
    check("B6 commit with deletion pins new HEAD", fx.version() == expect(sha2), fx.version().strip())


def make_submodule(fx, name="vendor/sub"):
    origin = fx.root.parent / f"{fx.root.name}-origin"
    origin.mkdir()
    git(origin, "init", "-q", "-b", "main")
    (origin / "sub.txt").write_text("sub\n")
    git(origin, "add", "-A")
    git(origin, "commit", "-q", "--no-gpg-sign", "-m", "sub")
    git(fx.root, "submodule", "add", "-q", str(origin), name)
    return origin, fx.root / name


def case_b7(work):
    fx = Fixture(work / "b7")
    (fx.root / "top.txt").write_text("top\n")
    fx.commit()
    origin, sub = make_submodule(fx)
    fx.commit()
    sha = head(fx.root)
    fx.build()
    check("B7 baseline clean with submodule", fx.version() == expect(sha), fx.version().strip())
    (sub / "sub.txt").write_text("changed\n")
    fx.build()
    check("B7 submodule content edit is dirty", fx.version() == expect(sha, dirty=True), fx.version().strip())
    git(sub, "checkout", "-q", "--", "sub.txt")
    fx.build()
    check("B7 submodule revert is clean", fx.version() == expect(sha), fx.version().strip())
    git(sub, "add", "sub.txt")
    (sub / "sub.txt").write_text("staged\n")
    git(sub, "add", "sub.txt")
    fx.build()
    check("B7 submodule staged edit is dirty", fx.version() == expect(sha, dirty=True), fx.version().strip())
    git(sub, "reset", "-q", "--hard")
    git(sub, "commit", "-q", "--no-gpg-sign", "--allow-empty", "-m", "sub2")
    fx.build()
    check("B7 submodule commit moves gitlink to dirty", fx.version() == expect(sha, dirty=True), fx.version().strip())
    git(sub, "checkout", "-q", "--detach", head(origin))
    fx.build()
    check("B7 submodule ref switch restores clean gitlink", fx.version() == expect(sha))
    assert not git(fx.root, "status", "--porcelain", "-uno").stdout
    (sub / "untracked.txt").write_text("u\n")
    assert_fresh(fx, "B7 default submodule untracked stays fresh")
    # Fresh cached output cannot test the measurement's untracked policy.
    proc = fx.build({"AGENT_VM_BUILD_PROVENANCE_STRICT": "1"})
    check("B7 untracked-submodule measurement executes probe",
          rebuild_events(proc.stdout + proc.stderr)[0] > 0)
    check("B7 from-clean submodule untracked stays clean",
          not git(fx.root, "status", "--porcelain", "--untracked-files=no",
                  "--ignore-submodules=untracked").stdout
          and bool(git(fx.root, "status", "--porcelain", "--untracked-files=no",
                       "--ignore-submodules=none").stdout)
          and fx.version() == expect(sha), fx.version().strip())
    (sub / "untracked.txt").unlink()
    proxy = Fixture.__new__(Fixture)
    proxy.root = sub
    _, nested = make_submodule(proxy, "nested")
    git(sub, "add", "-A")
    git(sub, "commit", "-q", "--no-gpg-sign", "-m", "nested")
    fx.commit()
    sha = head(fx.root)
    fx.build()
    check("B7 nested submodule clean baseline", fx.version() == expect(sha))
    (nested / "sub.txt").write_text("nested dirt\n")
    proc = fx.build()
    check("B7 nested tracked content invalidates",
          bool(git(fx.root, "status", "--porcelain", "-uno").stdout)
          and rebuild_events(proc.stdout + proc.stderr) != (0, 0)
          and fx.version() == expect(sha, dirty=True))
    git(nested, "checkout", "-q", "--", "sub.txt")
    fx.build()
    check("B7 nested restoration clean", fx.version() == expect(sha))


def case_b8(work):
    fx = Fixture(work / "b8")
    fx.commit()
    sha_c = head(fx.root)
    sha_a = "a" * 40
    sha_b = "b" * 40
    fx.build({"AGENT_VM_GIT_SHA": sha_a, "GITHUB_SHA": sha_b})
    check("B8 explicit override beats GITHUB_SHA and HEAD", fx.version() == expect(sha_a), fx.version().strip())
    fx.build({"GITHUB_SHA": sha_b})
    check("B8 GITHUB_SHA beats local HEAD", fx.version() == expect(sha_b), fx.version().strip())
    fx.build()
    check("B8 no override falls back to HEAD", fx.version() == expect(sha_c), fx.version().strip())


def case_b9(work):
    fx = Fixture(work / "b9")
    fx.commit()
    sha = head(fx.root)
    upper = "ABCDEF" + "0" * 34
    fx.build({"AGENT_VM_GIT_SHA": upper})
    check("B9 uppercase override is normalized", fx.version() == expect(upper.lower()), fx.version().strip())
    # A 64-character object id is accepted and normalized exactly, with no
    # second Git object format installed (sha256 repos are not required).
    full64 = "ABCDEF" + "1" * 58
    fx.build({"AGENT_VM_GIT_SHA": full64})
    check("B9 64-hex override is accepted and normalized",
          fx.version() == expect(full64.lower()), fx.version().strip())
    for label, value in [
        ("short", "abc123"),
        ("63-hex", "1" * 63),
        ("65-hex", "2" * 65),
        ("empty", ""),
        ("newline", "aa\nbb"),
        ("nonhex", "z" * 40),
        ("ref", "refs/heads/main"),
    ]:
        proc = fx.build({"AGENT_VM_GIT_SHA": value})
        output = fx.version()
        diagnostics = provenance_diagnostics(proc)
        no_echo = value == "" or value not in diagnostics
        check(
            f"B9 invalid override ({label}) falls back without echo",
            output == expect(sha) and no_echo and "\r" not in output,
            f"{output.strip()} diagnostics={diagnostics[:120]}",
        )
    injected = "cargo:rustc-env=AGENT_VM_BUILD_VERSION=evil\n"
    fx.build({"AGENT_VM_GIT_SHA": injected})
    check("B9 newline override cannot inject a directive",
          fx.version() == expect(sha) and "evil" not in fx.version(), fx.version().strip())


def case_b10(work):
    fx = Fixture(work / "b10")
    (fx.root / "notes.txt").write_text("a\n")
    fx.commit()
    sha_a = "c" * 40
    (fx.root / "notes.txt").write_text("b\n")
    fx.build({"AGENT_VM_GIT_SHA": sha_a})
    check("B10 override with tracked dirt is dirty", fx.version() == expect(sha_a, dirty=True), fx.version().strip())
    git(fx.root, "checkout", "-q", "--", "notes.txt")
    deceit = work / "b10-broken-git-bin"
    deceit.mkdir(exist_ok=True)
    broken_git = deceit / "git"
    broken_git.write_text("#!/bin/sh\nexit 127\n")
    broken_git.chmod(0o755)
    no_git = base_env()
    no_git["PATH"] = f"{deceit}:{os.environ['PATH']}"
    no_git["CARGO_TARGET_DIR"] = str(fx.target)
    no_git["AGENT_VM_GIT_SHA"] = sha_a
    run([CARGO, "build", "--offline", "-vv", "--manifest-path", str(fx.pkg / "Cargo.toml")],
        cwd=fx.root, env=no_git)
    check("B10 override with Git unavailable is state unknown",
          fx.version() == expect(sha_a, state_unknown=True), fx.version().strip())


def case_b11(work):
    fx = Fixture(work / "b11", git_init=False)
    fx.build()
    check("B11 no Git metadata is unknown", fx.version() == expect("", unknown=True), fx.version().strip())
    git(fx.root, "init", "-q", "-b", "main")
    git(fx.root, "config", "core.filemode", "true")
    fx.commit()
    sha = head(fx.root)
    fx.build()
    check("B11 Git restored recovers the real HEAD", fx.version() == expect(sha), fx.version().strip())


def case_b12(work):
    outer = work / "b12"
    (outer / "nested").mkdir(parents=True)
    git(outer, "init", "-q", "-b", "main")
    (outer / "outer.txt").write_text("outer\n")
    git(outer, "add", "-A")
    git(outer, "commit", "-q", "--no-gpg-sign", "-m", "outer")
    # A tarball unpacked inside an unrelated checkout: its own directory is not
    # a Git top level, so the outer repository's identity must not be adopted.
    fx = Fixture(outer / "nested", git_init=False)
    fx.build()
    check("B12 tarball nested in an unrelated repo is unknown",
          fx.version() == expect("", unknown=True), fx.version().strip())


def case_b13(work):
    origin = Fixture(work / "b13-origin")
    origin.commit("first")
    make_submodule(origin)
    origin.commit("second with optional gitlink")
    git(origin.root, "commit", "-q", "--no-gpg-sign", "--allow-empty", "-m", "third")
    clone = work / "b13-clone"
    git(work, "clone", "-q", "--depth", "1", origin.root.as_uri(), str(clone))
    fx = Fixture(clone, git_init=False)
    check("B13 actual file-transport shallow clone",
          (clone / ".git/shallow").is_file()
          and git(clone, "rev-parse", "--is-shallow-repository").stdout.strip() == "true"
          and git(clone, "rev-list", "--count", "HEAD").stdout.strip() == "1"
          and git(origin.root, "rev-list", "--count", "HEAD").stdout.strip() == "3")
    check("B13 optional gitlink remains uninitialized",
          (clone / "vendor/sub").is_dir() and not (clone / "vendor/sub/.git").exists())
    fx.build()
    check("B13 shallow clone with uninitialized gitlink is clean", fx.version() == expect(head(clone)))
    assert_fresh(fx, "B13 shallow optional gitlink stays fresh")


def case_b14(work):
    fx = Fixture(work / "b14")
    (fx.root / "outside.txt").write_text("base\n")
    fx.commit()
    sha = head(fx.root)
    fx.build()
    paths = fx.fingerprint_paths()
    check("B14 complete discovery omits the ENOTDIR fallback",
          FALLBACK_DEPENDENCY not in paths, f"fallback present: {sorted(p for p in paths if 'rerun' in p)}")
    assert_fresh(fx, "B14 first unchanged default build is fresh")
    assert_fresh(fx, "B14 second unchanged default build is fresh")
    (fx.root / "outside.txt").write_text("dirty-one\n")
    fx.build()
    check("B14 dirty content build is dirty", fx.version() == expect(sha, dirty=True), fx.version().strip())
    assert_fresh(fx, "B14 unchanged dirty build is fresh")
    (fx.root / "outside.txt").write_text("dirty-two\n")
    proc = fx.build()
    probe, rustc = rebuild_events(proc.stdout + proc.stderr)
    check("B14 dirty-X to dirty-Y reruns and stays dirty",
          probe > 0 and rustc > 0 and fx.version() == expect(sha, dirty=True),
          f"probe={probe} rustc={rustc}")


def case_b15(work):
    fx = Fixture(work / "b15")
    (fx.root / "note").write_text("plain\n")
    (fx.root / "note ").write_text("trailing space\n")
    (fx.root / "note middle").write_text("interior space\n")
    fx.commit()
    sha = head(fx.root)
    fx.build()
    paths = fx.fingerprint_paths()
    check("B15 safe names are package-relative spellings",
          "../../note" in paths and "../../note middle" in paths,
          str(sorted(p for p in paths if p.endswith("note") or "note" in p))[:300])
    check("B15 terminal-space candidate is omitted, not trimmed",
          "../../note " not in paths and "build.rs/agent-vm-provenance-always-rerun" in paths,
          "unsafe candidate was emitted or fallback missing")
    check("B15 no raw absolute watcher path", not any(p.startswith("/") for p in paths),
          str([p for p in paths if p.startswith("/")])[:200])
    (fx.root / "note ").write_text("edited trailing space\n")
    fx.build()
    check("B15 editing only the unsafe name still reports dirty",
          fx.version() == expect(sha, dirty=True), fx.version().strip())
    # Independent unsafe-name fixtures: one cannot mask another's omission.
    for label, name in [("LF", b"bad\nname"), ("CR", b"bad\rname"),
                        ("unicode", "caf\u00e9.txt".encode()), ("nonunicode", b"bad\xffname")]:
        weird = Fixture(work / f"b15-{label}")
        try:
            fd = os.open(os.fsencode(weird.root) + b"/" + name, os.O_CREAT | os.O_WRONLY, 0o644)
            os.close(fd)
        except OSError as error:
            if label != "nonunicode":
                raise
            print(f"NOTE B15 non-Unicode tracked name not runnable here: {error}")
            continue
        weird.commit()
        proc = weird.build()
        paths = weird.fingerprint_paths()
        check(f"B15 independent {label} name fallback",
              FALLBACK_DEPENDENCY in paths and "incomplete" in provenance_diagnostics(proc)
              and not any("\n" in p or "\r" in p or not p.isascii() for p in paths))
    # Source and target hazards are independent fixtures, so neither masks the other.
    for label, odd_name in [("spaces", "path middle"), ("unicode", "path-\u00e9"),
                            ("CR", "path\rroot"), ("LF", "path\nroot"),
                            ("terminal-space", "path ")]:
        for dimension in ["source", "target"]:
            base = work / f"b15-{dimension}-{label}"
            odd = Fixture(base / (odd_name if dimension == "source" else "source"))
            odd.commit()
            target = work / f"b15-output-{dimension}-{label}" / (odd_name if dimension == "target" else "target")
            odd.build(target=target)
            paths = odd.fingerprint_paths(target)
            unknown = dimension == "source" and label in ["CR", "LF"]
            check(f"B15 independent odd {label} {dimension}",
                  not any(p.startswith("/") or "\r" in p or "\n" in p or not p.isascii() for p in paths)
                  and odd.version(target) == (expect("", unknown=True) if unknown else expect(head(odd.root))))
    for label, common_name in [("spaces", "common middle"), ("CR", "common\rdir"),
                               ("unicode", "common-\u00e9")]:
        odd = Fixture(work / f"b15-common-{label}")
        odd.commit()
        common = work / common_name
        shutil.move(str(odd.root / ".git"), common)
        (odd.root / ".git").write_text(f"gitdir: {common}\n")
        proc = odd.build()
        paths = odd.fingerprint_paths()
        check(f"B15 independent odd {label} common Git dir",
              not any("\r" in p or not p.isascii() or p.startswith("/") for p in paths)
              and (any("common middle" in p for p in paths) if label == "spaces"
                   else FALLBACK_DEPENDENCY in paths and "incomplete" in provenance_diagnostics(proc)))


def chmod_executable(path, executable):
    mode = path.stat().st_mode
    path.chmod(mode | 0o111 if executable else mode & ~0o111)


def case_b16(work):
    fx = Fixture(work / "b16")
    script = fx.root / "run.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o755)
    fx.commit()
    sha = head(fx.root)
    strict = {"AGENT_VM_BUILD_PROVENANCE_STRICT": "1"}
    fx.build(strict)
    check("B16 strict clean baseline", fx.version() == expect(sha), fx.version().strip())
    paths = fx.fingerprint_paths()
    check("B16 strict emits the new child-of-build.rs dependency",
          FALLBACK_DEPENDENCY in paths and ".agent-vm-provenance-always-rerun" not in paths, str(sorted(paths))[:200])
    # A preserved-timestamp collision at the *old* reserved name.
    collision = fx.root / ".agent-vm-provenance-always-rerun"
    old = 946684800
    collision.write_text("collision\n")
    os.utime(collision, (old, old))
    chmod_executable(script, False)
    proc = fx.build(strict)
    probe, rustc = rebuild_events(proc.stdout + proc.stderr)
    check("B16 old-name file collision cannot disable strict",
          probe > 0 and rustc > 0 and fx.version() == expect(sha, dirty=True),
          f"probe={probe} rustc={rustc} version={fx.version().strip()}")
    chmod_executable(script, True)
    fx.build(strict)
    check("B16 strict reports clean after mode restore", fx.version() == expect(sha), fx.version().strip())
    collision.unlink()
    collision.mkdir()
    os.utime(collision, (old, old))
    chmod_executable(script, False)
    proc = fx.build(strict)
    probe, rustc = rebuild_events(proc.stdout + proc.stderr)
    check("B16 old-name directory collision cannot disable strict",
          probe > 0 and rustc > 0 and fx.version() == expect(sha, dirty=True),
          f"probe={probe} rustc={rustc} version={fx.version().strip()}")
    chmod_executable(script, True)
    proc = fx.build(strict)
    probe, rustc = rebuild_events(proc.stdout + proc.stderr)
    check("B16 unchanged strict build reruns", probe > 0 and rustc > 0, f"probe={probe} rustc={rustc}")
    # Default mode: only an untracked old-name entry must stay fresh.
    default = Fixture(work / "b16-default")
    default.commit()
    default.build()
    (default.root / ".agent-vm-provenance-always-rerun").write_text("collision\n")
    os.utime(default.root / ".agent-vm-provenance-always-rerun", (old, old))
    assert_fresh(default, "B16 default untracked old-name entry stays fresh")
    fallback = Fixture(work / "b16-fallback", git_init=False)
    fallback.build()
    for kind in ["file", "directory"]:
        collision = fallback.root / ".agent-vm-provenance-always-rerun"
        if kind == "file":
            collision.write_text("collision\n")
        else:
            collision.unlink()
            collision.mkdir()
        os.utime(collision, (old, old))
        proc = fallback.build()
        probe, rustc = rebuild_events(proc.stdout + proc.stderr)
        check(f"B16 fallback old-name {kind} collision retries",
              probe > 0 and rustc > 0 and FALLBACK_DEPENDENCY in fallback.fingerprint_paths())


def case_b17(work):
    fx = Fixture(work / "b17")
    script = fx.root / "tool.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o755)
    fx.commit()
    sha = head(fx.root)
    fx.build()
    check("B17 default baseline clean", fx.version() == expect(sha), fx.version().strip())
    chmod_executable(script, False)
    assert_fresh(fx, "B17 accepted default residual: mode-only chmod stays fresh")
    check("B17 default may retain a stale clean label", fx.version() == expect(sha), fx.version().strip())
    strict = {"AGENT_VM_BUILD_PROVENANCE_STRICT": "1"}
    fx.build(strict)
    check("B17 strict detects mode-only dirt", fx.version() == expect(sha, dirty=True), fx.version().strip())
    chmod_executable(script, True)
    fx.build(strict)
    check("B17 strict clean after restore", fx.version() == expect(sha), fx.version().strip())
    # Symlink replacement to an older-mtime target.
    target = fx.root / "older-target"
    target.write_text("target\n")
    target_old = 946684800
    os.utime(target, (target_old, target_old))
    regular = fx.root / "regular.txt"
    regular.write_text("regular\n")
    regular.chmod(0o644)
    git(fx.root, "add", "older-target", "regular.txt")
    git(fx.root, "commit", "-q", "--no-gpg-sign", "-m", "add")
    sha2 = head(fx.root)
    fx.build(strict)
    regular.unlink()
    regular.symlink_to("older-target")
    fx.build(strict)
    check("B17 strict detects a regular-to-symlink transition",
          fx.version() == expect(sha2, dirty=True), fx.version().strip())
    regular.unlink()
    regular.write_text("regular\n")
    regular.chmod(0o644)
    fx.build(strict)
    check("B17 strict clean after symlink restore", fx.version() == expect(sha2), fx.version().strip())
    _, sub = make_submodule(fx)
    tool = sub / "tool.sh"
    tool.write_text("#!/bin/sh\nexit 0\n")
    tool.chmod(0o755)
    git(sub, "config", "core.filemode", "true")
    git(sub, "add", "-A")
    git(sub, "commit", "-q", "--no-gpg-sign", "-m", "tool")
    fx.commit()
    sha3 = head(fx.root)
    fx.build(strict)
    before = tool.stat().st_mtime_ns
    chmod_executable(tool, False)
    proc = fx.build(strict)
    check("B17 strict submodule chmod dirt with unchanged mtime",
          before == tool.stat().st_mtime_ns and bool(git(fx.root, "status", "--porcelain", "-uno").stdout)
          and rebuild_events(proc.stdout + proc.stderr) != (0, 0)
          and fx.version() == expect(sha3, dirty=True))
    chmod_executable(tool, True)
    fx.build(strict)
    check("B17 strict submodule chmod restoration", fx.version() == expect(sha3))


def case_b18(work):
    fx = Fixture(work / "b18")
    script = fx.root / "tool.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o755)
    fx.commit()
    sha = head(fx.root)
    fx.build()
    check("B18 default baseline clean", fx.version() == expect(sha), fx.version().strip())
    chmod_executable(script, False)
    assert_fresh(fx, "B18 default chmod stays fresh (accepted residual)")
    fx.build({"AGENT_VM_BUILD_PROVENANCE_STRICT": "1"})
    check("B18 enabling strict measures dirt", fx.version() == expect(sha, dirty=True), fx.version().strip())
    chmod_executable(script, True)
    fx.build({"AGENT_VM_BUILD_PROVENANCE_STRICT": "1"})
    check("B18 strict reports clean after restore", fx.version() == expect(sha), fx.version().strip())
    proc = fx.build()
    check("B18 unsetting strict reruns once",
          rebuild_events(proc.stdout + proc.stderr) != (0, 0), "no rerun on unset transition")
    assert_fresh(fx, "B18 cheap behavior returns after unset")
    for value in ("2", "true"):
        proc = fx.build({"AGENT_VM_BUILD_PROVENANCE_STRICT": value}, check_=False)
        diagnostics = provenance_diagnostics(proc)
        check(f"B18 invalid strict value {value!r} hard-fails value-free",
              proc.returncode != 0 and value not in diagnostics
              and "AGENT_VM_BUILD_PROVENANCE_STRICT" in diagnostics,
              f"rc={proc.returncode} diagnostics={diagnostics[:120]}")
    for value in ("0", "1", ""):
        proc = fx.build({"AGENT_VM_BUILD_PROVENANCE_STRICT": value})
        check(f"B18 accepted strict value {value!r} builds", proc.returncode == 0, proc.stderr[-200:])
    # absent -> non-Unicode: invisible to Cargo's env fingerprint.
    clean_ws = Fixture(work / "b18-nonunicode")
    clean_ws.commit()
    clean_ws.build()
    env = base_env()
    env["CARGO_TARGET_DIR"] = str(clean_ws.target)
    env[b"AGENT_VM_BUILD_PROVENANCE_STRICT"] = b"\xff"
    before = clean_ws.version()
    proc = run([CARGO, "build", "--offline", "-vv", "--manifest-path", str(clean_ws.pkg / "Cargo.toml")],
               cwd=clean_ws.root, env=env)
    check("B18 absent-to-non-Unicode stays a cached default success",
          proc.returncode == 0 and rebuild_events(proc.stdout + proc.stderr) == (0, 0)
          and clean_ws.version() == before,
          f"rc={proc.returncode} events={rebuild_events(proc.stdout + proc.stderr)}")
    # An independently triggered probe with the non-Unicode value must hard-fail.
    (clean_ws.root / "change.txt").write_text("x\n")
    git(clean_ws.root, "add", "change.txt")
    proc = run([CARGO, "build", "--offline", "-vv", "--manifest-path", str(clean_ws.pkg / "Cargo.toml")],
               cwd=clean_ws.root, env=env, check_=False)
    check("B18 non-Unicode strict hard-fails when the probe runs",
          proc.returncode != 0 and "AGENT_VM_BUILD_PROVENANCE_STRICT" in proc.stderr, f"rc={proc.returncode}")


def case_b19(work):
    fx = Fixture(work / "b19")
    fx.commit()
    sha_a = head(fx.root)
    git(fx.root, "branch", "a")
    git(fx.root, "checkout", "-q", "-b", "b")
    git(fx.root, "commit", "-q", "--no-gpg-sign", "--allow-empty", "-m", "b")
    sha_b = head(fx.root)
    git(fx.root, "checkout", "-q", "main")
    git(fx.root, "symbolic-ref", "refs/heads/alias", "refs/heads/a")
    git(fx.root, "symbolic-ref", "HEAD", "refs/heads/alias")
    fx.build()
    check("B19 baseline through an alias chain is a", fx.version() == expect(sha_a), fx.version().strip())
    paths = fx.fingerprint_paths()
    check("B19 every symbolic link and terminal is watched",
          any(p.endswith("refs/heads/alias") for p in paths)
          and any(p.endswith("refs/heads/a") for p in paths)
          and any(p.endswith(".git/HEAD") for p in paths),
          str(sorted(p for p in paths if "refs/heads" in p or p.endswith("HEAD")))[:300])
    stable = non_alias_mtimes(fx)
    git(fx.root, "symbolic-ref", "refs/heads/alias", "refs/heads/b")
    check("B19 alias retarget preserves non-alias mtimes", stable == non_alias_mtimes(fx))
    fx.build()
    check("B19 retargeting only the alias yields b", fx.version() == expect(sha_b), fx.version().strip())
    git(fx.root, "symbolic-ref", "refs/heads/alias", "refs/heads/a")
    fx.build()
    check("B19 retargeting back yields a", fx.version() == expect(sha_a), fx.version().strip())
    assert_fresh(fx, "B19 fresh after alias retargeting")
    _, sub = make_submodule(fx)
    sub_a = head(sub)
    git(sub, "branch", "a")
    git(sub, "checkout", "-q", "-b", "b")
    git(sub, "commit", "-q", "--no-gpg-sign", "--allow-empty", "-m", "b")
    git(sub, "symbolic-ref", "refs/heads/alias", "refs/heads/a")
    git(sub, "symbolic-ref", "HEAD", "refs/heads/alias")
    fx.commit()
    top = head(fx.root)
    fx.build()
    check("B19 submodule alias baseline clean", head(sub) == sub_a and fx.version() == expect(top))
    check("B19 submodule intermediate alias watched",
          any(p.endswith("modules/vendor/sub/refs/heads/alias") for p in fx.fingerprint_paths()))
    stable = non_alias_mtimes(fx)
    git(sub, "symbolic-ref", "refs/heads/alias", "refs/heads/b")
    check("B19 submodule alias preserves non-alias mtimes", stable == non_alias_mtimes(fx))
    proc = fx.build()
    check("B19 submodule alias retarget invalidates to dirty",
          rebuild_events(proc.stdout + proc.stderr) != (0, 0) and fx.version() == expect(top, dirty=True))
    git(sub, "symbolic-ref", "refs/heads/alias", "refs/heads/a")
    fx.build()
    check("B19 submodule alias restoration clean", fx.version() == expect(top))
    assert_fresh(fx, "B19 submodule alias unchanged fresh")


def non_alias_mtimes(fx):
    paths = fx.fingerprint_paths()
    return {p: (fx.pkg / p).lstat().st_mtime_ns for p in paths
            if not p.endswith("/alias") and (fx.pkg / p).exists()}


def case_discovery_faults(work):
    real_git = shutil.which("git")
    for fault in ["HEAD", "packed-refs", "symbolic"]:
        fx = Fixture(work / f"fault-{fault}")
        fx.commit()
        a = head(fx.root)
        git(fx.root, "branch", "a")
        git(fx.root, "checkout", "-q", "-b", "b")
        git(fx.root, "commit", "-q", "--no-gpg-sign", "--allow-empty", "-m", "b")
        b = head(fx.root)
        git(fx.root, "symbolic-ref", "refs/heads/alias", "refs/heads/a")
        git(fx.root, "symbolic-ref", "HEAD", "refs/heads/alias")
        adapter = work / f"adapter-{fault}"
        adapter.mkdir()
        control = adapter / "fault"
        control.write_text(fault)
        wrapper = adapter / "git"
        wrapper.write_text(f"#!{sys.executable}\nimport os,sys\n"
                           f"fault=open({str(control)!r}).read()\n"
                           "args=sys.argv[1:]\n"
                           "if (fault == 'symbolic' and 'symbolic-ref' in args) or "
                           "(fault in ['HEAD','packed-refs'] and '--git-path' in args and args[-1] == fault):\n"
                           " sys.exit(128)\n"
                           f"os.execv({real_git!r}, [{real_git!r}, *args])\n")
        wrapper.chmod(0o755)
        extra = {"PATH": f"{adapter}:{os.environ['PATH']}"}
        proc = fx.build(extra)
        check(f"fault {fault} diagnosed fallback retains partial watchers",
              fx.version() == expect(a) and FALLBACK_DEPENDENCY in fx.fingerprint_paths()
              and "incomplete" in provenance_diagnostics(proc) and "build.rs" in fx.fingerprint_paths())
        proc = fx.build(extra)
        check(f"fault {fault} per-build retry", all(n > 0 for n in rebuild_events(proc.stdout + proc.stderr)))
        git(fx.root, "symbolic-ref", "refs/heads/alias", "refs/heads/b")
        proc = fx.build(extra)
        check(f"fault {fault} alias retarget regression",
              all(n > 0 for n in rebuild_events(proc.stdout + proc.stderr)) and fx.version() == expect(b))
        control.write_text("")
        fx.build(extra)
        check(f"fault {fault} successful Git recovery drops fallback",
              FALLBACK_DEPENDENCY not in fx.fingerprint_paths() and fx.version() == expect(b))
        assert_fresh(fx, f"fault {fault} recovered default fresh", extra=extra)
        git(fx.root, "checkout", "-q", "--detach", a)
        fx.build(extra)
        check(f"fault {fault} paired exit-1 detached terminal complete",
              FALLBACK_DEPENDENCY not in fx.fingerprint_paths() and fx.version() == expect(a))
        assert_fresh(fx, f"fault {fault} detached default fresh", extra=extra)


def case_dangling(work):
    variants = [(nested, parent, strict) for nested in [False, True]
                for parent in [False, True] for strict in [False, True]]
    for nested, parent_watch, strict in variants:
        extra = {"AGENT_VM_BUILD_PROVENANCE_STRICT": "1"} if strict else None
        label = (("submodule" if nested else "top") + (" parent" if parent_watch else " fallback")
                 + (" strict" if strict else " default"))
        fx = Fixture(work / ("dangling-" + label.replace(" ", "-")))
        fx.commit()
        tree = fx.root
        if nested:
            _, tree = make_submodule(fx)
        if parent_watch:
            tree = tree / "links"
            tree.mkdir()
        link = tree / "link"
        link.symlink_to("absent-one")
        git(tree, "add", "link")
        git(tree, "commit", "-q", "--no-gpg-sign", "-m", "link")
        if nested:
            fx.commit()
        sha = head(fx.root)
        fx.build(extra)
        check(f"dangling {label} baseline clean dependency policy",
              fx.version() == expect(sha)
              and (FALLBACK_DEPENDENCY in fx.fingerprint_paths()) == (strict or not parent_watch))
        proc = fx.build(extra)
        events = rebuild_events(proc.stdout + proc.stderr)
        check(f"dangling {label} unchanged cost policy",
              (events == (0, 0) if parent_watch and not strict else all(n > 0 for n in events))
              and fx.version() == expect(sha))
        if parent_watch and not strict:
            (fx.root / "untracked-sibling").mkdir()
            (fx.root / "untracked-sibling/output").write_text("unrelated\n")
            assert_fresh(fx, f"dangling {label} bounded to parent subtree")
        for change in ["delete", "retarget", "regular", "restore"]:
            if link.is_symlink() or link.exists():
                link.unlink()
            if change == "retarget":
                link.symlink_to("absent-two")
            elif change == "regular":
                link.write_text("new regular file\n")
            elif change == "restore":
                link.symlink_to("absent-one")
            dirty = change != "restore"
            proc = fx.build(extra)
            check(f"dangling {label} {change} invalidates and measures status",
                  all(n > 0 for n in rebuild_events(proc.stdout + proc.stderr))
                  and bool(git(fx.root, "status", "--porcelain", "-uno").stdout) == dirty
                  and fx.version() == expect(sha, dirty=dirty))
            paths = fx.fingerprint_paths()
            check(f"dangling {label} {change} required dependency not lost",
                  (any(p.endswith("/links") for p in paths) if parent_watch
                   else FALLBACK_DEPENDENCY in paths) if change in ["retarget", "restore"]
                  else any(p.endswith("/link") for p in paths))
            if parent_watch and not strict and change in ["retarget", "regular", "restore"]:
                assert_fresh(fx, f"dangling {label} {change} unchanged fresh")


def main():
    global LOG_DIR
    work = Path(tempfile.mkdtemp(prefix="bp-contract-"))
    LOG_DIR = work / "_cargo-logs"
    LOG_DIR.mkdir()
    cases = [
        case_b1, case_b2, case_b3, case_b4, case_b5, case_b6, case_b7,
        case_b8, case_b9, case_b10, case_b11, case_b12, case_b13,
        case_b14, case_b15, case_b16, case_b17, case_b18, case_b19,
        case_discovery_faults, case_dangling,
    ]
    for case in cases:
        try:
            case(work)
        except Exception as error:
            check(case.__name__, False, f"exception: {error.__class__.__name__}: {error}")
    print(f"\n{len(PASSES)} passed, {len(FAILURES)} failed")
    if FAILURES:
        print(f"Failure artifacts (verbose Cargo logs and fingerprint JSON): {work}")
        for case, detail in FAILURES:
            print(f"FAIL {case}: {detail}")
        return 1
    shutil.rmtree(work)
    return 0


sys.exit(main())
PY
