#!/usr/bin/env bash
# Host-only controls: no VM enforcement or guest-authorship evidence.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
repo="$(cd -- "${BASH_SOURCE[0]%/*}/../.." && pwd)"
python3 - "$repo" <<'PY'
import http.server
import importlib.util
import os
from pathlib import Path
import py_compile
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
root = Path(sys.argv[1])
fixtures = root / "script/test/fixtures/persisted-network"
with tempfile.TemporaryDirectory(prefix="pn-contract-") as tmp:
    work = Path(tmp)
    py_compile.compile(str(root / "script/test/lib/persisted-network.py"), cfile=str(work / "driver.pyc"), doraise=True)
    spec = importlib.util.spec_from_file_location("pn_contract", root / "script/test/lib/persisted-network.py")
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    inventory = work / "inventory"
    (inventory / "state").mkdir(parents=True)
    (inventory / "state/image").write_bytes(b"native image" * 200000)
    (inventory / "state/link").symlink_to("image")
    (inventory / "state/db-wal").write_bytes(b"sidecar")
    assert driver.snapshot_validation(inventory) == driver.EGRESS.snapshot_validation(inventory)
    before = driver.snapshot_validation(inventory)
    with (inventory / "state/image").open("ab") as handle: handle.write(b"changed")
    assert driver.snapshot_validation(inventory) != before
    (work / "dotfiles").mkdir()
    target = work / "dotfiles/agent-vm.toml"
    target.write_bytes(b"# stand-in\n")
    for file in ("guest-pn4-write.sh", "guest-pn-probe.sh"):
        shutil.copy2(fixtures / file, work / file)
    shutil.copy2(root / "script/test/fixtures/egress-probe.sh", work / "egress-probe.sh")
    result = subprocess.run(["bash", "./guest-pn4-write.sh"], cwd=work, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0 and result.stdout == "PN4_WRITE_OK\n", result
    assert target.read_bytes() == b"# stand-in\n[network]\nallow_host = true\n"
    (work / "r").mkdir()
    (work / "r/marker").write_bytes(b"receipt marker")
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(work), **kwargs)
        def log_message(self, *_args):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        result = subprocess.run(["bash", "./guest-pn-probe.sh", str(port), "marker", "127.0.0.1"], cwd=work, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and "PN_REACHED marker" in result.stdout, result
    finally:
        server.shutdown(); server.server_close(); thread.join(5)
    # Hold a bound, non-listening socket: no other process can steal the closed-port control.
    with socket.socket() as closed:
        closed.bind(("127.0.0.1", 0))
        result = subprocess.run(["bash", "./guest-pn-probe.sh", str(closed.getsockname()[1]), "marker", "127.0.0.1"], cwd=work, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and "PN_DENIED marker" in result.stdout, result
    live = (root / "script/test/persisted-network-live.sh").read_text()
    driver = (root / "script/test/lib/persisted-network.py").read_text()
    helper = (root / "script/test/lib/persisted-network.sh").read_text()
    assert 'pn_expected "$row"' in live and 'shell_helper("pn_expected", oracle)' in driver
    assert 'expected-stderr.tsv' in helper
    assert 'exec python3' in helper, 'trap PID must belong to the cleanup-owning driver'
    for line in (fixtures / "expected-stderr.tsv").read_text().splitlines():
        if not line or line.startswith('#'): continue
        _, text = line.split('\t')
        assert text not in live and text not in driver, "duplicated native stderr oracle"
    # ---- Build-provenance checker: P1-P5 --------------------------------
    import importlib.util
    checker_path = root / "script/test/lib/build-provenance.py"
    spec = importlib.util.spec_from_file_location("build_provenance", checker_path)
    checker = importlib.util.module_from_spec(spec)
    sys.modules["build_provenance"] = checker  # dataclass __module__ resolution
    spec.loader.exec_module(checker)
    sha_a = "a" * 40
    sha_b = "b" * 40

    def accepts(text, expected, status):
        try:
            checker.assert_committed_build(
                checker.parse_version(text), expected_sha=expected, tracked_status=status)
            return True
        except ValueError:
            return False

    # P1 positive, P2 prefix lookalike, P3 false-clean, P5 untracked-only.
    assert accepts(f"agent-vm 0.3.4 ({sha_a})\n", sha_a, ""), "P1 must accept"
    full64 = "abcdef1" + "0" * 57
    other64 = full64[:-1] + "1"
    assert accepts(f"agent-vm 0.3.4 ({full64})\n", full64, ""), "P1 64-hex exact equality"
    assert not accepts(f"agent-vm 0.3.4 ({full64})\n", other64, ""), "P2 64-hex inequality"
    prefix_a = "abcdef1" + "0" * 33
    prefix_b = "abcdef1" + "1" * 33
    assert not accepts(f"agent-vm 0.3.4 ({prefix_a})\n", prefix_b, ""), "P2 prefix must reject"
    assert accepts(f"agent-vm 0.3.4 ({sha_a})\n", sha_a, ""), "P5 allows unrelated untracked files"
    for text, status, why in [
        (f"agent-vm 0.3.4 ({sha_a}, dirty)\n", "", "dirty binary"),
        (f"agent-vm 0.3.4 ({sha_a})\n", " M x\n", "dirty tracked source"),
        (f"agent-vm 0.3.4 ({sha_a}, state unknown)\n", "", "unknown state"),
        ("agent-vm 0.3.4 (unknown)\n", "", "unknown revision"),
        ("agent-vm 0.3.3\n", "", "legacy bare version"),
        (f"agent-vm 0.3.4 ({sha_a})", "", "missing final newline"),
        (f"agent-vm 0.3.4 ({sha_a})\n\n", "", "extra blank line"),
        (f"agent-vm 0.3.4 ({sha_a[:7]})\n", "", "short SHA"),
        (f"agent-vm 0.3.4 ({sha_a}) trailing\n", "", "trailing junk"),
    ]:
        assert not accepts(text, sha_a, status), f"P3/P4 must reject {why}"
    # The checker CLI against real files.
    version_file = work / "checker-version.txt"
    status_file = work / "checker-status.txt"
    version_file.write_text(f"agent-vm 0.3.4 ({sha_a})\n")
    status_file.write_text("")
    good = subprocess.run([sys.executable, str(checker_path), str(version_file), sha_a, str(status_file)],
                          capture_output=True, text=True)
    assert good.returncode == 0 and good.stdout.strip() == "provenance: clean binary matches source HEAD", good
    version_file.write_bytes(b"agent-vm 0.3.4 (" + sha_a.encode() + b")\r\n")
    bad = subprocess.run([sys.executable, str(checker_path), str(version_file), sha_a, str(status_file)],
                         capture_output=True, text=True)
    assert bad.returncode != 0 and bad.stderr.startswith("provenance: "), bad
    invalid = work / "checker-invalid.txt"
    invalid.write_bytes(b"agent-vm 0.3.4 (" + sha_a.encode() + b")\xff\n")
    bad = subprocess.run([sys.executable, str(checker_path), str(invalid), sha_a, str(status_file)],
                         capture_output=True, text=True)
    assert bad.returncode != 0 and bad.stderr.startswith("provenance: "), bad

    # ---- Live-shell matrix: P6-P10 --------------------------------------
    git_env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
                   GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")

    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_NAMESPACE"):
        git_env.pop(key, None)

    def git_repo(path, message):
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True, env=git_env)
        subprocess.run(["git", "config", "core.filemode", "true"], cwd=path, check=True, env=git_env)
        subprocess.run(["git", "add", "-A"], cwd=path, check=True, env=git_env)
        subprocess.run(["git", "commit", "-q", "--no-gpg-sign", "-m", message], cwd=path, check=True, env=git_env)
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=path, capture_output=True, text=True, env=git_env).stdout.strip()

    repo_a = work / "A"
    (repo_a / "script").mkdir(parents=True)
    shutil.copytree(root / "script/test", repo_a / "script/test",
                    ignore=shutil.ignore_patterns("__pycache__"))
    sha_a_full = git_repo(repo_a, "A")
    repo_b = work / "B"
    repo_b.mkdir()
    (repo_b / "b.txt").write_text("b\n")
    sha_b_full = git_repo(repo_b, "B")

    tools = work / "tools"
    tools.mkdir()
    events = work / "events.log"

    def write_tool(name, body):
        path = tools / name
        path.write_text(body)
        path.chmod(0o755)
        return path

    real_git = shutil.which("git")
    real_shasum = shutil.which("shasum")
    write_tool("git", '#!/bin/sh\nif [ "${PN_FAIL_GIT:-}" = 1 ]; then exit 17; fi\nexec "$REAL_GIT" "$@"\n')
    write_tool("shasum", '#!/bin/sh\ncase "${PN_FAIL_HASH:-}:$*" in\n'
                          '  binary:*bin-*|diff:*tree.diff) exit 19 ;;\nesac\nexec "$REAL_SHASUM" "$@"\n')
    write_tool("uname", '#!/bin/sh\ncase "${1:-}" in -s) echo Darwin ;; -m) echo arm64 ;; *) echo Darwin ;; esac\n')
    write_tool("pgrep", '#!/bin/sh\nexit 1\n')
    write_tool("mktemp", '#!/bin/sh\nout="$("$REAL_MKTEMP" "$@")" || exit $?\n'
                         'case "$out" in /tmp/avm-pn.*|/private/tmp/avm-pn.*)\n'
                         '  printf "allocated %s\\n" "$out" >> "$PN_EVENTS"\n'
                         '  grep -Fxq "provenance: clean binary matches source HEAD" "$AGENT_VM_PN_EVIDENCE/provenance-check.txt" 2>/dev/null || { echo "scratch allocated before provenance success" >&2; exit 66; }\n'
                         '  ;;\nesac\nprintf "%s\\n" "$out"\n')
    write_tool("python3", '#!/bin/sh\ncase "${1:-}" in\n'
                          '  */build-provenance.py) exec "$REAL_PYTHON" "$@" ;;\n'
                          '  */persisted-network.py) if [ "${PN_FAIL_STARTUP:-}" = 1 ]; then echo "persisted-network driver startup failed" >&2; exit 29; fi; shift; exec "$REAL_PYTHON" "$STUB_DRIVER" "$@" ;;\n'
                          '  *) exec "$REAL_PYTHON" "$@" ;;\nesac\n')
    stub = work / "stub-driver.py"
    stub.write_text(
        "import os, shutil, sys\n"
        "events = os.environ['PN_EVENTS']\n"
        "def note(line):\n"
        "    with open(events, 'a') as handle:\n"
        "        handle.write(line + '\\n')\n"
        "root, evidence = sys.argv[1], sys.argv[2]\n"
        "note('driver')\n"
        "assert os.path.isdir(root), 'scratch missing'\n"
        "receipt = ''\n"
        "try:\n    receipt = open(os.path.join(evidence, 'provenance-check.txt')).read()\nexcept OSError:\n    pass\n"
        "assert 'provenance: clean binary matches source HEAD' in receipt, 'receipt must precede scratch'\n"
        "if os.environ.get('STUB_CLEANUP_FAIL') == '1':\n    note('cleanup-failed')\n    sys.exit(24)\n"
        "shutil.rmtree(root)\n"
        "note('cleanup')\n"
        "sys.exit(int(os.environ.get('STUB_EXIT', '0')))\n"
    )

    def live_env(env_extra=None):
        env = dict(os.environ)
        env["PATH"] = f"{tools}:{os.environ['PATH']}"
        env["REAL_MKTEMP"] = shutil.which("mktemp")
        env["REAL_GIT"] = real_git
        env["REAL_SHASUM"] = real_shasum
        env["REAL_PYTHON"] = sys.executable
        env["STUB_DRIVER"] = str(stub)
        env["PN_EVENTS"] = str(events)
        env["AGENT_VM_LIVE_TEST_IMAGE"] = "fixture-image"
        for key in ("AGENT_VM_BUILD_PROVENANCE_STRICT", "AGENT_VM_GIT_SHA", "GITHUB_SHA"):
            env.pop(key, None)
        if env_extra:
            env.update(env_extra)
        return env

    run_counter = [0]

    def run_live(script_repo, binary_body, *, name, env_extra=None):
        run_counter[0] += 1
        events.write_text("")
        binary = work / f"bin-{name}-{run_counter[0]}"
        binary.write_text(binary_body)
        binary.chmod(0o755)
        evidence = work / f"evidence-{name}-{run_counter[0]}"
        evidence.mkdir()
        env = live_env(env_extra)
        env["AGENT_VM_BIN"] = str(binary)
        env["AGENT_VM_PN_EVIDENCE"] = str(evidence)
        proc = subprocess.run(
            ["bash", str(script_repo / "script/test/persisted-network-live.sh")],
            cwd=script_repo, env=env, capture_output=True, text=True, timeout=180)
        return proc, evidence, events.read_text()

    def clean_binary(sha):
        return f"#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha})\\n'\n"

    def allocations(text):
        return [line.split(" ", 1)[1] for line in text.splitlines() if line.startswith("allocated ")]

    def rejected(name, *args, **kwargs):
        proc, evidence, log = run_live(repo_a, *args, name=name, **kwargs)
        ok = (proc.returncode != 0 and "driver" not in log.split()
              and allocations(log) == [] and (evidence / "provenance-check.txt").exists())
        assert ok, f"P6 {name}: rc={proc.returncode} log={log!r} stdout={proc.stdout[-400:]}"
        required = ["source.txt", "tree.diff", "tree.diff.sha256", "binary.sha256",
                    "harness.sha256", "image.txt", "binary-version.txt"]
        assert all((evidence / path).exists() for path in required), f"missing rejection manifest: {name}"
        assert "rebuild" in (evidence / "provenance-check.txt").read_text(), name
        return evidence

    # P6: dirty/mismatched/unknown candidates and a dirty source.
    flipped = sha_a_full[:-1] + ("0" if sha_a_full[-1] != "0" else "1")
    rejected("mismatch-sha", clean_binary(flipped))
    rejected("dirty-binary", f"#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a_full}, dirty)\\n'\n")
    rejected("unknown-state", f"#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a_full}, state unknown)\\n'\n")
    rejected("unknown-revision", "#!/bin/sh\nprintf 'agent-vm 0.3.4 (unknown)\\n'\n")
    (repo_a / "script/test/README-dirt").write_text("dirt\n")
    subprocess.run(["git", "add", "script/test/README-dirt"], cwd=repo_a, check=True, env=git_env)
    rejected("dirty-source-content", clean_binary(sha_a_full))
    subprocess.run(["git", "reset", "-q", "--hard"], cwd=repo_a, check=True, env=git_env)
    (repo_a / "script/test/README-dirt").unlink(missing_ok=True)
    script_dirt = repo_a / "script/test/persisted-network-live.sh"
    script_dirt.chmod(script_dirt.stat().st_mode & ~0o111)
    rejected("dirty-source-mode", clean_binary(sha_a_full))
    script_dirt.chmod(script_dirt.stat().st_mode | 0o111)
    subprocess.run(["git", "reset", "-q", "--hard"], cwd=repo_a, check=True, env=git_env)

    # P7: a matching clean candidate reaches one harmless driver.
    ok_proc, ok_evidence, ok_log = run_live(repo_a, clean_binary(sha_a_full), name="accept")
    ok_allocs = allocations(ok_log)
    assert ok_proc.returncode == 0, f"P7 rc={ok_proc.returncode} {ok_proc.stdout[-400:]} {ok_proc.stderr[-400:]}"
    assert ok_log.split().count("driver") == 1 and ok_log.split().count("cleanup") == 1, ok_log
    assert len(ok_allocs) == 1 and not os.path.exists(ok_allocs[0]), ok_log
    assert (ok_evidence / "binary.sha256").exists() and (ok_evidence / "provenance-check.txt").exists(), "evidence retained"
    (repo_a / "script/test/untracked-ok").write_text("u\n")
    unt_proc, _, unt_log = run_live(repo_a, clean_binary(sha_a_full), name="accept-untracked")
    assert unt_proc.returncode == 0 and len(allocations(unt_log)) == 1, unt_log
    (repo_a / "script/test/untracked-ok").unlink()

    # P8: driver status propagation and cleanup semantics.
    exit23, _, log23 = run_live(repo_a, clean_binary(sha_a_full), name="exit23",
                                env_extra={"STUB_EXIT": "23"})
    assert exit23.returncode == 23, f"P8 expected 23, got {exit23.returncode}"
    assert log23.split().count("driver") == 1 and "cleanup" in log23.split()
    assert allocations(log23) and not os.path.exists(allocations(log23)[0]), log23
    cleanfail, _, logcf = run_live(repo_a, clean_binary(sha_a_full), name="cleanfail",
                                   env_extra={"STUB_CLEANUP_FAIL": "1"})
    assert cleanfail.returncode == 24, f"P8 expected 24, got {cleanfail.returncode}"
    assert "cleanup-failed" in logcf, logcf
    cleanfail_scratch = allocations(logcf)
    assert len(cleanfail_scratch) == 1 and os.path.isdir(cleanfail_scratch[0]), \
        "failed cleanup must preserve owned scratch"
    shutil.rmtree(cleanfail_scratch[0])

    # No cleanup-owning driver exists on exec/startup or canonicalization failure.
    bash_env = work / "fail-scratch-cd.sh"
    bash_env.write_text('cd() { case "${1:-}" in /tmp/avm-pn.*|/private/tmp/avm-pn.*) '
                        'echo "scratch canonicalization failed" >&2; return 33 ;; '
                        '*) builtin cd "$@" ;; esac; }\n')
    for name, extra, status, diagnostic in [
        ("canonicalization-failure", {"BASH_ENV": str(bash_env)}, 33, "scratch canonicalization failed"),
        ("startup-failure", {"PN_FAIL_STARTUP": "1"}, 29, "driver startup failed"),
    ]:
        proc, _, log = run_live(repo_a, clean_binary(sha_a_full), name=name, env_extra=extra)
        owned = allocations(log)
        try:
            assert proc.returncode == status and diagnostic in proc.stderr, (name, proc)
            assert len(owned) == 1 and not os.path.exists(owned[0]), (name, log, proc.stderr)
            assert not {"driver", "cleanup", "cleanup-failed"}.intersection(log.split()), (name, log)
            print(f"P8 {name} PASS: status {status}, scratch removed, no driver/cleanup")
        finally:
            # Baseline regressions must not leave test-owned empty scratch behind.
            for path in owned:
                if os.path.isdir(path):
                    os.rmdir(path)

    # P9: inherited Git routing must not select checkout B.
    routing = {"GIT_DIR": str(repo_b / ".git"), "GIT_WORK_TREE": str(repo_b),
               "GIT_INDEX_FILE": str(repo_b / ".git/index"),
               "GIT_COMMON_DIR": str(repo_b / ".git"), "GIT_NAMESPACE": "other"}
    b_proc, b_evidence, b_log = run_live(repo_a, clean_binary(sha_b_full), name="routed-b", env_extra=routing)
    assert b_proc.returncode != 0 and allocations(b_log) == [] and "driver" not in b_log.split(), b_log
    assert f"commit: {sha_a_full}" in (b_evidence / "source.txt").read_text(), "must record A"
    a_proc, _, a_log = run_live(repo_a, clean_binary(sha_a_full), name="routed-a", env_extra=routing)
    assert a_proc.returncode == 0 and len(allocations(a_log)) == 1, f"P9 routed A must accept: {a_log}"
    # Wrong top level: the harness source lives in an unversioned subdirectory.
    repo_c = work / "C"
    (repo_c / "sub/script").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo_c, check=True, env=git_env)
    (repo_c / "outer.txt").write_text("outer\n")
    shutil.copytree(root / "script/test", repo_c / "sub/script/test",
                    ignore=shutil.ignore_patterns("__pycache__"))
    c_proc, c_evidence, c_log = run_live(repo_c / "sub", clean_binary(sha_a_full), name="wrong-root")
    assert c_proc.returncode != 0 and allocations(c_log) == [] and "driver" not in c_log.split(), c_log

    assert (c_evidence / "provenance-check.txt").exists(), "root rejection receipt"
    assert "not yet validated" in (c_evidence / "source.txt").read_text(), "root identity not trusted"
    for path in ["binary.sha256", "harness.sha256", "image.txt"]:
        assert (c_evidence / path).exists(), f"root rejection lost {path}"

    # Fallible preflight controls: rejection manifests, no scratch or driver.
    for name, extra, body in [
        ("git-failure", {"PN_FAIL_GIT": "1"}, clean_binary(sha_a_full)),
        ("binary-hash-failure", {"PN_FAIL_HASH": "binary"}, clean_binary(sha_a_full)),
        ("diff-hash-failure", {"PN_FAIL_HASH": "diff"}, clean_binary(sha_a_full)),
        ("version-failure", {}, "#!/bin/sh\nprintf partial; exit 9\n"),
    ]:
        proc, evidence, log = run_live(repo_a, body, name=name, env_extra=extra)
        assert proc.returncode != 0 and allocations(log) == [] and "driver" not in log.split(), name
        receipt = (evidence / "provenance-check.txt").read_text()
        assert "provenance:" in receipt and "rebuild" in receipt, name
        assert (evidence / "source.txt").exists() and (evidence / "image.txt").exists(), name
        if name == "version-failure":
            assert (evidence / "binary-version.txt").read_bytes() == b"partial", name
            assert all((evidence / path).exists() for path in
                       ["tree.diff", "tree.diff.sha256", "binary.sha256", "harness.sha256"]), name
        if name == "diff-hash-failure":
            assert (evidence / "tree.diff").exists() and (evidence / "binary.sha256").exists(), name

    # P10: the candidate's exact stdout bytes are preserved and rejected.
    def byte_case(name, body, expected_bytes):
        proc, evidence, log = run_live(repo_a, body, name=name)
        saved = (evidence / "binary-version.txt").read_bytes()
        assert proc.returncode != 0 and allocations(log) == [] and "driver" not in log.split(), f"P10 {name}: {log}"
        assert saved == expected_bytes, f"P10 {name}: saved {saved!r} != {expected_bytes!r}"

    byte_case("blank-lines", f"#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a_full})\\n\\n\\n'\n",
              f"agent-vm 0.3.4 ({sha_a_full})\n\n\n".encode())
    byte_case("second-line", f"#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a_full})\\nnoise\\n'\n",
              f"agent-vm 0.3.4 ({sha_a_full})\nnoise\n".encode())
    byte_case("no-final-lf", f"#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a_full})'\n",
              f"agent-vm 0.3.4 ({sha_a_full})".encode())
    byte_case("invalid-utf8", f"#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a_full})\\377\\n'\n",
              f"agent-vm 0.3.4 ({sha_a_full})".encode() + b"\xff\n")
    partial = f"agent-vm 0.3.4 ({sha_a_full[:20]}"
    proc, evidence, log = run_live(repo_a, f"#!/bin/sh\nprintf '{partial}'; exit 9\n", name="partial-exit")
    assert proc.returncode != 0 and allocations(log) == [] and "driver" not in log.split(), proc.stdout[-200:]
    assert (evidence / "binary-version.txt").read_bytes() == partial.encode(), "partial stdout preserved"

print("persisted network host-only controls PASS")
PY
cargo test --manifest-path "$repo/Cargo.toml" -p agent-vm --test config_launch_driven native_row_oracles_are_rendered_diagnostics
cargo test --manifest-path "$repo/Cargo.toml" -p agent-vm --test mount_protected_config m12_home_launch_refused_with_valid_network_authority
