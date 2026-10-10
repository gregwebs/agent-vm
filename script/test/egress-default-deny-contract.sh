#!/usr/bin/env bash
# Boot-free §6.7 join. Host-only controls are not native VM/egress evidence.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)

# An unrelated cwd must still resolve the existing owned-group helper, not a
# copied supervisor. The live timeout/interrupt launch controls run below.
python3 - "$REPO_ROOT" <<'PY'
import importlib.util
import json
import subprocess
import os
from pathlib import Path
import py_compile
import sys
import tempfile

root = Path(sys.argv[1])
with tempfile.TemporaryDirectory(prefix="egress-outside-") as tmp:
    os.chdir(tmp)
    path = root / "script/test/lib/egress-fixtures.py"
    py_compile.compile(str(path), cfile=str(Path(tmp) / "fixtures.pyc"), doraise=True)
    spec = importlib.util.spec_from_file_location("outside_egress", path)
    fixtures = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fixtures
    spec.loader.exec_module(fixtures)
    assert fixtures._load_owned_launch().__file__ == str(root / "script/test/released-image-launch.py")
    assert fixtures.self_test() == 0
    # Independent §10.2 inventory: deriving this from CASES would allow a
    # deleted case to disappear from both the builder and its expected output.
    expected = {(case, "ipv4") for case in (
        "P0 LC1 HC1 I1 D1 D1f L1 H1 I1a LH1 AD1 TP1 UP1 UP2 CI1 "
        "PX1 PX2 PX3 FL0 FL1 FL2 CR1c CR1 IN1 IN2 HK1c HK1 HK2c HK2 CL1").split()}
    expected |= {(case, "ipv6") for case in ("V6c", "DNS6c", "V6", "D1")}
    expected |= {("RB1", variant) for variant in
                 ("internet", "address", "tcp", "udp", "port", "tcp-port", "udp-port")}
    expected |= {("RJ1", variant) for variant in ("hostname", "cidr-port", "scheme")}
    output = subprocess.check_output(["bash", str(root / "script/test/egress-default-deny.sh"),
                                      "--print-plan"], text=True, timeout=10)
    rows = [json.loads(line) for line in output.splitlines()]
    cases = [row for row in rows if row["kind"] != "admin"]
    assert len(cases) == len(expected) == 44
    assert {(row["case"], row["variant"]) for row in cases} == expected
    base = {"HOME", "XDG_CONFIG_HOME", "AGENT_VM_STATE_DIR", "PATH", "TERM", "AGENT_VM_SHARE_MSB_CACHE"}
    for row in cases:
        case, argv = row["case"], row["argv"]
        tool = "egresscreds" if case in ("CR1", "CR1c") else "egressprobe"
        assert row["tool"] == argv[1] == tool
        assert row["kind"] == ("validation-only" if case == "RJ1" else "guest")
        if case != "RJ1":
            assert argv[argv.index("--") + 1] == case
        else:
            assert "--" not in argv
        extras = set(row["declared_extras"])
        assert extras <= ({"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"} if case.startswith("PX")
                          else {"MSB_CONFIG_PATH"} if case.startswith("FL") else set())
        assert set(row["env"]) == base | extras
        assert "shell" not in argv and "-c" not in argv
        assert row["timeout"] > 0 and row["grace"] > 0
        assert row["supervisor"] and row["shim"] and row["cwd"]
        assert isinstance(row["controls"], dict) and isinstance(row["prerequisites"], list)
        if case in ("CR1", "CR1c"):
            assert row["setup"], "synthetic seed lifecycle not declared"
    admins = [row for row in rows if row["kind"] == "admin"]
    expected_admin = {("image-load", "admin"), ("list", "admin"), ("stop", "admin"),
                      ("force-stop", "admin"), ("remove", "admin"), ("IN1", "curl"),
                      ("IN2", "curl"), ("fixture-health", "admin"), ("fixture-start", "admin")}
    assert len(admins) == len(expected_admin)
    assert {(row["case"], row["variant"]) for row in admins} == expected_admin
    for row in admins:
        assert row["tool"] is None
        assert "egressprobe" not in row["argv"] and "egresscreds" not in row["argv"]
    print("host-only per-case print-plan inventory PASS: 44 cases, 9 admin objects")
PY

# Primitive status/wire controls and dispatcher expectations are complementary:
# neither mocks of dispatcher routes nor owned-supervisor fakes prove framing.
python3 "$REPO_ROOT/script/test/lib/egress-wire-contract.py"
python3 "$REPO_ROOT/script/test/lib/egress-probe-contract.py"
python3 "$REPO_ROOT/script/test/lib/egress-supervisor-contract.py"

# Run the actual guard, then remove each required membership independently.
# Mutated copies live only in owned scratch; the working tree is never edited.
bash "$REPO_ROOT/script/test/ci-contracts.sh" --guard-only
python3 - "$REPO_ROOT" <<'PY'
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(sys.argv[1])
source = (root / "script/test/ci-contracts.sh").read_text()
files = ("script/test/egress-default-deny.sh",
         "script/test/egress-default-deny-contract.sh",
         "script/test/fixtures/egress-probe.sh")
run_list = source.split("# --- Shell guard rail", 1)[0]
assert 'bash "$REPO_ROOT/script/test/egress-default-deny-contract.sh"' in run_list
for array, label in (("syntax_check", "bash -n"), ("shellcheck_files", "shellcheck")):
    for script in files:
        start = source.index(array + "=(")
        end = source.index("\n)", start)
        block = source[start:end]
        entry = "    " + script + "\n"
        assert block.count(entry) == 1, (array, script)
        mutated = source[:start] + block.replace(entry, "", 1) + source[end:]
        with tempfile.TemporaryDirectory(prefix="egress-guard-mutation-") as tmp:
            path = Path(tmp) / "script/test/ci-contracts.sh"
            path.parent.mkdir(parents=True)
            path.write_text(mutated)
            result = subprocess.run(["bash", str(path), "--guard-only"],
                                    capture_output=True, text=True, timeout=10)
            assert result.returncode == 1, result.stdout + result.stderr
            assert f"({script}) is missing from the {label} guard list" in result.stderr, result.stderr
        print(f"host-only removal mutation PASS: {array}: {script}")
PY

echo 'host-only egress default-deny contract passed (six §6.7 items; no VM run)'
