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
print("persisted network host-only controls PASS")
PY
cargo test --manifest-path "$repo/Cargo.toml" -p agent-vm --test config_launch_driven native_row_oracles_are_rendered_diagnostics
cargo test --manifest-path "$repo/Cargo.toml" -p agent-vm --test mount_protected_config m12_home_launch_refused_with_valid_network_authority
