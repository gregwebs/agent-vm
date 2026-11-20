#!/usr/bin/env bash
# Boot-free controls for the runtime provenance driver.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
harness="${HARNESS_BIN_DIR:-$repo_root/target/debug}/harness"
[[ -x "$harness" ]] || {
    echo "runtime provenance: FAIL: missing harness binary: $harness (run: cargo build --locked -p agent-vm-harness --bins)" >&2
    exit 1
}

"$harness" runtime-provenance --self-test --repo-root "$repo_root"
