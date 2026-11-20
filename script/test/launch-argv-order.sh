#!/usr/bin/env bash
# Boot-free launch-option-order checks (issue #687).
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
harness="${HARNESS_BIN_DIR:-$repo_root/target/debug}/harness"
[[ -x "$harness" ]] || {
    echo "launch-argv-order: FAIL: missing harness binary: $harness (run: cargo build --locked -p agent-vm-harness --bins)" >&2
    exit 1
}

"$harness" launch-argv-order --self-test --repo-root "$repo_root"
