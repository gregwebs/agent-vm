#!/usr/bin/env bash
# Private-state native harness; --print-plan is boot-free, not native evidence.
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
harness="${HARNESS_BIN_DIR:-$REPO_ROOT/target/debug}/harness"
if [[ ! -x "$harness" ]]; then
    printf 'egress-default-deny: harness not found at %s; run: cargo build --locked -p agent-vm-harness --bins\n' \
        "$harness" >&2
    exit 2
fi
exec "$harness" egress-fixtures run "$@"
