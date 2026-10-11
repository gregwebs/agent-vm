#!/usr/bin/env bash
# Private-state native harness; --print-plan is boot-free, not native evidence.
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$SCRIPT_DIR/lib/egress-fixtures.py" run "$@"
