#!/usr/bin/env bash
# Contract for the build-identity probe (issue #335, controls B1-B19).
#
# The harness owns the parsing and provenance controls so this contract needs no
# host Python. Build it once with the command below; CI exports HARNESS_BIN_DIR
# after doing so for every shell caller.
set -euo pipefail
repo="$(cd -- "${BASH_SOURCE[0]%/*}/../.." && pwd -P)"
harness="${HARNESS_BIN_DIR:-$repo/target/debug}/harness"
[[ -x "$harness" ]] || {
    echo "build-provenance: FAIL: missing harness binary: $harness (run: cargo build --locked -p agent-vm-harness --bins)" >&2
    exit 1
}
[[ -z "${AGENT_VM_BUILD_PROVENANCE_STRICT:-}" ]] || {
    echo 'run this contract with AGENT_VM_BUILD_PROVENANCE_STRICT unset' >&2
    exit 1
}
"$harness" build-provenance --self-test
