#!/usr/bin/env bash
# Shared oracles and short-state setup for the persisted-authority harness.
set -euo pipefail
PN_SCRIPT_DIR="$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd)"
# shellcheck source=script/test/lib/config-dir-guard.sh
source "$PN_SCRIPT_DIR/lib/config-dir-guard.sh"
pn_expected() {
    awk -F '\t' -v row="$1" '$1 == row { print $2; found=1 } END { if (!found) exit 1 }' \
        "$PN_SCRIPT_DIR/fixtures/persisted-network/expected-stderr.tsv"
}
pn_fresh_state() {
    local work="$1"
    mkdir -p "$work/home/.config/agent-vm" "$work/state" "$work/proj"
    chmod 700 "$work/home/.config/agent-vm"
    avm_guard_state_dir_fits "$work/state"
}
pn_launch() {
    # Keep the trapped background PID equal to the driver, not a shell wrapper.
    exec python3 "$PN_SCRIPT_DIR/lib/persisted-network.py" "$@"
}
