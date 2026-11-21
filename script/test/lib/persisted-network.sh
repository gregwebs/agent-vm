#!/usr/bin/env bash
# Shared oracles for the persisted-authority harness (#696).
#
# The rows themselves are `harness persisted-network`: a Rust driver, so this
# library is only the tracked stderr oracle and the launch seam that must keep
# the trapped background PID equal to the driver's.
set -euo pipefail
PN_SCRIPT_DIR="$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd)"
PN_REPO_ROOT="$(cd -- "$PN_SCRIPT_DIR/../.." && pwd -P)"
# shellcheck source=script/test/lib/config-dir-guard.sh
source "$PN_SCRIPT_DIR/lib/config-dir-guard.sh"

# Every stderr oracle is obtained through this one renderer, never duplicated.
# `harness persisted-network` parses the same file with its own parser; the
# controls hold the two renderings equal, so a change to one cannot drift.
pn_expected() {
    awk -F '\t' -v row="$1" '$1 == row { print $2; found=1 } END { if (!found) exit 1 }' \
        "$PN_SCRIPT_DIR/fixtures/persisted-network/expected-stderr.tsv"
}

# Short-state setup. `harness persisted-network` performs this itself, in
# `Driver::fresh`, including the same control-socket budget check. This copy
# stays because `script/test/lib/config-mounts.py` still calls it, and that
# live suite is a separate port.
pn_fresh_state() {
    local work="$1"
    mkdir -p "$work/home/.config/agent-vm" "$work/state" "$work/proj"
    chmod 700 "$work/home/.config/agent-vm"
    avm_guard_state_dir_fits "$work/state"
}

# The harness binary the rows live in. A caller that cannot find it gets the
# build command, never a silent fallback.
pn_harness() {
    local harness="${HARNESS_BIN_DIR:-$PN_REPO_ROOT/target/debug}/harness"
    if [[ ! -x "$harness" ]]; then
        printf 'persisted-network: FAIL: missing harness binary: %s (run: cargo build --locked -p agent-vm-harness --bins)\n' \
            "$harness" >&2
        return 1
    fi
    printf '%s' "$harness"
}

pn_launch() {
    # exec, so the trapped background PID is the driver's and not a shell
    # wrapper's: that PID is the only identity a supervisor can KILL, and the
    # controls fail loudly when this stops being true.
    local harness
    harness="$(pn_harness)" || exit 2
    exec "$harness" persisted-network --repo-root "$PN_REPO_ROOT" "$@"
}
