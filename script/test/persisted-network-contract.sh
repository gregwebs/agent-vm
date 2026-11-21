#!/usr/bin/env bash
# Host-only controls; never native enforcement or guest-authorship evidence.
# The controls are `harness persisted-network-controls`: the probe, helper and
# live-shell groups moved out of Python with #696.
set -euo pipefail
repo="$(cd -- "${BASH_SOURCE[0]%/*}/../.." && pwd)"
harness="${HARNESS_BIN_DIR:-$repo/target/debug}/harness"
[[ -x "$harness" ]] || {
    echo "persisted network: FAIL: missing harness binary: $harness (run: cargo build --locked -p agent-vm-harness --bins)" >&2
    exit 1
}
"$harness" persisted-network-controls --repo-root "$repo"
(cd -- "$repo" && cargo test --locked --manifest-path "$repo/Cargo.toml" -p agent-vm \
  --test config_launch_driven native_row_oracles_are_rendered_diagnostics)
(cd -- "$repo" && cargo test --locked --manifest-path "$repo/Cargo.toml" -p agent-vm \
  --test mount_protected_config m12_home_launch_refused_with_valid_network_authority)
