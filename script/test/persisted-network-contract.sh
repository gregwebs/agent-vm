#!/usr/bin/env bash
# Host-only controls; never native enforcement or guest-authorship evidence.
set -euo pipefail
repo="$(cd -- "${BASH_SOURCE[0]%/*}/../.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
python3 "$repo/script/test/lib/persisted-network-contract.py"
(cd -- "$repo" && cargo test --locked --manifest-path "$repo/Cargo.toml" -p agent-vm \
  --test config_launch_driven native_row_oracles_are_rendered_diagnostics)
(cd -- "$repo" && cargo test --locked --manifest-path "$repo/Cargo.toml" -p agent-vm \
  --test mount_protected_config m12_home_launch_refused_with_valid_network_authority)
