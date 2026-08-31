#!/usr/bin/env bash
# Check that both Cargo roots and the nested firmware source form one runtime.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
static_only=false
if (($#)); then
    [[ "$1" == --static && $# -eq 1 ]] || { echo "usage: $0 [--static]" >&2; exit 2; }
    static_only=true
fi

firmware_dir=vendor/microsandbox/vendor/libkrunfw
[[ -d "$firmware_dir" ]] || { echo "runtime provenance: FAIL: firmware recursive submodule is not initialized; run git submodule update --init --recursive" >&2; exit 1; }
gitlink_entry="$(git -C vendor/microsandbox ls-tree HEAD vendor/libkrunfw)"
gitlink_mode="$(awk '{print $1}' <<<"$gitlink_entry")"
gitlink="$(awk '{print $3}' <<<"$gitlink_entry")"
firmware_head="$(git -C "$firmware_dir" rev-parse HEAD 2>/dev/null || true)"
firmware_dirty=false
if [[ -n "$(git -C "$firmware_dir" status --porcelain --untracked-files=normal)" ]]; then
    firmware_dirty=true
fi

args=(
    --root-lock Cargo.lock --nested-lock vendor/microsandbox/Cargo.lock
    --root-manifest Cargo.toml --nested-manifest vendor/microsandbox/Cargo.toml
    --constants vendor/microsandbox/crates/utils/lib/lib.rs --firmware-dir "$firmware_dir"
    --gitlink "$gitlink" --gitlink-mode "$gitlink_mode" --firmware-head "$firmware_head"
)
[[ "$firmware_dirty" == true ]] && args+=(--firmware-dirty)

if [[ "$static_only" == false ]]; then
    temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-vm-provenance.XXXXXX")"
    trap 'rm -rf "$temp_dir"' EXIT
    cargo metadata --locked --format-version 1 >"$temp_dir/root-metadata.json"
    cargo metadata --locked --format-version 1 --manifest-path vendor/microsandbox/Cargo.toml >"$temp_dir/nested-metadata.json"
    args+=(--root-metadata "$temp_dir/root-metadata.json" --nested-metadata "$temp_dir/nested-metadata.json")
fi
python3 script/check-runtime-provenance.py "${args[@]}"
