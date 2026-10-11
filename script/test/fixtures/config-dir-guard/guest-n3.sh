#!/usr/bin/env bash
# N3: the config dir is mounted read-only, so the guest must not be able to
# change config.toml. Three guards make this non-vacuous:
#   * `$1` is the exact seed the host wrote, trailing newline included; the
#     comparison is byte-exact via `cmp` against `printf '%s' "$want"`, so an
#     embedded NUL is compared rather than silently dropped the way `$(cat)`
#     drops it. The trailing newline survives because the host loads `$1` with
#     the `printf x` sentinel (the sentinel now lives only in that host load);
#   * an explicit write-success check, because bash exempts a bare `!` from
#     errexit, so `! sh -c "write"; echo ok` passes even when the write worked;
#   * the bytes are re-compared after the attempt, since the write could have
#     partially succeeded.
# CFG_PATH overrides /cfg/config.toml for the boot-free host controls.
set -euo pipefail
cfg="${CFG_PATH:-/cfg/config.toml}"
want="$1"
printf '%s' "$want" | cmp -s - "$cfg" || { echo N3_PRECONDITION_MISSING; exit 1; }
if sh -c 'echo x >> "$1"' sh "$cfg"; then
  echo N3_WRITE_SUCCEEDED
  exit 1
fi
printf '%s' "$want" | cmp -s - "$cfg" || { echo N3_CONTENT_CHANGED; exit 1; }
echo N3_GUEST_OK
