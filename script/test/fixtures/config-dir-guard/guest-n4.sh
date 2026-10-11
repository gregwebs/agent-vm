#!/usr/bin/env bash
# N4: the config dir is mounted as an independent copy (the fork mount). The
# append must succeed inside the guest while the host bytes stay unchanged.
# Assert the changed bytes are visible in the guest's own view and that they are
# exactly the seed plus the appended line, byte-exact via `cmp` against a
# `printf` pipe, so an embedded NUL is compared rather than silently dropped the
# way `$(cat)` drops it. The seed's trailing newline survives because the host
# loads `$1` with the `printf x` sentinel. The host `cmp` alone cannot tell an
# independent copy from a write that quietly did nothing.
set -euo pipefail
cfg="${CFG_PATH:-/cfg/config.toml}"
want="$1"
printf '%s' "$want" | cmp -s - "$cfg" || { echo N4_PRECONDITION_MISSING; exit 1; }
printf 'fork-only\n' >>"$cfg"
printf '%s%s\n' "$want" fork-only | cmp -s - "$cfg" || { echo N4_WRITE_MISSING; exit 1; }
echo N4_GUEST_OK
