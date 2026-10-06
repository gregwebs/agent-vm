#!/bin/bash
# Capture buildx's real stdout without replacing its exit status with tee's.
set -euo pipefail
if [[ "${1:-}" == buildx && "${2:-}" == build && -n "${BUILD_CAPTURE:-}" ]]; then
  umask 077
  (set -o noclobber; : > "$BUILD_CAPTURE") || exit 98
  set +e
  "$REAL_DOCKER" "$@" | tee "$BUILD_CAPTURE"
  statuses=("${PIPESTATUS[@]}")
  set -e
  if [[ "${statuses[1]}" != 0 ]]; then
    printf 'capture tee failed: %s\n' "${statuses[1]}" > "$BUILD_CAPTURE.error"
  fi
  exit "${statuses[0]}"
fi
exec "$REAL_DOCKER" "$@"
