#!/bin/bash
set -euo pipefail

BASE_DOCKERFILE=images/Dockerfile
LAYER_DOCKERFILE=examples/layers/chrome-devtools/Dockerfile
WRAPPER=examples/layers/chrome-devtools/agent-vm-chrome-mcp
MARKER=/etc/agent-vm-capabilities/chrome-devtools-mcp

for forbidden in 'chromium' 'agent-vm-chrome-mcp' 'chrome-devtools-mcp' 'chrome:x:9999'; do
    ! grep -Fq "$forbidden" "$BASE_DOCKERFILE" || { echo "base still contains $forbidden" >&2; exit 1; }
done
for required in \
    "$MARKER" \
    '/usr/bin/google-chrome-stable' \
    '/opt/google/chrome/chrome' \
    'visudo -cf' \
    'sudo -u chrome -H -- test -w' \
    'getent group 9999' \
    'getent passwd 9999'; do
    grep -Fq "$required" "$LAYER_DOCKERFILE" || { echo "layer lacks required contract check: $required" >&2; exit 1; }
done
grep -Fq "$MARKER" crates/agent-vm/src/defaults.rs
grep -Fq 'failed to prepare chrome NSS DB' "$WRAPPER"
grep -Fq 'sudo -u chrome -H -n' "$WRAPPER"
! grep -Fq '|| true' "$WRAPPER"
bash -n "$WRAPPER"
