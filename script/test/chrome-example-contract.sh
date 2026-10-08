#!/usr/bin/env bash
# The optional Chrome capability belongs to this user-Dockerfile example.
set -euo pipefail
ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
cd "$ROOT"
DOCKERFILE=examples/layers/chrome-devtools/Dockerfile
WRAPPER=examples/layers/chrome-devtools/agent-vm-chrome-mcp
DEFAULTS=crates/agent-vm/src/defaults.rs
marker="$(sed -n 's/^pub const CHROME_MCP_CAPABILITY_PATH: &str = "\([^"]*\)";$/\1/p' "$DEFAULTS")"
wrapper="$(sed -n 's/^pub const CHROME_MCP_WRAPPER_PATH: &str = "\([^"]*\)";$/\1/p' "$DEFAULTS")"
[[ -n "$marker" && -n "$wrapper" ]] || exit 1
for required in "$marker" "$wrapper" '/usr/bin/google-chrome-stable' \
    '/opt/google/chrome/chrome' 'visudo -cf' 'sudo -u chrome -H -- test -w' \
    'getent group 9999' 'getent passwd 9999'; do
    grep -Fq "$required" "$DOCKERFILE" || { echo "Chrome example lacks: $required" >&2; exit 1; }
done
[[ "$(tail -1 "$DOCKERFILE")" == " && : > $marker" ]] || { echo 'Chrome marker must be written last' >&2; exit 1; }
grep -Fq 'failed to prepare chrome NSS DB' "$WRAPPER"
grep -Fq 'sudo -u chrome -H -n' "$WRAPPER"
grep -Fq 'cannot cd to HOME' "$WRAPPER"
if grep -Fq '|| true' "$WRAPPER"; then
    echo 'Chrome wrapper must not swallow failures' >&2
    exit 1
fi
bash -n "$WRAPPER"
echo 'Chrome example static contract passed'
