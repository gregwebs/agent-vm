#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/av-pin.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
bash "$ROOT/script/test/standard-release-pin.sh"
mkdir -p "$WORK/crates/agent-vm/src" "$WORK/crates/agent-vm/tests/fixtures/standard-release" "$WORK/vendor/agent-vm-images/images/standard"
cp "$ROOT/.gitmodules" "$WORK/"
cp "$ROOT/crates/agent-vm/src/defaults.rs" "$WORK/crates/agent-vm/src/"
cp "$ROOT/crates/agent-vm/tests/fixtures/standard-release/release.json" "$WORK/crates/agent-vm/tests/fixtures/standard-release/"
fixture="$WORK/crates/agent-vm/tests/fixtures/standard-release/release.json"
sha="$(jq -er '.source_sha' "$fixture")"
version="$WORK/vendor/agent-vm-images/images/standard/version"
printf '%s\n' "$(jq -er '.version' "$fixture")" > "$version"
git -C "$WORK" init -q
git -C "$WORK" update-index --add --cacheinfo "160000,$sha,vendor/agent-vm-images"
bash "$ROOT/script/test/standard-release-pin.sh" "$WORK"
reject() {
    if bash "$ROOT/script/test/standard-release-pin.sh" "$WORK" > "$WORK/result" 2>&1; then
        echo "FAIL: pin check accepted $1" >&2; exit 1
    fi
    grep -Fq "$2" "$WORK/result" || { cat "$WORK/result" >&2; exit 1; }
}
git -C "$WORK" update-index --cacheinfo '160000,1111111111111111111111111111111111111111,vendor/agent-vm-images'
reject gitlink 'wrong image gitlink'
git -C "$WORK" update-index --cacheinfo "160000,$sha,vendor/agent-vm-images"
printf '0.0.0\n' > "$version"
reject version 'source version differs'
printf '%s\n' "$(jq -er '.version' "$fixture")" > "$version"
sed 's/ghcr.io\/gregwebs\/agent-vm-standard@/example.invalid\/child@/' "$ROOT/crates/agent-vm/src/defaults.rs" > "$WORK/crates/agent-vm/src/defaults.rs"
reject constant 'wrong or duplicate initial recommendation'
cp "$ROOT/crates/agent-vm/src/defaults.rs" "$WORK/crates/agent-vm/src/defaults.rs"
jq '.platforms[0].graph.manifest.digest = .index_digest' "$fixture" > "$WORK/changed.json"
mv "$WORK/changed.json" "$fixture"
reject platform-digest 'published metadata changed'
echo 'standard release pin negative controls passed'
