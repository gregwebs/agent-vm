#!/usr/bin/env bash
# Offline provenance check; installed launchers and Cargo tests need no sources.
set -euo pipefail

ROOT="$(cd "${1:-${BASH_SOURCE[0]%/*}/../..}" && pwd)"
[[ $# -le 1 ]] || { echo 'usage: standard-release-pin.sh [checkout]' >&2; exit 2; }
fail() { echo "standard release pin: $*" >&2; exit 1; }
fixture="$ROOT/crates/agent-vm/tests/fixtures/standard-release/release.json"
# This snapshot is the published metadata, not a locally generated protocol.
[[ "$(shasum -a 256 "$fixture" | awk '{print $1}')" == 402706fe8b213f52a2d9dff3de34a7cac63ab3f6d2df11df84dfa5e7d47532ad ]] || fail 'published metadata changed'
jq -e '.product == "standard" and (.platforms | length) == 2 and
    ([.platforms[].graph | [.os, .architecture]] | sort) == [["linux","amd64"],["linux","arm64"]] and
    ([.platforms[].graph.manifest.digest] | unique | length) == 2 and
    (.index_digest as $index | all(.platforms[]; .graph.manifest.digest != $index))' "$fixture" >/dev/null || fail 'invalid platform set'
source_sha="$(jq -er '.source_sha' "$fixture")"
version="$(jq -er '.version' "$fixture")"
index="$(jq -er '.index_digest' "$fixture")"
entries="$(git -C "$ROOT" config -f .gitmodules --get-regexp '^submodule\..*\.path$' | awk '$2 == "vendor/agent-vm-images" {print $1}')"
[[ "$entries" == submodule.vendor/agent-vm-images.path ]] || fail 'image submodule path/name must occur exactly once'
[[ "$(git -C "$ROOT" config -f .gitmodules --get-all submodule.vendor/agent-vm-images.url)" == https://github.com/gregwebs/agent-vm-images.git ]] || fail 'wrong image submodule URL'
[[ "$(git -C "$ROOT" ls-files --stage vendor/agent-vm-images)" == "160000 $source_sha 0"$'\tvendor/agent-vm-images' ]] || fail 'wrong image gitlink'
constant="$(sed -n 's/^pub const INITIAL_DEFAULT_IMAGE_REF: &str = "\([^"]*\)";$/\1/p' "$ROOT/crates/agent-vm/src/defaults.rs")"
[[ "$constant" == "ghcr.io/gregwebs/agent-vm-standard@$index" ]] || fail 'wrong or duplicate initial recommendation'
if [[ -f "$ROOT/vendor/agent-vm-images/images/standard/version" ]]; then
    printf '%s\n' "$version" | cmp - "$ROOT/vendor/agent-vm-images/images/standard/version" || fail 'source version differs from release'
elif [[ -e "$ROOT/vendor/agent-vm-images/.git" ]]; then
    fail 'initialized image sources lack images/standard/version'
else
    echo 'notice: image sources uninitialized; skipping source version check only' >&2
fi
echo 'standard release pin passed'
