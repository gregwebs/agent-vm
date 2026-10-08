#!/usr/bin/env bash
# Internal native consumer join, invoked only through e2e.sh.
# shellcheck disable=SC2016
set -euo pipefail
ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
# shellcheck source=script/test/lib/released-image-checks.sh
. "$ROOT/script/test/lib/released-image-checks.sh"
fail() { echo "released-image: $*" >&2; exit 1; }
# Gate prerequisites; declared in CONTRIBUTING.md "End-to-end (VM-boot) tests".
for tool in jq shasum python3; do
    command -v "$tool" >/dev/null 2>&1 || fail "the released-image join needs $tool on PATH"
done
BIN="${AGENT_VM_RELEASE_BIN:?set AGENT_VM_RELEASE_BIN to a relocated installed release}"
ASSETS="${AGENT_VM_E2E_RELEASE_ASSETS_DIR:?set AGENT_VM_E2E_RELEASE_ASSETS_DIR to verified native assets}"
OTHER="${AGENT_VM_E2E_OTHER_ASSETS_DIR:?set AGENT_VM_E2E_OTHER_ASSETS_DIR to verified opposite-architecture assets}"
[[ "$BIN" == /* && -x "$BIN" ]] || fail 'installed candidate must be an absolute executable path'
BIN="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$BIN")"
[[ "$BIN" != "$ROOT/"* ]] || fail 'relocate the complete release bundle outside the source checkout'
# Source provenance. The operator binds the candidate's ACTUAL build checkout to
# AGENT_VM_E2E_BUILD_SOURCE_DIR and records that binding alongside the reviewed
# build logs; this asserts that declared canonical path is absent rather than
# guessing a fixed scratch name. It checks only the declared path, so the
# correspondence is the operator's provenance claim to review, not something the
# code can detect. The helper never deletes or moves anything.
BUILD_SOURCE_CANONICAL="$(released_image_require_absent_build_source "${AGENT_VM_E2E_BUILD_SOURCE_DIR:-}")" \
    || fail 'bind AGENT_VM_E2E_BUILD_SOURCE_DIR to the candidate build checkout and make it absent'
case "$(uname -m)" in arm64|aarch64) ARCH=arm64; OTHER_ARCH=amd64 ;; x86_64) ARCH=amd64; OTHER_ARCH=arm64 ;; *) fail 'unsupported native host' ;; esac
if [[ "$(uname -s)" == Linux ]]; then
    [[ -r /dev/kvm && -w /dev/kvm ]] || fail 'native Linux join requires usable /dev/kvm'
else
    [[ "$(uname -s)" == Darwin && "$ARCH" == arm64 ]] || fail 'only Apple Silicon macOS is supported'
    prefix="$(cd "${BIN%/*}/.." && pwd -P)"
    [[ -x "$prefix/bin/msb" && -f "$prefix/lib/libkrunfw.5.dylib" ]] || fail 'relocate the complete bin/lib bundle'
    for source in images vendor Cargo.toml; do
        [[ ! -e "$prefix/$source" ]] || fail 'installed bundle contains source payloads'
    done
    codesign --verify --strict "$prefix/bin/agent-vm"
    codesign --verify --strict "$prefix/bin/msb"
    codesign --verify --strict "$prefix/lib/libkrunfw.5.dylib"
fi
fixture="$ROOT/crates/agent-vm/tests/fixtures/standard-release/release.json"
for dir in "$ASSETS" "$OTHER"; do
    [[ "$dir" == /* && -d "$dir" ]] || fail 'assets must be absolute existing directories'
    cmp "$fixture" "$dir/release.json" || fail 'asset metadata differs from committed release'
done
# Short canonical paths avoid macOS control-socket limits and guest /tmp mounts.
WORK="$(mktemp -d /tmp/av265.XXXXXX)"
WORK="$(cd "$WORK" && pwd -P)"
# Preserve logs and owned cache on either outcome; only the operator removes it,
# after confirming all VMs stopped. Never clean user caches to force cold pulls.
echo "released-image: private state and logs at $WORK"
uname -a > "$WORK/host.log"
shasum -a 256 "$BIN" > "$WORK/candidate.sha256"
printf 'build-source-absent %s\n' "$BUILD_SOURCE_CANONICAL" >> "$WORK/candidate.sha256"
if [[ "$(uname -s)" == Darwin ]]; then
    shasum -a 256 "$prefix/bin/msb" "$prefix/lib/libkrunfw.5.dylib" >> "$WORK/candidate.sha256"
fi
mkdir -p "$WORK/shim" "$WORK/r/home" "$WORK/r/project" "$WORK/a/home" "$WORK/a/project"
trap 'echo "released-image: logs retained at $WORK (status $?)" >&2' EXIT
jq --arg arch "$ARCH" '.platforms[] | select(.graph.architecture == $arch)' "$fixture" > "$WORK/native.json"
jq --arg arch "$OTHER_ARCH" '.platforms[] | select(.graph.architecture == $arch)' "$fixture" > "$WORK/other.json"
archive="$ASSETS/$(jq -er '.archive.name' "$WORK/native.json")"
other_archive="$OTHER/$(jq -er '.archive.name' "$WORK/other.json")"
for pair in native other; do
    file="$archive"; [[ "$pair" == native ]] || file="$other_archive"
    [[ -f "$file" ]] || fail "missing exact $pair archive"
    expected="$(jq -er '.archive.sha256 | sub("^sha256:"; "")' "$WORK/$pair.json")"
    [[ "$(shasum -a 256 "$file" | awk '{print $1}')" == "$expected" ]] || fail "$pair archive checksum mismatch"
done
REF="ghcr.io/gregwebs/agent-vm-standard@$(jq -er '.index_digest' "$fixture")"
for name in docker buildx; do
    cat > "$WORK/shim/$name" <<'SH'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$0 $*" >> "$BUILDER_LOG"
exit 97
SH
    chmod 755 "$WORK/shim/$name"
    status=0
    BUILDER_LOG="$WORK/calibration.log" "$WORK/shim/$name" calibration || status=$?
    [[ "$status" == 97 ]] || fail 'builder decoy calibration failed'
done
[[ "$(wc -l < "$WORK/calibration.log" | tr -d ' ')" == 2 ]] || fail 'decoys did not record calibration'
: > "$WORK/builder.log"
# Time bounds apply to the actual installed CLI, not an echoed/fake VM seam.
# A Node-dispatched (npm) candidate is invoked through a vetted absolute
# interpreter resolved from the caller PATH *before* isolation, because the
# isolated PATH may not contain an nvm//usr/local Node prefix; the native release
# is launched directly. Either way the launch runs in its own process group so a
# timeout or Ctrl-C/SIGTERM stops Node's native descendants too; the 900 s bound
# is the helper's validated default (see released-image-launch.py).
NODE_BIN=""
if released_image_is_node_candidate "$BIN"; then
    NODE_BIN="$(released_image_resolve_node "${AGENT_VM_E2E_NODE:-}")" \
        || fail 'the installed npm dispatcher needs a vetted Node interpreter'
fi
launch() {
    local route="$1" name="$2"
    shift 2
    (cd "$WORK/$route/project" && python3 "$ROOT/script/test/released-image-launch.py" \
        --root "$WORK/$route" --shim "$WORK/shim" --log "$WORK/builder.log" \
        --binary "$BIN" --interpreter "$NODE_BIN" -- "$@") > "$WORK/$name.log" 2>&1
}
inspect() {
    launch "$1" "$2" msb image inspect --format json "$3"
    jq -e --slurpfile p "$WORK/native.json" '
      .digest == $p[0].graph.manifest.digest and .os == "linux" and
      .architecture == $p[0].graph.architecture and .config.digest == $p[0].graph.config.digest and
      [.layers[].blob_digest] == [$p[0].graph.layers[].digest] and
      [.layers[].diff_id] == $p[0].graph.diff_ids and
      [.layers[].media_type] == [$p[0].graph.layers[].media_type]' "$WORK/$2.log" >/dev/null || fail 'native registry/archive graph mismatch'
}
# Probe text is ordinary guest input, not an image-owner private module import.
PROBE='set -euo pipefail
printf "uid=%s\ngid=%s\narch=%s\n" "$(id -u)" "$(id -g)" "$(uname -m)"
for tool in dsh pi codex opencode claude copilot; do
  command -v "$tool"
  version="$("$tool" --version)"
  test -n "$version"
  printf "%s\n" "$version"
  echo "agent-ok=$tool"
done
test -w "$HOME"
test "$(readlink "$HOME/.pi")" = /agent-vm-state/pi
mkdir -p "$HOME/.pi/agent"
printf persisted-265 > "$HOME/.pi/agent/released-265"
test "$(command -v pi)" = /usr/local/bin/pi
test -r /opt/agent-vm/seed.d/20-pi-claude-bridge
test -r /opt/agent-vm/pi-packages/node_modules/pi-claude-bridge/package.json
test -r /opt/agent-vm/pi-extensions/guest-credential-warning.js
echo probe-ok=265'
probe() {
    local route="$1" name="$2"
    shift 2
    launch "$route" "$name" shell --no-git "$@" -- bash -c "$PROBE"
    grep -qx "uid=$(id -u)" "$WORK/$name.log"
    grep -qx "gid=$(id -g)" "$WORK/$name.log"
    grep -qx "arch=$(uname -m | sed 's/arm64/aarch64/')" "$WORK/$name.log"
    for tool in dsh pi codex opencode claude copilot; do grep -qx "agent-ok=$tool" "$WORK/$name.log"; done
    grep -qx probe-ok=265 "$WORK/$name.log"
}
launch r version --version
cat "$WORK/version.log"
# This first launch has no config, override or test seam; all tool provisioning
# uses the shipped catalog. Managed policy/keyring must have no GHCR credential.
probe r registry
record="$WORK/r/home/.config/agent-vm/default-image.json"
jq -e --arg ref "$REF" '.version == 1 and .image == $ref' "$record" >/dev/null
cp "$record" "$WORK/record.before"
inspect r registry-inspect "$REF"
launch r persistence shell --no-git -- bash -c 'test "$(cat "$HOME/.pi/agent/released-265")" = persisted-265'
cmp "$record" "$WORK/record.before"
mkdir -p "$WORK/r/project/.agent-vm/layers/poison"
printf 'not a Dockerfile\n' > "$WORK/r/project/.agent-vm/layers/poison/Dockerfile"
launch r inert-layers shell --no-git -- bash -c true
grep -qx 'not a Dockerfile' "$WORK/r/project/.agent-vm/layers/poison/Dockerfile"
launch a archive-import msb image load --input "$archive" --tag av265:archive
inspect a archive-inspect av265:archive
probe a archive --image av265:archive
[[ ! -e "$WORK/a/home/.config/agent-vm/default-image.json" ]] || fail 'explicit archive import/boot adopted a default'
# A compatible historical selection (child ref) remains retained, even though
# this launcher recommends the index. Distinct-content cases remain in custom-image.
child="ghcr.io/gregwebs/agent-vm-standard@$(jq -er '.graph.manifest.digest' "$WORK/native.json")"
launch r child-import msb image load --input "$archive" --tag "$child"
jq -n --arg ref "$child" '{version:1,image:$ref}' > "$record"
cp "$record" "$WORK/retained.before"
launch r retained shell --no-git -- bash -c true
# Immediate: a launch that rewrote the retained child to the recommendation must
# fail here, before the manual overwrite/restore below can mask it.
released_image_assert_record_unchanged "$record" "$WORK/retained.before" retained \
    || fail 'retained launch rewrote the retained selection record'
# Each higher tier wins over an intentionally unusable lower-tier reference;
# the compatible winner is imported locally, so no alternate pull can mask it.
launch r override-import msb image load --input "$archive" --tag av265:override
project="$WORK/r/project/.agent-vm/config.toml"
user="$WORK/r/home/.config/agent-vm/config.toml"
printf 'image = "av265:override"\n' > "$project"
# A broken retained fallback makes project precedence observable at acquisition,
# rather than inferring it from two aliases containing identical guest bytes.
jq -n '{version:1,image:"invalid.example/unavailable@sha256:1111111111111111111111111111111111111111111111111111111111111111"}' > "$record"
cp "$record" "$WORK/override-record.before"
cp "$project" "$WORK/project.before"
launch r project-override shell --no-git -- bash -c true
cmp "$project" "$WORK/project.before"
printf 'image = "invalid.example/unavailable:test"\n' > "$project"
printf 'image = "av265:override"\n' > "$user"
cp "$project" "$WORK/project.bad.before"
cp "$user" "$WORK/user.before"
launch r user-override shell --no-git -- bash -c true
cmp "$project" "$WORK/project.bad.before"
cmp "$user" "$WORK/user.before"
printf 'image = "invalid.example/unavailable:test"\n' > "$user"
cp "$user" "$WORK/user.bad.before"
launch r env-override IMAGE_ENV=av265:override shell --no-git -- bash -c true
launch r cli-override IMAGE_ENV=invalid.example/unavailable:test shell --no-git --image av265:override -- bash -c true
cmp "$record" "$WORK/override-record.before"
cmp "$project" "$WORK/project.bad.before"
cmp "$user" "$WORK/user.bad.before"
cp "$WORK/retained.before" "$record"
# Negative imports target the working archive ref; failure must preserve it.
printf corrupt-archive > "$WORK/corrupt.tar"
if launch a corrupt-import msb image load --input "$WORK/corrupt.tar" --tag av265:archive; then fail 'corrupt archive accepted'; fi
inspect a after-corrupt av265:archive
if launch a wrong-arch msb image load --input "$other_archive" --tag av265:archive; then fail 'opposite-architecture archive accepted'; fi
inspect a after-wrong-arch av265:archive
cmp "$WORK/archive-inspect.log" "$WORK/after-corrupt.log"
cmp "$WORK/archive-inspect.log" "$WORK/after-wrong-arch.log"
launch a archive-after-negatives shell --no-git --image av265:archive -- bash -c true
[[ ! -e "$WORK/a/home/.config/agent-vm/default-image.json" ]] || fail 'negative imports adopted a default'
[[ ! -s "$WORK/builder.log" ]] || fail 'installed consumer invoked a builder'
released_image_assert_record_unchanged "$record" "$WORK/retained.before" retained \
    || fail 'retained selection record not restored before the negative imports'
echo 'released-image: registry/archive native join passed'
