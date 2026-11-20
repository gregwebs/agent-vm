#!/usr/bin/env bash
# Phase 0 native CPU-commitment evidence (issue #647, plan P0-A..P0-F).
#
# One invocation owns: a fresh evidence directory, a fresh owned recursive checkout of the
# pinned commits, an isolated CARGO_TARGET_DIR, a rebuilt signed runtime pair, the fresh
# runtime HOME/state, and exactly one live sandbox at a time. It never writes to the
# operator's checkout, never touches operator policy/keychain, and never cleans anything it
# did not create.
#
# Usage: script/test/cpu-commitment-native.sh [calibration|integrated]
#
# Exit codes: 0 attested host-local PASS, 1 a qualified trial failed its criteria,
# 2 invocation misuse, 3 INCONCLUSIVE/BLOCKED prerequisite (missing provenance, host,
# container identity, image, capacity or enforcement). No PASS file survives a nonzero exit.
#
# Operator-authorized deviation from P0-A image acquisition (recorded in
# evidence/cache-source.txt): the fresh MSB_HOME gets a read-only-intent symlink to the
# operator's content-addressed image cache instead of a registry pull, because registry pulls
# are unreliable on this host. This makes image provenance the cache's, not a fresh pull's; it
# is recorded, never hidden. Set AGENT_VM_CPU_ALLOW_REGISTRY_PULL=1 to skip the symlink.

set -euo pipefail
set -E

MODE="${1:-calibration}"
case "$MODE" in
  calibration | integrated) ;;
  *)
    echo "cpu-commitment-native: unknown mode ${MODE:-<empty>}; expected calibration|integrated" >&2
    exit 2
    ;;
esac
[[ $# -le 1 ]] || {
  echo "cpu-commitment-native: expected at most one mode argument" >&2
  exit 2
}

ROOT="$(pwd -P)"
V="$ROOT/vendor/microsandbox"
VENDOR_PIN="25c29e17c58c54d0f5e0efedfd9347ad8b7d00f2"
E="$(mktemp -d /tmp/c647.XXXXXX)"
BUILD="$ROOT/target/$(basename "$E")"
PAIR="$BUILD/pair"
SRC="$BUILD/vendor-source"
test ! -e "$BUILD"
test ! -e "$PAIR"
mkdir -p "$E/home" "$E/state" "$E/msb" "$E/evidence" "$BUILD" "$PAIR"
export CARGO_TARGET_DIR="$BUILD/agent"
printf '%s\n' "ROOT=$ROOT E=$E BUILD=$BUILD SRC=$SRC PAIR=$PAIR MODE=$MODE" \
  | tee "$E/evidence/paths.txt"
# ADR-0072: the selection, manifest, snapshot and identity steps are harness
# subcommands. Built once by the caller; see crates/harness/README.md.
HARNESS="${HARNESS_BIN_DIR:-$ROOT/target/debug}/harness"
[[ -x "$HARNESS" ]] || {
  printf 'INCONCLUSIVE: missing harness binary %s (run: cargo build --locked -p agent-vm-harness --bins)\n' \
    "$HARNESS" | tee "$E/evidence/status.txt" >&2
  exit 3
}
# Retain outputs, including on failure; nothing under E/BUILD/SRC is auto-deleted.
exec > >(tee -a "$E/evidence/commands.log") 2>&1
export PS4='+ ${BASH_SOURCE##*/}:${LINENO}: '
set -x

# The ERR trap invokes this indirectly, which shellcheck cannot see.
# shellcheck disable=SC2329
on_error() {
  local status=$?
  printf 'FAILED_COMMAND status=%s command=%s\n' "$status" "$BASH_COMMAND" \
    >>"$E/evidence/failure.txt"
}
trap on_error ERR

verify_pin_and_cleanliness() {
  case "$(uname -s)" in
    Darwin) ;;
    Linux)
      printf '%s\n' 'BLOCKED: Linux/KVM — no host supplied' | tee "$E/evidence/status.txt"
      exit 3
      ;;
    *)
      printf '%s\n' 'INCONCLUSIVE: unattested host' | tee "$E/evidence/status.txt"
      exit 3
      ;;
  esac
  [[ "$(git -C "$V" rev-parse HEAD)" == "$VENDOR_PIN" ]]
  git -C "$V" diff --exit-code HEAD
  git -C "$V" submodule status --recursive >"$E/evidence/submodules.txt"
  if grep -Eq '^[+U-]' "$E/evidence/submodules.txt"; then
    printf '%s\n' 'INCONCLUSIVE: a nested vendor submodule is uninitialized or drifted' \
      | tee "$E/evidence/status.txt"
    exit 3
  fi
  git -C "$V" submodule foreach --recursive 'git diff --exit-code HEAD'
  git rev-parse HEAD >"$E/evidence/agent-sha.txt"
  git -C "$V" rev-parse HEAD >"$E/evidence/vendor-sha.txt"
  uname -a >"$E/evidence/host.txt"
}

snapshot_committed_inputs() {
  "$HARNESS" cpu-commitment snapshot "$V" "$SRC" >"$E/evidence/build-inputs.jsonl"
  # Generated kernels/bundles and host libraries are never tracked inputs; their absence from
  # the snapshot ledger is asserted rather than assumed.
  if grep -Eq 'kernel\.c|linux-[^"]|libkrunfw[^"]*\.(dylib|so)' "$E/evidence/build-inputs.jsonl"; then
    printf '%s\n' 'INCONCLUSIVE: the build-input ledger names generated artifacts' \
      | tee "$E/evidence/status.txt"
    exit 3
  fi
}

build_runtime_pair() {
  # The pinned macOS container recipe, unmodified; no installed-firmware fallback.
  export LIBKRUNFW_BUILD_BACKEND=docker
  docker version >"$E/evidence/container-version.txt"
  docker pull fedora:latest
  docker image inspect fedora:latest >"$E/evidence/container-before.json"
  shasum -a 256 "$SRC/justfile" "$SRC/vendor/libkrunfw/build_in_docker.sh" \
    "$SRC/vendor/libkrunfw/Makefile" >"$E/evidence/firmware-recipe-sha256.txt"
  (cd "$SRC" && JUST_UNSTABLE=1 just build-deps)
  docker image inspect fedora:latest >"$E/evidence/container-after.json"
  "$HARNESS" cpu-commitment container-identity \
    "$E/evidence/container-before.json" "$E/evidence/container-after.json"
  (cd "$SRC" && CARGO_TARGET_DIR="$BUILD/vendor" cargo build --locked --release \
    --no-default-features --features embed-binaries,net,ssh,keyring -p microsandbox-cli)
  cp "$BUILD/vendor/release/msb" "$PAIR/msb"
  cp "$SRC/build/libkrunfw.5.dylib" "$PAIR/libkrunfw.5.dylib"
  codesign --entitlements "$SRC/msb-entitlements.plist" --force -s - "$PAIR/msb"
  codesign --verify --verbose "$PAIR/msb"
  FW="$PAIR/libkrunfw.5.dylib"
  printf '%s\n' "firmware_path=$FW" 'origin=pinned macOS container recipe' \
    'clean-from-source firmware rebuild: UNPROVEN' >"$E/evidence/firmware-provenance.txt"
  shasum -a 256 "$PAIR/msb" "$FW" >"$E/evidence/runtime-sha256.txt"
}

build_test_binary() {
  cargo test --locked -p agent-vm --bin agent-vm --no-run --message-format=json \
    >"$E/evidence/cargo.jsonl"
  TEST_BIN="$("$HARNESS" cpu-commitment select "$E/evidence/cargo.jsonl" "$CARGO_TARGET_DIR")"
  test -x "$TEST_BIN"
  "$TEST_BIN" --list >"$E/evidence/tests.txt"
  grep -Fx 'resources::tests::native_cpu_commitment_evidence: test' "$E/evidence/tests.txt"
  shasum -a 256 "$TEST_BIN" >"$E/evidence/test-sha256.txt"
}

prepare_fresh_runtime_home() {
  local cache="${AGENT_VM_CPU_IMAGE_CACHE:-$HOME/.microsandbox/cache}"
  if [[ "${AGENT_VM_CPU_ALLOW_REGISTRY_PULL:-0}" == "1" ]]; then
    printf '%s\n' 'image_acquisition=registry-pull (operator opted out of the cache symlink)' \
      >"$E/evidence/cache-source.txt"
  else
    [[ -d "$cache" ]] || {
      printf 'INCONCLUSIVE: the operator image cache %s is missing\n' "$cache" \
        | tee "$E/evidence/status.txt"
      exit 3
    }
    ln -s "$cache" "$E/msb/cache"
    printf 'image_acquisition=cache-symlink cache=%s\n' "$cache" \
      >"$E/evidence/cache-source.txt"
  fi
  "$HARNESS" cpu-commitment manifest verify "$E/evidence" "$PAIR/msb" "$FW"
}

run_protocol() {
  verify_pin_and_cleanliness
  snapshot_committed_inputs
  build_runtime_pair
  "$HARNESS" cpu-commitment manifest write "$E/evidence" \
    "$PAIR/msb" "$FW" "$(cat "$E/evidence/agent-sha.txt")" "$(cat "$E/evidence/vendor-sha.txt")"
  "$HARNESS" cpu-commitment manifest verify "$E/evidence" "$PAIR/msb" "$FW"
  build_test_binary
  prepare_fresh_runtime_home
  env -i HOME="$E/home" PATH="/opt/homebrew/bin:/usr/bin:/bin" \
    AGENT_VM_STATE_DIR="$E/state" MSB_HOME="$E/msb" \
    MSB_PATH="$PAIR/msb" MSB_LIBKRUNFW_PATH="$FW" \
    AGENT_VM_CPU_EVIDENCE_DIR="$E/evidence" AGENT_VM_CPU_EVIDENCE_MODE="$MODE" \
    "$TEST_BIN" resources::tests::native_cpu_commitment_evidence \
    --ignored --exact --nocapture --test-threads=1
  # The harness writes success only after every criterion AND owned cleanup succeeded.
  test -f "$E/evidence/PASS"
  git -C "$V" diff --exit-code HEAD
  git -C "$V" submodule foreach --recursive 'git diff --exit-code HEAD'
}

set +e
# Errexit must be *on inside* the protocol. `set +e` here only preserves the status of the
# subshell; without re-enabling it there, a failed prerequisite (a build, a provenance check, a
# selector) would fall through to later stages and could end with a passing final command and a
# PASS. The subshell's own `set -e` is what makes each stage fatal.
( set -e; run_protocol )
STATUS=$?
set -e

STATUS_TEXT="$(cat "$E/evidence/status.txt" 2>/dev/null || true)"
if [[ $STATUS -ne 0 || "$STATUS_TEXT" != PASS:* ]]; then
  rm -f "$E/evidence/PASS"
  printf 'wrapper exit status=%s harness status=%s\n' "$STATUS" "${STATUS_TEXT:-<none>}" \
    >>"$E/evidence/script-status.txt"
  case "$STATUS_TEXT" in
    INCONCLUSIVE:*)
      printf 'INCONCLUSIVE: %s\n' "${STATUS_TEXT#INCONCLUSIVE: }" >&2
      exit 3
      ;;
    FAIL:*)
      printf 'FAIL: %s\n' "${STATUS_TEXT#FAIL: }" >&2
      exit 1
      ;;
    MISUSE:*)
      printf 'MISUSE: %s\n' "${STATUS_TEXT#MISUSE: }" >&2
      exit 2
      ;;
  esac
  printf 'INCONCLUSIVE: protocol step exited %s; see %s\n' "$STATUS" \
    "$E/evidence/commands.log" >&2
  exit 3
fi
printf 'PASS: attested host-local Phase 0 evidence in %s\n' "$E/evidence"
exit 0
