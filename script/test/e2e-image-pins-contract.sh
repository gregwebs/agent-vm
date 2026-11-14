#!/usr/bin/env bash
# Boot-free contract for the shared pins environment (script/test/lib/e2e-image-pins.sh).
#
# Runs the **production** helpers against a fake binary that records its actual
# child environment, cwd and argv, so the ambient-override wiring cannot silently
# rot: a prefix assignment, an exported override or a mutated `PINS_ENV` all fail
# here. It also guards the one production call site that needs the ambient form,
# because correct helpers alone do not prove the call site uses them (#543).
#
# No registry, runtime, Docker or VM is touched; the release-only native e2e
# (`script/test/e2e.sh custom-image`) still needs its dedicated serial host.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="$REPO_ROOT/script/test/lib/e2e-image-pins.sh"
E2E="$REPO_ROOT/script/test/e2e.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/avpinscontract.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# The fake binary records what the **child process** actually saw: its whole
# environment for the two variables that matter, its cwd and its argv.
RECORD="$WORK/record"
: >"$RECORD"
FAKE_BIN="$WORK/av-fake"
cat >"$FAKE_BIN" <<EOF
#!/bin/sh
{
  printf 'tag=%s\n' "\${AGENT_VM_IMAGE_TAG-<unset>}"
  printf 'home=%s\n' "\$HOME"
  printf 'state=%s\n' "\${AGENT_VM_STATE_DIR-<unset>}"
  printf 'cwd=%s\n' "\$(pwd -P)"
  printf 'argv='
  for arg in "\$@"; do printf '%s|' "\$arg"; done
  printf '\n'
} >>'$RECORD'
exit 0
EOF
chmod +x "$FAKE_BIN"

PROJECT="$WORK/project"
HOME_DIR="$WORK/home"
STATE_DIR="$WORK/state"
mkdir -p "$PROJECT" "$HOME_DIR" "$STATE_DIR"
PROJECT_REAL="$(cd "$PROJECT" && pwd -P)"

# shellcheck source=script/test/lib/e2e-image-pins.sh
. "$LIB"

last_record() {
    tail -n 5 "$RECORD"
}

reset_record() { : >"$RECORD"; }

# --- pins_default_clears_inherited_image_override ------------------------------
# The default helper clears an inherited image override in the actual child.
PINS_BIN="$FAKE_BIN"
export AGENT_VM_IMAGE_TAG="inherited-sentinel:1"
pins_env "$HOME_DIR" "$STATE_DIR"
reset_record
pins_avm "$PROJECT" image refresh || fail "pins_avm exited nonzero"
record="$(last_record)"
grep -qx 'tag=<unset>' <<<"$record" || fail "the default helper leaked an inherited AGENT_VM_IMAGE_TAG:
$record"
grep -qx "home=$HOME_DIR" <<<"$record" || fail "the default helper lost HOME:
$record"
grep -qx "state=$STATE_DIR" <<<"$record" || fail "the default helper lost the state root:
$record"
grep -qx "cwd=$PROJECT_REAL" <<<"$record" || fail "the default helper ran outside the project:
$record"
grep -qx 'argv=image|refresh|' <<<"$record" || fail "the default helper changed argv:
$record"

# --- pins_ambient_override_reaches_the_actual_child ----------------------------
# The ambient helper's value reaches the actual child, and does not leak into a
# later default command.
reset_record
pins_avm_ambient "$PROJECT" "registry.example:5000/native:fixture" image refresh ||
    fail "pins_avm_ambient exited nonzero"
record="$(last_record)"
grep -qx 'tag=registry.example:5000/native:fixture' <<<"$record" ||
    fail "the ambient override did not reach the child (a prefix assignment would be erased):
$record"
grep -qx "cwd=$PROJECT_REAL" <<<"$record" || fail "the ambient helper ran outside the project:
$record"
grep -qx 'argv=image|refresh|' <<<"$record" || fail "the ambient helper changed argv:
$record"

# A following default command still sees the override cleared: the ambient
# helper must not leak its value into `PINS_ENV` or the caller's environment.
reset_record
pins_avm "$PROJECT" image refresh || fail "the follow-up pins_avm exited nonzero"
record="$(last_record)"
grep -qx 'tag=<unset>' <<<"$record" || fail "the ambient override leaked into a later command:
$record"
[ "${AGENT_VM_IMAGE_TAG-}" = "inherited-sentinel:1" ] ||
    fail "the ambient helper mutated the caller's environment"
unset AGENT_VM_IMAGE_TAG || true

# --- pins_live_seed_dispatch_uses_ambient_helper -------------------------------
# The production live-seed call site uses the ambient helper.
# Helpers alone do not certify wiring, so the real script's one live-seed
# dispatch is checked between two uniquely anchored lines. Missing, duplicated or
# reordered anchors fail closed; they are never skipped.
python3 - "$E2E" <<'PY' || exit 1
import re
import sys

path = sys.argv[1]
lines = open(path, encoding="utf-8").read().splitlines()
anchor = 'live_id="$(pins_project_id "$live")"'
starts = [index for index, line in enumerate(lines) if line.strip() == anchor]
if len(starts) != 1:
    sys.exit(f"FAIL: expected exactly one live-seed anchor, found {len(starts)}")
start = starts[0]
window_end = start + 13
end_anchor = 'if ! jq -e --arg p "$live_id" --arg r "$tag" --arg d "$digest_a" \\'
ends = [
    index
    for index, line in enumerate(lines[start + 1 : window_end], start=start + 1)
    if line.strip() == end_anchor
]
if len(ends) != 1:
    sys.exit(f"FAIL: expected exactly one jq anchor within 12 lines, found {len(ends)}")
end = ends[0]
calls = [
    (index, line.strip())
    for index, line in enumerate(lines[start + 1 : end], start=start + 1)
    if "image refresh" in line
]
expected = 'pins_avm_ambient "$live" "$tag" image refresh >"$WORK/pins-live-pin.out" 2>&1 || {'
if len(calls) != 1:
    sys.exit(f"FAIL: expected exactly one live-seed refresh call, found {calls}")
if calls[0][1] != expected:
    sys.exit(
        "FAIL: the live-seed dispatch must be the ambient helper form "
        f"{expected!r}, found {calls[0][1]!r}"
    )
close = [
    index
    for index, line in enumerate(lines[calls[0][0] + 1 : end], start=calls[0][0] + 1)
    if line.strip() == "}"
]
if not close:
    sys.exit("FAIL: the live-seed failure block has no closing brace before the jq check")
PY

echo "control pins_default_clears_inherited_image_override passed"
echo "control pins_ambient_override_reaches_the_actual_child passed"
echo "control pins_live_seed_dispatch_uses_ambient_helper passed"
echo "e2e image pins contract passed"
