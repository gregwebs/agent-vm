#!/usr/bin/env bash
# These assertions grep for literal text, so $VAR must not expand (SC2016).
# shellcheck disable=SC2016
# VM-free fault checks for the Phase 0 native protocol (plan T20).
#
# These checks never boot a VM and never run the expensive build: they drive the selector and
# manifest helpers directly and use a failing fake `docker` to prove the wrapper stops before
# any native invocation or PASS. The actual isolated build and the stale-input build fixture
# are host-gated in the protocol itself, not mocked here.
#
# Exit 0 when every fault check produced its required refusal; exit 1 otherwise.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
SCRIPT="script/test/cpu-commitment-native.sh"
SELECT="script/test/cpu-commitment-select.py"
MANIFEST="script/test/cpu-commitment-manifest.py"
WORK="$(mktemp -d /tmp/c647-contract.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail() {
  echo "contract: FAIL: $*" >&2
  exit 1
}

expect_status() {
  local expected="$1"
  shift
  set +e
  "$@" >"$WORK/out.txt" 2>&1
  local status=$?
  set -e
  [[ $status -eq $expected ]] || {
    echo "--- output ---" >&2
    cat "$WORK/out.txt" >&2
    fail "expected status $expected from $* but got $status"
  }
}

# 1. Syntax and mode handling.
bash -n "$SCRIPT"
bash -n "$(dirname "$SCRIPT")/cpu-commitment-native-contract.sh"
expect_status 2 bash "$SCRIPT" bogus-mode
expect_status 2 bash "$SCRIPT" calibration extra
grep -Fq 'AGENT_VM_CPU_EVIDENCE_MODE="$MODE"' "$SCRIPT" ||
  fail "the wrapper must forward the declared mode"
grep -Fq 'resources::tests::native_cpu_commitment_evidence' "$SCRIPT" ||
  fail "the wrapper must invoke the documented test path"
grep -Fq 'CARGO_TARGET_DIR="$BUILD/agent"' "$SCRIPT" ||
  fail "the wrapper must use an explicit isolated CARGO_TARGET_DIR"
grep -Fq 'set -euo pipefail' "$SCRIPT" || fail "the wrapper must be fail-fast"

# 2. Selector: 0 or 2 matching artifacts, outside-target, nonexistent and stale paths.
mkdir -p "$WORK/isolated/deps"
artifact() {
  # $1 reason, $2 target name, $3 kind, $4 test profile, $5 executable, $6 success
  python3 - "$@" <<'PY'
import json, sys
reason, name, kind, test_profile, executable, success = sys.argv[1:7]
row = {"reason": reason}
if reason == "compiler-artifact":
    row["target"] = {"name": name, "kind": [kind]}
    row["profile"] = {"test": test_profile == "true"}
    row["executable"] = executable
else:
    row["success"] = success == "true"
print(json.dumps(row))
PY
}
write_artifact() {
  local path="$1"
  printf '#!/bin/sh\nexit 0\n' >"$path"
  chmod +x "$path"
}

write_artifact "$WORK/isolated/deps/agent_vm-aaaa"
{
  artifact build-finished agent-vm bin false "" true
  artifact compiler-artifact agent-vm bin true "$WORK/isolated/deps/agent_vm-aaaa" ""
} >"$WORK/good.jsonl"
expect_status 0 python3 "$SELECT" "$WORK/good.jsonl" "$WORK/isolated"

{
  artifact build-finished agent-vm bin false "" true
} >"$WORK/zero.jsonl"
expect_status 1 python3 "$SELECT" "$WORK/zero.jsonl" "$WORK/isolated"

write_artifact "$WORK/isolated/deps/agent_vm-bbbb"
{
  artifact build-finished agent-vm bin false "" true
  artifact compiler-artifact agent-vm bin true "$WORK/isolated/deps/agent_vm-aaaa" ""
  artifact compiler-artifact agent-vm bin true "$WORK/isolated/deps/agent_vm-bbbb" ""
} >"$WORK/two.jsonl"
expect_status 1 python3 "$SELECT" "$WORK/two.jsonl" "$WORK/isolated"

write_artifact "$WORK/outside-agent_vm"
{
  artifact build-finished agent-vm bin false "" true
  artifact compiler-artifact agent-vm bin true "$WORK/outside-agent_vm" ""
} >"$WORK/outside.jsonl"
expect_status 1 python3 "$SELECT" "$WORK/outside.jsonl" "$WORK/isolated"
# A stale executable planted in another target directory is never selected by name search.
mkdir -p "$WORK/other-target/deps"
write_artifact "$WORK/other-target/deps/agent_vm-stale"
expect_status 1 python3 "$SELECT" "$WORK/outside.jsonl" "$WORK/isolated"

{
  artifact build-finished agent-vm bin false "" true
  artifact compiler-artifact agent-vm bin true "$WORK/isolated/deps/does-not-exist" ""
} >"$WORK/missing.jsonl"
expect_status 1 python3 "$SELECT" "$WORK/missing.jsonl" "$WORK/isolated"

{
  artifact build-finished agent-vm bin false "" false
  artifact compiler-artifact agent-vm bin true "$WORK/isolated/deps/agent_vm-aaaa" ""
} >"$WORK/failed-build.jsonl"
expect_status 1 python3 "$SELECT" "$WORK/failed-build.jsonl" "$WORK/isolated"

{
  artifact build-finished agent-vm bin false "" true
  artifact compiler-artifact agent-vm lib false "" ""
} >"$WORK/lib-only.jsonl"
expect_status 1 python3 "$SELECT" "$WORK/lib-only.jsonl" "$WORK/isolated"

expect_status 2 python3 "$SELECT" "$WORK/good.jsonl"

# 3. Manifest: write/verify, then every missing or mismatched provenance refuses.
mkdir -p "$WORK/evidence"
printf 'msb' >"$WORK/msb"
printf 'firmware' >"$WORK/firmware"
expect_status 0 python3 "$MANIFEST" write "$WORK/evidence" "$WORK/msb" "$WORK/firmware" \
  "$(printf 'a%.0s' {1..40})" "$(printf 'b%.0s' {1..40})"
expect_status 0 python3 "$MANIFEST" verify "$WORK/evidence" "$WORK/msb" "$WORK/firmware"

cp -r "$WORK/evidence" "$WORK/no-manifest"
rm "$WORK/no-manifest/runtime-manifest.json"
expect_status 3 python3 "$MANIFEST" verify "$WORK/no-manifest" "$WORK/msb" "$WORK/firmware"

cp -r "$WORK/evidence" "$WORK/mismatch"
printf 'firmware-changed' >>"$WORK/mismatch-firmware"
printf 'firmware' >"$WORK/mismatch-firmware"
expect_status 3 python3 "$MANIFEST" verify "$WORK/mismatch" "$WORK/msb" "$WORK/mismatch-firmware"

cp -r "$WORK/evidence" "$WORK/hash-only"
python3 - "$WORK/hash-only/runtime-manifest.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
manifest = json.loads(path.read_text())
manifest["clean_firmware_rebuild"] = "PROVEN"
path.write_text(json.dumps(manifest))
PY
expect_status 3 python3 "$MANIFEST" verify "$WORK/hash-only" "$WORK/msb" "$WORK/firmware"

# 4. Wrapper fail-fast: a failing fake docker stops the protocol before any native invocation
#    and leaves no PASS. Old executables under target/ are irrelevant to the selection.
mkdir -p "$WORK/fakebin"
printf '#!/bin/sh\necho "fake docker refuses" >&2\nexit 1\n' >"$WORK/fakebin/docker"
chmod +x "$WORK/fakebin/docker"
set +e
PATH="$WORK/fakebin:$PATH" bash "$SCRIPT" calibration >"$WORK/script.txt" 2>&1
STATUS=$?
set -e
[[ $STATUS -eq 3 ]] || fail "a failing vendor build must exit 3, got $STATUS"
EVID="$(sed -n 's/.* E=\([^ ]*\).*/\1/p' "$WORK/script.txt" | head -1)"
[[ -n "$EVID" && -d "$EVID" ]] || fail "the wrapper must name its evidence directory"
[[ ! -e "$EVID/evidence/PASS" ]] || fail "a failing protocol must leave no PASS"
[[ ! -e "$EVID/evidence/PASS" ]] || fail "PASS file survived a refusal"
grep -Fq 'fake docker refuses' "$EVID/evidence/commands.log" ||
  fail "the evidence must retain the exact failing command output"
grep -Fq 'FAILED_COMMAND' "$EVID/evidence/failure.txt" ||
  fail "the evidence must name the failed command"
grep -Fq '"source"' "$EVID/evidence/build-inputs.jsonl" ||
  fail "the owned recursive snapshot ledger must be recorded"
if grep -Eq 'kernel\.c|libkrunfw[^"]*\.(dylib|so)' "$EVID/evidence/build-inputs.jsonl"; then
  fail "the snapshot ledger must exclude generated kernel/bundle inputs"
fi
grep -Fq 'libkrunfw.5.dylib' "$SCRIPT" || fail "the firmware artifact must be named"
grep -Fq 'UNPROVEN' "$SCRIPT" || fail "the UNPROVEN clean-rebuild label must persist"
# The failed run's owned build directory is test-created scratch, not operator state.
rm -rf "$EVID" "$ROOT/target/$(basename "$EVID")"

# 5. Errexit inside the protocol subshell (review F2). The wrapper captures the protocol's status
#    with `set +e`, which also disables errexit for everything the subshell inherits. The subshell
#    must re-enable it, or a failed prerequisite falls through to later stages and a passing last
#    command can still produce a PASS.
grep -Fq '( set -e; run_protocol )' "$SCRIPT" ||
  fail "the protocol subshell must re-enable errexit"

# The same construct with a three-stage chain whose middle stage fails and whose last stage would
# succeed: the third stage must not run, and the subshell must report the failure rather than the
# last command's status. This pins the shell semantics the wrapper depends on; the end-to-end
# fake-`docker` case above pins one real stage failing.
stage_protocol() {
  : >"$WORK/stage-1-ran"
  false
  : >"$WORK/stage-3-ran"
}
set +e
( set -e; stage_protocol )
STAGE_STATUS=$?
set -e
[[ $STAGE_STATUS -ne 0 ]] || fail "a failed protocol stage must not report success"
[[ -e "$WORK/stage-1-ran" ]] || fail "the stage before the failure must have run"
[[ ! -e "$WORK/stage-3-ran" ]] ||
  fail "errexit inside the protocol subshell must prevent any later stage"

# The same chain without the inner `set -e` reproduces the defect, so the sentinel above is not
# vacuous: it would pass only if errexit were doing the work.
stage_protocol_without_errexit() {
  : >"$WORK/no-errexit-1-ran"
  false
  : >"$WORK/no-errexit-3-ran"
}
set +e
( stage_protocol_without_errexit )
NO_ERREXIT_STATUS=$?
set -e
[[ -e "$WORK/no-errexit-3-ran" && $NO_ERREXIT_STATUS -eq 0 ]] ||
  fail "the defect control must reproduce a silently continued protocol"

# 6. The selector's own refusals, including a failed build that must not be reported as "no
#    artifact": the wrapper's failure has to stay attributable.
echo "contract: ok"
