#!/usr/bin/env bash
# Boot-free host controls for the config-mounts evidence (#394 / ADR-0046).
#
# These are host-only controls, never native VM evidence: no VM, no agent-vm
# launch and no image. They run the *actual* guest probe the native harness
# copies into the owned project, against a synthetic layout on this filesystem,
# including negative controls that a probe which always answers the same way
# cannot pass. They then run the *actual* live wrapper through its preflight
# refusals and prove that no native scratch is allocated before provenance is
# accepted. Finally they prove the `ci-contracts.sh` guard entries are load
# bearing by removing each one in a throwaway copy.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT_DIR="$REPO_ROOT/script/test"
FIXTURES="$SCRIPT_DIR/fixtures/config-mounts"
PROBE="$FIXTURES/guest-cm-probe.sh"
LIVE="$SCRIPT_DIR/config-mounts-live.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/avm-cmctl.XXXXXX")"
# A read-only fixture directory cannot be removed until it is writable again.
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT

# --- Probe rows against a host-side layout -----------------------------------
# The probe's CM_ROOT prefix is what makes the guest statements runnable here;
# in the guest it is empty and the paths are the declared /cm/* ones.
layout="$work/layout"
mkdir -p "$layout/cm/ro" "$layout/cm/rw" "$layout/cm/fork"
printf 'seed-ro' > "$layout/cm/ro/marker"
printf 'seed-rw' > "$layout/cm/rw/marker"
printf 'seed-fork' > "$layout/cm/fork/marker"
# A read-only bind is a read-only *filesystem*: neither the directory nor the
# file inside it accepts a write. 0555 alone would leave the existing marker
# writable at its own mode, which is not what the guest row measures.
chmod 0444 "$layout/cm/ro/marker"
chmod 0555 "$layout/cm/ro"
chmod 0755 "$layout/cm/rw" "$layout/cm/fork"

project="$work/proj"
mkdir -p "$project"
printf 'project\n' > "$project/project-marker"

run_probe() {
    local root="$1" phase="$2"
    shift 2
    ( cd "${PROBE_CWD:-$project}" && CM_ROOT="$root" bash "$PROBE" "$phase" "$@" )
}

is_root=false
if [[ "$(id -u)" -eq 0 ]]; then
    is_root=true
fi

if [[ "$is_root" == true ]]; then
    # Mode 0555 does not deny writes to uid 0, so the read-only row cannot be
    # exercised: say so instead of claiming it ran.
    echo 'NOT RUN CM-N1 read-only control: running as root, mode 0555 does not deny writes'
else
    out="$(run_probe "$layout" n1)"
    [[ "$out" == 'CM-N1 read=seed-ro write=denied' ]] ||
        fail "N1 probe did not report a refused write on a 0555 tree: $out"
    # Negative control: a probe that always says "denied" must fail here.
    chmod 0644 "$layout/cm/ro/marker"
    chmod 0755 "$layout/cm/ro"
    out="$(run_probe "$layout" n1)"
    [[ "$out" == 'CM-N1 read=seed-ro write=allowed' ]] ||
        fail "N1 probe did not report an allowed write on a writable tree: $out"
    # The control overwrote the marker; restore the fixture before the rows
    # that read it, and leave no file behind.
    rm -f "$layout/cm/ro/new"
    printf 'seed-ro' > "$layout/cm/ro/marker"
    chmod 0444 "$layout/cm/ro/marker"
    chmod 0555 "$layout/cm/ro"
fi

out="$(run_probe "$layout" n2)"
[[ "$out" == 'CM-N2 wrote' ]] || fail "N2 probe did not report its write: $out"
[[ "$(cat "$layout/cm/rw/marker")" == 'guest-rw' ]] ||
    fail 'N2 control did not change the writable fixture'

out="$(run_probe "$layout" n3a)"
[[ "$out" == 'CM-N3a read=seed-fork wrote' ]] || fail "N3a probe output: $out"
[[ "$(cat "$layout/cm/fork/marker")" == 'guest-fork' ]] ||
    fail 'N3a control did not write the fork fixture'
out="$(run_probe "$layout" n3b)"
[[ "$out" == 'CM-N3b read=guest-fork' ]] || fail "N3b probe output: $out"

# Negative control: a missing fork marker must never read as the seed.
rm "$layout/cm/fork/marker"
out="$(run_probe "$layout" n3b)"
[[ "$out" == 'CM-N3b read=absent' ]] ||
    fail "N3b probe invented a value for a missing marker: $out"

# The opt-out row: nothing mounted under the root, project still visible.
empty="$work/empty"
mkdir -p "$empty"
out="$(run_probe "$empty" n4)"
[[ "$out" == 'CM-N4 ro=absent rw=absent fork=absent project=present' ]] ||
    fail "N4 probe output: $out"
# Positive control for the same row: a layout that does hold the mounts.
mkdir -p "$work/full/cm/ro"
out="$(run_probe "$work/full" n4)"
[[ "$out" == 'CM-N4 ro=present rw=absent fork=absent project=present' ]] ||
    fail "N4 probe did not see a present mount: $out"

out="$(run_probe "$layout" n5)"
[[ "$out" == 'CM-N5 read=absent' ]] || fail "N5 probe output: $out"

# An unknown phase must fail rather than print nothing (a silent pass).
if run_probe "$layout" bogus >/dev/null 2>&1; then
    fail 'the probe accepted an unknown phase'
fi
echo 'probe controls passed (rows, positive and negative controls; no VM)'

# --- Wrapper preflight refusals ----------------------------------------------
# The fakes make the host gate deterministic, record every native scratch
# allocation, and keep CI (Linux) able to run these controls.
tools="$work/tools"
mkdir -p "$tools"
allocations="$work/allocations.log"
: > "$allocations"
real_mktemp="$(command -v mktemp)"
cat > "$tools/uname" <<'SH'
#!/bin/sh
case "${1:-}" in
    -s) echo "${FAKE_UNAME_S:-Darwin}" ;;
    -m) echo "${FAKE_UNAME_M:-arm64}" ;;
    *) echo "${FAKE_UNAME_S:-Darwin}" ;;
esac
SH
printf '#!/bin/sh\nexit 1\n' > "$tools/pgrep"
cat > "$tools/sysctl" <<'SH'
#!/bin/sh
echo 'fixture-model fixture-cpu'
SH
printf '#!/bin/sh\necho "ProductName:\t\tsynthetic fixture"\n' > "$tools/sw_vers"
printf '#!/bin/sh\necho "codesign: fixture unsigned"\n' > "$tools/codesign"
cat > "$tools/mktemp" <<SH
#!/bin/sh
out="\$("$real_mktemp" "\$@")" || exit \$?
case "\$out" in
    /tmp/avm-cm.*|/private/tmp/avm-cm.*) printf '%s\n' "\$out" >> "$allocations" ;;
esac
printf '%s\n' "\$out"
SH
chmod 0755 "$tools/uname" "$tools/pgrep" "$tools/sysctl" "$tools/sw_vers" \
    "$tools/codesign" "$tools/mktemp"

# A fake bundle is enough to reach the refusals below without a real candidate.
mkdir -p "$work/bundle/bin" "$work/bundle/lib"
printf '#!/bin/sh\nprintf "agent-vm 0.0.0 (deadbeef)\\n"\n' > "$work/bundle/bin/agent-vm"
printf '#!/bin/sh\necho "msb 0.0.0"\n' > "$work/bundle/bin/msb"
printf 'fixture firmware\n' > "$work/bundle/lib/libkrunfw.5.dylib"
chmod 0755 "$work/bundle/bin/agent-vm" "$work/bundle/bin/msb"

digest_image='registry.example.invalid/owner/image@sha256:0000000000000000000000000000000000000000000000000000000000000000'

run_live() {
    local name="$1"
    shift
    local evidence="$work/evidence-$name"
    mkdir -p "$evidence"
    : > "$allocations"
    set +e
    env PATH="$tools:$PATH" AGENT_VM_CM_EVIDENCE="$evidence" "$@" \
        bash "$LIVE" > "$work/$name.log" 2>&1
    local status=$?
    set -e
    [[ "$status" -ne 0 ]] || fail "$name: the wrapper accepted a host it must refuse"
    [[ ! -s "$allocations" ]] || fail "$name: native scratch was allocated before the refusal"
    printf '%s' "$evidence"
}

evidence="$(run_live relative-binary AGENT_VM_BIN=./relative AGENT_VM_LIVE_TEST_IMAGE="$digest_image")"
grep -q 'AGENT_VM_BIN must be an absolute path to an executable' "$work/relative-binary.log" ||
    fail 'relative-binary: unexpected first error'

evidence="$(run_live tagged-image AGENT_VM_BIN="$work/bundle/bin/agent-vm" AGENT_VM_LIVE_TEST_IMAGE='repo:tag')"
grep -q 'must be digest-pinned' "$work/tagged-image.log" ||
    fail 'tagged-image: unexpected first error'

evidence="$(run_live linux-host FAKE_UNAME_S=Linux AGENT_VM_BIN="$work/bundle/bin/agent-vm" \
    AGENT_VM_LIVE_TEST_IMAGE="$digest_image")"
grep -q 'needs a macOS arm64 host' "$work/linux-host.log" ||
    fail 'linux-host: unexpected first error'

mv "$work/bundle/bin/msb" "$work/bundle/bin/msb.away"
evidence="$(run_live missing-msb AGENT_VM_BIN="$work/bundle/bin/agent-vm" AGENT_VM_LIVE_TEST_IMAGE="$digest_image")"
grep -q 'no executable sibling msb' "$work/missing-msb.log" ||
    fail 'missing-msb: unexpected first error'
mv "$work/bundle/bin/msb.away" "$work/bundle/bin/msb"

# The full preflight reaches provenance, which must refuse this fixture binary
# and still leave no scratch: provenance precedes allocation.
#
# The refusal must be the *checker's*. Every `reject()` in the wrapper prints
# `provenance: …` too, so matching that prefix alone would pass on a run where
# `build-provenance.py` never executed. The fixture reports
# `agent-vm 0.0.0 (deadbeef)`, whose revision is not a 40/64-hex commit, so the
# checker's own reason is this exact sentence.
provenance_reason='provenance: not one agent-vm version line'
evidence="$(run_live provenance AGENT_VM_BIN="$work/bundle/bin/agent-vm" AGENT_VM_LIVE_TEST_IMAGE="$digest_image")"
grep -qF "$provenance_reason" "$work/provenance.log" ||
    fail 'provenance: the refusal did not come from build-provenance.py'
[[ -s "$evidence/provenance-check.txt" ]] || fail 'provenance: no retained provenance-check.txt'

# Negative control for that guard, in the style of the ci-contract mutations
# below: break the checker's precondition and require the guard to fail for the
# exact reason it names. A bundle whose `--version` fails is refused by the
# wrapper's own `reject` before the checker runs — the weak prefix guard would
# still match it, so the specific assertion must not.
mv "$work/bundle/bin/agent-vm" "$work/bundle/bin/agent-vm.real"
printf '#!/bin/sh\nexit 1\n' > "$work/bundle/bin/agent-vm"
chmod 0755 "$work/bundle/bin/agent-vm"
run_live provenance-early-reject AGENT_VM_BIN="$work/bundle/bin/agent-vm" \
    AGENT_VM_LIVE_TEST_IMAGE="$digest_image" >/dev/null
mv "$work/bundle/bin/agent-vm.real" "$work/bundle/bin/agent-vm"
grep -q 'provenance: ' "$work/provenance-early-reject.log" ||
    fail 'provenance control: the early refusal was not receipted as provenance'
if grep -qF "$provenance_reason" "$work/provenance-early-reject.log"; then
    fail 'provenance control: the checker-specific guard accepted an early reject'
fi

# An unset prerequisite is the first refusal a caller can hit, and it must be
# receipted like the rest — the run is blocked, so it owes the reader a reason.
# Only the variable under test is unset; the other keeps its valid value so this
# control cannot pass because of a different refusal.
evidence="$(run_live unset-agent-vm-bin env -u AGENT_VM_BIN \
    AGENT_VM_LIVE_TEST_IMAGE="$digest_image")"
grep -q 'rejected: set AGENT_VM_BIN' "$work/unset-agent-vm-bin.log" ||
    fail 'unset-agent-vm-bin: an unset AGENT_VM_BIN was not refused by name'
grep -q 'rejected: ' "$evidence/rejection.txt" ||
    fail 'unset-agent-vm-bin: an unset prerequisite left no rejection.txt'
evidence="$(run_live unset-live-test-image env -u AGENT_VM_LIVE_TEST_IMAGE \
    AGENT_VM_BIN="$work/bundle/bin/agent-vm")"
grep -q 'rejected: set AGENT_VM_LIVE_TEST_IMAGE' "$work/unset-live-test-image.log" ||
    fail 'unset-live-test-image: an unset image was not refused by name'
grep -q 'rejected: ' "$evidence/rejection.txt" ||
    fail 'unset-live-test-image: an unset prerequisite left no rejection.txt'

# Each refusal is receipted for the reader, not only printed.
for name in relative-binary tagged-image linux-host missing-msb; do
    grep -q 'rejected: ' "$work/evidence-$name/rejection.txt" ||
        fail "$name: the refusal left no rejection.txt"
done
echo 'wrapper preflight controls passed (refusals receipted, zero scratch allocated)'

# --- The ci-contracts.sh guard entries are load bearing ----------------------
python3 - "$REPO_ROOT" <<'PY'
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(sys.argv[1])
source = (root / "script/test/ci-contracts.sh").read_text()
files = ("script/test/config-mounts-live.sh",
         "script/test/config-mounts-contract.sh",
         "script/test/lib/config-mounts.py",
         "script/test/fixtures/config-mounts/guest-cm-probe.sh")
# The companion must actually run in CI, not merely be listed.
run_list = source.split("# --- Shell guard rail", 1)[0]
assert 'bash "$REPO_ROOT/script/test/config-mounts-contract.sh"' in run_list, \
    "ci-contracts.sh does not invoke the host controls"
for array, label in (("syntax_check", "bash -n"), ("shellcheck_files", "shellcheck")):
    for script in files:
        if script.endswith(".py"):
            # shellcheck and bash -n have nothing to say about a Python driver.
            continue
        start = source.index(array + "=(")
        end = source.index("\n)", start)
        block = source[start:end]
        entry = "    " + script + "\n"
        assert block.count(entry) == 1, (array, script)
        assert f"assert_listed '{label}' '{script}'" in source, \
            f"no explicit {label} membership assertion for {script}"
        mutated = source[:start] + block.replace(entry, "", 1) + source[end:]
        with tempfile.TemporaryDirectory(prefix="cm-control-mutation-") as tmp:
            path = Path(tmp) / "script/test/ci-contracts.sh"
            path.parent.mkdir(parents=True)
            path.write_text(mutated)
            result = subprocess.run(["bash", str(path), "--guard-only"],
                                    capture_output=True, text=True, timeout=10)
            assert result.returncode == 1, result.stdout + result.stderr
            assert f"({script}) is missing from the {label} guard list" in result.stderr, result.stderr
        print(f"host-only removal mutation PASS: {array}: {script}")
PY

echo 'host-only config-mounts controls passed (probe rows, preflight refusals, guard entries; no VM run)'
