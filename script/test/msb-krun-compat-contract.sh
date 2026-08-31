#!/usr/bin/env bash
# Observable public-interface contract; this is not VM compatibility evidence.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/agent-vm-compat-contract.XXXXXX")"
cleanup() { rm -r -- "$tmp"; }
trap cleanup EXIT
mkdir -p "$tmp/bin" "$tmp/evidence"

cat >"$tmp/bin/uname" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
    -s) printf 'Darwin\n' ;;
    -m) printf 'arm64\n' ;;
    *) exit 2 ;;
esac
SH
cat >"$tmp/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
    info) exit 0 ;;
    image) printf 'linux/arm64\n' ;;
    save) printf archive ;;
    *) exit 9 ;;
esac
SH
cat >"$tmp/bin/msb" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
: "${MSB_HOME:?}"
: "${MSB_LIBKRUNFW_PATH:?}"
printf '%s\t%s\n' "$MSB_HOME" "$*" >>"${MSB_COMPAT_TEST_LOG:?}"
case "$1" in
    image) cat >/dev/null ;;
    run)
        mounts=()
        mount_count=0
        case_name=unknown
        while (($#)); do
            if [[ "$1" == --name ]]; then case_name="${2#compat-}"; shift 2; continue; fi
            if [[ "$1" == -v ]]; then mounts+=("$2"); shift 2; continue; fi
            shift
        done
        for mount in "${mounts[@]}"; do
            host="${mount%%:*}"
            guest="${mount#*:}"
            [[ "$guest" =~ ^/m[0-9][0-9][0-9]$ ]] || continue
            mount_count=$((mount_count + 1))
            index="${guest#/m}"
            printf 'guest-%s-%s\n' "$case_name" "$((10#$index))" >"$host/host-write"
        done
        if [[ "${MSB_COMPAT_TEST_FAIL_COUNT:-}" == "$mount_count" ]]; then
            printf 'synthetic mount failure for %s\n' "$mount_count" >&2
            exit 7
        fi
        # Two non-user virtio-mmio devices, one pre-existing virtiofs device.
        printf 'FDT|/soc/virtio-mmio@0|00000000|00000001\n'
        printf 'FDT|/soc/virtio-mmio@1|00000001|00000002\n'
        printf 'VIRTIO|virtio0|virtio:d0000001|virtiofs\n'
        for mount in "${mounts[@]}"; do
            host="${mount%%:*}"
            guest="${mount#*:}"
            [[ "$guest" =~ ^/m[0-9][0-9][0-9]$ ]] || continue
            index="${guest#/m}"
            if [[ "${MSB_COMPAT_INVALID_EVIDENCE:-}" != 1 ]]; then
                printf 'FDT|/soc/virtio-mmio@%s|00%s|00%s\n' "$((10#$index + 10))" "$index" "$index"
            fi
            printf 'VIRTIO|virtio%s|virtio:d0000001|virtiofs\n' "$((10#$index + 1))"
            printf 'MOUNTINFO|36 25 0:30 / %s rw - virtiofs tag-%s rw\n' "$guest" "$index"
            printf 'MARKER|%s|seed-%s-%s-%s\n' "$((10#$index))" "$case_name" "$mount_count" "$((10#$index))"
        done
        printf 'CMDLINE_BYTES|202\nguest-bootstrap-sentinel\n'
        ;;
    logs) printf 'guest-console-sentinel\n' ;;
    *) exit 8 ;;
esac
SH
chmod +x "$tmp/bin/uname" "$tmp/bin/docker" "$tmp/bin/msb"
printf firmware >"$tmp/firmware"

run() {
    local requested_mode="$1"
    shift
    PATH="$tmp/bin:$PATH" MSB_COMPAT_TEST_LOG="$tmp/invocations.log" \
    MSB_COMPAT_CASE_NAME="${MSB_COMPAT_CASE_NAME:-$requested_mode}" \
    MSB_BIN="$tmp/bin/msb" MSB_LIBKRUNFW_PATH="$tmp/firmware" \
    MSB_COMPAT_DOCKER_IMAGE=alpine:3.20 MSB_KRUN_COMPAT_EVIDENCE_DIR="$tmp/evidence" \
    MSB_KRUN_MEASURE_REPEATS=1 MSB_KRUN_MEASURE_MAX_MOUNTS=4 \
    "$repo_root/script/test/msb-krun-compat.sh" "$requested_mode" "$@"
}

# A failure in a run_case must survive the successful commands which follow it.
cat >"$tmp/bin/msb-fails-run" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in image) cat >/dev/null ;; run) printf guest-bootstrap-sentinel; exit 7 ;; *) exit 0 ;; esac
SH
chmod +x "$tmp/bin/msb-fails-run"
if PATH="$tmp/bin:$PATH" MSB_BIN="$tmp/bin/msb-fails-run" MSB_LIBKRUNFW_PATH="$tmp/firmware" \
    MSB_COMPAT_DOCKER_IMAGE=alpine:3.20 MSB_KRUN_COMPAT_EVIDENCE_DIR="$tmp/evidence" \
    "$repo_root/script/test/msb-krun-compat.sh" smoke >/dev/null 2>&1; then
    echo "expected early run failure to fail smoke" >&2
    exit 1
fi

run smoke
find "$tmp/evidence/smoke" -type f -name manifest.json -print -quit | grep -q . || { echo "smoke did not retain a manifest" >&2; exit 1; }
find "$tmp/evidence/smoke" -type f -path '*/logs/image-load.out' -print -quit | grep -q . || { echo "smoke did not retain image-load logs" >&2; exit 1; }
grep -q $'\timage load --tag msb-krun-compat:local' "$tmp/invocations.log"
grep -q 'logs --source system' "$repo_root/script/test/msb-krun-compat.sh"
grep -q -- '--mount-named compat-disk:/mnt/compat-disk:kind=disk,size=128M' "$tmp/invocations.log"
if grep -q -- '-v /tmp/msbkc\.' "$tmp/invocations.log"; then
    echo "bind-mount fixtures must not live under the isolated MSB_HOME" >&2
    exit 1
fi

# Darwin's accepted evidence is FDT/sysfs and virtiofs mountinfo, never x86 cmdline growth.
run boundary
boundary_discovery="$(find "$tmp/evidence/boundary" -name 'boundary-64-discovery.json' -print -quit)"
[[ -n "$boundary_discovery" ]] || { echo "Darwin boundary did not record discovery" >&2; exit 1; }
python3 - "$boundary_discovery" <<'PY'
import json, sys
with open(sys.argv[1]) as source: result = json.load(source)
assert result["fdt_delta"] == 64
assert result["virtio_fs_delta"] == 64
assert result["cmdline_bytes"] == 202
assert set(result["selected_mounts"]) == {"/m000", "/m031", "/m063"}
PY
if MSB_KRUN_COMPAT_CMDLINE_MOUNTS=64 run boundary >/dev/null 2>&1; then
    echo "Darwin must reject a cmdline profile override" >&2
    exit 1
fi
# Invalid Darwin evidence must fail at the Rust seam and leave no partial discovery JSON.
set +e
invalid_run_output="$(MSB_COMPAT_INVALID_EVIDENCE=1 run boundary 2>&1)"
invalid_status=$?
set -e
[[ $invalid_status -ne 0 ]] || { echo "expected invalid Darwin evidence to fail boundary" >&2; exit 1; }
invalid_attempt="$(printf '%s\n' "$invalid_run_output" | awk -F': ' '/^compatibility evidence: / { evidence = $2 } END { print evidence }')"
[[ -n "$invalid_attempt" && -d "$invalid_attempt" ]] || { echo "invalid evidence did not report its attempt directory" >&2; exit 1; }
[[ ! -e "$invalid_attempt/boundary-4-discovery.json" ]] || { echo "invalid evidence wrote a discovery file" >&2; exit 1; }

# The CLI must not truncate a retained evidence file when create-new rejects a rerun.
printf 'retained\n' >"$tmp/already.json"
printf 'CMDLINE_BYTES|1\n' >"$tmp/guest.log"
if cargo run --locked --quiet --manifest-path "$repo_root/Cargo.toml" -p msb-krun-compat-evidence --     discovery --guest-log "$tmp/guest.log" --output "$tmp/already.json" --expected-mounts 0 --selected-indexes= >/dev/null 2>&1; then
    echo "expected create-new discovery output to fail" >&2
    exit 1
fi
[[ "$(cat "$tmp/already.json")" == retained ]] || { echo "create-new failure truncated evidence" >&2; exit 1; }

# Rust CLI boundary failures must preserve the harness's no-partial-evidence contract.
printf '{malformed baseline' >"$tmp/malformed-baseline.json"
if cargo run --locked --quiet --manifest-path "$repo_root/Cargo.toml" -p msb-krun-compat-evidence -- \
    discovery --guest-log "$tmp/guest.log" --output "$tmp/malformed-baseline-output.json" \
    --expected-mounts 0 --selected-indexes= --baseline "$tmp/malformed-baseline.json" >/dev/null 2>&1; then
    echo "expected malformed baseline to fail discovery" >&2
    exit 1
fi
[[ ! -e "$tmp/malformed-baseline-output.json" ]] || { echo "malformed baseline wrote discovery output" >&2; exit 1; }
if cargo run --locked --quiet --manifest-path "$repo_root/Cargo.toml" -p msb-krun-compat-evidence -- \
    discovery --guest-log "$tmp/guest.log" --output "$tmp/invalid-index-output.json" \
    --expected-mounts 0 --selected-indexes=not-a-number >/dev/null 2>&1; then
    echo "expected invalid selected index to fail discovery" >&2
    exit 1
fi
[[ ! -e "$tmp/invalid-index-output.json" ]] || { echo "invalid selected index wrote discovery output" >&2; exit 1; }

# The former Python int() parser accepted whitespace, Unicode decimal digits, and unbounded integers.
printf 'malformed\r\nCMDLINE_BYTES| 999999999999999999999999999999999999999999999999 \rCMDLINE_BYTES|１_٢𝟛\n' >"$tmp/python-int.log"
cargo run --locked --quiet --manifest-path "$repo_root/Cargo.toml" -p msb-krun-compat-evidence -- \
    discovery --guest-log "$tmp/python-int.log" --output "$tmp/python-int.json" --expected-mounts 0 --selected-indexes=
python3 - "$tmp/python-int.json" <<'PY'
import json, sys
with open(sys.argv[1]) as source: result = json.load(source)
assert result["cmdline_bytes"] == 123
PY

after_boundary="$(find "$tmp/evidence/boundary" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
run boundary
[[ "$(find "$tmp/evidence/boundary" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" -gt "$after_boundary" ]] || {
    echo "evidence attempts were overwritten" >&2
    exit 1
}

run measure
observations="$(find "$tmp/evidence/measure" -name observations.json -print -quit)"
python3 - "$observations" <<'PY'
import json, sys
with open(sys.argv[1]) as source: result = json.load(source)
assert result["discovery_kind"] == "fdt-sysfs"
assert result["reviewed_profile_candidate"] == {"boundary_mounts": [4, 64], "high_mounts": 112, "stress_mounts": 64}
assert "cmdline_mounts" not in result["reviewed_profile_candidate"]
PY
# A measurement retains a known first failed probe and still tests the frozen high case.
PATH="$tmp/bin:$PATH" MSB_COMPAT_TEST_LOG="$tmp/invocations.log" MSB_COMPAT_TEST_FAIL_COUNT=8 \
MSB_BIN="$tmp/bin/msb" MSB_LIBKRUNFW_PATH="$tmp/firmware" MSB_COMPAT_DOCKER_IMAGE=alpine:3.20 \
MSB_KRUN_COMPAT_EVIDENCE_DIR="$tmp/evidence" MSB_KRUN_MEASURE_REPEATS=1 MSB_KRUN_MEASURE_MAX_MOUNTS=8 \
"$repo_root/script/test/msb-krun-compat.sh" measure
failure_observations="$(grep -rl '"first_attempted_failure": 8' "$tmp/evidence/measure")"
[[ -n "$failure_observations" ]] || { echo "measure did not retain the first failure" >&2; exit 1; }
python3 - "$failure_observations" <<'PY'
import json, sys
with open(sys.argv[1]) as source: result = json.load(source)
assert result["observed_successful_mounts"] == 4
assert result["first_attempted_failure"] == 8
assert "synthetic mount failure" in result["failure_reason"]
PY

# Linux remains a distinct profile with four required values and an x86-only cmdline proof.
grep -q 'Linux KVM profile not calibrated; set:' "$repo_root/script/test/msb-krun-compat.sh"
grep -q 'MSB_KRUN_COMPAT_BOUNDARY_MOUNTS' "$repo_root/script/test/msb-krun-compat.sh"
grep -q 'MSB_KRUN_COMPAT_HIGH_MOUNTS' "$repo_root/script/test/msb-krun-compat.sh"
grep -q 'MSB_KRUN_COMPAT_CMDLINE_MOUNTS' "$repo_root/script/test/msb-krun-compat.sh"
grep -q 'MSB_KRUN_COMPAT_STRESS_MOUNTS' "$repo_root/script/test/msb-krun-compat.sh"
grep -q 'command line did not exceed 2048 bytes' "$repo_root/script/test/msb-krun-compat.sh"

echo 'msb krun compatibility orchestration contract tests passed'
