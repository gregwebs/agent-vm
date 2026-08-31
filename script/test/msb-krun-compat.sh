#!/usr/bin/env bash
# Black-box compatibility tracer for a freshly built official msb_krun cohort.
set -euo pipefail

readonly LOCAL_TAG=msb-krun-compat:local
readonly DEFAULT_MEASURE_REPEATS=3
readonly DEFAULT_MEASURE_MAX_MOUNTS=256
readonly DEFAULT_STRESS_RUNS=100
readonly COMPAT_DISK_SIZE=128M
readonly BOOT_TIMEOUT_SECONDS="${MSB_KRUN_BOOT_TIMEOUT_SECONDS:-90}"
readonly DARWIN_BOUNDARY_MOUNTS=4,64
readonly DARWIN_HIGH_MOUNTS=112
readonly DARWIN_STRESS_MOUNTS=64

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
command -v cargo >/dev/null || { echo "error: Cargo is required for compatibility evidence" >&2; exit 1; }
compat_evidence() {
    cargo run --locked --quiet --manifest-path "$repo_root/Cargo.toml" -p msb-krun-compat-evidence -- "$@"
}

mode="${1:-}"
[[ $# -eq 1 && "$mode" =~ ^(smoke|boundary|stress|measure)$ ]] || {
    echo "usage: $0 smoke|boundary|stress|measure" >&2
    exit 2
}
: "${MSB_BIN:?set MSB_BIN to the freshly built msb binary}"
: "${MSB_LIBKRUNFW_PATH:?set MSB_LIBKRUNFW_PATH to the freshly built firmware file}"
: "${MSB_COMPAT_DOCKER_IMAGE:?set MSB_COMPAT_DOCKER_IMAGE to a local guest image}"
[[ -f "$MSB_BIN" && -x "$MSB_BIN" ]] || { echo "error: MSB_BIN must be an executable regular file" >&2; exit 1; }
[[ -f "$MSB_LIBKRUNFW_PATH" && -r "$MSB_LIBKRUNFW_PATH" ]] || { echo "error: MSB_LIBKRUNFW_PATH must be a readable regular file" >&2; exit 1; }
[[ "$BOOT_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] || { echo "error: MSB_KRUN_BOOT_TIMEOUT_SECONDS must be positive" >&2; exit 1; }
command -v docker >/dev/null || { echo "error: Docker is required to load the isolated image" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "error: Docker daemon is unavailable" >&2; exit 1; }

host_os="$(uname -s)"
host_arch="$(uname -m)"
case "$host_os/$host_arch" in
    Darwin/arm64) image_arch=arm64 ;;
    Linux/x86_64)
        image_arch=amd64
        [[ -r /dev/kvm && -w /dev/kvm ]] || { echo "error: Linux compatibility runs require readable/writable /dev/kvm" >&2; exit 1; }
        ;;
    *) echo "error: supported compatibility hosts are Apple Silicon macOS/HVF and Linux x86_64/KVM; found $host_os/$host_arch" >&2; exit 1 ;;
esac
image_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$MSB_COMPAT_DOCKER_IMAGE" 2>/dev/null)" || {
    echo "error: Docker image $MSB_COMPAT_DOCKER_IMAGE was not found locally" >&2
    exit 1
}
[[ "$image_platform" == "linux/$image_arch" ]] || { echo "error: Docker image must be linux/$image_arch, found $image_platform" >&2; exit 1; }

state_dir="$(mktemp -d "${TMPDIR:-/tmp}/msbkc.XXXXXX")"
evidence_root="${MSB_KRUN_COMPAT_EVIDENCE_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/msb-krun-compat-evidence.XXXXXX")}"
mkdir -p "$evidence_root/$mode"
attempt_dir="$(mktemp -d "$evidence_root/$mode/attempt.XXXXXX")"
log_dir="$attempt_dir/logs"
fixture_dir="$attempt_dir/fixtures"
mkdir -p "$log_dir" "$fixture_dir"
finished=false
cleanup() {
    if [[ "$finished" == true ]]; then
        rm -r -- "$state_dir"
    else
        echo "compatibility failure preserved state: $state_dir" >&2
    fi
    echo "compatibility evidence: $attempt_dir" >&2
}
trap cleanup EXIT

write_manifest() {
    compat_evidence manifest --output "$attempt_dir/manifest.json" --mode "$mode" --host-os "$host_os" --host-arch "$host_arch" --binary "$MSB_BIN" --firmware "$MSB_LIBKRUNFW_PATH" --image "$MSB_COMPAT_DOCKER_IMAGE" --image-platform "$image_platform"
}
write_manifest

run_msb() {
    local label="$1"
    shift
    MSB_HOME="$state_dir" MSB_LIBKRUNFW_PATH="$MSB_LIBKRUNFW_PATH" "$MSB_BIN" "$@" >"$log_dir/$label.out" 2>"$log_dir/$label.err"
}
run_timeout() {
    local label="$1"
    shift
    python3 - "$BOOT_TIMEOUT_SECONDS" "$log_dir/$label.out" "$log_dir/$label.err" "$MSB_BIN" "$MSB_LIBKRUNFW_PATH" "$state_dir" -- "$@" <<'PY'
import os, subprocess, sys
seconds, out, err, binary, firmware, home = sys.argv[1:7]
command = sys.argv[8:]
env = os.environ | {"MSB_HOME": home, "MSB_LIBKRUNFW_PATH": firmware}
with open(out, "wb") as stdout, open(err, "wb") as stderr:
    try:
        sys.exit(subprocess.run([binary, *command], env=env, stdout=stdout, stderr=stderr,
                                timeout=int(seconds)).returncode)
    except subprocess.TimeoutExpired:
        print("compatibility boot timed out", file=sys.stderr)
        sys.exit(124)
PY
}

# Loading through the same isolated home removes dependence on another msb cache.
docker save "$MSB_COMPAT_DOCKER_IMAGE" | MSB_HOME="$state_dir" MSB_LIBKRUNFW_PATH="$MSB_LIBKRUNFW_PATH" "$MSB_BIN" image load --tag "$LOCAL_TAG" >"$log_dir/image-load.out" 2>"$log_dir/image-load.err"

validate_profile() {
    local boundaries="$1" high="$2" cmdline="$3" stress="$4" item previous=0
    [[ "$boundaries" =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ && "$high" =~ ^[1-9][0-9]*$ && "$stress" =~ ^[1-9][0-9]*$ ]] || return 1
    if [[ "$host_os" == Linux ]]; then
        [[ "$cmdline" =~ ^[1-9][0-9]*$ ]] || return 1
    else
        [[ -z "$cmdline" ]] || return 1
    fi
    local -a values
    IFS=, read -r -a values <<<"$boundaries"
    for item in "${values[@]}"; do ((item > previous)) || return 1; previous="$item"; done
    ((high > previous && previous <= stress && stress < high)) || return 1
    [[ "$host_os" != Linux ]] || ((cmdline <= high))
}
resolve_profile() {
    if [[ "$host_os" == Darwin ]]; then
        [[ -z "${MSB_KRUN_COMPAT_CMDLINE_MOUNTS:-}" ]] || {
            echo "error: Darwin/HVF uses FDT/sysfs discovery; MSB_KRUN_COMPAT_CMDLINE_MOUNTS is not applicable" >&2
            return 1
        }
        boundary_mounts="${MSB_KRUN_COMPAT_BOUNDARY_MOUNTS:-$DARWIN_BOUNDARY_MOUNTS}"
        high_mounts="${MSB_KRUN_COMPAT_HIGH_MOUNTS:-$DARWIN_HIGH_MOUNTS}"
        stress_mounts="${MSB_KRUN_COMPAT_STRESS_MOUNTS:-$DARWIN_STRESS_MOUNTS}"
        cmdline_mounts=""
    else
        boundary_mounts="${MSB_KRUN_COMPAT_BOUNDARY_MOUNTS:-}"
        high_mounts="${MSB_KRUN_COMPAT_HIGH_MOUNTS:-}"
        cmdline_mounts="${MSB_KRUN_COMPAT_CMDLINE_MOUNTS:-}"
        stress_mounts="${MSB_KRUN_COMPAT_STRESS_MOUNTS:-}"
        local missing=() variable
        for variable in MSB_KRUN_COMPAT_BOUNDARY_MOUNTS MSB_KRUN_COMPAT_HIGH_MOUNTS MSB_KRUN_COMPAT_CMDLINE_MOUNTS MSB_KRUN_COMPAT_STRESS_MOUNTS; do
            [[ -n "${!variable:-}" ]] || missing+=("$variable")
        done
        ((${#missing[@]} == 0)) || { echo "error: Linux KVM profile not calibrated; set: ${missing[*]}" >&2; return 1; }
    fi
    validate_profile "$boundary_mounts" "$high_mounts" "$cmdline_mounts" "$stress_mounts" || { echo "error: invalid compatibility profile" >&2; return 1; }
}

make_mounts() {
    local name="$1" count="$2" i host marker
    for ((i=0; i<count; i+=1)); do
        host="$fixture_dir/m$(printf '%03d' "$i")"
        mkdir -p "$host"
        marker="seed-${name}-${count}-${i}"
        printf '%s\n' "$marker" >"$host/marker"
        printf '%s\0' -v "$host:/m$(printf '%03d' "$i")"
    done
}
selected_mounts() {
    local count="$1"
    case "$count" in
        0) ;;
        4) printf '0,3' ;;
        64) printf '0,31,63' ;;
        112) printf '0,63,111' ;;
        *) printf '0,%d' "$((count - 1))" ;;
    esac
}
write_guest_probe() {
    local path="$1" count="$2" selected="$3" name="$4"
    cat >"$path" <<'SH'
#!/bin/sh
set -eu
selected="$1"
case_name="$2"
count="$3"
if [ "$count" -gt 0 ]; then
    old_ifs=$IFS
    IFS=,
    for index in $selected; do
        mount="/m$(printf '%03d' "$index")"
        test -f "$mount/marker"
        marker=$(cat "$mount/marker")
        printf 'MARKER|%s|%s\n' "$index" "$marker"
        printf 'guest-%s-%s\n' "$case_name" "$index" >"$mount/host-write"
    done
    IFS=$old_ifs
fi
for compatible in /sys/firmware/devicetree/base/*/compatible /sys/firmware/devicetree/base/*/*/compatible; do
    [ -f "$compatible" ] || continue
    if tr '\000' '\n' <"$compatible" | grep -Fx 'virtio,mmio' >/dev/null; then
        node=${compatible%/compatible}
        reg=$(od -An -tx1 "$node/reg" 2>/dev/null | tr -d ' \n' || true)
        interrupts=$(od -An -tx1 "$node/interrupts" 2>/dev/null | tr -d ' \n' || true)
        printf 'FDT|%s|%s|%s\n' "$node" "$reg" "$interrupts"
    fi
done
for device in /sys/bus/virtio/devices/virtio*; do
    [ -e "$device" ] || continue
    modalias=$(cat "$device/modalias" 2>/dev/null || true)
    driver=$(basename "$(readlink "$device/driver" 2>/dev/null || printf unbound)")
    printf 'VIRTIO|%s|%s|%s\n' "${device##*/}" "$modalias" "$driver"
done
awk '$5 ~ /^\/m[0-9][0-9][0-9]$/ { print "MOUNTINFO|" $0 }' /proc/self/mountinfo
printf 'CMDLINE_BYTES|%s\n' "$(wc -c </proc/cmdline | tr -d ' ')"
printf 'guest-bootstrap-sentinel\n'
printf 'guest-console-sentinel\n' >/dev/console
SH
    chmod +x "$path"
}
assert_clean_logs() {
    local name="$1"
    run_msb "$name-system" logs --source system "compat-$name" || return 1
    grep -q guest-console-sentinel "$log_dir/$name-system.out" || return 1
    ! grep -Eqi 'probe .*failed|missing root device|ioapic.*error|console.*(error|failed)|handshake.*(timeout|failed)|abnormal.*exit|panic|queue-index.*spin' "$log_dir/$name-system.out"
}
assert_markers() {
    local name="$1" count="$2" selected="$3" index expected actual
    [[ "$count" == 0 ]] && return 0
    IFS=, read -r -a indexes <<<"$selected"
    for index in "${indexes[@]}"; do
        expected="seed-${name}-${count}-${index}"
        grep -Fqx "MARKER|$index|$expected" "$log_dir/$name.out" || return 1
        actual="guest-${name}-${index}"
        [[ "$(cat "$fixture_dir/m$(printf '%03d' "$index")/host-write")" == "$actual" ]] || return 1
    done
}
record_darwin_discovery() {
    local name="$1" count="$2" selected="$3" baseline="${4:-}" output
    output="$attempt_dir/$name-discovery.json"
    local -a baseline_args=()
    [[ -n "$baseline" ]] && baseline_args=(--baseline "$baseline")
    compat_evidence discovery --guest-log "$log_dir/$name.out" --output "$output" --expected-mounts "$count" --selected-indexes="$selected" "${baseline_args[@]}"
}
run_case() {
    local name="$1" count="$2" require_cmdline="${3:-false}" baseline="${4:-}" argument selected probe
    local -a mounts=()
    while IFS= read -r -d '' argument; do mounts+=("$argument"); done < <(make_mounts "$name" "$count")
    selected="$(selected_mounts "$count")"
    probe="$fixture_dir/$name-guest-probe.sh"
    write_guest_probe "$probe" "$count" "$selected" "$name"
    run_timeout "$name" run --replace --name "compat-$name" \
        -v "$fixture_dir:/compat-fixtures" "${mounts[@]}" \
        --mount-named "compat-disk:/mnt/compat-disk:kind=disk,size=$COMPAT_DISK_SIZE" \
        "$LOCAL_TAG" -- sh "/compat-fixtures/${name}-guest-probe.sh" "$selected" "$name" "$count" || return 1
    grep -q guest-bootstrap-sentinel "$log_dir/$name.out" || return 1
    assert_markers "$name" "$count" "$selected" || return 1
    assert_clean_logs "$name" || return 1
    if [[ "$host_os" == Darwin ]]; then
        record_darwin_discovery "$name" "$count" "$selected" "$baseline" || return 1
    elif [[ "$require_cmdline" == true ]]; then
        local cmdline_length
        cmdline_length="$(awk -F'|' '/^CMDLINE_BYTES\|/ { print $2 }' "$log_dir/$name.out" | tail -1)"
        [[ "$cmdline_length" =~ ^[0-9]+$ && "$cmdline_length" -gt 2048 ]] || { echo "error: $name command line did not exceed 2048 bytes" >&2; return 1; }
    fi
}
run_darwin_case_with_baseline() {
    local name="$1" count="$2" baseline_name
    baseline_name="$name-baseline"
    run_case "$baseline_name" 0 false || return 1
    run_case "$name" "$count" false "$attempt_dir/$baseline_name-discovery.json"
}
assert_darwin_baseline_stable() {
    compat_evidence baseline-stable --before "$1" --after "$2"
}
write_observations() {
    local last_good="$1" first_failure="$2" repeats="$3" failure_reason="${4:-}"
    compat_evidence observations --output "$attempt_dir/observations.json" --host-os "$host_os" --host-arch "$host_arch" --last-good "$last_good" --first-failure "$first_failure" --repeats "$repeats" --failure-reason="$failure_reason"
}
measure() {
    local repeats="${MSB_KRUN_MEASURE_REPEATS:-$DEFAULT_MEASURE_REPEATS}" max="${MSB_KRUN_MEASURE_MAX_MOUNTS:-$DEFAULT_MEASURE_MAX_MOUNTS}"
    local count repeat last_good=0 first_failure=0 failure_reason="" measurement_baseline=""
    [[ "$repeats" =~ ^[1-9][0-9]*$ && "$max" =~ ^([4-9]|[1-9][0-9]+)$ ]] || { echo "error: measurement inputs must be positive integers and cap at least 4" >&2; return 1; }
    if [[ "$host_os" == Darwin ]]; then
        run_case measure-baseline-start 0 false || return 1
        measurement_baseline="$attempt_dir/measure-baseline-start-discovery.json"
    fi
    for ((count=4; count<=max; count*=2)); do
        for ((repeat=1; repeat<=repeats; repeat+=1)); do
            if [[ "$host_os" == Darwin ]]; then
                if ! run_case "measure-${count}-${repeat}" "$count" false "$measurement_baseline"; then
                    first_failure="$count"
                    failure_reason="$(grep -m1 'RegisterFsDevice(IrqsExhausted)' "$log_dir/measure-${count}-${repeat}.err" 2>/dev/null || tail -n 1 "$log_dir/measure-${count}-${repeat}.err" 2>/dev/null || true)"
                    break 2
                fi
            elif ! run_case "measure-${count}-${repeat}" "$count"; then
                first_failure="$count"
                failure_reason="$(grep -m1 'RegisterFsDevice(IrqsExhausted)' "$log_dir/measure-${count}-${repeat}.err" 2>/dev/null || tail -n 1 "$log_dir/measure-${count}-${repeat}.err" 2>/dev/null || true)"
                break 2
            fi
        done
        last_good="$count"
    done
    ((last_good > 0)) || { write_observations "$last_good" "$first_failure" "$repeats" "$failure_reason"; return 1; }
    if [[ "$host_os" == Darwin ]]; then
        run_case measure-high "$DARWIN_HIGH_MOUNTS" false "$measurement_baseline" || { write_observations "$last_good" "$first_failure" "$repeats" "$failure_reason"; return 1; }
        run_case measure-baseline-end 0 false || { write_observations "$last_good" "$first_failure" "$repeats" "$failure_reason"; return 1; }
        assert_darwin_baseline_stable "$measurement_baseline" "$attempt_dir/measure-baseline-end-discovery.json" || { write_observations "$last_good" "$first_failure" "$repeats" "$failure_reason"; return 1; }
    else
        run_case measure-cmdline "$last_good" true || { write_observations "$last_good" "$first_failure" "$repeats" "$failure_reason"; return 1; }
    fi
    write_observations "$last_good" "$first_failure" "$repeats" "$failure_reason"
    echo "measure observations: $attempt_dir/observations.json"
}

case "$mode" in
    smoke) run_case smoke 4 ;;
    measure) measure ;;
    boundary)
        resolve_profile
        IFS=, read -r -a cases <<<"$boundary_mounts"
        declare -A ran=()
        for count in "${cases[@]}" "$high_mounts" ${cmdline_mounts:+"$cmdline_mounts"}; do
            [[ -n "${ran[$count]:-}" ]] && continue
            ran[$count]=true
            if [[ "$host_os" == Darwin ]]; then
                run_darwin_case_with_baseline "boundary-$count" "$count"
            else
                run_case "boundary-$count" "$count" "$( [[ "$count" == "$cmdline_mounts" ]] && echo true || echo false )"
            fi
        done
        ;;
    stress)
        resolve_profile
        runs="${MSB_KRUN_STRESS_RUNS:-$DEFAULT_STRESS_RUNS}"
        [[ "$runs" =~ ^[1-9][0-9]*$ ]] || { echo "error: MSB_KRUN_STRESS_RUNS must be positive" >&2; exit 1; }
        if [[ "$host_os" == Darwin ]]; then
            run_case stress-baseline-start 0 false
            stress_baseline="$attempt_dir/stress-baseline-start-discovery.json"
            for ((n=1; n<=runs; n+=1)); do
                run_case "stress-$n" "$stress_mounts" false "$stress_baseline"
            done
            run_case stress-baseline-end 0 false
            assert_darwin_baseline_stable "$stress_baseline" "$attempt_dir/stress-baseline-end-discovery.json"
        else
            for ((n=1; n<=runs; n+=1)); do
                run_case "stress-$n" "$stress_mounts"
            done
        fi
        ;;
esac
finished=true
