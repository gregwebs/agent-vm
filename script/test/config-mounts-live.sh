#!/usr/bin/env bash
# Native evidence only: dedicated macOS Apple Silicon host, no concurrent VMs.
#
# The rows themselves are script/test/lib/config-mounts.py; this wrapper exists
# to refuse a host that cannot produce trustworthy evidence *before* allocating
# native scratch, and to retain the identities a reader needs to decide whether
# the rows came from the committed candidate (#394 / ADR-0046).
set -euo pipefail

evidence="${AGENT_VM_CM_EVIDENCE:-$(mktemp -d /tmp/avm-cm-evidence.XXXXXX)}"
mkdir -p "$evidence"
evidence="$(cd "$evidence" && pwd -P)"
printf 'Evidence: %s\n' "$evidence"
# Every refusal below is receipted in the evidence directory: a blocked run must
# leave the reason behind, not just a non-zero exit. That includes the two
# "unset" refusals, which are the first ones a caller can hit — `refuse` is
# defined before either is read, and the evidence directory already exists, so no
# exit path is unreceipted.
refuse() {
    printf 'rejected: %s\n' "$1" | tee "$evidence/rejection.txt" >&2
    exit 1
}

[[ -n "${AGENT_VM_BIN:-}" ]] || refuse 'set AGENT_VM_BIN to an absolute native bundle binary'
[[ -n "${AGENT_VM_LIVE_TEST_IMAGE:-}" ]] ||
    refuse 'set AGENT_VM_LIVE_TEST_IMAGE to a digest-pinned OCI image'
[[ "$AGENT_VM_BIN" = /* && -x "$AGENT_VM_BIN" ]] ||
    refuse 'AGENT_VM_BIN must be an absolute path to an executable'
# A tag would make every row depend on what the registry serves later. The
# private cache and the first-pin approval are only meaningful for fixed bytes.
printf '%s' "$AGENT_VM_LIVE_TEST_IMAGE" |
    grep -Eq '^[^[:space:]@]+@sha256:[0-9a-f]{64}$' ||
    refuse 'AGENT_VM_LIVE_TEST_IMAGE must be digest-pinned (<repo>@sha256:<64 lowercase hex>)'
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] ||
    refuse 'this harness needs a macOS arm64 host'
# Exclude command lines merely mentioning agent-vm, such as editor/agent prompts.
if pgrep -x agent-vm >/dev/null || pgrep -x msb >/dev/null; then
    refuse 'concurrent agent-vm/msb process: use a dedicated idle host'
fi
# The runtime must be the one beside the candidate, named explicitly below, so a
# launch that used some other msb cannot be reported as these rows.
bundle="${AGENT_VM_BIN%/*}"
bundle="$(cd -- "$bundle" && pwd -P)" || refuse 'the AGENT_VM_BIN directory is not readable'
msb="$bundle/msb"
libkrunfw="$bundle/../lib/libkrunfw.5.dylib"
[[ -x "$msb" ]] || refuse "the bundle has no executable sibling msb ($msb)"
[[ -f "$libkrunfw" ]] || refuse "the bundle has no ../lib/libkrunfw.5.dylib ($libkrunfw)"

script_dir="$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"

# Every source-metadata call goes through this one adapter. `-C` does not
# override an inherited GIT_DIR/GIT_WORK_TREE, so a caller could otherwise route
# Git to a clean checkout B while the harness source stays in A; strip those
# variables for git's child only and never touch the caller's shell.
# `--no-optional-locks` keeps observation from refreshing/writing an index.
cm_git() {
    env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE \
        -u GIT_COMMON_DIR -u GIT_NAMESPACE \
        git --no-optional-locks -C "$repo_root" "$@"
}

printf 'harness root: %s\nsource identity: not yet validated\n' "$repo_root" > "$evidence/source.txt"
reject() {
    printf 'provenance: %s\n' "$1" | tee "$evidence/provenance-check.txt" >&2
    echo 'Commit current tracked source and rebuild the candidate from it before retrying.' |
        tee -a "$evidence/provenance-check.txt" >&2
    exit 1
}
# Artifact facts survive root/Git/version/checker rejection. No native scratch is
# allocated until every fallible capture and validation succeeds.
printf 'Image: %s\n' "$AGENT_VM_LIVE_TEST_IMAGE" | tee "$evidence/image.txt"
{
    printf 'candidate: %s\n' "$(cd -- "${AGENT_VM_BIN%/*}" && pwd -P)/${AGENT_VM_BIN##*/}"
    shasum -a 256 "$AGENT_VM_BIN"
    # Recorded whether or not it signs: an unsigned/ad-hoc bundle is legitimate
    # evidence of *which* file ran, which is the claim being made.
    codesign -dv --verbose=4 "$AGENT_VM_BIN" 2>&1 || printf 'codesign: unavailable or unsigned\n'
} > "$evidence/candidate.txt" || reject 'candidate identity capture failed'
{
    printf 'msb: %s\n' "$(cd -- "${msb%/*}" && pwd -P)/${msb##*/}"
    shasum -a 256 "$msb"
    codesign -dv --verbose=4 "$msb" 2>&1 || printf 'codesign: unavailable or unsigned\n'
    "$msb" --version 2>&1 || printf 'msb --version: failed\n'
    printf 'libkrunfw: %s\n' "$(cd -- "${libkrunfw%/*}" && pwd -P)/${libkrunfw##*/}"
    shasum -a 256 "$libkrunfw"
    codesign -dv --verbose=4 "$libkrunfw" 2>&1 || printf 'codesign: unavailable or unsigned\n'
} > "$evidence/runtime.txt" || refuse 'runtime identity capture failed'
{
    sw_vers
    uname -a
    sysctl -n hw.model machdep.cpu.brand_string
} > "$evidence/host.txt" 2>&1 || printf 'host details: partially unavailable\n' >> "$evidence/host.txt"
find "$script_dir" -type f ! -path '*/__pycache__/*' -print0 |
    xargs -0 shasum -a 256 | sort -k2 > "$evidence/harness.sha256" || reject 'harness hash failed'

# A tarball inside another checkout must not adopt the outer source identity.
toplevel="$(cm_git rev-parse --show-toplevel)" || reject 'cannot discover the Git top level'
[[ "$toplevel" != *$'\n'* && "$toplevel" != *$'\r'* ]] || reject 'the Git top level contains a newline'
toplevel="$(cd -- "$toplevel" && pwd -P)" || reject 'the Git top level is not a directory'
[[ "$toplevel" == "$repo_root" ]] || reject 'the harness source is not its own Git top level'
commit="$(cm_git rev-parse HEAD)" || reject 'git rev-parse HEAD failed'
printf 'harness root: %s\ncommit: %s\n' "$repo_root" "$commit" > "$evidence/source.txt"
cm_git status --porcelain --untracked-files=no --ignore-submodules=untracked \
    > "$evidence/tracked-status.txt" || reject 'git tracked status failed'
cm_git status --porcelain > "$evidence/all-status.txt" || reject 'git status failed'
{
    printf 'status --porcelain (all; still lists unrelated untracked files):\n'
    cat "$evidence/all-status.txt"
    printf 'status --porcelain --untracked-files=no --ignore-submodules=untracked (empty means the tracked tree matches the commit):\n'
    cat "$evidence/tracked-status.txt"
} >> "$evidence/source.txt"
cm_git diff HEAD > "$evidence/tree.diff" || reject 'git diff failed'
shasum -a 256 "$evidence/tree.diff" > "$evidence/tree.diff.sha256" || reject 'tree diff hash failed'
# Direct redirection preserves partial output, trailing blank lines and invalid
# bytes for the independent checker and failure diagnosis.
"$AGENT_VM_BIN" --version > "$evidence/binary-version.txt" || reject 'the binary does not report --version'
if ! python3 "$script_dir/lib/build-provenance.py" \
    "$evidence/binary-version.txt" "$commit" "$evidence/tracked-status.txt" \
    2>&1 | tee "$evidence/provenance-check.txt"; then
    echo 'Commit current tracked source and rebuild the candidate from it before retrying.' |
        tee -a "$evidence/provenance-check.txt" >&2
    exit 1
fi
cat "$evidence/binary-version.txt"

root=''
shell_owns_scratch=1
driver=''
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    # A launched driver may still be alive, so its launch record and scratch must
    # survive until it is absent: $root/driver.pid is the only identity a
    # supervisor can use to KILL a TERM-resistant driver. Reap the driver first.
    if [[ -n "$driver" ]] && kill -0 "$driver" 2>/dev/null; then
        # The driver's finally block calls cleanup_run (bounded, identity-checked),
        # preserves evidence, then removes owned scratch.
        kill -TERM "$driver" 2>/dev/null || true
        wait "$driver" || status=1
    fi
    if [[ "$shell_owns_scratch" == 1 && -n "$root" ]]; then
        # Only our mktemp result and our own launch record exist, and the driver
        # is now absent; drop the record and reclaim the now-empty scratch.
        rm -f -- "$root/driver.pid"
        rmdir -- "$root" || status=1
    fi
    if [[ "$shell_owns_scratch" == 0 && "$status" != 0 && "$status" != 24 && -d "$root" ]]; then
        # Job creation is not driver initialization. After the child is dead,
        # reclaim only empty scratch; never erase driver state or status-24
        # evidence. driver.pid is our own launch record, so drop it first.
        rm -f -- "$root/driver.pid"
        if rmdir -- "$root"; then
            echo "Driver failed (status $status); reclaimed empty scratch" >&2
        else
            echo "Driver failed (status $status); retained nonempty scratch: $root" >&2
        fi
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
root="$(mktemp -d /tmp/avm-cm.XXXXXX)"
root="$(cd "$root" && pwd -P)"
[[ "$evidence" != "$root" && "$evidence" != "$root/"* ]] ||
    refuse 'AGENT_VM_CM_EVIDENCE must be outside the scratch root'
# Keep the trapped background PID equal to the driver, not a shell wrapper.
cm_launch() {
    exec python3 "$script_dir/lib/config-mounts.py" "$@"
}
cm_launch "$root" "$evidence" "$AGENT_VM_BIN" "$AGENT_VM_LIVE_TEST_IMAGE" "$msb" &
driver=$!
# Record the driver's identity inside the scratch it is about to receive, before
# any handoff, so a supervisor that cannot observe readiness can still reap it.
printf '%s' "$driver" > "$root/driver.pid"
shell_owns_scratch=0
wait "$driver"
driver=''
