#!/usr/bin/env bash
# Native evidence only: dedicated macOS Apple Silicon host, no concurrent VMs.
set -euo pipefail
: "${AGENT_VM_BIN:?set an absolute native bundle binary}"
: "${AGENT_VM_LIVE_TEST_IMAGE:?set a verified native image}"
[[ "$AGENT_VM_BIN" = /* && -x "$AGENT_VM_BIN" ]] ||
    { echo 'AGENT_VM_BIN must be an absolute path to an executable' >&2; exit 1; }
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] ||
    { echo 'this harness needs a macOS arm64 host' >&2; exit 1; }
# Exclude command lines merely mentioning agent-vm, such as editor/agent prompts.
if pgrep -x agent-vm >/dev/null || pgrep -x msb >/dev/null; then
    echo 'Concurrent agent-vm/msb process: use a dedicated idle host' >&2
    exit 1
fi
script_dir="$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"
# shellcheck source=script/test/lib/persisted-network.sh
source "$script_dir/lib/persisted-network.sh"
# Every stderr oracle is obtained through this shared renderer, never duplicated.
for row in PN1 PN2 PN3 PN4B PN5; do pn_expected "$row" >/dev/null; done

# Every source-metadata call goes through this one adapter. `-C` does not
# override an inherited GIT_DIR/GIT_WORK_TREE, so a caller could otherwise
# route Git to a clean checkout B while the harness source stays in A; strip
# those variables for git's child only and never touch the caller's shell.
# `--no-optional-locks` keeps observation from refreshing/writing an index.
pn_git() {
    env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE \
        -u GIT_COMMON_DIR -u GIT_NAMESPACE \
        git --no-optional-locks -C "$repo_root" "$@"
}

# Rejection evidence exists even when source discovery cannot be trusted.
evidence="${AGENT_VM_PN_EVIDENCE:-$(mktemp -d /tmp/avm-pn-evidence.XXXXXX)}"
mkdir -p "$evidence"
evidence="$(cd "$evidence" && pwd -P)"
printf 'Evidence: %s\n' "$evidence"
printf 'harness root: %s\nsource identity: not yet validated\n' "$repo_root" > "$evidence/source.txt"
reject() {
    printf 'provenance: %s\n' "$1" | tee "$evidence/provenance-check.txt" >&2
    echo 'Commit current tracked source and rebuild the candidate from it before retrying.' |
        tee -a "$evidence/provenance-check.txt" >&2
    exit 1
}
# Available artifact facts survive root/Git/version/checker rejection. No native
# scratch is allocated until every fallible capture and validation succeeds.
printf 'Image: %s\n' "$AGENT_VM_LIVE_TEST_IMAGE" | tee "$evidence/image.txt"
shasum -a 256 "$AGENT_VM_BIN" > "$evidence/binary.sha256" || reject 'binary hash failed'
find "$script_dir" -type f ! -path '*/__pycache__/*' -print0 |
    xargs -0 shasum -a 256 | sort -k2 > "$evidence/harness.sha256" || reject 'harness hash failed'

# A tarball inside another checkout must not adopt the outer source identity.
toplevel="$(pn_git rev-parse --show-toplevel)" || reject 'cannot discover the Git top level'
[[ "$toplevel" != *$'\n'* && "$toplevel" != *$'\r'* ]] || reject 'the Git top level contains a newline'
toplevel="$(cd -- "$toplevel" && pwd -P)" || reject 'the Git top level is not a directory'
[[ "$toplevel" == "$repo_root" ]] || reject 'the harness source is not its own Git top level'
commit="$(pn_git rev-parse HEAD)" || reject 'git rev-parse HEAD failed'
printf 'harness root: %s\ncommit: %s\n' "$repo_root" "$commit" > "$evidence/source.txt"
pn_git status --porcelain --untracked-files=no --ignore-submodules=untracked \
    > "$evidence/tracked-status.txt" || reject 'git tracked status failed'
pn_git status --porcelain > "$evidence/all-status.txt" || reject 'git status failed'
{
    printf 'status --porcelain (all; still lists unrelated untracked files):\n'
    cat "$evidence/all-status.txt"
    printf 'status --porcelain --untracked-files=no --ignore-submodules=untracked (empty means the tracked tree matches the commit):\n'
    cat "$evidence/tracked-status.txt"
} >> "$evidence/source.txt"
pn_git diff HEAD > "$evidence/tree.diff" || reject 'git diff failed'
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
    # If it ignores TERM this blocks in wait; the record then stays on disk when
    # the supervisor kills the shell, so recovery is still possible.
    if [[ -n "$driver" ]] && kill -0 "$driver" 2>/dev/null; then
        # Driver's finally block calls cleanup_run (bounded, identity-checked),
        # reaps its http.server, preserves evidence, then removes owned scratch.
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
        # reclaim only empty scratch; never erase driver state or status-24 evidence.
        # driver.pid is our own launch record, not driver state, so drop it first.
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
root="$(mktemp -d /tmp/avm-pn.XXXXXX)"
canonical_root="$(cd "$root" && pwd -P)"
root="$canonical_root"
[[ "$evidence" != "$root" && "$evidence" != "$root/"* ]] ||
    reject 'AGENT_VM_PN_EVIDENCE must be outside the scratch root'
pn_launch "$root" "$evidence" "$AGENT_VM_BIN" "$AGENT_VM_LIVE_TEST_IMAGE" &
driver=$!
# Record the driver's identity inside the scratch it is about to receive, before
# any handoff. A supervisor that cannot observe the driver's readiness or its
# own startup publication can still reap this PID (or fail closed) instead of
# deleting scratch around a live driver.
printf '%s' "$driver" > "$root/driver.pid"
shell_owns_scratch=0
wait "$driver"
driver=''
