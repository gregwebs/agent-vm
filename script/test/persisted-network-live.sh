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
script_dir="$(cd -- "${BASH_SOURCE[0]%/*}" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
# shellcheck source=script/test/lib/persisted-network.sh
source "$script_dir/lib/persisted-network.sh"
# Every stderr oracle is obtained through this shared renderer, never duplicated.
for row in PN1 PN2 PN3 PN4B PN5; do pn_expected "$row" >/dev/null; done
root="$(mktemp -d /tmp/avm-pn.XXXXXX)"
root="$(cd "$root" && pwd -P)"
evidence="${AGENT_VM_PN_EVIDENCE:-$(mktemp -d /tmp/avm-pn-evidence.XXXXXX)}"
mkdir -p "$evidence"
evidence="$(cd "$evidence" && pwd -P)"
[[ "$evidence" != "$root" && "$evidence" != "$root/"* ]] ||
    { echo 'AGENT_VM_PN_EVIDENCE must be outside the scratch root' >&2; exit 1; }
printf 'Evidence: %s\n' "$evidence"
# Self-identifying provenance: which source, tree state, harness and binary
# produced these rows. `git status --porcelain` is never empty in a workspace
# that has unrelated untracked files, so the tracked tree is recorded on its
# own line too (empty there means the tracked files match the commit) and
# `tree.diff` holds the actual tracked changes with their digest. The harness
# files are enumerated from the tree, not hand-listed, so a new fixture cannot
# silently escape the manifest.
commit="$(git -C "$repo_root" rev-parse HEAD)" ||
    { echo 'provenance: git rev-parse HEAD failed' >&2; exit 1; }
version="$("$AGENT_VM_BIN" --version)" ||
    { echo 'provenance: the binary does not report --version' >&2; exit 1; }
{
    printf 'commit: %s\n' "$commit"
    printf 'status --porcelain (all; still lists unrelated untracked files):\n'
    git -C "$repo_root" status --porcelain
    printf 'status --porcelain --untracked-files=no (empty means the tracked tree matches the commit):\n'
    git -C "$repo_root" status --porcelain --untracked-files=no
} | tee "$evidence/source.txt"
git -C "$repo_root" diff HEAD |
    tee "$evidence/tree.diff" | shasum -a 256 | tee "$evidence/tree.diff.sha256"
shasum -a 256 "$AGENT_VM_BIN" | tee "$evidence/binary.sha256"
printf '%s\n' "$version" | tee "$evidence/binary-version.txt"
printf 'Image: %s\n' "$AGENT_VM_LIVE_TEST_IMAGE" | tee "$evidence/image.txt"
# Hash every file under script/test/, not a hand list: the driver imports
# lib/egress-fixtures.py (which imports lib/egress-hostname-fixtures.py and
# released-image-launch.py), lib/persisted-network.sh sources
# lib/config-dir-guard.sh and reads fixtures/persisted-network/, and the guest
# probes, egress-probe.sh and user-allow-host.toml are copied from fixtures/.
# Any of these can decide a row's verdict. `git diff HEAD` above pins tracked
# files outside script/test/. Compiled caches are not source.
find "$script_dir" -type f ! -path '*/__pycache__/*' -print0 |
    xargs -0 shasum -a 256 | sort -k2 | tee "$evidence/harness.sha256"
driver=''
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n "$driver" ]] && kill -0 "$driver" 2>/dev/null; then
        # Driver's finally block calls cleanup_run (bounded, identity-checked),
        # reaps its http.server, preserves evidence, then removes owned scratch.
        kill -TERM "$driver" 2>/dev/null || true
        wait "$driver" || status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
pn_launch "$root" "$evidence" "$AGENT_VM_BIN" "$AGENT_VM_LIVE_TEST_IMAGE" &
driver=$!
wait "$driver"
driver=''
