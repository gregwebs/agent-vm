#!/usr/bin/env bash
# SPIKE (throwaway) -- assert every declared tool resolves in a merged image.
#
# This is the check whose absence let the first COPY_ROOTS table ship an image
# with no codex/copilot. It is the seed of the merged-image contract that would
# replace the prefix-stack clauses (C1/C2) for shipped tools.
#
#   ./verify-merge.sh <image> cmd1,cmd2,...
set -euo pipefail

image="${1:?usage: verify-merge.sh <image> cmd1,cmd2,...}"
cmds="${2:?usage: verify-merge.sh <image> cmd1,cmd2,...}"

fail=0
for c in ${cmds//,/ }; do
    if docker run --rm --entrypoint bash "$image" -c "type -P $(printf '%q' "$c") >/dev/null" 2>/dev/null; then
        echo "  ok    $c"
    else
        echo "  MISS  $c" >&2
        fail=1
    fi
done
exit "$fail"
