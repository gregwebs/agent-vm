#!/bin/sh
# Shared recipe-contract helper: the installation envelope.
#
# Canonical source: images/recipe-contract/run-install.sh
# Byte-identical copies live under images/tools/<tool>/contract/; regenerate
# them with `script/build/sync-recipe-contracts.sh --write`. Do not edit a copy.
#
# Usage: run-install.sh NAME RESULT_FILE INTERPRETER SCRIPT [ARG ...]
#
# Runs `INTERPRETER SCRIPT [ARG ...]` (arguments are argv, never eval) and
# normalises its exit status:
#
#   0           -> 0   success
#   anything    -> 1   hard failure
#
# The classified-transport protocol (exit 75 + a fresh receipt) is handled by
# the *owning* hook (SCRIPT), which alone knows which partial artifacts are
# recipe-owned and may soften a failure when AGENT_INSTALL_SOFT_FAIL is set.
# run-install.sh guarantees that a raw 75 -- a classified transport the owning
# hook declined to soften, or a native subprocess that happened to exit 75 --
# can never escape as success.
#
# It also owns two shared mechanics:
#   * a private mktemp receipt path exported as AGENT_VM_TRANSPORT_RECEIPT, so
#     download.sh/run-npm.sh have one home for a classified failure;
#   * the RESULT_FILE status record, written `pending` before the attempt so an
#     inherited `installed` from an earlier layer cannot mask a failed install.
set -eu

if [ "$#" -lt 4 ]; then
    echo "run-install.sh: usage: run-install.sh NAME RESULT_FILE INTERPRETER SCRIPT [ARG ...]" >&2
    exit 2
fi
name=$1
result=$2
interpreter=$3
script=$4
shift 4

AGENT_VM_TRANSPORT_RECEIPT=$(mktemp)
export AGENT_VM_TRANSPORT_RECEIPT
trap 'rm -f "$AGENT_VM_TRANSPORT_RECEIPT"' EXIT INT TERM HUP

# The record starts pending. The owning hook overwrites it with `installed`
# only after the report/equality/T5 gates pass, or with an `absent-...` record
# when it softens a classified transport failure.
if [ -n "$result" ]; then
    mkdir -p "$(dirname "$result")"
    printf 'pending\n' >"$result"
fi

status=0
"$interpreter" "$script" "$@" || status=$?

if [ "$status" -eq 0 ]; then
    exit 0
fi

if [ "$status" -eq 75 ] && grep -Eq '^transport (download [0-9]+|npm [A-Za-z0-9_]+)$' "$AGENT_VM_TRANSPORT_RECEIPT"; then
    echo "run-install.sh: $name hit a classified transport failure the owning hook did not soften" >&2
    echo "run-install.sh: receipt: $(cat "$AGENT_VM_TRANSPORT_RECEIPT")" >&2
    exit 1
fi

echo "run-install.sh: $name installer failed (exit $status); no classified receipt" >&2
exit 1
