#!/usr/bin/env bash
# shellcheck disable=SC2016  # guest-side commands deliberately single-quote `$(...)`
# Hardware gate for the narrowed fork contract (agent-vm #113, building on #89).
# It deliberately tests a booted guest rather than treating AGENT_VM_DEBUG_CONFIG
# as guest-visibility evidence.
set -euo pipefail

: "${AGENT_VM_BIN:?set AGENT_VM_BIN to the built agent-vm binary}"
: "${AGENT_VM_MOUNT_TEST_IMAGE:?set AGENT_VM_MOUNT_TEST_IMAGE to a cached image}"

root="$(mktemp -d "${TMPDIR:-/tmp}/agent-vm-fork-live.XXXXXX")"
trap 'rm -rf "$root"' EXIT
source="$root/source"
state="$root/state"
mkdir -p "$source/cache"
printf 'seed' >"$source/visible"
printf 'secret' >"$source/hidden"
printf 'cache-secret' >"$source/cache/hidden"

run_guest() {
  AGENT_VM_STATE_DIR="$state" "$AGENT_VM_BIN" shell --no-git \
    --image "$AGENT_VM_MOUNT_TEST_IMAGE" "$@"
}

# Fork seeding, persistence, and the physical exclusion are all observable
# from the guest.  Source mutation after the first launch must not propagate.
run_guest --mount "$source:/fork:fork:exclude=hidden:exclude=cache" -- \
  bash -ceu '[ "$(cat /fork/visible)" = seed ]; test ! -e /fork/hidden; test ! -e /fork/cache; printf guest >/fork/visible'
printf 'host-later' >"$source/visible"
run_guest --mount "$source:/fork:fork:exclude=hidden:exclude=cache" -- \
  bash -ceu '[ "$(cat /fork/visible)" = guest ]; test ! -e /fork/hidden; test ! -e /fork/cache'
[ "$(cat "$source/visible")" = host-later ]

# Default fork policy preserves raw link text; explicit follow materializes a
# private copy of a nested file target and never observes the later host
# mutation.  This proves nested regular-file copying still works now that a
# file cannot itself be a fork root.
external="$root/external"
printf outside >"$external"
ln -s "$external" "$source/link"
run_guest --mount "$source:/links:fork" -- \
  bash -ceu 'test -L /links/link; test "$(readlink /links/link)" = "'"$external"'"'
run_guest --mount "$source:/follow:fork:follow-links" -- \
  bash -ceu 'test ! -L /follow/link; test -f /follow/link; test "$(cat /follow/link)" = outside'
printf changed >"$external"
run_guest --mount "$source:/follow:fork:follow-links" -- \
  bash -ceu 'test "$(cat /follow/link)" = outside'
