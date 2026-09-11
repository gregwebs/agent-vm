#!/usr/bin/env bash
# Hardware gate for issue #89.  It deliberately tests a booted guest rather
# than treating AGENT_VM_DEBUG_CONFIG as guest-visibility evidence.
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

# Bind masks are opaque regular files/directories even if the hidden source is
# unreadable.  The check is intentionally guest-side; debug config is not
# evidence of mount ordering or agentd file-target preparation.
mkdir -p "$source/masked-dir"
printf hidden >"$source/masked-file"
printf nested >"$source/masked-dir/nested"
chmod 0400 "$source/masked-file"
run_guest --mount "$source:/live:ro:exclude=masked-file:exclude=masked-dir" -- \
  bash -ceu 'test -f /live/masked-file; test ! -s /live/masked-file; test ! -w /live/masked-file; test -d /live/masked-dir; test -z "$(ls -A /live/masked-dir)"; test ! -w /live/masked-dir'
# The writable form keeps nonexcluded content live while masks remain opaque.
run_guest --mount "$source:/live-rw:rw:exclude=masked-file:exclude=masked-dir" -- \
  bash -ceu 'test -f /live-rw/masked-file; test ! -s /live-rw/masked-file; test ! -w /live-rw/masked-file; test -d /live-rw/masked-dir; test -z "$(ls -A /live-rw/masked-dir)"; printf rw-visible >/live-rw/visible'
[ "$(cat "$source/visible")" = rw-visible ]

# Default fork policy preserves raw link text; explicit follow materializes a
# private copy and never observes the later host mutation.
external="$root/external"
printf outside >"$external"
ln -s "$external" "$source/link"
run_guest --mount "$source:/links:fork" -- \
  bash -ceu 'test -L /links/link; test "$(readlink /links/link)" = "'"$external"'"'
run_guest --mount "$source:/follow:fork:follow-links" -- \
  bash -ceu 'test ! -L /follow/link; test "$(cat /follow/link)" = outside'
printf changed >"$external"
run_guest --mount "$source:/follow:fork:follow-links" -- \
  bash -ceu 'test "$(cat /follow/link)" = outside'

# A single-file fork exercises agentd's file mount leaf preparation and must
# retain a guest write across a relaunch.
file="$root/file"
printf file-seed >"$file"
run_guest --mount "$file:/single:fork" -- bash -ceu 'printf guest-file >/single'
run_guest --mount "$file:/single:fork" -- bash -ceu '[ "$(cat /single)" = guest-file ]'
[ "$(cat "$file")" = file-seed ]
