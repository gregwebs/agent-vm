#!/bin/bash
set -euo pipefail

# Long-lived PTY heartbeat reproducer for issue #41.
#
# The bug: a long-lived exec/PTY session (agent-vm shell, a REPL, a build
# watcher) could be reclaimed by the host's idle/heartbeat monitor when
# agentd's heartbeat.json momentarily stopped advancing under host load or
# virtiofs write latency, even though the exec session was actively
# running the whole time. #41 added a two-window grace/confirmation to
# HeartbeatReader::check (vendor/microsandbox/crates/runtime/lib/heartbeat.rs)
# so a brief stale window (< 2x STALE_HEARTBEAT_TIMEOUT, i.e. < 10s at the
# shipped default) never kills an active session, while a heartbeat that
# stays stale past that budget still gets reclaimed as AgentUnresponsive.
#
# This script holds a real exec/PTY session open for DURATION_SECS
# (default well beyond the 10s failure window, into the minutes range) and
# asserts the session ran to completion uninterrupted. It boots a real
# sandbox, so it requires a VM-capable host (macOS arm64 libkrun, or Linux
# x86_64 with /dev/kvm) and a built `agent-vm` on PATH. Not run in CI by
# default — invoke manually:
#
#   ./script/test/heartbeat-longlived.sh
#   DURATION_SECS=300 ./script/test/heartbeat-longlived.sh

DURATION_SECS=${DURATION_SECS:-90}

command -v agent-vm >/dev/null || {
    echo "heartbeat-longlived: agent-vm not found on PATH (build it first)" >&2
    exit 2
}

project_dir=$(mktemp -d)
trap 'rm -rf "$project_dir"' EXIT

# A black-box guest workload: ticks once a second for DURATION_SECS and
# prints a DONE marker. Deliberately doesn't touch agentd's own heartbeat
# file — the fix under test is host-side monitoring, not the guest.
script="i=0; while [ \$i -lt $DURATION_SECS ]; do echo \"tick \$i\"; sleep 1; i=\$((i+1)); done; echo HEARTBEAT_LONGLIVED_DONE"

timeout_secs=$((DURATION_SECS + 90))
echo "heartbeat-longlived: holding a PTY session open for ${DURATION_SECS}s (timeout ${timeout_secs}s)..."

output=$(cd "$project_dir" && timeout "$timeout_secs" agent-vm shell --no-git -- bash -lc "$script")

echo "$output" | grep -q '^HEARTBEAT_LONGLIVED_DONE$' || {
    echo "heartbeat-longlived: session did not complete; output was:" >&2
    echo "$output" >&2
    exit 1
}

tick_count=$(echo "$output" | grep -c '^tick ' || true)
if [ "$tick_count" -lt "$DURATION_SECS" ]; then
    echo "heartbeat-longlived: expected >= $DURATION_SECS ticks, saw $tick_count (session was likely reclaimed early)" >&2
    exit 1
fi

echo "heartbeat-longlived: OK ($tick_count ticks over ${DURATION_SECS}s; session survived uninterrupted)"
