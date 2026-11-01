#!/bin/sh
# PROTOTYPE (throwaway): stand-in for a runtime pause. Launches a throwaway
# agent-vm session in /tmp/PROTOTYPE-494, waits for the guest's marker, then
# freezes that session's msb process (SIGSTOP) for N seconds and resumes it.
# On macOS this matches VmControl::pause today: vCPUs stop, the guest counter runs on.
# usage: pause.sh clock|held|stream SECONDS
set -eu
scenario=$1; n=$2; here=$(cd "$(dirname "$0")" && pwd); work=/tmp/PROTOTYPE-494
mkdir -p "$work"; cp "$here/guest.sh" "$work/"; rm -f "$work/marker"; cd "$work"
before=$(pgrep -f 'msb machine' || true)
agent-vm -T --allow-egress httpbin.org run env MAXTIME="${MAXTIME:-0}" sh ./guest.sh "$scenario" "$n" 2>&1 | grep -v '^==>' &
while [ ! -e marker ]; do sleep 0.01; done
msb=$(pgrep -f 'msb machine' | grep -vxF "${before:-none}" | tail -1)
printf 'host freeze msb=%s for %ss at wall=%s\n' "$msb" "$n" "$(date -u +%s.%N)"
kill -STOP "$msb"; sleep "$n"; kill -CONT "$msb"
printf 'host resume at wall=%s\n' "$(date -u +%s.%N)"
wait
