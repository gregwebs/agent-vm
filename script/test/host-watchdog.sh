#!/usr/bin/env bash
# Black-box tests for the host process-group watchdog
# (script/test/host-watchdog.py).
#
# The load-bearing property is that escalation does NOT depend on the group
# leader exiting: a grandchild that ignores SIGTERM must still be SIGKILLed, and
# an inherited SIGTERM must be forwarded to the child group. These are the two
# ways an orphaned `docker run`/buildx client could survive a harness timeout.
set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
WATCHDOG="$REPO_ROOT/script/test/host-watchdog.py"

command -v python3 >/dev/null 2>&1 || { echo "FAIL: python3 is required" >&2; exit 1; }

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/host-watchdog.XXXXXX")"
trap 'rm -rf "$ROOT"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# A descendant that ignores SIGTERM and records its own pid.
cat >"$ROOT/grandchild.py" <<'PY'
import os, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with open(sys.argv[1], "w") as handle:
    handle.write(str(os.getpid()))
time.sleep(300)
PY

# A leader that spawns the ignoring grandchild and then sleeps too.
cat >"$ROOT/leader.py" <<'PY'
import subprocess, sys, time
subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])
time.sleep(300)
PY

alive() {
    kill -0 "$1" 2>/dev/null
}

# --- 1. a SIGTERM-ignoring grandchild is SIGKILLed on timeout ----------------

pidfile="$ROOT/grandchild.pid"
set +e
python3 "$WATCHDOG" 1 python3 "$ROOT/leader.py" "$ROOT/grandchild.py" "$pidfile"
status=$?
set -e
[[ $status -eq 124 ]] || fail "expected timeout exit 124, got $status"
[[ -f "$pidfile" ]] || fail "the grandchild never started"
gpid="$(cat "$pidfile")"
if alive "$gpid"; then
    kill -9 "$gpid" 2>/dev/null || true
    fail "SIGTERM-ignoring grandchild $gpid survived the watchdog timeout"
fi

# --- 2. an inherited SIGTERM is forwarded to the child group -----------------

cat >"$ROOT/sleeper.py" <<'PY'
import os, sys, time
with open(sys.argv[1], "w") as handle:
    handle.write(str(os.getpid()))
time.sleep(300)
PY

pidfile="$ROOT/sleeper.pid"
python3 "$WATCHDOG" 300 python3 "$ROOT/sleeper.py" "$pidfile" &
watchdog_pid=$!
for _ in $(seq 1 200); do
    [ -f "$pidfile" ] && break
    sleep 0.05
done
[[ -f "$pidfile" ]] || { kill -9 "$watchdog_pid" 2>/dev/null || true; fail "the sleeper never started"; }
spid="$(cat "$pidfile")"
kill -TERM "$watchdog_pid"
set +e
wait "$watchdog_pid"
set -e
if alive "$spid"; then
    kill -9 "$spid" 2>/dev/null || true
    fail "the child group survived a forwarded SIGTERM (sleeper $spid)"
fi

echo "host-watchdog black-box tests passed"
