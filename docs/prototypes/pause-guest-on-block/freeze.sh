#!/bin/sh
# PROTOTYPE (throwaway): freeze one of your running agent-vm sessions for N
# seconds, as a runtime pause would, so you can see what a paused session is like.
# usage: freeze.sh SECONDS [MSB_PID]   (with no pid, lists your sessions)
set -eu
n=${1:?usage: freeze.sh SECONDS [MSB_PID]}; pid=${2:-}
if [ -z "$pid" ]; then
  echo "your sessions (MSB_PID  launcher project):"
  pgrep -u "$(id -u)" -f 'msb machine --name agent-vm-' | while read -r p; do
    lp=$(ps -o command= -p "$p" | sed -E 's/.*--name agent-vm-[0-9a-f]+-([0-9]+).*/\1/')
    printf '  %s  %s %s\n' "$p" "$(ps -o command= -p "$lp" 2>/dev/null | cut -c1-60)" \
      "$(lsof -a -p "$lp" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p')"
  done
  echo "rerun with the MSB_PID to freeze"; exit 0
fi
ps -o command= -p "$pid" | grep -q 'msb machine --name agent-vm-' || { echo "not an agent-vm msb: $pid" >&2; exit 2; }
trap 'kill -CONT "$pid"; echo resumed' EXIT INT TERM
echo "freezing $pid for ${n}s (Ctrl-C resumes early)"; kill -STOP "$pid"; sleep "$n"
