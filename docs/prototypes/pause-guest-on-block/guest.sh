#!/bin/sh
# PROTOTYPE (throwaway): runs inside the guest. Prints guest clocks around a
# host-side freeze of the msb process. Touches ./marker to ask the host to freeze.
scenario=$1; n=$2
ts() { printf '%s wall=%s up=%s\n' "$1" "$(date -u +%s.%N)" "$(cut -d' ' -f1 /proc/uptime)"; }
case $scenario in
clock)
  ts before; : > marker
  i=0; while [ $i -lt $((n + 8)) ]; do sleep 1; ts tick; i=$((i + 1)); done ;;
held)   # response pending (server delays 2 s) when the freeze lands
  ts before; : > marker
  curl -sS -o /dev/null --max-time "${MAXTIME:-0}" -w 'curl http=%{http_code} dns=%{time_namelookup} tcp=%{time_connect} tls=%{time_appconnect} total=%{time_total}\n' https://httpbin.org/delay/2
  echo "curl exit=$?"; ts after ;;
stream) # 1 MB trickled over 10 s (httpbin's maximum); freeze lands mid-stream
  ts before
  ( sleep 3; : > marker ) &
  curl -sS -o /dev/null -w 'curl http=%{http_code} bytes=%{size_download} total=%{time_total}\n' 'https://httpbin.org/drip?numbytes=1000000&duration=10&delay=0'
  echo "curl exit=$?"; ts after ;;
pending) # request sent, server answers after 8 s; freeze lands while waiting
  ts before
  ( sleep 3; : > marker ) &
  curl -sS -o /dev/null --max-time "${MAXTIME:-0}" -w 'curl http=%{http_code} dns=%{time_namelookup} tcp=%{time_connect} tls=%{time_appconnect} first-byte=%{time_starttransfer} total=%{time_total}\n' https://httpbin.org/delay/8
  echo "curl exit=$?"; ts after ;;
esac
dmesg 2>/dev/null | grep -iE 'rcu|lockup|stall|clocksource|watchdog|timekeeping' | tail -5
