#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=script/test/fixtures/egress-probe.sh
EGRESS_PROBE_LIB=1 source ./egress-probe.sh
rc=0
# The optional host is for the boot-free loopback control; native rows omit it.
http_get "${3:-host.microsandbox.internal}" "$1" "$2" || rc=$?
case "$rc" in
    0) printf 'PN_REACHED %s\n' "$2" ;;
    1) printf 'PN_DENIED %s\n' "$2" ;;
    *) echo "probe harness error: $rc" >&2; exit "$rc" ;;
esac
