#!/bin/sh
# Shared recipe-contract helper: a classified download.
#
# Canonical source: images/recipe-contract/download.sh
# Byte-identical copies live under images/tools/<tool>/contract/; regenerate
# them with `script/build/sync-recipe-contracts.sh --write`. Do not edit a copy.
#
# Usage: download.sh URL OUTPUT
#
# Fetch URL into OUTPUT with curl. A *transport* failure is classified: the
# helper writes a machine-readable receipt and exits 75 so the owning installer
# can soften it when AGENT_INSTALL_SOFT_FAIL is set. Everything else -- an HTTP
# error such as 404, a malformed/unsafe URL, a local write error, or a curl
# code that is not a known transport failure -- is hard (exit 1), because it is
# not evidence that the network was briefly unavailable.
#
# The receipt path comes from AGENT_VM_TRANSPORT_RECEIPT (set by run-install.sh).
# It is cleared at the start of every attempt so a later unrelated failure can
# never consume an earlier attempt's receipt.
set -eu

if [ "$#" -ne 2 ]; then
    echo "download.sh: usage: download.sh URL OUTPUT" >&2
    exit 2
fi
url=$1
output=$2

receipt="${AGENT_VM_TRANSPORT_RECEIPT:-}"
if [ -z "$receipt" ]; then
    # Without a receipt there is no way to certify a transport failure as
    # classified, so the contract cannot be met. Hard-fail rather than guess.
    echo "download.sh: AGENT_VM_TRANSPORT_RECEIPT is unset; refusing to download" >&2
    exit 1
fi

case "$url" in
    https://*) ;;
    *)
        echo "download.sh: URL must be absolute https: $url" >&2
        exit 1
        ;;
esac
# curl is always invoked with "$url" quoted, but reject characters that have no
# place in an asset URL as defence in depth: a value interpolated from a
# manifest or a build arg must never smuggle shell syntax or an option. Delete
# every allowed byte and require nothing to remain: `grep` is line-oriented, so
# an embedded newline would otherwise pass a per-line match.
forbidden=$(printf '%s' "$url" | tr -d 'A-Za-z0-9._~:/?#@!$&()*+,;=%-' | wc -c)
forbidden=$(printf '%s' "$forbidden" | tr -d '[:space:]')
if [ "$forbidden" != "0" ]; then
    echo "download.sh: URL contains forbidden characters: $url" >&2
    exit 1
fi

: >"$receipt"

status=0
curl -fsSL --http1.1 --retry 5 --retry-all-errors \
    --connect-timeout 15 --max-time 180 --retry-max-time 600 \
    -o "$output" "$url" || status=$?

if [ "$status" -eq 0 ]; then
    exit 0
fi

# curl's exit codes for a transport-layer failure: proxy/service errors, DNS,
# connect, partial transfer, timeout, TLS handshake, empty reply, send/recv
# error, peer cert. 22 (an HTTP error such as 404), 23 (local write), 3 (bad
# URL) and everything else are contract failures, never transport.
case "$status" in
    5 | 6 | 7 | 18 | 28 | 35 | 52 | 55 | 56 | 60)
        printf 'transport download %s\n' "$status" >"$receipt"
        exit 75
        ;;
esac

echo "download.sh: curl failed (exit $status) for $url" >&2
exit 1
