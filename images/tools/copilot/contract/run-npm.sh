#!/bin/sh
# Shared recipe-contract helper: a classified `npm` invocation.
#
# Canonical source: images/recipe-contract/run-npm.sh
# Byte-identical copies live under images/tools/<tool>/contract/; regenerate
# them with `script/build/sync-recipe-contracts.sh --write`. Do not edit a copy.
#
# Usage: run-npm.sh RESULT_FILE -- npm <args...>
#
# Runs `npm <args...> --json --loglevel=error` under a 600s bound (TERM, then a
# KILL escalation so a TERM-ignoring npm cannot hang the build), capturing
# stdout (the JSON report, also written to RESULT_FILE) and stderr separately.
# The argv after `--` is the FULL command ("npm ci …"): this helper does not
# prepend `npm` itself, so the usage line and every caller agree. Exit 0 is
# success. A nonzero exit is classified as a *transport* failure -- the only
# case the owning installer may soften -- only when BOTH hold:
#
#   * the process exited normally (not killed by timeout/signal);
#   * stdout is exactly one JSON object whose `.error.code` is one of
#     EAI_AGAIN, ENOTFOUND, ECONNREFUSED, ECONNRESET, ETIMEDOUT; and
#   * every structured `npm error code <CODE>` line on stderr repeats that same
#     code (or there is none).
#
# Everything else -- unparseable/multiple/absent error objects, a contradictory
# stderr code, EINTEGRITY, E401, E404, ERESOLVE, a timeout or a signal -- is a
# hard failure. The classification is written to the receipt from
# AGENT_VM_TRANSPORT_RECEIPT (cleared at the start of the attempt) and the exit
# is 75; the owning hook decides whether to soften it.
set -eu

if [ "$#" -lt 3 ]; then
    echo "run-npm.sh: usage: run-npm.sh RESULT_FILE -- npm <args...>" >&2
    exit 2
fi
result=$1
shift
if [ "$1" != "--" ]; then
    echo "run-npm.sh: expected -- before the npm argv" >&2
    exit 2
fi
shift

receipt="${AGENT_VM_TRANSPORT_RECEIPT:-}"
if [ -z "$receipt" ]; then
    echo "run-npm.sh: AGENT_VM_TRANSPORT_RECEIPT is unset; refusing to run npm" >&2
    exit 1
fi
: >"$receipt"

scratch=$(mktemp -d)
# The trap action is single-quoted, so it stays the literal `rm -rf "$scratch"`;
# the quoted expansion happens at cleanup time and its result is never re-parsed,
# so a TMPDIR containing a single quote cannot inject a command into the exit
# trap. (`trap "rm -rf '$scratch'"` would build a shell program out of the
# path.)
trap 'rm -rf "$scratch"' EXIT INT TERM HUP
out=$scratch/stdout
err=$scratch/stderr

status=0
timeout --kill-after=5 600 "$@" --json --loglevel=error >"$out" 2>"$err" || status=$?

cp "$out" "$result" 2>/dev/null || true
if [ -s "$err" ]; then
    cat "$err" >&2
fi

if [ "$status" -eq 0 ]; then
    exit 0
fi

hard() {
    echo "run-npm.sh: $1; not a classified transport failure" >&2
    exit 1
}

[ "$status" -lt 124 ] || hard "npm exited $status (timeout or signal)"
[ "$status" -lt 128 ] || hard "npm exited $status (signal)"

parsed=$(jq -c . "$out" 2>/dev/null) || hard "npm stdout is not JSON"
count=$(printf '%s\n' "$parsed" | wc -l | tr -d ' ')
[ "$count" -eq 1 ] || hard "npm stdout has $count JSON documents, expected exactly one"
case "$parsed" in
    *'"error"'*) ;;
    *) hard "npm stdout has no error object" ;;
esac
code=$(printf '%s\n' "$parsed" | jq -r '.error.code // empty')
case "$code" in
    EAI_AGAIN | ENOTFOUND | ECONNREFUSED | ECONNRESET | ETIMEDOUT) ;;
    *) hard "npm error code '${code:-<none>}'" ;;
esac

# Every structured npm `error code` line on stderr must repeat the same code.
# A different one means npm also saw a non-transport failure it is not telling
# us about in the JSON object; treat that as hard rather than trusting narrow
# JSON. `|| [ -n "$line" ]` keeps a final line with no trailing newline (a bare
# `while read` drops it, so an unterminated contradictory `EINTEGRITY` would be
# classified as transport).
bad=0
while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
        "npm error code "*)
            seen=${line#npm error code }
            seen=${seen%% *}
            [ "$seen" = "$code" ] || bad=1
            ;;
    esac
done <"$err"
[ "$bad" -eq 0 ] || hard "npm stderr reports a different error code"

printf 'transport npm %s\n' "$code" >"$receipt"
exit 75
