#!/bin/bash
# Runtime behaviour matrix for the pinned Pi layer: the acceptance criteria that
# only a built image can prove -- the locked version, the mandatory warning in
# the modes a human reads, stdout cleanliness in the machine modes, fail-closed
# when the mandatory extension is gone or broken, subcommand passthrough, and
# arbitrary-uid access (C7). Everything is credential-free.
#
# Usage: script/test/pi-layer-runtime.sh BASE_IMAGE LAYER_IMAGE
#
# The workflow (`.github/workflows/pi-layer.yml`) builds both images with
# `--load` and passes them in, exactly as chrome-layer-contract.yml does.

set -euo pipefail

[ "$#" = 2 ] || { echo "usage: $0 BASE_IMAGE LAYER_IMAGE" >&2; exit 2; }
base=$1
layer=$2

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
PINNED="$(jq -r '.dependencies["@earendil-works/pi-coding-agent"]' \
    "$REPO_ROOT/images/tools/pi/package.json")"
MANDATORY=/opt/agent-vm/pi-extensions/guest-credential-warning.js
TMP="$(mktemp -d "${TMPDIR:-/tmp}/pi-layer-runtime.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# A container that writes nothing durable into the image and does not read the
# host's Pi config. `-e HOME=/tmp` and PI_TELEMETRY=0 keep Pi from touching a
# real config; the container's own filesystem is discarded anyway.
run() {
    docker run --rm -e HOME=/tmp -e PI_TELEMETRY=0 "$@"
}

# Sets CAP_OUT, CAP_ERR, CAP_STATUS from one `docker run`, tolerating a non-zero
# exit (several cases below expect one).
capture() {
    local out_file="${TMP}/out" err_file="${TMP}/err"
    set +e
    printf '' | run "$@" >"$out_file" 2>"$err_file"
    CAP_STATUS=$?
    set -e
    CAP_OUT="$(cat "$out_file")"
    CAP_ERR="$(cat "$err_file")"
}

assert_warns() {
    local label="$1" text="$2"
    grep -q '"method":"notify"' <<<"$text" || fail "${label}: no notify frame"
    grep -q 'agent-vm: signing in here' <<<"$text" || fail "${label}: warning text missing"
    # The warning is scoped to what #95 delivers (a readable credential plus the
    # microVM boundary); #96/#94/#91 restore the persistence / host-precedence /
    # host-import clauses together with their behaviour. The positive greps pin
    # the current literal and the negative grep fails the day a removed clause
    # is written back ahead of its implementation.
    grep -q 'any process in this guest can read' <<<"$text" || fail "${label}: warning scope missing"
    grep -q 'microVM' <<<"$text" || fail "${label}: boundary clause missing"
    if grep -Eq 'persistent guest state|takes precedence|imported from your host' <<<"$text"; then
        fail "${label}: warning still claims unimplemented #96/#94/#91 behaviour"
    fi
    grep -q '"notifyType":"warning"' <<<"$text" || fail "${label}: notifyType is not warning"
}

# --- the tool-free base ships no pi and no wrapper --------------------------

docker run --rm "$base" sh -ec '
    ! command -v pi
    ! test -e /opt/agent-vm/pi
    ! test -e /usr/local/bin/pi
'

# --- the locked version, and arbitrary-uid access (C7) -----------------------

version="$(run "$layer" pi --version)"
[[ "$version" = "$PINNED" ]] || fail "pi --version reported '$version', lockfile pins '$PINNED'"

as_guest="$(docker run --rm --user 1000:1000 -e HOME=/tmp "$layer" pi --version)"
[[ "$as_guest" = "$PINNED" ]] || fail "non-root pi --version reported '$as_guest'"

# --- the warning rides hasUI: present in tui/rpc, absent in print/json -------

capture "$layer" pi --mode rpc --no-session --no-approve
[[ $CAP_STATUS -eq 0 ]] || fail "rpc run exited $CAP_STATUS: $CAP_ERR"
assert_warns "rpc" "$CAP_OUT"

capture "$layer" pi -ne --mode rpc --no-session --no-approve
[[ $CAP_STATUS -eq 0 ]] || fail "rpc -ne run exited $CAP_STATUS: $CAP_ERR"
assert_warns "rpc -ne (--no-extensions cannot silence it)" "$CAP_OUT"

capture "$layer" pi -p --no-session
[[ $CAP_STATUS -eq 0 ]] || fail "print run exited $CAP_STATUS: $CAP_ERR"
[[ -z "$CAP_OUT" ]] || fail "print mode stdout must be empty, got: $CAP_OUT"

capture "$layer" pi --mode json --no-session
[[ $CAP_STATUS -eq 0 ]] || fail "json run exited $CAP_STATUS: $CAP_ERR"
[[ "$(printf '%s\n' "$CAP_OUT" | wc -l | tr -d ' ')" = 1 ]] \
    || fail "json mode must emit exactly one line, got: $CAP_OUT"
jq -e '.type == "session"' <<<"$CAP_OUT" >/dev/null || fail "json mode's single line is not the session event"
[[ "$CAP_OUT" != *extension_ui_request* ]] || fail "json mode leaked the warning frame"

# --- fail-closed when the mandatory extension is gone or broken --------------

capture "$layer" sh -c "rm -f $MANDATORY; pi --mode rpc --no-session </dev/null"
[[ $CAP_STATUS -eq 1 ]] || fail "a deleted mandatory extension must exit 1, got $CAP_STATUS"
[[ -z "$CAP_OUT" ]] || fail "a deleted mandatory extension wrote to stdout: $CAP_OUT"
[[ "$CAP_ERR" == *"$MANDATORY"* ]] || fail "the error must name the mandatory path: $CAP_ERR"

capture "$layer" sh -c "printf 'export default function( {' > $MANDATORY; pi --mode rpc --no-session </dev/null"
[[ $CAP_STATUS -eq 1 ]] || fail "a syntax-broken mandatory extension must exit 1, got $CAP_STATUS"

capture "$layer" sh -c "printf 'export default function(){ throw new Error(\"boom\") }' > $MANDATORY; pi --mode rpc --no-session </dev/null"
[[ $CAP_STATUS -eq 1 ]] || fail "a throwing mandatory extension must exit 1, got $CAP_STATUS"

# Weaker variant kept on purpose: a user-specified missing path (not the
# mandatory one) is also fatal, and names the path.
capture "$layer" pi -e /opt/agent-vm/pi-extensions/definitely-absent.js --mode rpc --no-session
[[ $CAP_STATUS -ne 0 ]] || fail "a missing user -e path must be fatal"
[[ "$CAP_ERR" == *definitely-absent.js* ]] || fail "the error must name the missing path"

# --- subcommand dispatch is positional: forwarded, never turned into a prompt -

capture "$layer" pi list
[[ $CAP_STATUS -eq 0 ]] || fail "pi list exited $CAP_STATUS: $CAP_ERR"
[[ "$CAP_OUT" = "No packages installed." ]] || fail "pi list output was '$CAP_OUT'"

# `auth check` maps ready->0, not_ready->1, other->2 (Pi's dist/main.js), so a
# credential-free run is EXPECTED to exit 1. Capture the status explicitly.
capture "$layer" pi auth check --provider anthropic
[[ $CAP_STATUS -eq 1 ]] || fail "pi auth check must exit 1 credential-free, got $CAP_STATUS"
[[ "$CAP_OUT" = "not_ready" ]] || fail "pi auth check output was '$CAP_OUT'"

# --- the seam ADR-0012 promises: a replaced install keeps the wrapper ---------
# A later layer replaces the Pi installation and leaves the wrapper and the
# mandatory extension alone. The wrapper (which that layer must not replace)
# still routes the mandatory --extension to WHATEVER entry point is installed.
# We assert that routing with a stub entry point that echoes its argv; the
# warning frame itself is proven by the rpc cases above against the real Pi.
replacement="${layer}-replacement"
ctx="${TMP}/replacement"
mkdir -p "$ctx"
cat >"$ctx/Dockerfile" <<'EOF'
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
# Replace only the installation; the wrapper (/usr/local/bin/pi) and the
# mandatory extension are left untouched, exactly as ADR-0012 requires.
RUN rm -rf /opt/agent-vm/pi \
 && mkdir -p /opt/agent-vm/pi/node_modules/.bin \
 && printf '#!/bin/sh\nprintf "REPLACEMENT-AW: routed"; printf " <%%s>" "$@"; printf "\\n"\n' > /opt/agent-vm/pi/node_modules/.bin/pi \
 && chmod 0755 /opt/agent-vm/pi/node_modules/.bin/pi \
 && chmod -R a+rX /opt/agent-vm/pi
EOF
docker build --build-arg "BASE_IMAGE=$layer" -t "$replacement" "$ctx" >/dev/null
capture "$replacement" pi --mode rpc
[[ $CAP_STATUS -eq 0 ]] || fail "replacement-seam run exited $CAP_STATUS: $CAP_ERR"
[[ "$CAP_OUT" == *"REPLACEMENT-AW: routed"* ]] || fail "the wrapper did not reach the replacement entry point: $CAP_OUT"
[[ "$CAP_OUT" == *"--extension"* ]] || fail "the wrapper did not pass --extension to the replacement: $CAP_OUT"
[[ "$CAP_OUT" == *"$MANDATORY"* ]] \
    || fail "the wrapper stopped routing the mandatory --extension after a replacement: $CAP_OUT"

# The mandatory extension lives outside /opt/agent-vm/pi, so replacing the
# installation must not have removed it.
docker run --rm "$replacement" test -r "$MANDATORY" \
    || fail "replacing the installation removed the mandatory extension"

echo 'pi layer runtime contract: OK'
