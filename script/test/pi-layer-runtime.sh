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
# real config; the container's own filesystem is discarded anyway. This is the
# harness's own environment, not the wrapper's behaviour: the wrapper forces no
# telemetry default (see the env-stub cases below).
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
    # #96 landed the ~/.pi persistence mapping, so the persistence clause is
    # back. The host-precedence / host-import clauses stay out: they would be
    # about Pi's own `auth.json`. #94 (Anthropic through host Pi) was closed as
    # superseded by #164 -- which imports a *different* credential (Claude
    # Code's) into a different file -- but #91 (OpenAI/Codex credentials through
    # host Pi) is still open, so the clause stays out until #91 lands it together
    # with its behaviour. The negative grep is what fails the day this message
    # claims behaviour it does not describe.
    grep -q 'any process in this guest can read' <<<"$text" || fail "${label}: warning scope missing"
    grep -q 'microVM' <<<"$text" || fail "${label}: boundary clause missing"
    grep -q 'persistent guest state' <<<"$text" \
        || fail "${label}: persistence clause missing (#96 restored it)"
    if grep -Eq 'takes precedence|imported from your host' <<<"$text"; then
        fail "${label}: warning claims host-import behaviour #91 has not implemented"
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

# --- the image-owned bridge: registration, degradation, and its seed hook -----
#
# The build gate (verify-pi.sh) proves the bridge registers as root. This is the
# case that actually exercises the interesting half of loading it: a NON-root uid
# against the root-owned, read-only /opt tree, where jiti's transpile cache must
# fall back to the OS temp dir. The build gate's root run cannot see that
# difference, so this leg is not redundant. Keep the probe body in sync with the
# copy in images/tools/pi/verify-pi.sh.
out=$(docker run --rm --user 1000:1000 -e HOME=/tmp -e PI_TELEMETRY=0 "$layer" sh -ec '
    mkdir -p /tmp/probe
    cat > /tmp/probe/probe.js <<\PROBE
export default function (pi) {
  pi.on("session_start", (_event, ctx) => {
    const p = ctx.modelRegistry.getProvider("claude-bridge");
    const n = p && typeof p.getModels === "function" ? p.getModels().length
            : p && Array.isArray(p.models) ? p.models.length : 0;
    ctx.ui.notify(p ? `AGENT-VM-BRIDGE-REGISTERED models=${n}` : "AGENT-VM-BRIDGE-MISSING",
                  "warning");
  });
}
PROBE
    pi -e /tmp/probe/probe.js --mode rpc --no-session --no-approve </dev/null
')
grep -q 'agent-vm: signing in here' <<<"$out" \
    || fail "the non-root bridge run lost the mandatory warning: $out"
case "$out" in
    *AGENT-VM-BRIDGE-REGISTERED\ models=0*)
        fail "as uid 1000 the bridge registered with an empty model catalog: $out" ;;
    *AGENT-VM-BRIDGE-REGISTERED*)
        : ;;
    *)  fail "as uid 1000 the bridge did not register its provider: $out" ;;
esac

# The degradation contract: an AGENT_INSTALL_SOFT_FAIL build may ship without
# the bridge tree (or a user may remove it). pi must still run and still warn --
# the wrapper's existence check is what makes the bridge cost the bridge, not pi.
capture "$layer" sh -c "rm -rf /opt/agent-vm/pi-packages; pi --mode rpc --no-session --no-approve </dev/null"
[[ $CAP_STATUS -eq 0 ]] || fail "a removed pi-packages tree must not break pi, got $CAP_STATUS: $CAP_ERR"
assert_warns "bridge-removed" "$CAP_OUT"

# The seed hook points the bridge at the image's own claude. It is a plain shell
# script with no Pi dependency, so these cases run it directly in the layer
# container -- which is base + pi only, i.e. it has NO `claude`, exactly the
# "custom catalog without the claude layer" case the hook has to survive.
#
# `seed_case` supplies the two things every case needs -- the state root a guest
# would have, and a throwaway `claude` -- and runs `$1` under `set -e`. The
# "no claude layer" case removes it again. `$1` reaches the container verbatim:
# the host shell expands it once and does not re-parse its quotes or `$`.
seed_case() {
    docker run --rm "$layer" sh -ec "
        mkdir -p /agent-vm-state/pi /opt/agent/.local/bin
        touch /opt/agent/.local/bin/claude
        chmod 0755 /opt/agent/.local/bin/claude
        $1"
}

# Fresh state: exactly one key, and a trailing newline.
out=$(seed_case '
    /opt/agent-vm/seed.d/20-pi-claude-bridge
    echo > /tmp/nl
    tail -c 1 /agent-vm-state/pi/agent/claude-bridge.json | cmp -s - /tmp/nl
    cat /agent-vm-state/pi/agent/claude-bridge.json
')
jq -e '.provider.pathToClaudeCodeExecutable == "/opt/agent/.local/bin/claude"' <<<"$out" >/dev/null \
    || fail "the seed hook did not point the bridge at the image claude: $out"
jq -e 'keys == ["provider"] and (.provider | keys) == ["pathToClaudeCodeExecutable"]' <<<"$out" >/dev/null \
    || fail "the seed hook must merge exactly one key: $out"

# An existing path is honoured, and an unrelated user key survives.
out=$(seed_case '
    mkdir -p /agent-vm-state/pi/agent
    printf "%s" "{\"provider\":{\"pathToClaudeCodeExecutable\":\"/usr/bin/custom-claude\"},\"startupNoticeShown\":true}" \
        > /agent-vm-state/pi/agent/claude-bridge.json
    /opt/agent-vm/seed.d/20-pi-claude-bridge
    cat /agent-vm-state/pi/agent/claude-bridge.json
')
jq -e '.provider.pathToClaudeCodeExecutable == "/usr/bin/custom-claude" and .startupNoticeShown == true' \
    <<<"$out" >/dev/null \
    || fail "the seed hook must not clobber a user's bridge settings: $out"

out=$(seed_case '
    mkdir -p /agent-vm-state/pi/agent
    printf "%s" "{\"startupNoticeShown\":true}" > /agent-vm-state/pi/agent/claude-bridge.json
    /opt/agent-vm/seed.d/20-pi-claude-bridge
    cat /agent-vm-state/pi/agent/claude-bridge.json
')
jq -e '.startupNoticeShown == true and .provider.pathToClaudeCodeExecutable == "/opt/agent/.local/bin/claude"' \
    <<<"$out" >/dev/null \
    || fail "the seed hook must merge into, not replace, an existing file: $out"

# An unparseable file is left byte-identical (never clobbered).
out=$(seed_case '
    mkdir -p /agent-vm-state/pi/agent
    printf "%s" "{\"provider\": {" > /agent-vm-state/pi/agent/claude-bridge.json
    cp /agent-vm-state/pi/agent/claude-bridge.json /tmp/before
    /opt/agent-vm/seed.d/20-pi-claude-bridge
    cmp -s /tmp/before /agent-vm-state/pi/agent/claude-bridge.json && printf "UNCHANGED\n"
')
[[ "$out" == "UNCHANGED" ]] \
    || fail "an unparseable bridge config must be left byte-identical: $out"

# A write that fails part-way must also leave the original byte-identical. The
# hook writes a sibling temp file and renames it into place, so a truncated
# write cannot clobber a parseable user config. `ulimit -f 1` caps a file at 512
# bytes, forcing the write to fail mid-stream; before the atomic fix this left a
# 512-byte CORRUPTED file behind (and still exited 0).
out=$(seed_case '
    mkdir -p /agent-vm-state/pi/agent
    { printf "{\"startupNoticeShown\":true,\"padding\":\"";
      head -c 10000 /dev/zero | tr "\0" x;
      printf "\"}"; } > /agent-vm-state/pi/agent/claude-bridge.json
    cp /agent-vm-state/pi/agent/claude-bridge.json /tmp/before
    ( ulimit -f 1; /opt/agent-vm/seed.d/20-pi-claude-bridge )
    cmp -s /tmp/before /agent-vm-state/pi/agent/claude-bridge.json && printf "INTACT\n"
')
[[ "$out" == "INTACT" ]] \
    || fail "a failed seed-hook write must leave the config byte-identical: $out"

# The atomic write swaps the inode (sibling temp file + rename), so the hook has
# to carry the original file's mode across or a chmod'd config silently widens.
# Every other case here writes a fresh 0644 file, so only a pre-chmod'd config
# catches a rename that dropped the mode. Reproduction-only before this case
# (code review §7 F2).
out=$(seed_case '
    mkdir -p /agent-vm-state/pi/agent
    printf "%s" "{\"startupNoticeShown\":true}" > /agent-vm-state/pi/agent/claude-bridge.json
    chmod 0600 /agent-vm-state/pi/agent/claude-bridge.json
    /opt/agent-vm/seed.d/20-pi-claude-bridge
    stat -c %a /agent-vm-state/pi/agent/claude-bridge.json
')
[[ "$out" == "600" ]] \
    || fail "the seed hook's atomic write must preserve the config's mode (got '$out')"

# The merge is per-key, not per-object: a sibling the user set inside `provider`
# (the bridge's own `plan`) survives, and the seeded key is added. USAGE.md
# documents exactly this asymmetry -- changing the value is honoured, removing
# it is not, because the bridge cannot run without it.
out=$(seed_case '
    mkdir -p /agent-vm-state/pi/agent
    printf "%s" "{\"provider\":{\"plan\":\"max\"},\"startupNoticeShown\":true}" \
        > /agent-vm-state/pi/agent/claude-bridge.json
    /opt/agent-vm/seed.d/20-pi-claude-bridge
    cat /agent-vm-state/pi/agent/claude-bridge.json
')
jq -e '.provider.plan == "max"
       and .provider.pathToClaudeCodeExecutable == "/opt/agent/.local/bin/claude"
       and .startupNoticeShown == true' <<<"$out" >/dev/null \
    || fail "the seed hook must merge one provider key, preserving its siblings: $out"

# Without the claude layer the hook is a silent no-op (the custom-catalog case).
out=$(seed_case '
    rm -f /opt/agent/.local/bin/claude
    /opt/agent-vm/seed.d/20-pi-claude-bridge
    test ! -e /agent-vm-state/pi/agent/claude-bridge.json && printf "ABSENT\n"
')
[[ "$out" == "ABSENT" ]] \
    || fail "with no claude layer the seed hook must write nothing at all: $out"

# Running it twice is a no-op (it is a first-boot hook that may run every boot).
out=$(seed_case '
    /opt/agent-vm/seed.d/20-pi-claude-bridge
    cp /agent-vm-state/pi/agent/claude-bridge.json /tmp/before
    /opt/agent-vm/seed.d/20-pi-claude-bridge
    cmp -s /tmp/before /agent-vm-state/pi/agent/claude-bridge.json && printf "IDEMPOTENT\n"
')
[[ "$out" == "IDEMPOTENT" ]] || fail "the seed hook must be idempotent: $out"

# --- subcommand dispatch is positional: forwarded, never turned into a prompt -

# `pi list` reports only Pi-managed packages, and the bridge is deliberately
# NOT one: it is image-owned (an explicit wrapper --extension), so `pi list`,
# `pi update` and `pi uninstall` do not see it and cannot move its pin. This
# assertion is what records that -- see ADR-0023.
capture "$layer" pi list
[[ $CAP_STATUS -eq 0 ]] || fail "pi list exited $CAP_STATUS: $CAP_ERR"
[[ "$CAP_OUT" = "No packages installed." ]] || fail "pi list output was '$CAP_OUT'"

# `auth check` maps ready->0, not_ready->1, other->2 (Pi's dist/main.js), so a
# credential-free run is EXPECTED to exit 1. Capture the status explicitly.
capture "$layer" pi auth check --provider anthropic
[[ $CAP_STATUS -eq 1 ]] || fail "pi auth check must exit 1 credential-free, got $CAP_STATUS"
[[ "$CAP_OUT" = "not_ready" ]] || fail "pi auth check output was '$CAP_OUT'"

# --- #96 parity: the wrapper forces no trust, so a project's own .pi/
# --- resources follow Pi's own project-trust decision -- dropped while the
# --- project is untrusted (the default: no stored answer, and rpc has no trust
# --- prompt UI), loaded under an explicit --approve, and dropped under an
# --- explicit --no-approve. A user's answer is remembered in the persistent
# --- ~/.pi/agent/trust.json.
marker_js="export default function(pi){pi.on('session_start',(_e,ctx)=>{if(ctx.hasUI)ctx.ui.notify('PROJECT-EXTENSION-LOADED','warning')})}"
# shellcheck disable=SC2016  # $MARKER_JS must expand in the CONTAINER, not here
project_setup='mkdir -p /tmp/pi-project/.pi/extensions && printf %s "$MARKER_JS" > /tmp/pi-project/.pi/extensions/marker.js && cd /tmp/pi-project'

# No --approve: the wrapper injects no trust default, and Pi's trust store is
# empty, so the checkout is untrusted and its .pi/extensions are dropped.
capture -e "MARKER_JS=$marker_js" "$layer" sh -c "$project_setup && pi --mode rpc --no-session"
[[ $CAP_STATUS -eq 0 ]] || fail "untrusted-default run exited $CAP_STATUS: $CAP_ERR"
[[ "$CAP_OUT" != *PROJECT-EXTENSION-LOADED* ]] \
    || fail "the project .pi/extensions loaded while untrusted; the wrapper must force no trust: $CAP_OUT"

# An explicit --approve is Pi's own flag, forwarded verbatim, and loads them.
capture -e "MARKER_JS=$marker_js" "$layer" sh -c "$project_setup && pi --approve --mode rpc --no-session"
[[ $CAP_STATUS -eq 0 ]] || fail "--approve run exited $CAP_STATUS: $CAP_ERR"
[[ "$CAP_OUT" == *PROJECT-EXTENSION-LOADED* ]] \
    || fail "an explicit --approve did not load the project .pi/extensions: $CAP_OUT"

# An explicit --no-approve drops them.
capture -e "MARKER_JS=$marker_js" "$layer" sh -c "$project_setup && pi --no-approve --mode rpc --no-session"
[[ $CAP_STATUS -eq 0 ]] || fail "--no-approve run exited $CAP_STATUS: $CAP_ERR"
[[ "$CAP_OUT" != *PROJECT-EXTENSION-LOADED* ]] \
    || fail "--no-approve did not drop the project .pi/extensions: $CAP_OUT"

# --- #96 parity: the wrapper forces no telemetry policy; the only env it
# --- enforces is PI_SKIP_VERSION_CHECK. A stub entry point prints its
# --- environment; `pi` still runs the real wrapper, so this observes exactly
# --- what the wrapper exports.
env_stub='printf "#!/bin/sh\nenv\n" > /tmp/entry && chmod 0755 /tmp/entry && AGENT_VM_PI_ENTRY=/tmp/entry pi'

out="$(docker run --rm -e HOME=/tmp "$layer" sh -c "$env_stub")"
grep -qx 'PI_SKIP_VERSION_CHECK=1' <<<"$out" \
    || fail "the wrapper did not enforce PI_SKIP_VERSION_CHECK=1"
if grep -q '^PI_TELEMETRY=' <<<"$out"; then
    fail "the wrapper set PI_TELEMETRY; Pi's telemetry policy is Pi's own"
fi

out="$(docker run --rm -e HOME=/tmp -e PI_TELEMETRY=1 "$layer" sh -c "$env_stub")"
grep -qx 'PI_TELEMETRY=1' <<<"$out" \
    || fail "an explicit PI_TELEMETRY did not pass through the wrapper"
grep -qx 'PI_SKIP_VERSION_CHECK=1' <<<"$out" \
    || fail "PI_SKIP_VERSION_CHECK must stay enforced even with PI_TELEMETRY set"

# --- the seam ADR-0012 promises: a replaced install keeps the wrapper ---------
# A later layer replaces the Pi installation and leaves the wrapper and the
# mandatory extension alone. The wrapper (which that layer must not replace)
# still routes the mandatory --extension to WHATEVER entry point is installed,
# and injects NO trust flag of its own; an explicit approve flag is forwarded
# verbatim. We assert that routing with a stub entry point that echoes its argv;
# the warning frame itself is proven by the rpc cases above against the real Pi.
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
[[ "$CAP_OUT" != *"--approve"* ]] \
    || fail "the wrapper injected a trust flag; it must forward none: $CAP_OUT"

# An explicit --approve is Pi's own flag and is forwarded verbatim.
capture "$replacement" pi --approve --mode rpc
[[ $CAP_STATUS -eq 0 ]] || fail "replacement explicit --approve run exited $CAP_STATUS: $CAP_ERR"
[[ "$CAP_OUT" == *"--approve"* ]] \
    || fail "an explicit --approve was not forwarded to the replacement entry point: $CAP_OUT"

# The mandatory extension lives outside /opt/agent-vm/pi, so replacing the
# installation must not have removed it.
docker run --rm "$replacement" test -r "$MANDATORY" \
    || fail "replacing the installation removed the mandatory extension"

echo 'pi layer runtime contract: OK'
