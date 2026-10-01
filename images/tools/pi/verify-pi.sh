#!/bin/sh
# Build-time verification gate for the pinned Pi layer, run from the layer's
# final `RUN --mount=type=bind` (see images/tools/pi/Dockerfile). Bind-mounted,
# never COPYed, so the script stays out of the shipped image and needs no
# execute bit.
#
# It is reached in BOTH outcomes of install-pi.sh: a hard install failure
# already aborted the build, and a softened transport failure exited 0 having
# deleted /opt/agent-vm/pi entirely and recorded `absent-transport CODE`. The
# `! -x` branch below accepts that degraded state ONLY with a fresh absence
# record; otherwise a missing command is a hard failure regardless of
# AGENT_INSTALL_SOFT_FAIL.
#
# Every Pi invocation is bounded and its status is checked BEFORE its output is
# parsed: a command that prints the expected version/marker and then exits
# nonzero, or hangs, fails. The version contract is the committed manifest, and
# the bridge is checked by manifest-to-installed package.json equality PLUS a
# behavioral provider/models probe (metadata alone is not proof a working
# extension). On full success both slots are recorded `installed`; a
# bridge-only transport degradation leaves a working Pi `installed` and the
# bridge `absent-transport CODE`, never `installed`.
#
# All paths are explicit seams (production defaults asserted by the tests); the
# hermetic black-box test points every one at a case temp root.
set -eu

CONTRACT="${AGENT_VM_CONTRACT_DIR:-/tmp/recipe-contract}"
PI_PREFIX="${AGENT_VM_PI_PREFIX:-/opt/agent-vm/pi}"
WRAPPER="${AGENT_VM_PI_WRAPPER:-/usr/local/bin/pi}"
PACKAGES_PREFIX="${AGENT_VM_PI_PACKAGES_PREFIX:-/opt/agent-vm/pi-packages}"
EXTENSION_DIR="${AGENT_VM_PI_EXTENSION_DIR:-/opt/agent-vm/pi-extensions}"
GATE_WORK_DIR="${AGENT_VM_PI_GATE_WORK_DIR:-/tmp/pi-gate}"
SEED_HOOK="${AGENT_VM_PI_SEED_HOOK:-/opt/agent-vm/seed.d/20-pi-claude-bridge}"
STATUS_DIR="${AGENT_VM_INSTALL_STATUS_DIR:-/opt/agent-vm/install-status}"
PI_VERSION="${AGENT_VM_VERSION_PI:-}"
BRIDGE_VERSION="${AGENT_VM_VERSION_PI_CLAUDE_BRIDGE:-}"

pi_bin="$PI_PREFIX/node_modules/.bin/pi"

# --- destructive-path authorization (review ST2) -----------------------------
# Every path this gate deletes must be the exact production default or a
# canonical child of AGENT_VM_FIXTURE_ROOT. A mistaken seam pointing at another
# real tree must be refused, and a symlinked target is refused outright.
FIXTURE_ROOT="${AGENT_VM_FIXTURE_ROOT:-}"

authorize_destructive() { # $1 path, $2 exact production default
    _p=$1
    _prod=$2
    if [ -L "$_p" ]; then
        echo "  pi: refusing to delete symlink $_p" >&2
        return 1
    fi
    _dir=$(dirname "$_p")
    _base=$(basename "$_p")
    if [ -d "$_dir" ]; then
        _full="$(cd "$_dir" && pwd -P)/$_base"
    else
        _full=$_p
    fi
    if [ "$_full" = "$_prod" ]; then
        return 0
    fi
    if [ -z "$FIXTURE_ROOT" ]; then
        echo "  pi: refusing to delete $_full (not the production path $2; AGENT_VM_FIXTURE_ROOT is unset)" >&2
        return 1
    fi
    [ -d "$FIXTURE_ROOT" ] || {
        echo "  pi: AGENT_VM_FIXTURE_ROOT is not a directory: $FIXTURE_ROOT" >&2
        return 1
    }
    _root=$(cd "$FIXTURE_ROOT" && pwd -P)
    case "$_full" in
        "$_root"/*) return 0 ;;
    esac
    echo "  pi: refusing to delete $_full (outside the fixture root $_root)" >&2
    return 1
}

# bound EXE [ARGS...] -> PI_RUN_STATUS, stdout/stderr in $OUT/$ERR. stdin is
# /dev/null so an rpc-mode run sees EOF instead of the build's terminal.
OUT=
ERR=
PI_RUN_STATUS=0
pi_run() { # $1 = seconds, $2 = out, $3 = err, rest = executable + args
    seconds=$1
    OUT=$2
    ERR=$3
    shift 3
    PI_RUN_STATUS=0
    sh "$CONTRACT/run-report.sh" "$seconds" "$OUT" "$ERR" "$@" </dev/null || PI_RUN_STATUS=$?
}

# Path state via lstat: a present-but-unusable command (e.g. a 0644 entry point)
# is a contract violation, not an absence, and its tree must NOT be deleted.
bin_state=0
python3 "$CONTRACT/install-status.py" path-state "$pi_bin" || bin_state=$?
if [ "$bin_state" -eq 0 ]; then
    if python3 "$CONTRACT/install-status.py" code "$STATUS_DIR/pi" >/dev/null 2>&1; then
        echo "  pi: ABSENT ($(cat "$STATUS_DIR/pi")); raw developer build only"
        authorize_destructive "$WRAPPER" "/usr/local/bin/pi" || exit 1
        authorize_destructive "$SEED_HOOK" "/opt/agent-vm/seed.d/20-pi-claude-bridge" || exit 1
        authorize_destructive "$PI_PREFIX" "/opt/agent-vm/pi" || exit 1
        authorize_destructive "$EXTENSION_DIR" "/opt/agent-vm/pi-extensions" || exit 1
        authorize_destructive "$PACKAGES_PREFIX" "/opt/agent-vm/pi-packages" || exit 1
        rm -f "$WRAPPER" "$SEED_HOOK"
        rm -rf "$PI_PREFIX" "$EXTENSION_DIR" "$PACKAGES_PREFIX"
        mkdir -p "$STATUS_DIR"
        printf 'absent-pi\n' >"$STATUS_DIR/pi-claude-bridge"
        exit 0
    fi
    echo "  pi: MISSING with no absence record -- hard sanity failure" >&2
    exit 1
fi
if [ "$bin_state" -eq 2 ]; then
    echo "  pi: cannot stat $pi_bin (permission/loop) -- hard failure" >&2
    exit 1
fi

scratch=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf '$scratch'" EXIT INT TERM HUP

export HOME="$GATE_WORK_DIR" XDG_CONFIG_HOME="$GATE_WORK_DIR/.config" PI_TELEMETRY=0
mkdir -p "$HOME"

# The pin is the committed (or prepared) manifest; `npm ci` resolved nothing, so
# asserting the wrapper reports it is the whole version contract.
want=$(jq -r '.dependencies["@earendil-works/pi-coding-agent"]' "$PI_PREFIX/package.json")
if [ -n "$PI_VERSION" ] && [ "$PI_VERSION" != "$want" ]; then
    echo "  pi: layer asked for $PI_VERSION but the manifest pins $want" >&2
    exit 1
fi

pi_run 60 "$scratch/v.out" "$scratch/v.err" "$WRAPPER" --version
if [ "$PI_RUN_STATUS" -ne 0 ]; then
    echo "  pi: --version exited $PI_RUN_STATUS; refusing to accept the report" >&2
    sed -n '1,10p' "$scratch/v.err" >&2
    exit 1
fi
got=$(sed -n '1p' "$scratch/v.out")
if [ "$got" != "$want" ]; then
    echo "  pi: /usr/local/bin/pi --version reported '$got', lockfile pins '$want'" >&2
    exit 1
fi
# The pinned report is one version line; any further non-blank line is an
# ambiguous/unrecognized report. The `|| [ -n ]` handles a final line with no
# trailing newline, which a bare `while read` would silently drop.
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    [ "$lineno" -eq 1 ] && continue
    [ -z "$line" ] && continue
    echo "  pi: unexpected --version output on line $lineno: '$line'" >&2
    exit 1
done <"$scratch/v.out"
echo "  pi: $got (pinned)"

# The wrapper decides "subcommand vs prompt" from a hard-coded allowlist; this
# pins that allowlist against the installed Pi's own `--help`, so a version that
# adds/renames a subcommand fails the build instead of silently turning it into
# a prompt.
pi_run 60 "$scratch/h.out" "$scratch/h.err" "$WRAPPER" --help
if [ "$PI_RUN_STATUS" -ne 0 ]; then
    echo "  pi: --help exited $PI_RUN_STATUS; refusing to accept the output" >&2
    exit 1
fi
helped=$(sed -n 's/^  pi \([a-z][a-z-]*\) .*/\1/p' "$scratch/h.out" | sort -u | tr '\n' ' ')
declared=$(sed -n 's/^PI_SUBCOMMANDS="\(.*\)"$/\1/p' "$WRAPPER" | tr ' ' '\n' | sort -u | tr '\n' ' ')
if [ "$helped" != "$declared" ]; then
    echo "  pi: wrapper subcommands [$declared] != pi --help [$helped]" >&2
    exit 1
fi
echo "  pi: subcommand allowlist matches pi --help"

# The extension is image-owned and mandatory: a real invocation must load it and
# emit the credential warning. Both halves are checked -- it is present, and it
# actually runs -- with the process status checked before the output is scanned.
if [ ! -r "$EXTENSION_DIR/guest-credential-warning.js" ]; then
    echo "  pi: the mandatory extension is missing" >&2
    exit 1
fi
pi_run 60 "$scratch/w.out" "$scratch/w.err" "$WRAPPER" --mode rpc --no-session --no-approve
if [ "$PI_RUN_STATUS" -ne 0 ]; then
    echo "  pi: a real invocation exited $PI_RUN_STATUS; refusing to scan its output" >&2
    sed -n '1,10p' "$scratch/w.err" >&2
    exit 1
fi
if ! grep -q 'agent-vm: signing in here' "$scratch/w.out"; then
    echo "  pi: a real invocation does not load the mandatory extension" >&2
    exit 1
fi
echo "  pi: mandatory extension loads and warns"

# The image-owned pi-claude-bridge extension (ADR-0023). Its absence is legal in
# exactly one case -- a transport-soft build whose `npm ci` failed and recorded
# `absent-transport` -- and then the wrapper's own existence check skips it, so
# the image degrades to "no bridge" rather than "no pi". Anything else (missing
# with no record, unreadable, wrong version, not loading) is hard.
BRIDGE_MANIFEST="$PACKAGES_PREFIX/package.json"
BRIDGE_PKG="$PACKAGES_PREFIX/node_modules/pi-claude-bridge"
BRIDGE_SRC="$BRIDGE_PKG/src/index.ts"
bridge_shipped=
# Present-but-unreadable or present-but-broken is hard; only a genuinely
# absent tree with a valid absence record may degrade to "no bridge".
bridge_state=0
python3 "$CONTRACT/install-status.py" path-state "$BRIDGE_PKG" || bridge_state=$?
if [ "$bridge_state" -eq 0 ]; then
    if python3 "$CONTRACT/install-status.py" code "$STATUS_DIR/pi-claude-bridge" >/dev/null 2>&1; then
        echo "  pi: pi-claude-bridge ABSENT ($(cat "$STATUS_DIR/pi-claude-bridge")); the wrapper will skip it"
        # The extension tree is gone, so its seed hook must go too: left behind
        # it would write a claude-bridge.json for an extension this image does
        # not ship.
        authorize_destructive "$SEED_HOOK" "/opt/agent-vm/seed.d/20-pi-claude-bridge" || exit 1
        rm -f "$SEED_HOOK"
    else
        echo "  pi: pi-claude-bridge is missing with no absence record -- hard failure" >&2
        exit 1
    fi
elif [ "$bridge_state" -eq 2 ]; then
    echo "  pi: cannot stat $BRIDGE_PKG (permission/loop) -- hard failure" >&2
    exit 1
else
    bridge_shipped=1
    if [ ! -r "$BRIDGE_SRC" ]; then
        echo "  pi: pi-claude-bridge is present but its source is unreadable -- hard failure" >&2
        exit 1
    fi
    # A version bump that regenerated the lock but installed nothing would leave
    # package metadata at the new pin while the tree stayed stale; the installed
    # package.json is the tree's own version.
    bridge_want=$(jq -r '.dependencies["pi-claude-bridge"]' "$BRIDGE_MANIFEST")
    bridge_got=$(jq -r '.version' "$BRIDGE_PKG/package.json")
    if [ "$bridge_got" != "$bridge_want" ]; then
        echo "  pi: pi-claude-bridge installed $bridge_got but the manifest pins $bridge_want" >&2
        exit 1
    fi
    if [ -n "$BRIDGE_VERSION" ] && [ "$BRIDGE_VERSION" != "$bridge_want" ]; then
        echo "  pi: layer asked for bridge $BRIDGE_VERSION but the manifest pins $bridge_want" >&2
        exit 1
    fi

    # A --extension Pi cannot load is fatal before session startup, so a run that
    # exits 0 already proves every top-level import resolved (the Agent SDK, the
    # MCP SDK, cc-session-io, change-case, and the loader-aliased typebox / pi
    # peers). The probe adds the half that matters: the provider actually
    # REGISTERED, and the model catalog is non-empty (the bridge registers even
    # after printing "no models available from pi-ai's anthropic catalog",
    # src/index.ts:2045-2048). Keep the probe body in sync with the non-root copy
    # in script/test/pi-layer-runtime.sh.
    cat > "$GATE_WORK_DIR/probe.js" <<'PROBE'
export default function (pi) {
  pi.on("session_start", (_event, ctx) => {
    const p = ctx.modelRegistry.getProvider("claude-bridge");
    // `Provider.getModels()` is the typed surface (pi-ai's models.d.ts); the
    // raw `models` array the bridge passes to registerProvider may also be
    // present, so accept either and fail closed on neither.
    const n = p && typeof p.getModels === "function" ? p.getModels().length
            : p && Array.isArray(p.models) ? p.models.length : 0;
    ctx.ui.notify(p ? `AGENT-VM-BRIDGE-REGISTERED models=${n}` : "AGENT-VM-BRIDGE-MISSING",
                  "warning");
  });
}
PROBE
    pi_run 120 "$scratch/p.out" "$scratch/p.err" \
        "$WRAPPER" -e "$GATE_WORK_DIR/probe.js" --mode rpc --no-session --no-approve
    if [ "$PI_RUN_STATUS" -ne 0 ]; then
        echo "  pi: the bridge probe exited $PI_RUN_STATUS; refusing to scan its output" >&2
        sed -n '1,10p' "$scratch/p.err" >&2
        exit 1
    fi
    probe_out="$scratch/p.out"
    # The probe result may be a complete plain marker line OR a valid single-line
    # JSON notification whose `.message` is the marker (real Pi wraps the
    # `ctx.ui.notify` text). Require EXACTLY ONE unambiguous registration
    # result and a strictly positive canonical model count: a bare prefix match
    # used to accept `models=00` (a zero), a non-JSON line like
    # `models=12"garbage`, or a positive marker contradicted by a later
    # `AGENT-VM-BRIDGE-MISSING`.
    registered_count=""
    result_count=0
    malformed=0
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        msg="$line"
        registration_bearing=0
        case "$line" in
            *'AGENT-VM-BRIDGE-REGISTERED'* | *'AGENT-VM-BRIDGE-MISSING'*)
                registration_bearing=1 ;;
        esac
        case "$line" in
            '{'*)
                # A registration marker may arrive inside a single-line JSON
                # notification, so decode `.message`. The WHOLE line must parse:
                # `jq ... || true` used to erase a truncated/invalid notification,
                # silently discarding a `...BRIDGE-MISSING` marker it carried and
                # letting a lone positive pass. Fail closed instead.
                if msg="$(printf '%s\n' "$line" | jq -r \
                    'if type == "object" and (.message | type) == "string" then .message else empty end' \
                    2>/dev/null)"; then
                    :
                else
                    if [ "$registration_bearing" -eq 1 ]; then malformed=1; fi
                    continue
                fi ;;
        esac
        # A registration-bearing line -- plain or JSON -- must decode to exactly
        # the supported marker shape. A line that merely MENTIONS a marker (a
        # JSON notification whose `.message` is null/absent/non-marker, or a
        # plain line with surrounding text) is malformed, not silently ignored.
        # Unrelated RPC output (no marker) is accepted and ignored.
        if [ "$registration_bearing" -eq 1 ]; then
            case "$msg" in
                'AGENT-VM-BRIDGE-MISSING')
                    result_count=$((result_count + 1)) ;;
                'AGENT-VM-BRIDGE-REGISTERED models='*)
                    result_count=$((result_count + 1))
                    registered_count="${msg#AGENT-VM-BRIDGE-REGISTERED models=}" ;;
                *)
                    malformed=1 ;;
            esac
        fi
    done <"$probe_out"

    if [ "$malformed" -eq 1 ]; then
        echo "  pi: pi-claude-bridge emitted a malformed registration line" >&2
        exit 1
    fi
    if [ "$result_count" -ne 1 ]; then
        if [ "$result_count" -eq 0 ]; then
            echo "  pi: pi-claude-bridge did not register its provider" >&2
        else
            echo "  pi: pi-claude-bridge emitted $result_count conflicting registration results" >&2
        fi
        exit 1
    fi
    case "$registered_count" in
        '')
            echo "  pi: pi-claude-bridge did not register its provider" >&2; exit 1 ;;
        0 | 0*)
            echo "  pi: pi-claude-bridge registered but its model catalog is empty" >&2; exit 1 ;;
        *[!0-9]*)
            echo "  pi: pi-claude-bridge reported a non-numeric model count '$registered_count'" >&2; exit 1 ;;
    esac
    echo "  pi: pi-claude-bridge registered the claude-bridge provider"
fi

# Leavings from the gate runs above (Pi's own caches) are removed so they cannot
# be baked into the shipped image. The overridable work dir is authorised; the
# two `/tmp` literals are hardcoded and cannot be redirected.
authorize_destructive "$GATE_WORK_DIR" "/tmp/pi-gate" || exit 1
rm -rf "$GATE_WORK_DIR" /tmp/jiti /tmp/node-compile-cache

# T5: every shipped tree must be usable by an arbitrary uid. All-class bits
# ((mode & 0o444) == 0o444 for content, (mode & 0o111) == 0o111 for
# directories) prove access for any uid/gid; owner/group-only bits do not.
assert_world_readable() {
    [ -d "$1" ] || { echo "  pi: $1 is missing (C7)" >&2; exit 1; }
    if [ -n "$(find "$1" ! -perm -444 -print -quit)" ]; then
        echo "  pi: something under $1 is not world-readable (C7)" >&2; exit 1
    fi
    if [ -n "$(find "$1" -type d ! -perm -111 -print -quit)" ]; then
        echo "  pi: a directory under $1 is not world-searchable (C7)" >&2; exit 1
    fi
}
assert_world_readable "$PI_PREFIX"
assert_world_readable "$EXTENSION_DIR"
if [ -n "$bridge_shipped" ]; then
    assert_world_readable "$PACKAGES_PREFIX"
fi
for executable in "$WRAPPER" "$pi_bin"; do
    if [ ! -r "$executable" ] || [ ! -x "$executable" ]; then
        echo "  pi: $executable is not a+rx (C7)" >&2; exit 1
    fi
done
python3 "$CONTRACT/check-tool-access.py" "$WRAPPER" "$pi_bin"
# The wrapper loads required extension content on every invocation; that content
# must itself be readable and reachable by any uid. The `find` tree walks above
# do not follow symlinks (they inspect the link's own 0777 mode), so a required
# file symlinked into a 0700 directory would pass them. `--content` resolves
# symlinks, audits the lexical AND target ancestors, and requires all-class read
# (these files are data, not executed directly, so no execute bit is needed).
python3 "$CONTRACT/check-tool-access.py" --content \
    "$EXTENSION_DIR/guest-credential-warning.js"
if [ -n "$bridge_shipped" ]; then
    python3 "$CONTRACT/check-tool-access.py" --content "$BRIDGE_SRC"
fi

mkdir -p "$STATUS_DIR"
printf 'installed\n' >"$STATUS_DIR/pi"
if [ -n "$bridge_shipped" ]; then
    printf 'installed\n' >"$STATUS_DIR/pi-claude-bridge"
fi
echo "  pi: readable and executable by any uid"
