#!/bin/sh
# Build-time verification gate for the pinned Pi layer, run from the layer's
# final `RUN --mount=type=bind` (see images/tools/pi/Dockerfile). Bind-mounted,
# never COPYed, so the script stays out of the shipped image and needs no
# execute bit.
#
# It is reached in BOTH outcomes of install-pi.sh: a hard install failure
# already aborted the build, and a soft failure exited 0 having deleted
# /opt/agent-vm/pi entirely -- so the `! -x` branch below is what turns a
# soft-failed install into "this image ships no pi", wrapper included.
#
# `timeout` bounds every Pi invocation so a future version that decides to
# prompt cannot hang the build. HOME/XDG point at a scratch dir and
# PI_TELEMETRY=0 keeps THIS GATE hermetic: --version and --help must not read or
# write a config, and must not be the thing that creates /root/.pi in the image.
# This is the gate's OWN environment, not the wrapper's behaviour -- the wrapper
# deliberately sets no telemetry default (see images/tools/pi/pi.sh).
#
# This body used to live inline in the Dockerfile's RUN. There the Dockerfile
# parser pre-expands a base image's `ENV` values, so the plan's `mkdir -p
# "$HOME"` silently created the base's /root instead of the scratch dir and the
# literal /tmp/pi-gate was hard-coded to dodge that. A bind-mounted script is
# never parsed by Docker, so the shell's own `$HOME` -- the value exported just
# below -- is what `mkdir` sees, and the workaround is gone.
set -eu

if [ ! -x /opt/agent-vm/pi/node_modules/.bin/pi ]; then
    # AGENT_INSTALL_SOFT_FAIL arrives as an environment variable: Docker exposes
    # a build ARG's value to the RUN, and the script inherits it.
    if [ -n "${AGENT_INSTALL_SOFT_FAIL:-}" ]; then
        echo "  pi: MISSING (soft-fail mode); removing the wrapper so nothing claims to be pi"
        rm -f /usr/local/bin/pi
        rm -rf /opt/agent-vm/pi /opt/agent-vm/pi-extensions /opt/agent-vm/pi-packages
        # The bridge tree goes above, so its seed hook must go with it: left
        # behind it would still write a claude-bridge.json on every launch,
        # pointing at an extension this image does not ship.
        rm -f /opt/agent-vm/seed.d/20-pi-claude-bridge
        exit 0
    fi
    echo "  pi: MISSING -- hard sanity failure" >&2; exit 1
fi

export HOME=/tmp/pi-gate XDG_CONFIG_HOME=/tmp/pi-gate/.config PI_TELEMETRY=0
mkdir -p "${HOME}"

# The pin is the committed package.json; `npm ci` resolved nothing, so asserting
# the wrapper reports it is the whole version contract.
want=$(jq -r '.dependencies["@earendil-works/pi-coding-agent"]' /opt/agent-vm/pi/package.json)
got=$(timeout 60 /usr/local/bin/pi --version)
if [ "$got" != "$want" ]; then
    echo "  pi: /usr/local/bin/pi --version reported '$got', lockfile pins '$want'" >&2; exit 1
fi
echo "  pi: $got (pinned)"

# The wrapper decides "subcommand vs prompt" from a hard-coded allowlist; this
# pins that allowlist against the installed Pi's own `--help`, so a version that
# adds/renames a subcommand fails the build instead of silently turning it into
# a prompt.
helped=$(timeout 60 /usr/local/bin/pi --help | sed -n 's/^  pi \([a-z][a-z-]*\) .*/\1/p' | sort -u | tr '\n' ' ')
declared=$(sed -n 's/^PI_SUBCOMMANDS="\(.*\)"$/\1/p' /usr/local/bin/pi | tr ' ' '\n' | sort -u | tr '\n' ' ')
if [ "$helped" != "$declared" ]; then
    echo "  pi: wrapper subcommands [$declared] != pi --help [$helped]" >&2; exit 1
fi
echo "  pi: subcommand allowlist matches pi --help"

# The extension is image-owned and mandatory: a real invocation must load it and
# emit the credential warning. Both halves are checked -- it is present, and it
# actually runs.
if [ ! -r /opt/agent-vm/pi-extensions/guest-credential-warning.js ]; then
    echo "  pi: the mandatory extension is missing" >&2; exit 1
fi
if ! timeout 60 /usr/local/bin/pi --mode rpc --no-session --no-approve </dev/null 2>/dev/null | grep -q 'agent-vm: signing in here'; then
    echo "  pi: a real invocation does not load the mandatory extension" >&2; exit 1
fi
echo "  pi: mandatory extension loads and warns"

# The image-owned pi-claude-bridge extension (ADR-0023). Its absence is legal in
# exactly one case -- an AGENT_INSTALL_SOFT_FAIL build whose `npm ci` failed and
# deleted the tree -- and in that case the wrapper's own existence check skips
# it, so the image degrades to "no bridge" rather than "no pi".
BRIDGE=/opt/agent-vm/pi-packages/node_modules/pi-claude-bridge/src/index.ts
if [ ! -r "$BRIDGE" ]; then
    if [ -n "${AGENT_INSTALL_SOFT_FAIL:-}" ]; then
        echo "  pi: pi-claude-bridge MISSING (soft-fail mode); the wrapper will skip it"
        bridge_shipped=
    else
        echo "  pi: pi-claude-bridge is missing -- hard sanity failure" >&2; exit 1
    fi
else
    bridge_shipped=1
    # A --extension Pi cannot load is fatal before session startup, so a run that
    # exits 0 already proves every top-level import resolved (the Agent SDK, the
    # MCP SDK, cc-session-io, change-case, and the loader-aliased typebox / pi
    # peers). The probe adds the half that matters: the provider actually
    # REGISTERED, and the model catalog is non-empty (the bridge registers even
    # after printing "no models available from pi-ai's anthropic catalog",
    # src/index.ts:2045-2048). Keep the probe body in sync with the non-root copy
    # in script/test/pi-layer-runtime.sh.
    cat > /tmp/pi-gate/probe.js <<'PROBE'
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
    out=$(timeout 120 /usr/local/bin/pi -e /tmp/pi-gate/probe.js \
              --mode rpc --no-session --no-approve </dev/null 2>/dev/null || true)
    case "$out" in
        *AGENT-VM-BRIDGE-REGISTERED\ models=0*)
            echo "  pi: pi-claude-bridge registered but its model catalog is empty" >&2; exit 1 ;;
        *AGENT-VM-BRIDGE-REGISTERED*)
            echo "  pi: pi-claude-bridge registered the claude-bridge provider" ;;
        *)  echo "  pi: pi-claude-bridge did not register its provider" >&2; exit 1 ;;
    esac
fi

# Leavings from the gate runs above (Pi's own caches) are removed so they cannot
# be baked into the shipped image.
rm -rf /tmp/pi-gate /tmp/jiti /tmp/node-compile-cache

# C7: every image as a whole must be used by an arbitrary uid, so each tree
# exists, every file is world-readable, every directory is world-searchable, and
# both entry points are a+rx.
assert_world_readable() {
    [ -d "$1" ] || { echo "  pi: $1 is missing (C7)" >&2; exit 1; }
    if [ -n "$(find "$1" ! -perm -o+r -print -quit)" ]; then
        echo "  pi: something under $1 is not world-readable (C7)" >&2; exit 1
    fi
    if [ -n "$(find "$1" -type d ! -perm -o+x -print -quit)" ]; then
        echo "  pi: a directory under $1 is not world-searchable (C7)" >&2; exit 1
    fi
}
assert_world_readable /opt/agent-vm/pi
assert_world_readable /opt/agent-vm/pi-extensions
# The bridge tree is asserted only when it actually shipped: a permitted
# soft-fail build deleted it, and a missing directory must not turn that
# permitted outcome into a hard failure. It is deliberately NOT in the cleanup
# list above -- that removes scratch, not shipped trees.
if [ -n "${bridge_shipped:-}" ]; then
    assert_world_readable /opt/agent-vm/pi-packages
fi
for executable in /usr/local/bin/pi /opt/agent-vm/pi/node_modules/.bin/pi; do
    if [ ! -r "$executable" ] || [ ! -x "$executable" ]; then
        echo "  pi: $executable is not a+rx (C7)" >&2; exit 1
    fi
done
echo "  pi: readable and executable by any uid"
