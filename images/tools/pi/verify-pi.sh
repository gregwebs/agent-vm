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
# PI_TELEMETRY=0 keeps the gate hermetic: --version and --help must not read or
# write a config, and must not be the thing that creates /root/.pi in the image.
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
        rm -f /usr/local/bin/pi; rm -rf /opt/agent-vm/pi /opt/agent-vm/pi-extensions; exit 0
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

# The wrapper injects --approve by default (#96). A pin bump that renamed or
# dropped the approve flags would otherwise break every launch at runtime
# instead of at build time.
helptext=$(timeout 60 /usr/local/bin/pi --help)
printf '%s' "$helptext" | grep -q -- '--approve' || {
    echo "  pi: pi --help no longer documents --approve (the wrapper injects it)" >&2; exit 1; }
printf '%s' "$helptext" | grep -q -- '--no-approve' || {
    echo "  pi: pi --help no longer documents --no-approve" >&2; exit 1; }
echo "  pi: approve flags still documented by pi --help"

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

# Leavings from the gate runs above (Pi's own caches) are removed so they cannot
# be baked into the shipped image.
rm -rf /tmp/pi-gate /tmp/jiti /tmp/node-compile-cache

# C7: every image as a whole must be used by an arbitrary uid, so both trees
# exist, every file is world-readable, every directory is world-searchable, and
# both entry points are a+rx.
for c7dir in /opt/agent-vm/pi /opt/agent-vm/pi-extensions; do
    [ -d "$c7dir" ] || { echo "  pi: $c7dir is missing (C7)" >&2; exit 1; }
done
if [ -n "$(find /opt/agent-vm/pi /opt/agent-vm/pi-extensions ! -perm -o+r -print -quit)" ]; then
    echo "  pi: something under /opt/agent-vm is not world-readable (C7)" >&2; exit 1
fi
if [ -n "$(find /opt/agent-vm/pi /opt/agent-vm/pi-extensions -type d ! -perm -o+x -print -quit)" ]; then
    echo "  pi: a directory under /opt/agent-vm is not world-searchable (C7)" >&2; exit 1
fi
for executable in /usr/local/bin/pi /opt/agent-vm/pi/node_modules/.bin/pi; do
    if [ ! -r "$executable" ] || [ ! -x "$executable" ]; then
        echo "  pi: $executable is not a+rx (C7)" >&2; exit 1
    fi
done
echo "  pi: readable and executable by any uid"
