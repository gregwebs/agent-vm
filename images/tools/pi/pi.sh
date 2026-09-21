#!/bin/sh
# agent-vm's stable `pi` wrapper (docs/adr/0012-stable-pi-image-customization-seam.md).
#
# The Pi installation under /opt/agent-vm/pi and the extensions under
# /opt/agent-vm/pi-extensions may both be replaced or extended by a later image
# layer. THIS FILE MAY NOT BE: it is the only thing that guarantees the guest
# credential warning is loaded for every normal Pi invocation, including a bare
# `pi` typed into `agent-vm shell`.
#
# It makes three decisions and then execs:
#   1. the Pi env defaults (PI_SKIP_VERSION_CHECK, PI_TELEMETRY);
#   2. subcommand dispatch (forwarded verbatim);
#   3. the mandatory extension plus the project-trust default.
# This amends ADR-0012's "exactly one decision" framing; see
# docs/adr/0021-project-scoped-pi-home-and-trust-defaults.md.
set -eu

# agent-vm owns the Pi binary: it is a root-owned image layer, `pi update self`
# cannot write to it, and the pin lives in images/tools/pi/package.json. The
# startup "a newer pi is available" fetch can therefore only ever be noise and a
# network call the guest did not ask for. Enforced, not defaulted: Pi treats any
# non-empty value as "skip" (dist/utils/version-check.js).
export PI_SKIP_VERSION_CHECK=1

# Install telemetry is off unless the user asked otherwise. `:=` assigns only
# when unset or empty, so an explicit PI_TELEMETRY already in the guest
# environment (from a tool's config `env`, or from the guest shell) reaches Pi
# untouched -- this is a default, not a policy. agent-vm does not forward the
# HOST's PI_TELEMETRY into the guest; see USAGE.md for the supported override.
: "${PI_TELEMETRY:=0}"
export PI_TELEMETRY

# Overridable only so the black-box test in script/test/pi-wrapper.sh can point
# at a fake. It is not a protection: the warning is advisory (the microVM is the
# boundary), and a guest can reach the entry point directly anyway.
PI_ENTRY="${AGENT_VM_PI_ENTRY:-/opt/agent-vm/pi/node_modules/.bin/pi}"

MANDATORY_EXTENSION=/opt/agent-vm/pi-extensions/guest-credential-warning.js

# Pi dispatches a subcommand only when it is the FIRST argument: `pi -e X list`
# treats `list` as a prompt and runs an agent turn, and `pi list -e X` rejects
# the option. So a subcommand invocation is forwarded verbatim. The image build
# asserts this list equals `pi --help`'s Commands block, so a pin bump that adds
# a subcommand fails the build instead of silently mis-dispatching.
PI_SUBCOMMANDS="auth config install list remove uninstall update"

if [ "$#" -gt 0 ]; then
    for subcommand in ${PI_SUBCOMMANDS}; do
        if [ "$1" = "${subcommand}" ]; then
            exec "${PI_ENTRY}" "$@"
        fi
    done
fi

# Pi already fails closed when an explicit --extension cannot be loaded (missing
# path, throw, or syntax error all exit 1 before session startup, verified in
# every mode), so there is deliberately no existence check here to duplicate --
# and diverge from -- that message.
# Pi's project-trust prompt has no good answer inside agent-vm: the microVM is
# the boundary, the checkout is the thing the guest was booted to work on, and a
# non-interactive guest cannot answer at all (Pi returns "not trusted" and
# silently drops the project's .pi/ extensions and skills). So the checkout's own
# resources are trusted by default -- the same reasoning that gives claude
# `--dangerously-skip-permissions`.
#
# NOT `args = ["--approve"]` in default-tools.toml: a prepended flag displaces
# argv[1] and would turn `pi list` into a prompt (see the subcommand note above
# and ADR-0012). The wrapper is also the only place that reaches a bare `pi`
# typed into `agent-vm shell`.
#
# Pi's own parse is last-wins, so the user's explicit flag beats this default
# whatever the scan does; the scan exists so the guest command line does not
# carry a contradictory pair. `--` ends option parsing for Pi, so it ends the
# scan too: after it, `--no-approve` is a message, not a flag.
#
# The scan deliberately does not model option VALUES (Pi has ~20 value-taking
# options and nothing here could keep a copy of that list honest against the
# pin). Two bounded consequences, both pinned by script/test/pi-wrapper.sh:
# `pi --name -a` drops the default without setting an override (fails toward
# LESS trust), and `pi --name -- --no-approve` still emits the pair (Pi's
# last-wins then resolves it in the user's favour). See ADR-0021.
approve=--approve
for argument in "$@"; do
    case "${argument}" in
        --) break ;;
        --approve|-a|--no-approve|-na) approve=""; break ;;
    esac
done

if [ -n "${approve}" ]; then
    exec "${PI_ENTRY}" --extension "${MANDATORY_EXTENSION}" "${approve}" "$@"
fi
exec "${PI_ENTRY}" --extension "${MANDATORY_EXTENSION}" "$@"
