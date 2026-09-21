#!/bin/sh
# agent-vm's stable `pi` wrapper (docs/adr/0012-stable-pi-image-customization-seam.md).
#
# The Pi installation under /opt/agent-vm/pi and the extensions under
# /opt/agent-vm/pi-extensions may both be replaced or extended by a later image
# layer. THIS FILE MAY NOT BE: it is the only thing that guarantees the guest
# credential warning is loaded for every normal Pi invocation, including a bare
# `pi` typed into `agent-vm shell`.
#
# It makes two decisions and then execs:
#   1. the Pi env enforcement (PI_SKIP_VERSION_CHECK);
#   2. subcommand dispatch (forwarded verbatim);
# plus the mandatory extension below.
#
# agent-vm intervenes in Pi's behaviour only where agent-vm introduced the
# condition (the parity principle; see ADR-0021). It deliberately injects NO
# project-trust default and NO telemetry default: --approve / --no-approve /
# --extension and PI_TELEMETRY are forwarded untouched, so a user gets Pi's own
# policy. Pi's project-trust prompt appears on its own terms, and the answer a
# user gives is remembered in the now-persistent ~/.pi/agent/trust.json. ADR-0012's
# wrapper counted its one decision as the mandatory extension; counting the
# extension the same way, this wrapper makes three.
set -eu

# agent-vm owns the Pi binary: it is a root-owned image layer, `pi update self`
# cannot write to it, and the pin lives in images/tools/pi/package.json. The
# startup "a newer pi is available" fetch can therefore only ever be noise and a
# network call the guest did not ask for. Enforced, not defaulted: Pi treats any
# non-empty value as "skip" (dist/utils/version-check.js).
export PI_SKIP_VERSION_CHECK=1

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
# The extension is agent-vm-introduced: agent-vm persists guest credentials in
# project-scoped state readable by any guest process, so agent-vm is the one
# that must warn about it. Nothing else is injected: no --approve default (Pi's
# project-trust prompt is Pi's own, and a user's answer now sticks because
# ~/.pi/agent/trust.json is persistent), and no PI_TELEMETRY default (Pi's
# telemetry policy is Pi's own).
exec "${PI_ENTRY}" --extension "${MANDATORY_EXTENSION}" "$@"
