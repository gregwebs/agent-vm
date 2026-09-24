#!/bin/sh
# Installs the pinned Pi extension packages into /opt/agent-vm/pi-packages from
# the committed lockfile. See images/tools/README.md and
# docs/adr/0023-image-owned-pi-extension-packages.md.
#
# No bespoke integrity re-verification here, deliberately: install-pi.sh needs
# one ONLY because npm ignores our lock for Pi's shrinkwrapped subtree. This
# tree has no shrinkwrap anywhere in its chain, so `npm ci` authenticates every
# tarball itself -- and tool_layer::tests::every_bridge_locked_package_carries_integrity
# fails the build if a regenerated lock ever loses that property.
#
# `--legacy-peer-deps` is not optional, on this `npm ci` and on the committed
# lock that generated it: without it npm tries to solve the bridge's
# `@earendil-works`/`typebox` peer ranges and installs a SECOND, version-skewed
# Pi under this tree (Pi's own loader aliases those imports, so they must not be
# installed). `--omit=optional` drops the Claude Agent SDK's platform packages,
# each of which carries a whole second Claude Code binary -- the guest-platform
# size is in docs/adr/0023-image-owned-pi-extension-packages.md. The image
# already ships one at /opt/agent/.local/bin/claude. `--ignore-scripts` matches
# install-pi.sh: no upstream lifecycle script runs during the build.
#
# Soft-fail policy mirrors install-pi.sh's one level down: under
# AGENT_INSTALL_SOFT_FAIL a download/registry failure deletes the whole tree and
# exits 0, and the WRAPPER's existence check then degrades the image to "no
# bridge" rather than "no pi". A half-installed extension is worse than an
# absent one, and an absent one must not make every `pi` invocation fatal.
set -eu
# The install root is fixed: nothing overrides it, and the wrapper loads the
# bridge from this exact path. Keep the two in lockstep rather than adding an
# override in front of an `rm -rf`.
PREFIX=/opt/agent-vm/pi-packages
if ! (cd "${PREFIX}" && npm ci --ignore-scripts --omit=optional --legacy-peer-deps \
                              --no-audit --no-fund); then
    message="==> pi-packages: npm ci FAILED"
    rm -rf "${PREFIX}"
    if [ -n "${AGENT_INSTALL_SOFT_FAIL:-}" ]; then
        echo "${message} (soft-fail mode; image will ship without pi-claude-bridge)"
        exit 0
    fi
    echo "${message}" >&2
    exit 1
fi
rm -rf "${HOME:-/root}/.npm"
chmod -R a+rX "${PREFIX}"
