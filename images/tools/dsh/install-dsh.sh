#!/bin/sh
# Owning install hook for the dsh layer. Bind-mounted, never COPYed, so it stays
# out of the shipped image.
#
# dsh installs from a COMMITTED lockfile, not a floating installer. When an
# explicit version slot is supplied (AGENT_VERSION_DSH / AGENT_VERSION_PNPM),
# prepare-lock.sh first rewrites only those `dependencies` entries and validates
# the result against the committed lock with the location freeze; when both
# slots are empty or equal it reuses the committed files untouched.
#
# dsh is never soft-failable: a partial node_modules is a broken agent, not a
# missing one (the same "no silently-cached hole" rule AGENT_INSTALL_SOFT_FAIL
# exists for, but dsh deliberately ignores it). Every failure here is hard.
set -eu

PREFIX="${AGENT_VM_DSH_PREFIX:-/opt/agent-vm/dsh}"
PREPARE_LOCK="${AGENT_VM_PREPARE_LOCK:-/tmp/prepare-lock.sh}"
DSH_VERSION="${AGENT_VM_VERSION_DSH:-}"
PNPM_VERSION="${AGENT_VM_VERSION_PNPM:-}"

[ -r "$PREPARE_LOCK" ] || {
    echo "install-dsh.sh: prepare-lock.sh not found at $PREPARE_LOCK" >&2
    exit 1
}

sh "$PREPARE_LOCK" "$PREFIX" "$DSH_VERSION" "$PNPM_VERSION"

# `npm ci` installs exactly the (possibly prepared) committed tree into the
# private prefix; dsh and pnpm are linked onto PATH by the Dockerfile below.
# `--ignore-scripts` mirrors the pi layer (no package here compiles on install).
#
# NODE_EXTRA_CA_CERTS points Node at the base's merged system bundle: Node
# otherwise trusts only its bundled roots, so the documented MITM escape of
# building the layer locally would fail at `npm ci` -- and there is no soft path
# back from that.
(cd "$PREFIX" &&
    NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt \
        npm ci --ignore-scripts --no-audit --no-fund)

chmod -R a+rX "$PREFIX"
rm -rf "${HOME:-/root}/.npm"
