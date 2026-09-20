#!/bin/sh
# Installs the pinned Pi into /opt/agent-vm/pi from the committed lockfile, then
# verifies the five tarballs npm does NOT integrity-check (see
# images/tools/pi/package-lock.json and images/tools/README.md).
#
# A download/registry failure is soft-failable under AGENT_INSTALL_SOFT_FAIL and
# leaves NO partial installation behind. An integrity mismatch is never
# soft-failable -- same rule as images/install-zellij.sh.
set -eu

PREFIX="${AGENT_VM_PI_PREFIX:-/opt/agent-vm/pi}"
NESTED="${PREFIX}/node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works"
soft_fail="${AGENT_INSTALL_SOFT_FAIL:-}"

# `npm ci` (not `npm install`): the lockfile is authoritative and the build
# fails if package.json and the lock disagree. `--ignore-scripts`: no upstream
# postinstall code runs during the image build (esbuild resolves its platform
# binary directly, verified).
if ! (cd "${PREFIX}" && npm ci --ignore-scripts --no-audit --no-fund); then
    message="==> pi: npm ci FAILED -- install in-VM with: npm ci in ${PREFIX}"
    rm -rf "${PREFIX}/node_modules"
    if [ -n "${soft_fail}" ]; then
        rm -rf "${PREFIX}"
        echo "${message} (soft-fail mode; image will ship without pi)"
        exit 0
    fi
    echo "${message}" >&2
    exit 1
fi

# The five @earendil-works siblings whose integrity npm ignores because Pi's
# published npm-shrinkwrap.json omits it. Read name/resolved/integrity out of
# the committed lock so there is exactly one home for the pin.
#
# The selector is anchored to pi-coding-agent's OWN node_modules so it matches
# only the shrinkwrap-only siblings. A looser substring match would also catch
# pi-ai's own nested deps (agent-base, https-proxy-agent), which DO carry
# integrity -- see the guard test in tool_layer.rs.
verified=0
jq -r '.packages | to_entries[]
       | select(.key | test("^node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/[^/]+$"))
       | [(.key | split("/") | last), .value.resolved, .value.integrity] | @tsv' \
    "${PREFIX}/package-lock.json" > /tmp/pi-siblings.tsv
while IFS="$(printf '\t')" read -r name resolved integrity; do
    [ -n "${integrity}" ] && [ "${integrity}" != "null" ] || {
        echo "==> pi: ${name} has no integrity in the committed lock -- refill it (images/tools/README.md)" >&2
        exit 1; }
    tarball="/tmp/pi-verify/${name}.tgz"
    mkdir -p /tmp/pi-verify/x
    if ! curl -fsSL --retry 5 --retry-all-errors --http1.1 "${resolved}" -o "${tarball}"; then
        # A download failure here is the same class as the npm one above.
        message="==> pi: could not fetch ${resolved} for integrity verification"
        if [ -n "${soft_fail}" ]; then
            rm -rf "${PREFIX}" /tmp/pi-verify
            echo "${message} (soft-fail mode; image will ship without pi)"
            exit 0
        fi
        echo "${message}" >&2
        exit 1
    fi
    actual="sha512-$(openssl dgst -sha512 -binary "${tarball}" | openssl base64 -A)"
    if [ "${actual}" != "${integrity}" ]; then
        echo "==> pi: INTEGRITY MISMATCH for ${name} (${resolved})" >&2
        echo "    committed ${integrity}" >&2
        echo "    fetched   ${actual}" >&2
        exit 1
    fi
    rm -rf /tmp/pi-verify/x && mkdir -p /tmp/pi-verify/x
    tar -xzf "${tarball}" -C /tmp/pi-verify/x
    # `-x node_modules`: npm nests a package's own transitive deps UNDER it
    # (pi-ai carries agent-base + https-proxy-agent here), so a plain `diff -r`
    # would report npm's extra sub-tree even though every byte of the verified
    # tarball matched. Excluding it compares exactly the bytes the tarball
    # claims to ship, which is the property being verified.
    if ! diff -r -x node_modules /tmp/pi-verify/x/package "${NESTED}/${name}" >/dev/null; then
        echo "==> pi: ${name} as installed differs from its verified tarball" >&2
        exit 1
    fi
    verified=$((verified + 1))
done < /tmp/pi-siblings.tsv

# A selector that matches nothing must not read as success: if a future pin
# changes the nested layout, this is what says so.
if [ "${verified}" -ne 5 ]; then
    echo "==> pi: verified ${verified} unhashed siblings, expected 5 -- the lock's nested layout moved" >&2
    exit 1
fi
echo "==> pi: ${verified}/5 shrinkwrap-only tarballs verified against the committed integrity"

rm -rf /tmp/pi-verify /tmp/pi-siblings.tsv "${HOME:-/root}/.npm"
chmod -R a+rX "${PREFIX}"
