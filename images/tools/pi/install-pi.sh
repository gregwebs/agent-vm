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

# The five @earendil-works siblings whose `integrity` Pi's published
# npm-shrinkwrap.json omits. npm ignores the committed lock's `integrity` for
# pi's ENTIRE nested subtree -- it installs that subtree from the shrinkwrap,
# not from our lock -- so these five are the ones npm fetches without checking
# any hash of its own; this script is the only thing between that fetch and the
# shipped bytes. Read name/resolved/integrity out of the committed lock so there
# is exactly one home for the pin.
#
# The selector is anchored to pi-coding-agent's OWN node_modules so it matches
# only the shrinkwrap-only siblings. A looser substring match would also catch
# pi-ai's own nested deps (agent-base, https-proxy-agent), which DO carry
# integrity -- see the guard test in tool_layer.rs.
verified=0
jq -r '.packages | to_entries[]
       | select(.key | test("^node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/[^/]+$"))
       | [.key, (.key | split("/") | last), .value.resolved, .value.integrity] | @tsv' \
    "${PREFIX}/package-lock.json" > /tmp/pi-siblings.tsv
while IFS="$(printf '\t')" read -r key name resolved integrity; do
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
    extracted=/tmp/pi-verify/x/package

    # Compare the verified extraction against what npm installed in FULL, with
    # NO basename exclusions. `-x node_modules` is a blind spot: it skips the
    # basename at EVERY depth, so a shadow `node_modules` planted in the
    # installed tree (e.g. pi-ai/dist/node_modules/<pkg>, which wins Node's
    # resolution from inside pi-ai/dist) would never be looked at. The one
    # legitimate difference is that npm also installs this sibling's own
    # transitive dependencies under its `node_modules`; those are exactly the
    # root-relative nested dependency directories the committed lock declares
    # for this sibling, and npm authenticated them (they carry `integrity` in
    # Pi's shrinkwrap). Fold each declared directory into the extraction from
    # the installed tree, then require a plain `diff -r` to be empty. Any other
    # extra file, directory or symlink -- a shadow `node_modules` at a path the
    # lock does not declare, a tampered shipped file, a missing one -- fails.
    jq -r --arg key "${key}" \
        '.packages | keys[] | select(startswith($key + "/")) | ltrimstr($key + "/")' \
        "${PREFIX}/package-lock.json" > /tmp/pi-nested.tsv
    while IFS= read -r rel; do
        [ -n "${rel}" ] || continue
        if [ ! -e "${NESTED}/${name}/${rel}" ] && [ ! -L "${NESTED}/${name}/${rel}" ]; then
            echo "==> pi: ${name}: the lock declares ${rel}, but npm did not install it" >&2
            exit 1
        fi
        # The verified tarball must not itself ship a path we are about to
        # treat as a lock-declared addition -- that would mask a difference in
        # bytes the hash already authenticated.
        if [ -e "${extracted}/${rel}" ] || [ -L "${extracted}/${rel}" ]; then
            echo "==> pi: ${name}: the verified tarball already contains ${rel}" >&2
            exit 1
        fi
        case "${rel}" in
            */*) mkdir -p "${extracted}/${rel%/*}" ;;
        esac
        cp -a "${NESTED}/${name}/${rel}" "${extracted}/${rel}"
    done < /tmp/pi-nested.tsv

    if ! diff -r "${extracted}" "${NESTED}/${name}" > /tmp/pi-verify/diff.out; then
        echo "==> pi: ${name} as installed differs from its verified tarball:" >&2
        sed -n '1,20p' /tmp/pi-verify/diff.out >&2
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

rm -rf /tmp/pi-verify /tmp/pi-siblings.tsv /tmp/pi-nested.tsv "${HOME:-/root}/.npm"
chmod -R a+rX "${PREFIX}"
