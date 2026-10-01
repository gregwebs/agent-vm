#!/bin/sh
# Owning install hook for the opencode layer: validate the exact `v` slot, run
# the pinned vendored installer, and (only) soften a positively classified
# transport failure by removing the recipe's own partial artifacts and writing
# an absence record. Bind-mounted, never COPYed, so it stays out of the shipped
# image.
#
# The vendored installer at $AGENT_VM_VENDOR_DIR/install.sh is OpenCode's
# published installer with the exact-selection, classified-download,
# already-installed-skip and progress-machinery removal patches in
# images/tools/opencode/vendor/install.patch. Running it as a child (not through
# run-install's own interpreter) is what lets this hook inspect the classified
# 75 and decide.
set -eu

VENDOR="${AGENT_VM_VENDOR_DIR:-/opt/agent-vm/recipe-vendor}"
# Production prefix is the installer's $HOME. The seam lets the host black-box
# test point at a temp root; production always uses the default.
prefix="${AGENT_VM_OPENCODE_PREFIX:-/opt/agent}"
link="${AGENT_VM_OPENCODE_LINK:-/usr/local/bin/opencode}"
version="${AGENT_VM_VERSION_OPENCODE:?install-opencode.sh needs AGENT_VM_VERSION_OPENCODE}"
receipt="${AGENT_VM_TRANSPORT_RECEIPT:-}"
status_dir="${AGENT_VM_INSTALL_STATUS_DIR:-/opt/agent-vm/install-status}"

# The opencode contract accepts only the canonical `v` + semver spelling: no
# bare version, dist-tag, range or URL. The vendored installer receives the
# stripped numeric version.
case "$version" in
    v*) numeric="${version#v}" ;;
    *)
        echo "install-opencode.sh: expected v<version>, got '$version'" >&2
        exit 1
        ;;
esac
# Reject an embedded newline first: `grep` is line-oriented, so a multi-line
# range whose first line looks exact would otherwise pass, then require the
# whole value to match the canonical semver grammar.
if [ "$(printf '%s' "$numeric" | wc -l | tr -d ' ')" -ne 0 ] ||
    ! printf '%s' "$numeric" |
        grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'; then
    echo "install-opencode.sh: not an exact semver version: '$version'" >&2
    exit 1
fi
[ -r "$VENDOR/install.sh" ] || {
    echo "install-opencode.sh: vendored installer missing at $VENDOR/install.sh" >&2
    exit 1
}

HOME=$prefix
export HOME
VERSION="$numeric"
export VERSION

rc=0
# --no-modify-path is the installer's documented headless option: this layer
# already puts the binary on PATH via ENV and a /usr/local/bin link, so writing
# shell profiles during a build would only add build-local noise.
bash "$VENDOR/install.sh" --no-modify-path || rc=$?
if [ "$rc" -eq 0 ]; then
    chmod -R a+rX "$prefix/.opencode"
    mkdir -p "$(dirname "$link")"
    ln -sf "$prefix/.opencode/bin/opencode" "$link"
    exit 0
fi

# Only a classified transport failure with a fresh receipt may be softened, and
# only when AGENT_INSTALL_SOFT_FAIL is non-empty. Anything else stays hard.
if [ "$rc" -eq 75 ] && [ -n "$receipt" ] &&
    grep -Eq '^transport download [0-9]+$' "$receipt"; then
    if [ -n "${AGENT_INSTALL_SOFT_FAIL:-}" ]; then
        code=$(awk '{print $3}' "$receipt")
        # Recipe-owned partial artifacts only: the install dir and the link the
        # hook would have published.
        rm -rf "$prefix/.opencode"
        rm -f "$link"
        mkdir -p "$status_dir"
        printf 'absent-transport %s\n' "$code" >"$status_dir/opencode"
        echo "==> opencode: ABSENT (transport download $code; soft-fail mode)"
        exit 0
    fi
fi

echo "install-opencode.sh: opencode installer failed (exit $rc)" >&2
exit 1
