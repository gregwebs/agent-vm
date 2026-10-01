#!/bin/sh
# Owning install hook for the claude layer: validate the exact version, run the
# pinned vendored installer, and (only) soften a positively classified transport
# failure by removing the recipe's own partial artifacts and writing an absence
# record. Bind-mounted, never COPYed, so it stays out of the shipped image.
#
# The vendored installer at $AGENT_VM_VENDOR_DIR/install.sh is Anthropic's
# published script with the exact-selection, classified-download and
# native-install patches in images/tools/claude/vendor/install.patch. Running it
# as a child (not through run-install's own interpreter) is what lets this hook
# inspect the classified 75 and decide.
set -eu

VENDOR="${AGENT_VM_VENDOR_DIR:-/opt/agent-vm/recipe-vendor}"
# Production prefix is the native installer's $HOME. The seam lets the host
# black-box test point at a temp root; production always uses the default.
prefix="${AGENT_VM_CLAUDE_PREFIX:-/opt/agent}"
version="${AGENT_VM_VERSION_CLAUDE:?install-claude.sh needs AGENT_VM_VERSION_CLAUDE}"
receipt="${AGENT_VM_TRANSPORT_RECEIPT:-}"
status_dir="${AGENT_VM_INSTALL_STATUS_DIR:-/opt/agent-vm/install-status}"

# --- destructive-cleanup authorization (review B6) --------------------------
# The softened-transport branch below deletes recipe-owned partial artifacts.
# The prefix seam is env-overridable, so before deleting anything require the
# target to be the exact production path or a canonical child of
# AGENT_VM_FIXTURE_ROOT. Resolving the leaf's parent physically also rejects an
# intermediate directory symlink -- e.g. an env-overridden prefix symlinked at
# another real tree -- that would otherwise make `rm -rf` delete outside the
# authorized tree.
FIXTURE_ROOT="${AGENT_VM_FIXTURE_ROOT:-}"
# Resolve a path to its physical location without following a final symlink; a
# non-existent tail is resolved against its deepest existing ancestor. This
# rejects an intermediate directory symlink escaping the authorized tree.
physical_parent() { # $1 path
    _p=$1
    _dir=$(dirname "$_p")
    _tail=$(basename "$_p")
    while [ ! -d "$_dir" ] && [ "$_dir" != "/" ] && [ "$_dir" != "." ]; do
        _tail="$(basename "$_dir")/$_tail"
        _dir=$(dirname "$_dir")
    done
    if [ -d "$_dir" ]; then
        printf '%s/%s' "$(cd "$_dir" && pwd -P)" "$_tail"
    else
        printf '%s' "$_p"
    fi
}
cleanup_authorized() { # $1 target path, $2 exact production target
    _full=$(physical_parent "$1")
    if [ "$_full" = "$2" ]; then
        return 0
    fi
    if [ -z "$FIXTURE_ROOT" ]; then
        echo "  claude: refusing to clean $_full (not the production path $2; AGENT_VM_FIXTURE_ROOT is unset)" >&2
        return 1
    fi
    if [ ! -d "$FIXTURE_ROOT" ]; then
        echo "  claude: AGENT_VM_FIXTURE_ROOT is not a directory: $FIXTURE_ROOT" >&2
        return 1
    fi
    _root=$(cd "$FIXTURE_ROOT" && pwd -P)
    case "$_full" in
        "$_root"/*) return 0 ;;
    esac
    echo "  claude: refusing to clean $_full (outside the fixture root $_root)" >&2
    return 1
}

case "$version" in
    *[!0-9A-Za-z.+-]*)
        echo "install-claude.sh: not an exact version: '$version'" >&2
        exit 1
        ;;
esac
if ! printf '%s' "$version" |
    grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$'; then
    echo "install-claude.sh: not an exact semver version: '$version'" >&2
    exit 1
fi
[ -r "$VENDOR/install.sh" ] || {
    echo "install-claude.sh: vendored installer missing at $VENDOR/install.sh" >&2
    exit 1
}

HOME=$prefix
export HOME
# A build must not send non-essential telemetry to api.anthropic.com: it is a
# phone-home with nothing to do with selecting the pinned version, and it keeps
# the restricted-egress audit's allowlist strictly to downloads.claude.ai. The
# native `install` subprocess honours this.
CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC

rc=0
bash "$VENDOR/install.sh" "$version" || rc=$?
if [ "$rc" -eq 0 ]; then
    exit 0
fi

# Only a classified transport failure with a fresh receipt may be softened, and
# only when AGENT_INSTALL_SOFT_FAIL is non-empty. Anything else stays hard.
if [ "$rc" -eq 75 ] && [ -n "$receipt" ] &&
    grep -Eq '^transport download [0-9]+$' "$receipt"; then
    if [ -n "${AGENT_INSTALL_SOFT_FAIL:-}" ]; then
        code=$(awk '{print $3}' "$receipt")
        # Recipe-owned partial artifacts only: the download cache and any
        # half-published command. Never a broader tree. Authorize BOTH targets
        # (exact production path, or a canonical fixture-root child) before
        # deleting either, so a mistaken seam cannot remove another real tree.
        cleanup_authorized "$prefix/.claude/downloads" "/opt/agent/.claude/downloads" || exit 1
        cleanup_authorized "$prefix/.local/bin/claude" "/opt/agent/.local/bin/claude" || exit 1
        rm -rf "$prefix/.claude/downloads"
        rm -f "$prefix/.local/bin/claude"
        mkdir -p "$status_dir"
        printf 'absent-transport %s\n' "$code" >"$status_dir/claude"
        echo "==> claude: ABSENT (transport download $code; soft-fail mode)"
        exit 0
    fi
fi

echo "install-claude.sh: claude installer failed (exit $rc)" >&2
exit 1
