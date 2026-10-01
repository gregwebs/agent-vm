#!/bin/sh
# Prepare the combined dsh + pnpm lock for the explicit version slots.
#
# Usage:
#   prepare-lock.sh PREFIX DSH_VERSION PNPM_VERSION [--refresh-lock]
#
# DSH_VERSION and PNPM_VERSION are each either an exact npm version or empty.
# Empty means "keep the committed pin"; a value equal to the committed pin is
# treated the same way. In that case this script only re-checks the local
# invariants and exits, leaving the committed manifest and lock byte-identical
# and making NO registry request.
#
# When a slot changes it stages an incremental copy (the committed lock is the
# starting point, so unrelated transitive pins do not move), updates only the
# changed `dependencies` entries, runs `npm install --package-lock-only`, and
# validates the result before replacing the committed files in PREFIX.
#
# Validation is the build-mode location freeze in the sibling
# check-lock-update.js (see its header). `--refresh-lock` is a DEVELOPER-ONLY
# escape hatch: it still runs the pin/integrity/layout invariants but skips the
# location freeze, permitting a reviewed transitive refresh. Ordinary and
# release builds never pass it.
#
# PREFIX is the production installation prefix, or -- only in tests -- a
# canonical child of AGENT_VM_FIXTURE_ROOT. The prefix is resolved physically
# before anything is written, so a symlink cannot redirect the staged replace.
set -eu

usage() {
    echo "usage: prepare-lock.sh PREFIX DSH_VERSION PNPM_VERSION [--refresh-lock]" >&2
}

if [ "$#" -lt 3 ]; then
    usage
    exit 2
fi

PREFIX=$1
DSH_VERSION=$2
PNPM_VERSION=$3
shift 3

refresh=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --refresh-lock) refresh=1 ;;
        *)
            usage
            exit 2
            ;;
    esac
    shift
done

self_dir=$(cd "$(dirname "$0")" && pwd)
CHECK="${AGENT_VM_CHECK_LOCK:-$self_dir/check-lock-update.js}"

exact_version() {
    # Require one line first: `grep` is line-oriented, so a multi-line range
    # whose FIRST line (or any line) looks exact -- e.g. "0.1.5-rc.1\n||\n>=..."
    # -- would otherwise be accepted and handed to npm as a range. Then require
    # the whole value to match the canonical semver grammar, which forbids
    # leading-zero numeric components AND leading-zero numeric prerelease ids.
    [ "$(printf '%s' "$1" | wc -l | tr -d ' ')" -eq 0 ] || return 1
    printf '%s' "$1" |
        grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
}

for slot in "$DSH_VERSION" "$PNPM_VERSION"; do
    [ -n "$slot" ] || continue
    exact_version "$slot" || {
        echo "prepare-lock.sh: not an exact npm version: '$slot'" >&2
        exit 1
    }
done

# Physical-prefix gate: production path, or a canonical child of the fixture
# root the test harness owns. Anything else -- especially a path that resolves
# outside the fixture root -- is refused before any write.
[ -d "$PREFIX" ] || {
    echo "prepare-lock.sh: prefix is not a directory: $PREFIX" >&2
    exit 1
}
prefix_phys=$(cd "$PREFIX" && pwd -P)
production_prefix="/opt/agent-vm/dsh"
if [ "$prefix_phys" != "$production_prefix" ]; then
    fixture_root="${AGENT_VM_FIXTURE_ROOT:-}"
    [ -n "$fixture_root" ] || {
        echo "prepare-lock.sh: refusing non-production prefix $PREFIX without AGENT_VM_FIXTURE_ROOT" >&2
        exit 1
    }
    [ -d "$fixture_root" ] || {
        echo "prepare-lock.sh: AGENT_VM_FIXTURE_ROOT is not a directory: $fixture_root" >&2
        exit 1
    }
    root_phys=$(cd "$fixture_root" && pwd -P)
    case "$prefix_phys" in
        "$root_phys"/*) ;;
        *)
            echo "prepare-lock.sh: prefix $prefix_phys is outside the fixture root $root_phys" >&2
            exit 1
            ;;
    esac
fi

manifest="$PREFIX/package.json"
lock="$PREFIX/package-lock.json"
[ -f "$manifest" ] || {
    echo "prepare-lock.sh: no committed manifest at $manifest" >&2
    exit 1
}
[ -f "$lock" ] || {
    echo "prepare-lock.sh: no committed lock at $lock" >&2
    exit 1
}

committed_dsh=$(jq -r '.dependencies["@deepseek-ai/dsh"]' "$manifest")
committed_pnpm=$(jq -r '.dependencies.pnpm' "$manifest")
effective_dsh=${DSH_VERSION:-$committed_dsh}
effective_pnpm=${PNPM_VERSION:-$committed_pnpm}

changed=0
[ "$effective_dsh" != "$committed_dsh" ] && changed=1
[ "$effective_pnpm" != "$committed_pnpm" ] && changed=1

# The pin/integrity/layout invariants the cargo guards and the old upgrade
# script both enforced, now in one place. Runs on whatever lock is handed to it.
validate_lock() {
    jq -e --arg d "$effective_dsh" --arg p "$effective_pnpm" '
        .packages as $pk
        | ($pk[""].dependencies["@deepseek-ai/dsh"] == $d)
        and ($pk[""].dependencies.pnpm == $p)
        and ($pk["node_modules/@deepseek-ai/dsh"].version == $d)
        and ($pk["node_modules/pnpm"].version == $p)
        and ([$pk | to_entries[] | select(.key != "" and (.value.integrity | not))] | length == 0)
    ' "$1" >/dev/null
}

# dsh-sandbox-local must sit where dsh's plugin loader resolves it: directly
# under the root node_modules, or directly under dsh's own node_modules.
check_sandbox() {
    sandbox=$(jq -r '.packages | keys[] | select(endswith("/@deepseek-ai/dsh-sandbox-local"))' "$1")
    allowed='^node_modules/(@deepseek-ai/dsh/node_modules/)?@deepseek-ai/dsh-sandbox-local$'
    if printf '%s\n' "$sandbox" | grep -q 'dsh-base/node_modules/'; then
        echo "prepare-lock.sh: dsh-sandbox-local is nested under dsh-base/node_modules," >&2
        echo "                 which dsh's plugin loader cannot resolve:" >&2
        printf '                   %s\n' "$sandbox" >&2
        exit 1
    fi
    if [ -z "$sandbox" ] || printf '%s\n' "$sandbox" | grep -qvE "$allowed"; then
        echo "prepare-lock.sh: dsh-sandbox-local is not installed where dsh resolves it:" >&2
        printf '                   %s\n' "${sandbox:-<absent>}" >&2
        exit 1
    fi
}

if [ "$changed" -eq 0 ]; then
    validate_lock "$lock" || {
        echo "prepare-lock.sh: the committed dsh lock fails the pin/integrity checks" >&2
        exit 1
    }
    check_sandbox "$lock"
    echo "prepare-lock.sh: dsh $effective_dsh / pnpm $effective_pnpm unchanged; committed lock reused"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM HUP

jq --arg d "$effective_dsh" --arg p "$effective_pnpm" \
    '.dependencies["@deepseek-ai/dsh"] = $d | .dependencies.pnpm = $p' \
    "$manifest" >"$work/package.json"
cp "$lock" "$work/package-lock.json"

echo "prepare-lock.sh: dsh $committed_dsh -> $effective_dsh, pnpm $committed_pnpm -> $effective_pnpm"
(cd "$work" && npm install --ignore-scripts --package-lock-only --no-audit --no-fund --loglevel=error)

if [ "$refresh" -eq 1 ]; then
    validate_lock "$work/package-lock.json" || {
        echo "prepare-lock.sh: the refreshed lock fails the pin/integrity checks" >&2
        exit 1
    }
    check_sandbox "$work/package-lock.json"
else
    node "$CHECK" "$manifest" "$lock" "$work/package.json" "$work/package-lock.json" \
        "$DSH_VERSION" "$PNPM_VERSION" || exit 1
fi

cp "$work/package.json" "$manifest"
cp "$work/package-lock.json" "$lock"
echo "prepare-lock.sh: wrote the prepared dsh lock"
