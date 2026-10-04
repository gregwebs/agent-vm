#!/bin/sh
# Prepare the Pi lock for an explicit version slot.
#
# Usage:
#   prepare-lock.sh PREFIX PI_VERSION [--refresh-lock]
#
# PI_VERSION is either an exact npm version or empty. Empty means "keep the
# committed pin"; a value equal to the committed pin is treated the same way. In
# that case this script only re-checks the local invariants and exits, leaving
# the committed manifest and lock byte-identical and making NO registry request.
#
# When the slot changes the Pi project is REGENERATED from its exact manifest
# (not incrementally: Pi's published npm-shrinkwrap.json moves the nested
# @earendil-works tree wholesale), then the five sibling hashes npm omits are
# refilled from the registry with exact-only queries, and the pin/integrity/
# sibling invariants are validated before the committed files are replaced.
#
# `--refresh-lock` is accepted for interface parity with the dsh recipe and the
# calling bump tool; Pi regeneration is already a fresh resolve, so it changes
# nothing here.
#
# PREFIX is the production installation prefix, or -- only in tests -- a
# canonical child of AGENT_VM_FIXTURE_ROOT. The prefix is resolved physically
# before anything is written.
set -eu

usage() {
    echo "usage: prepare-lock.sh PREFIX PI_VERSION [--refresh-lock]" >&2
}

if [ "$#" -lt 2 ]; then
    usage
    exit 2
fi

PREFIX=$1
PI_VERSION=$2
shift 2

while [ "$#" -gt 0 ]; do
    case "$1" in
        --refresh-lock) ;;
        *)
            usage
            exit 2
            ;;
    esac
    shift
done

PACKAGE=@earendil-works/pi-coding-agent
NESTED="node_modules/${PACKAGE}/node_modules/@earendil-works"
SIBLINGS="chord pi-agent-core pi-ai pi-telemetry pi-tui"

exact_version() {
    # Require one line first: `grep` is line-oriented, so a multi-line range
    # whose FIRST line (or any line) looks exact -- e.g. "0.87.0\n||\n>=..."
    # -- would otherwise be accepted and handed to npm as a range. Then require
    # the whole value to match the canonical semver grammar, which forbids
    # leading-zero numeric components AND leading-zero numeric prerelease ids.
    [ "$(printf '%s' "$1" | wc -l | tr -d ' ')" -eq 0 ] || return 1
    printf '%s' "$1" |
        grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
}

[ -n "$PI_VERSION" ] || PI_VERSION=
if [ -n "$PI_VERSION" ]; then
    exact_version "$PI_VERSION" || {
        echo "prepare-lock.sh: not an exact npm version: '$PI_VERSION'" >&2
        exit 1
    }
fi

[ -d "$PREFIX" ] || {
    echo "prepare-lock.sh: prefix is not a directory: $PREFIX" >&2
    exit 1
}
prefix_phys=$(cd "$PREFIX" && pwd -P)
production_prefix="/opt/agent-vm/pi"
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

committed=$(jq -r --arg p "$PACKAGE" '.dependencies[$p]' "$manifest")
effective=${PI_VERSION:-$committed}

# The same invariants install-pi.sh, upgrade-pi.sh and the `image_sources` cargo
# guards enforce: the pin is the only home, every entry carries integrity, the
# nested selector matches exactly the five known siblings, and they are all at
# the pin.
validate_lock() {
    jq -e --arg p "$PACKAGE" --arg v "$effective" --arg n "$NESTED" --arg s "$SIBLINGS" '
        .packages as $pk
        | ($pk[""].dependencies[$p] == $v)
        and ($pk["node_modules/" + $p].version == $v)
        and ([$pk | to_entries[] | select(.key != "" and (.value.integrity | not))] | length == 0)
        and ([$pk | keys[] | select(startswith($n + "/")) | ltrimstr($n + "/") | select(contains("/") | not)]
             | sort == ($s | split(" ") | sort))
        and ([$s | split(" ")[] | $pk[$n + "/" + .].version] | all(. == $v))
    ' "$1" >/dev/null
}

if [ "$effective" = "$committed" ]; then
    validate_lock "$lock" || {
        echo "prepare-lock.sh: the committed pi lock fails the pin/integrity/sibling checks" >&2
        exit 1
    }
    echo "prepare-lock.sh: pi ${effective} unchanged; committed lock reused"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM HUP

jq --arg p "$PACKAGE" --arg v "$effective" '.dependencies[$p] = $v' \
    "$manifest" >"$work/package.json"

echo "prepare-lock.sh: pi ${committed} -> ${effective}"
(cd "$work" && npm install --ignore-scripts --package-lock-only --no-audit --no-fund --loglevel=error)

# Refill every entry npm left without `integrity`. The only legitimate ones are
# the five shrinkwrap-only siblings nested directly under pi-coding-agent;
# anything else is a layout change install-pi.sh does not verify, so refuse it.
missing=$(jq -r '.packages | to_entries[] | select(.key != "" and (.value.integrity | not)) | .key' \
    "$work/package-lock.json")
for key in $missing; do
    name=${key#"${NESTED}/"}
    case " $SIBLINGS " in
        *" $name "*) ;;
        *)
            echo "prepare-lock.sh: lock entry $key has no integrity and is not one of the known shrinkwrap siblings ($SIBLINGS)" >&2
            echo "                 Pi's dependency layout changed -- review install-pi.sh." >&2
            exit 1
            ;;
    esac
    entry_version=$(jq -r --arg k "$key" '.packages[$k].version' "$work/package-lock.json")
    # The version comes from the freshly generated lock, not from the validated
    # tool slot, so re-validate it before it can reach a registry query: a
    # malformed upstream layout could otherwise make `npm view` resolve a
    # tag/range (`latest`) instead of the locked exact sibling.
    exact_version "$entry_version" || {
        echo "prepare-lock.sh: sibling $key has a non-canonical version '${entry_version}'" >&2
        exit 1
    }
    if [ "$entry_version" != "$effective" ]; then
        echo "prepare-lock.sh: sibling $key is ${entry_version}, expected the effective pin ${effective}" >&2
        exit 1
    fi
    integrity=$(npm view "@earendil-works/${name}@${entry_version}" dist.integrity)
    if [ -z "$integrity" ]; then
        echo "prepare-lock.sh: registry has no dist.integrity for @earendil-works/${name}@${entry_version}" >&2
        exit 1
    fi
    echo "    refilled @earendil-works/${name}@${entry_version}"
    jq --arg k "$key" --arg i "$integrity" '
        .packages[$k] |= (to_entries
            | map(if .key == "resolved" then ., {key: "integrity", value: $i} else . end)
            | from_entries)' \
        "$work/package-lock.json" >"$work/lock.tmp"
    mv "$work/lock.tmp" "$work/package-lock.json"
done

validate_lock "$work/package-lock.json" || {
    echo "prepare-lock.sh: the regenerated pi lock fails the pin/integrity/sibling checks" >&2
    exit 1
}

cp "$work/package.json" "$manifest"
cp "$work/package-lock.json" "$lock"
echo "prepare-lock.sh: wrote the prepared pi lock"
