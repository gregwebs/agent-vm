#!/usr/bin/env bash
# Bump the pinned Pi version: rewrite package.json's pin, regenerate
# package-lock.json from scratch, and refill the integrity hashes npm leaves
# out. See images/tools/pi/README.md for usage and images/tools/README.md
# ("Bumping the `pi` pin") for why the refill is needed.
#
# Host-side only. The Dockerfile neither COPYs nor bind-mounts this file, so it
# never reaches the image. Run it as `bash upgrade-pi.sh`: like every file under
# images/tools/ it is committed 0644 (tool_layer.rs's
# embedded_layer_sources_are_committed_without_the_execute_bit).
#
# The lock is generated in a scratch directory and only copied over the
# committed one once every check below passes, so a failed run leaves the
# working tree untouched.

set -euo pipefail

PACKAGE=@earendil-works/pi-coding-agent
# npm inherits Pi's published npm-shrinkwrap.json, which omits `integrity` for
# exactly these siblings. install-pi.sh verifies them at build time against the
# hashes this script writes, and tool_layer.rs's
# the_build_verified_sibling_set_is_exactly_the_five_nested_earendil_packages
# pins the same set.
SIBLINGS="chord pi-agent-core pi-ai pi-telemetry pi-tui"
NESTED="node_modules/${PACKAGE}/node_modules/@earendil-works"

usage() {
    cat <<EOF
Usage: bash images/tools/pi/upgrade-pi.sh [VERSION]

Pin ${PACKAGE} to VERSION, an exact version or a dist-tag (default: the
registry's \`latest\` dist-tag), and regenerate package.json +
package-lock.json beside this script.
EOF
}

case "${1:-}" in
    -h | --help)
        usage
        exit 0
        ;;
esac
if [ $# -gt 1 ]; then
    usage >&2
    exit 2
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Shared prerequisite check and version resolution; see the helper's header for
# why the copy is not inlined. source=/dev/null: shellcheck cannot follow a path
# built from $DIR, and npm-pin.sh is linted on its own.
# shellcheck source=/dev/null
. "$DIR/../../../script/build/npm-pin.sh"

require_tools jq npm

current=$(jq -r --arg p "$PACKAGE" '.dependencies[$p]' "$DIR/package.json")

version_arg="${1:-}"
version=$(resolve_npm_version "$PACKAGE" "$version_arg")
if [ -z "$version_arg" ]; then
    echo "==> latest ${PACKAGE} is ${version}"
fi

echo "==> pinning ${PACKAGE}: ${current} -> ${version}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Exact pin, never a range: verify-pi.sh asserts `pi --version` equals it.
jq --arg p "$PACKAGE" --arg v "$version" '.dependencies[$p] = $v' \
    "$DIR/package.json" >"$work/package.json"

echo "==> regenerating package-lock.json"
(cd "$work" && npm install --ignore-scripts --package-lock-only --no-audit --no-fund --loglevel=error)

# Refill every entry npm left without `integrity`. Anything outside the known
# sibling set is a layout change install-pi.sh does not verify, so refuse it
# rather than paper over it.
missing=$(jq -r '.packages | to_entries[] | select(.key != "" and (.value.integrity | not)) | .key' \
    "$work/package-lock.json")
for key in $missing; do
    name=${key#"${NESTED}/"}
    case " $SIBLINGS " in
        *" $name "*) ;;
        *)
            echo "error: lock entry $key has no integrity and is not one of the known" >&2
            echo "       shrinkwrap siblings ($SIBLINGS)." >&2
            echo "       Pi's dependency layout changed; install-pi.sh and tool_layer.rs need review." >&2
            exit 1
            ;;
    esac
    entry_version=$(jq -r --arg k "$key" '.packages[$k].version' "$work/package-lock.json")
    integrity=$(npm view "@earendil-works/${name}@${entry_version}" dist.integrity)
    if [ -z "$integrity" ]; then
        echo "error: registry has no dist.integrity for @earendil-works/${name}@${entry_version}" >&2
        exit 1
    fi
    echo "    refilled @earendil-works/${name}@${entry_version}"
    # Insert right after `resolved`, where npm itself writes it.
    jq --arg k "$key" --arg i "$integrity" '
        .packages[$k] |= (to_entries
            | map(if .key == "resolved" then ., {key: "integrity", value: $i} else . end)
            | from_entries)' \
        "$work/package-lock.json" >"$work/lock.tmp"
    mv "$work/lock.tmp" "$work/package-lock.json"
done

# The same invariants `cargo test -p agent-vm tool_layer` enforces, checked here
# so a bad lock never lands in the working tree.
jq -e --arg p "$PACKAGE" --arg v "$version" --arg n "$NESTED" --arg s "$SIBLINGS" '
    .packages as $pk
    | ($pk[""].dependencies[$p] == $v)
    and ($pk["node_modules/" + $p].version == $v)
    and ([$pk | to_entries[] | select(.key != "" and (.value.integrity | not))] | length == 0)
    and ([$pk | keys[] | select(startswith($n + "/")) | ltrimstr($n + "/") | select(contains("/") | not)]
         | sort == ($s | split(" ") | sort))
    and ([$s | split(" ")[] | $pk[$n + "/" + .].version] | all(. == $v))
' "$work/package-lock.json" >/dev/null || {
    echo "error: the regenerated lock fails the pin/integrity/sibling checks; not writing it" >&2
    exit 1
}

cp "$work/package.json" "$DIR/package.json"
cp "$work/package-lock.json" "$DIR/package-lock.json"

cat <<EOF
==> pinned ${PACKAGE}@${version}
Next:
  cargo test -p agent-vm tool_layer   # lock guards + embedded snapshot
  then rebuild the tool layers -- see images/tools/pi/README.md
EOF
