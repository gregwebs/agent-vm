#!/usr/bin/env bash
# Bump the pinned dsh (and optionally pnpm) version: rewrite package.json's
# pin and update package-lock.json. See images/tools/README.md ("The pinned
# lockfile layers") for why the lock matters here.
#
# Host-side only. The Dockerfile neither COPYs nor bind-mounts this file, so it
# never reaches the image. Run it as `bash upgrade-dsh.sh`: like every file under
# images/tools/ it is committed 0644 (tool_layer.rs's
# embedded_layer_sources_are_committed_without_the_execute_bit).
#
# The lock is updated INCREMENTALLY (the committed lock is the starting point),
# not regenerated from scratch: dsh ships no shrinkwrap, so a fresh resolve
# would move hundreds of unrelated transitive pins. It runs in a scratch
# directory and is only copied over the committed files once every check below
# passes, so a failed run leaves the working tree untouched.

set -euo pipefail

PACKAGE=@deepseek-ai/dsh

usage() {
    cat <<EOF
Usage: bash images/tools/dsh/upgrade-dsh.sh [VERSION] [--pnpm PNPM_VERSION]

Pin ${PACKAGE} to VERSION, an exact version or a dist-tag (default: the
registry's \`latest\` dist-tag), and update package.json + package-lock.json
beside this script. pnpm keeps its current pin unless --pnpm is given
(\`--pnpm latest\` resolves the dist-tag).
EOF
}

version=
pnpm_version=
while [ $# -gt 0 ]; do
    case "$1" in
        -h | --help)
            usage
            exit 0
            ;;
        --pnpm)
            [ $# -ge 2 ] || {
                usage >&2
                exit 2
            }
            pnpm_version=$2
            shift 2
            ;;
        -*)
            usage >&2
            exit 2
            ;;
        *)
            [ -z "$version" ] || {
                usage >&2
                exit 2
            }
            version=$1
            shift
            ;;
    esac
done

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Shared prerequisite check and version resolution; see the helper's header for
# why the copy is not inlined. source=/dev/null: shellcheck cannot follow a path
# built from $DIR, and npm-pin.sh is linted on its own.
# shellcheck source=/dev/null
. "$DIR/../../../script/build/npm-pin.sh"

require_tools jq npm

current=$(jq -r --arg p "$PACKAGE" '.dependencies[$p]' "$DIR/package.json")
current_pnpm=$(jq -r '.dependencies.pnpm' "$DIR/package.json")
version=$(resolve_npm_version "$PACKAGE" "$version")
if [ -n "$pnpm_version" ]; then
    pnpm_version=$(resolve_npm_version pnpm "$pnpm_version")
else
    pnpm_version=$current_pnpm
fi

echo "==> pinning ${PACKAGE}: ${current} -> ${version}"
echo "==> pinning pnpm: ${current_pnpm} -> ${pnpm_version}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Exact pins, never ranges: verify-dsh.sh asserts `dsh --version` equals it.
jq --arg p "$PACKAGE" --arg v "$version" --arg pn "$pnpm_version" \
    '.dependencies[$p] = $v | .dependencies.pnpm = $pn' \
    "$DIR/package.json" >"$work/package.json"
cp "$DIR/package-lock.json" "$work/package-lock.json"

echo "==> updating package-lock.json"
(cd "$work" && npm install --ignore-scripts --package-lock-only --no-audit --no-fund --loglevel=error)

# The tool_layer.rs cargo guards (pins agree, every entry carries integrity),
# plus the layout the lock exists to freeze: dsh's plugin loader resolves
# dsh-sandbox-local from the app, so it must sit at the root or directly under
# dsh's own node_modules -- never nested under dsh-base/node_modules, where
# `dsh web` aborts at boot.
jq -e --arg p "$PACKAGE" --arg v "$version" --arg pn "$pnpm_version" '
    .packages as $pk
    | ($pk[""].dependencies[$p] == $v)
    and ($pk[""].dependencies.pnpm == $pn)
    and ($pk["node_modules/" + $p].version == $v)
    and ($pk["node_modules/pnpm"].version == $pn)
    and ([$pk | to_entries[] | select(.key != "" and (.value.integrity | not))] | length == 0)
' "$work/package-lock.json" >/dev/null || {
    echo "error: the updated lock fails the pin/integrity checks; not writing it" >&2
    exit 1
}
sandbox=$(jq -r '.packages | keys[] | select(endswith("/@deepseek-ai/dsh-sandbox-local"))' \
    "$work/package-lock.json")
# The one allowed location: directly under the root node_modules, or directly
# under dsh's own. A copy anywhere else (including under dsh-base, below) is a
# copy dsh's plugin loader never sees.
allowed='^node_modules/(@deepseek-ai/dsh/node_modules/)?@deepseek-ai/dsh-sandbox-local$'
if printf '%s\n' "$sandbox" | grep -q 'dsh-base/node_modules/'; then
    echo "error: dsh-sandbox-local is nested under dsh-base/node_modules, which dsh's" >&2
    echo "       plugin loader cannot resolve (see images/tools/README.md):" >&2
    printf '         %s\n' "$sandbox" >&2
    exit 1
fi
# EVERY copy must be in an allowed location, and at least one must exist: a lock
# with one good copy plus a stray one still ships the stray, so a per-line match
# on any line (`grep -q`) would accept it.
if [ -z "$sandbox" ] || printf '%s\n' "$sandbox" | grep -qvE "$allowed"; then
    echo "error: dsh-sandbox-local is not installed where dsh resolves it:" >&2
    printf '         %s\n' "${sandbox:-<absent>}" >&2
    exit 1
fi

cp "$work/package.json" "$DIR/package.json"
cp "$work/package-lock.json" "$DIR/package-lock.json"

cat <<EOF
==> pinned ${PACKAGE}@${version}
Next:
  cargo test -p agent-vm tool_layer   # lock guards + embedded snapshot
  Build the dsh layer locally BEFORE opening a PR: no PR workflow builds it
  (.github/workflows/build-image.yml runs only after merge, and pi's PR gate
  does not cover dsh). verify-dsh.sh in that build is the real gate, and npm's
  \`latest\` for dsh is a release candidate:
    docker buildx build --load --build-arg BASE_IMAGE=<a base image> images/tools/dsh
  then rebuild the tool layers -- see images/tools/README.md ("Upgrading a tool")
EOF
