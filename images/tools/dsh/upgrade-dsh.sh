#!/usr/bin/env bash
# Bump the pinned dsh (and optionally pnpm) version: rewrite package.json's
# pin, update package-lock.json, and move the Dockerfile's LABEL fallback in
# lockstep. See images/tools/README.md ("The pinned lockfile layers") for why
# the lock matters here.
#
# Host-side only. The Dockerfile neither COPYs nor bind-mounts this file, so it
# never reaches the image. Run it as `bash upgrade-dsh.sh`: like every file under
# images/tools/ it is committed 0644 and run with `bash` (the recipes
# bind-mount their scripts rather than COPYing them with the execute bit).
#
# This is the DEVELOPER-only path. It resolves a dist-tag at the host seam, then
# calls the shared prepare-lock.sh with `--refresh-lock`, which keeps today's
# INCREMENTAL update (the committed lock is the starting point, so unrelated
# transitive pins do not move) and runs the pin/integrity/layout invariants but
# deliberately skips the build-mode location freeze: a reviewed transitive
# refresh is the point of a bump. Ordinary builds never pass that flag.
#
# Everything is staged in a scratch directory and only copied over the committed
# files once every check below passes, so a failed run leaves the working tree
# untouched.

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
# shellcheck source=/dev/null
. "$DIR/../../../script/build/dockerfile-label.sh"
# shellcheck source=/dev/null
. "$DIR/../../../script/build/transactional-publish.sh"

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

# Stage the manifest, lock and Dockerfile. prepare-lock.sh writes only the
# staged copy; a failure leaves the committed files untouched.
mkdir -p "$work/dsh"
cp "$DIR/package.json" "$work/dsh/package.json"
cp "$DIR/package-lock.json" "$work/dsh/package-lock.json"
cp "$DIR/Dockerfile" "$work/Dockerfile"

echo "==> updating package-lock.json"
AGENT_VM_FIXTURE_ROOT="$work" sh "$DIR/prepare-lock.sh" "$work/dsh" \
    "$version" "$pnpm_version" --refresh-lock

staged_dsh=$(jq -r --arg p "$PACKAGE" '.dependencies[$p]' "$work/dsh/package.json")
staged_pnpm=$(jq -r '.dependencies.pnpm' "$work/dsh/package.json")
[ "$staged_dsh" = "$version" ] || {
    echo "error: staged manifest pins ${PACKAGE} ${staged_dsh}, expected ${version}" >&2
    exit 1
}
[ "$staged_pnpm" = "$pnpm_version" ] || {
    echo "error: staged manifest pins pnpm ${staged_pnpm}, expected ${pnpm_version}" >&2
    exit 1
}

# Move the LABEL fallbacks in lockstep. set_version_label fails unless each
# label appears exactly once.
set_version_label "$work/Dockerfile" dsh AGENT_VERSION_DSH "$version"
set_version_label "$work/Dockerfile" pnpm AGENT_VERSION_PNPM "$pnpm_version"
grep -Fq "org.agent-vm.version.dsh=\"\${AGENT_VERSION_DSH:-${version}}\"" "$work/Dockerfile" || {
    echo "error: the staged Dockerfile dsh label does not mirror ${version}" >&2
    exit 1
}
grep -Fq "org.agent-vm.version.pnpm=\"\${AGENT_VERSION_PNPM:-${pnpm_version}}\"" "$work/Dockerfile" || {
    echo "error: the staged Dockerfile pnpm label does not mirror ${pnpm_version}" >&2
    exit 1
}

publish_transactional "$work/publish-backup" \
    "$work/dsh/package.json" "$DIR/package.json" \
    "$work/dsh/package-lock.json" "$DIR/package-lock.json" \
    "$work/Dockerfile" "$DIR/Dockerfile"

cat <<EOF
==> pinned ${PACKAGE}@${version} (pnpm ${pnpm_version}); Dockerfile LABELs updated
Next:
  cargo test --locked -p agent-vm --test image_sources   # lock guards + label mirrors
  The shipped-tool-recipes PR gate builds the dsh layer with a numeric-uid
  report/T5 audit, and verify-dsh.sh in that build is the real gate; you can
  also build it locally before opening a PR. npm's \`latest\` for dsh is a
  release candidate:
    docker buildx build --load --build-arg BASE_IMAGE=<a base image> images/tools/dsh
  then rebuild the tool layers -- see images/tools/README.md ("Upgrading a tool")
EOF
