#!/usr/bin/env bash
# Offline ownership guard for #265: the installed launcher must not need image
# sources. No compiled production source or shipped package file may name the
# in-repo image recipes or the contributor-only image-source submodule.
#
# Out of scope on purpose: tests, docs, and contributor scripts may name image
# sources (script/test/standard-release-pin.sh reads them). Their references are
# not a runtime dependency, so they are excluded rather than allow-listed
# per file — which would let the exclusion silently widen as files are added.
set -euo pipefail

ROOT="$(cd "${1:-${BASH_SOURCE[0]%/*}/../..}" && pwd)"
[[ $# -le 1 ]] || {
    echo 'usage: no-image-source-dependency.sh [checkout]' >&2
    exit 2
}

fail() {
    echo "image-source dependency: $*" >&2
    exit 1
}

# The image-source tree, and the in-repo recipe paths #265 retired. A match in a
# scanned file means production or shipped code still reaches for image sources.
patterns=(
    'vendor/agent-vm-images'
    'images/build\.sh'
    'images/Dockerfile'
    'images/tools'
    'images/recipe-contract'
    'min-agent-vm-version'
)

# Compiled sources, build scripts, and the files a published npm package runs
# or ships as configuration. `npm-dist/**/*.md` is shipped prose, so it is
# deliberately excluded; only executables and manifests matter here.
targets=()
for directory in "$ROOT"/crates/*/src "$ROOT/npm-dist"; do
    [[ -d "$directory" ]] && targets+=("$directory")
done
for file in "$ROOT"/crates/*/build.rs; do
    [[ -f "$file" ]] && targets+=("$file")
done
[[ ${#targets[@]} -gt 0 ]] || fail "no production or shipped files found under $ROOT"

# Comments describe the image repo; they are not a dependency, so drop any
# match whose line, after the `file:line:` prefix, opens a comment. This is a
# line-based heuristic on purpose: a guard that flagged prose would be turned
# off the first time it fired, which is worse than the narrow gap it leaves.
code_only() {
    grep -vE ':[0-9]+:[[:space:]]*(//|/\*|\*|#)' || true
}

status=0
for pattern in "${patterns[@]}"; do
    if matches="$(grep -rnE --include='*.rs' --include='*.js' --include='*.json' \
        -- "$pattern" "${targets[@]}" 2>/dev/null | code_only)" && [[ -n "$matches" ]]; then
        printf '%s\n' "$matches" >&2
        status=1
    fi
done

[[ $status == 0 ]] || fail 'production or shipped code references image sources'
echo 'no image-source dependency in production or shipped files'
