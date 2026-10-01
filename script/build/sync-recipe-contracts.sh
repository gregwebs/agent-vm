#!/usr/bin/env bash
# Distribute the canonical images/recipe-contract/ helpers into each standalone
# recipe build context, and check that the committed copies have not drifted.
#
# Every recipe builds FROM the tool-free base as its own Docker context, so a
# shared helper has to be *inside* that context to be bind-mountable. The copies
# are committed (an npm-installed launcher has no checkout to run this script),
# so this tool is the one place the bytes are written, and `--check` is what
# catches a hand-edited copy. See images/tools/README.md.
#
# Usage: script/build/sync-recipe-contracts.sh --write | --check
set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
CANON="$REPO_ROOT/images/recipe-contract"
TOOLS=(dsh pi codex opencode claude copilot)
FILES=(run-install.sh download.sh run-npm.sh run-report.sh check-tool-access.py install-status.py)

usage() {
    cat <<'EOF'
Usage: script/build/sync-recipe-contracts.sh --write | --check

  --write  Copy the canonical images/recipe-contract/ helpers into every
           recipe's committed contract/ directory (0644), removing extras.
  --check  Fail if a copy is missing, extra, or differs from the canonical file.
EOF
}

case "${1:-}" in
    --write | --check) mode=$1 ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
[ $# -eq 1 ] || {
    usage >&2
    exit 2
}

if [ ! -d "$CANON" ]; then
    echo "error: canonical contract directory is missing: $CANON" >&2
    exit 1
fi
for f in "${FILES[@]}"; do
    [ -f "$CANON/$f" ] || {
        echo "error: canonical contract file is missing: images/recipe-contract/$f" >&2
        exit 1
    }
done

failed=0

for tool in "${TOOLS[@]}"; do
    dest="$REPO_ROOT/images/tools/$tool/contract"
    if [ "$mode" = --write ]; then
        mkdir -p "$dest"
    elif [ ! -d "$dest" ]; then
        echo "drift: images/tools/$tool/contract/ is missing" >&2
        failed=1
        continue
    fi

    # Extras: any entry under contract/ -- hidden, dangling or not -- that is not
    # one of the canonical helpers is a copy nobody regenerates. The dot globs
    # are their own patterns because a bare `*` never matches a dot entry; a
    # dangling symlink is enumerated but `-e` follows it and reports absence, so
    # `-L` is what keeps it visible.
    for existing in "$dest"/* "$dest"/.[!.]* "$dest"/..?*; do
        [ -e "$existing" ] || [ -L "$existing" ] || continue
        base="$(basename "$existing")"
        keep=
        for f in "${FILES[@]}"; do
            [ "$base" = "$f" ] && keep=1
        done
        if [ -z "$keep" ]; then
            if [ "$mode" = --write ]; then
                rm -f "$existing"
                echo "removed extra images/tools/$tool/contract/$base"
            else
                echo "drift: images/tools/$tool/contract/$base is not a canonical helper" >&2
                failed=1
            fi
        fi
    done

    for f in "${FILES[@]}"; do
        if [ "$mode" = --write ]; then
            # Replace a pre-existing file or (dangling) symlink outright rather
            # than letting `install` write through it.
            if [ -L "$dest/$f" ] || [ -f "$dest/$f" ]; then
                rm -f "$dest/$f"
            fi
            install -m 0644 "$CANON/$f" "$dest/$f"
        elif [ ! -f "$dest/$f" ]; then
            echo "drift: images/tools/$tool/contract/$f is missing" >&2
            failed=1
        elif ! cmp -s "$CANON/$f" "$dest/$f"; then
            echo "drift: images/tools/$tool/contract/$f differs from images/recipe-contract/$f" >&2
            failed=1
        fi
    done
done

if [ "$mode" = --write ]; then
    echo "recipe-contract copies written; commit images/tools/*/contract/"
    exit 0
fi
if [ "$failed" -ne 0 ]; then
    echo "recipe-contract copies have drifted; run script/build/sync-recipe-contracts.sh --write" >&2
    exit 1
fi
echo "recipe-contract copies are in sync"
