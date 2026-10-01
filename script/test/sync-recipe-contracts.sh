#!/usr/bin/env bash
# Black-box tests for the contract-copy sync tool
# (script/build/sync-recipe-contracts.sh).
#
# No repo writes: a repo-shaped fixture tree holds the real script and copies of
# the canonical helpers, so the script's own REPO_ROOT derivation points at the
# fixture. The cases are the extras the old enumeration silently kept -- a
# hidden dot entry and a dangling symlink -- which `--check` must report and
# `--write` must remove, plus ordinary drift/missing detection.
set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
TOOLS=(dsh pi codex opencode claude copilot)
FILES=(run-install.sh download.sh run-npm.sh run-report.sh check-tool-access.py install-status.py)

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/sync-contracts.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# A fresh repo-shaped fixture with everything in sync (copied from the repo).
make_fixture() { # $1 name
    FIX="$TEST_ROOT/$1"
    mkdir -p "$FIX/script/build" "$FIX/images"
    cp "$REPO_ROOT/script/build/sync-recipe-contracts.sh" "$FIX/script/build/"
    cp -R "$REPO_ROOT/images/recipe-contract" "$FIX/images/recipe-contract"
    for tool in "${TOOLS[@]}"; do
        mkdir -p "$FIX/images/tools/$tool"
        cp -R "$REPO_ROOT/images/tools/$tool/contract" "$FIX/images/tools/$tool/contract"
    done
}

sync() { # $1 = --check | --write
    set +e
    RUN_OUTPUT="$(bash "$FIX/script/build/sync-recipe-contracts.sh" "$1" 2>&1)"
    RUN_STATUS=$?
    set -e
}

# --- a clean fixture starts in sync -----------------------------------------

make_fixture clean
sync --check
[[ $RUN_STATUS -eq 0 ]] || fail "a clean fixture must be in sync: $RUN_OUTPUT"

# --- A5: a hidden extra is detected and removed -----------------------------

make_fixture hidden-extra
touch "$FIX/images/tools/pi/contract/.extra"
sync --check
[[ $RUN_STATUS -ne 0 ]] || fail "a hidden extra must fail --check: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *"contract/.extra"* ]] || fail "the hidden extra must be named: $RUN_OUTPUT"
sync --write
[[ $RUN_STATUS -eq 0 ]] || fail "--write must succeed: $RUN_OUTPUT"
[[ ! -e "$FIX/images/tools/pi/contract/.extra" ]] || fail "--write must remove the hidden extra"

# --- A5: a dangling symlink extra is detected and removed -------------------

make_fixture dangling-extra
ln -s nowhere "$FIX/images/tools/pi/contract/dangling-extra"
sync --check
[[ $RUN_STATUS -ne 0 ]] || fail "a dangling extra must fail --check: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *"contract/dangling-extra"* ]] || fail "the dangling extra must be named: $RUN_OUTPUT"
sync --write
[[ $RUN_STATUS -eq 0 ]] || fail "--write must succeed: $RUN_OUTPUT"
[[ ! -e "$FIX/images/tools/pi/contract/dangling-extra" && ! -L "$FIX/images/tools/pi/contract/dangling-extra" ]] ||
    fail "--write must remove the dangling extra"

# --- ordinary visible extras, missing copies and drift still fail -----------

make_fixture visible-extra
touch "$FIX/images/tools/pi/contract/visible-extra"
sync --check
[[ $RUN_STATUS -ne 0 ]] || fail "a visible extra must fail --check: $RUN_OUTPUT"

make_fixture missing-copy
rm -f "$FIX/images/tools/claude/contract/download.sh"
sync --check
[[ $RUN_STATUS -ne 0 ]] || fail "a missing copy must fail --check: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *"contract/download.sh is missing"* ]] || fail "the missing copy must be named: $RUN_OUTPUT"

make_fixture drift
printf 'drift\n' >>"$FIX/images/tools/pi/contract/run-npm.sh"
sync --check
[[ $RUN_STATUS -ne 0 ]] || fail "byte drift must fail --check: $RUN_OUTPUT"

# --- a canonical helper replaced by a dangling symlink is repaired ----------

make_fixture dangling-copy
rm -f "$FIX/images/tools/pi/contract/download.sh"
ln -s nowhere "$FIX/images/tools/pi/contract/download.sh"
sync --check
[[ $RUN_STATUS -ne 0 ]] || fail "a dangling canonical copy must fail --check: $RUN_OUTPUT"
sync --write
[[ $RUN_STATUS -eq 0 ]] || fail "--write must succeed: $RUN_OUTPUT"
[[ -f "$FIX/images/tools/pi/contract/download.sh" && ! -L "$FIX/images/tools/pi/contract/download.sh" ]] ||
    fail "--write must replace the dangling canonical copy with a regular file"
cmp -s "$REPO_ROOT/images/recipe-contract/download.sh" "$FIX/images/tools/pi/contract/download.sh" ||
    fail "--write must restore the canonical bytes"

# --- every written copy is 0644 ---------------------------------------------

make_fixture modes
sync --write
for tool in "${TOOLS[@]}"; do
    for f in "${FILES[@]}"; do
        mode="$(python3 -c 'import os,sys;print("%o" % (os.stat(sys.argv[1]).st_mode & 0o7777))' \
            "$FIX/images/tools/$tool/contract/$f")"
        [[ "$mode" == "644" ]] || fail "images/tools/$tool/contract/$f must be 0644 (is $mode)"
    done
done

echo "sync-recipe-contracts black-box tests passed"
