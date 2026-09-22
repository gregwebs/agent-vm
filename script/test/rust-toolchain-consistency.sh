#!/usr/bin/env bash
# Exercise script/check-rust-toolchain.sh's --root seam against synthetic
# copies of the real pin-consumer files, mutated one at a time.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
CHECKER="$REPO_ROOT/script/check-rust-toolchain.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/agent-vm-rust-toolchain-consistency.XXXXXX")"
# See script/test/build-workflow.sh's identical comment: macOS's TMPDIR ends
# in a trailing slash, so re-normalize via cd + pwd before comparing paths.
TEST_ROOT="$(cd "$TEST_ROOT" && pwd)"
trap 'rm -rf "$TEST_ROOT"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    case "$1" in
        *"$2"*) ;;
        *) fail "expected output to contain: $2"$'\n'"--- actual output ---"$'\n'"$1" ;;
    esac
}

# Copies the real pin-consumer files into a fresh scratch tree so each test
# case mutates its own private copy; the checker never touches the real repo.
make_tree() {
    local name="$1" dir
    dir="$TEST_ROOT/$name"
    mkdir -p "$dir/.github/workflows" "$dir/script/build" "$dir/examples/layers/rust-dev"
    cp "$REPO_ROOT/rust-toolchain.toml" "$dir/rust-toolchain.toml"
    cp "$REPO_ROOT/Cargo.toml" "$dir/Cargo.toml"
    cp "$REPO_ROOT/.github/workflows/ci.yml" "$dir/.github/workflows/ci.yml"
    cp "$REPO_ROOT/.github/workflows/verus.yml" "$dir/.github/workflows/verus.yml"
    cp "$REPO_ROOT/.github/workflows/release-npm.yml" "$dir/.github/workflows/release-npm.yml"
    cp "$REPO_ROOT/script/build/macos.sh" "$dir/script/build/macos.sh"
    cp "$REPO_ROOT/macos-build.md" "$dir/macos-build.md"
    cp "$REPO_ROOT/examples/layers/rust-dev/Dockerfile" \
        "$dir/examples/layers/rust-dev/Dockerfile"
    cp "$REPO_ROOT"/examples/layers/rust-dev/*.sh "$dir/examples/layers/rust-dev/"
    printf '%s\n' "$dir"
}

expect_pass() {
    local dir="$1" output
    output="$("$CHECKER" --root "$dir" 2>&1)" ||
        fail "checker unexpectedly failed for $dir"$'\n'"--- output ---"$'\n'"$output"
    printf '%s' "$output"
}

expect_fail() {
    local dir="$1" expected_status="$2" output status
    set +e
    output="$("$CHECKER" --root "$dir" 2>&1)"
    status=$?
    set -e
    [[ "$status" == "$expected_status" ]] ||
        fail "checker exited $status for $dir, expected $expected_status"$'\n'"--- output ---"$'\n'"$output"
    printf '%s' "$output"
}

# Replaces the first line containing $search with $replacement (awk's sub()
# treats $search as an ERE, which is fine here since our search strings are
# unambiguous plain-text anchors already proven not to collide elsewhere).
replace_first_occurrence() {
    local file="$1" search="$2" replacement="$3" tmp
    tmp="$file.tmp"
    awk -v search="$search" -v replacement="$replacement" '
        !done && index($0, search) { sub(search, replacement); done = 1 }
        { print }
    ' "$file" >"$tmp"
    mv "$tmp" "$file"
}

# Deletes the first line containing $search entirely.
delete_first_matching_line() {
    local file="$1" search="$2" tmp
    tmp="$file.tmp"
    awk -v search="$search" '
        !done && index($0, search) { done = 1; next }
        { print }
    ' "$file" >"$tmp"
    mv "$tmp" "$file"
}

# Read the real repo's current channel dynamically (not hardcoded) so this
# test suite keeps working across future pin bumps without edits.
current_channel="$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$REPO_ROOT/rust-toolchain.toml")"
[[ -n "$current_channel" ]] || fail "could not read the current channel from $REPO_ROOT/rust-toolchain.toml"
# Deliberately distinct from the real pin for every mismatch case below.
other_channel="9.99"

# Case 1: a verbatim copy of the real tree passes, and self-proves the
# current repo is consistent. It also embeds macos.sh's unrelated
# version-shaped tokens ("rustup 1.29", "OSStatus -26276") verbatim, so this
# doubles as the false-positive guard (case 8) made explicit below.
tree="$(make_tree case1-match)"
output="$(expect_pass "$tree")"
assert_contains "$output" "all consumers agree"

# Case 2: mismatched Cargo.toml rust-version.
tree="$(make_tree case2-cargo)"
sed -i.bak "s/^rust-version = \"$current_channel\"\$/rust-version = \"$other_channel\"/" "$tree/Cargo.toml"
rm -f "$tree/Cargo.toml.bak"
output="$(expect_fail "$tree" 1)"
assert_contains "$output" "Cargo.toml"
assert_contains "$output" "$current_channel"
assert_contains "$output" "$other_channel"

# Case 3: mismatched ci.yml toolchain input.
tree="$(make_tree case3-ci)"
sed -i.bak "s/toolchain: \"$current_channel\"/toolchain: \"$other_channel\"/" "$tree/.github/workflows/ci.yml"
rm -f "$tree/.github/workflows/ci.yml.bak"
output="$(expect_fail "$tree" 1)"
assert_contains "$output" "ci.yml"
assert_contains "$output" "$other_channel"

# Case 4: one of release-npm.yml's two occurrences drifts (proves
# per-occurrence checking, not just presence).
tree="$(make_tree case4-release-one)"
replace_first_occurrence "$tree/.github/workflows/release-npm.yml" \
    "rustup toolchain install $current_channel" "rustup toolchain install $other_channel"
output="$(expect_fail "$tree" 1)"
assert_contains "$output" "release-npm.yml"
assert_contains "$output" "$other_channel"

# Case 5: one of release-npm.yml's two occurrences is removed entirely
# (proves the count==2 guard, distinct from a version mismatch).
tree="$(make_tree case5-release-count)"
delete_first_matching_line "$tree/.github/workflows/release-npm.yml" \
    "rustup toolchain install $current_channel"
output="$(expect_fail "$tree" 1)"
assert_contains "$output" "release-npm.yml"
assert_contains "$output" "expected 2"

# Case 6: macos.sh's RUST_TOOLCHAIN copy drifts from the canonical channel.
# (Until cf8a418 this case mutated a hardcoded `minor < N` floor literal; that
# commit derived the floor from $RUST_TOOLCHAIN and deleted the checker's
# check_macos_floor_guard, leaving this case's sed matching nothing. Do not
# restore the old form -- there is no floor literal.)
tree="$(make_tree case6-macos-var)"
sed -i.bak "s/^RUST_TOOLCHAIN=$current_channel\$/RUST_TOOLCHAIN=$other_channel/" \
    "$tree/script/build/macos.sh"
rm -f "$tree/script/build/macos.sh.bak"
output="$(expect_fail "$tree" 1)"
assert_contains "$output" "script/build/macos.sh"
assert_contains "$output" "$other_channel"
assert_contains "$output" "fix: set RUST_TOOLCHAIN=$current_channel"

# Case 7: one of macos-build.md's copy-paste commands drifts (proves the
# docs copy is checked per-occurrence, not merely for presence).
tree="$(make_tree case7-docs)"
replace_first_occurrence "$tree/macos-build.md" \
    "rustup toolchain install $current_channel" "rustup toolchain install $other_channel"
output="$(expect_fail "$tree" 1)"
assert_contains "$output" "macos-build.md"
assert_contains "$output" "$other_channel"

# Case 8: false-positive guard, made explicit. macos.sh's unrelated
# version-shaped tokens ("rustup 1.29" recovery hint, "OSStatus -26276")
# must never trip the anchored patterns. macos-build.md independently
# mentions the same two unrelated tokens; guard both files. Case 1 already
# proves this via a verbatim copy; assert the fixture assumption holds and
# re-check the pass.
tree="$(make_tree case8-false-positive)"
grep -q "rustup 1.29" "$tree/script/build/macos.sh" ||
    fail "test fixture assumption violated: macos.sh no longer mentions rustup 1.29"
grep -q -- "-26276" "$tree/script/build/macos.sh" ||
    fail "test fixture assumption violated: macos.sh no longer mentions OSStatus -26276"
grep -q "rustup 1.29" "$tree/macos-build.md" ||
    fail "test fixture assumption violated: macos-build.md no longer mentions rustup 1.29"
grep -q -- "-26276" "$tree/macos-build.md" ||
    fail "test fixture assumption violated: macos-build.md no longer mentions OSStatus -26276"
output="$(expect_pass "$tree")"
assert_contains "$output" "all consumers agree"

# Case 9: an unreadable/blank canonical channel is a hard error, not a
# silent "all agree".
tree="$(make_tree case9-unreadable)"
: >"$tree/rust-toolchain.toml"
output="$(expect_fail "$tree" 2)"
assert_contains "$output" "rust-toolchain.toml"

# Case 10: --print mode returns just the channel and exits 0.
tree="$(make_tree case10-print)"
output="$("$CHECKER" --root "$tree" --print)"
[[ "$output" == "$current_channel" ]] || fail "expected --print to output $current_channel, got: $output"

# Case 11: an unrecognized flag is a usage error (exit 2), not a silent
# no-op or a crash -- distinct from case 9's "canonical unreadable" exit 2.
set +e
output="$("$CHECKER" --bogus-flag 2>&1)"
status=$?
set -e
[[ "$status" == 2 ]] || fail "expected exit 2 for an unrecognized flag, got $status"$'\n'"--- output ---"$'\n'"$output"
assert_contains "$output" "Usage:"

# Case 12: --root pointing at a nonexistent directory is a clear, explicit
# error (exit 2) rather than an uncontrolled `cd` failure leaking a raw
# shell error with no actionable context.
tree="$TEST_ROOT/case12-missing-root"
set +e
output="$("$CHECKER" --root "$tree" 2>&1)"
status=$?
set -e
[[ "$status" == 2 ]] || fail "expected exit 2 for a nonexistent --root, got $status"$'\n'"--- output ---"$'\n'"$output"
assert_contains "$output" "$tree"
assert_contains "$output" "not a directory"

# Case 13: mismatched verus.yml toolchain input (mirrors case 3 for the
# verification workflow's own copy of the pin).
tree="$(make_tree case13-verus)"
sed -i.bak "s/toolchain: \"$current_channel\"/toolchain: \"$other_channel\"/" \
    "$tree/.github/workflows/verus.yml"
rm -f "$tree/.github/workflows/verus.yml.bak"
output="$(expect_fail "$tree" 1)"
assert_contains "$output" "verus.yml"
assert_contains "$output" "$other_channel"

# Case 14: the rust-dev layer Dockerfile's RUST_TOOLCHAIN copy drifts.
tree="$(make_tree case14-layer-rust)"
sed -i.bak "s/^ARG RUST_TOOLCHAIN=$current_channel\$/ARG RUST_TOOLCHAIN=$other_channel/" \
    "$tree/examples/layers/rust-dev/Dockerfile"
rm -f "$tree/examples/layers/rust-dev/Dockerfile.bak"
output="$(expect_fail "$tree" 1)"
assert_contains "$output" "examples/layers/rust-dev/Dockerfile"
assert_contains "$output" "$other_channel"

# Case 15: the layer's Verus release drifts from verus.yml (the owner of the
# Verus pin), even though verus.yml itself is untouched.
tree="$(make_tree case15-layer-verus-release)"
sed -i.bak "s/^ARG VERUS_RELEASE=.*\$/ARG VERUS_RELEASE=9.9.9/" \
    "$tree/examples/layers/rust-dev/Dockerfile"
rm -f "$tree/examples/layers/rust-dev/Dockerfile.bak"
output="$(expect_fail "$tree" 1)"
assert_contains "$output" "VERUS_RELEASE is 9.9.9"
assert_contains "$output" "verus.yml"

# Case 16: the layer's Verus *digest* drifts while the release matches, so a
# release-only comparison would miss it.
tree="$(make_tree case16-layer-verus-sha)"
sed -i.bak "s/^ARG VERUS_SHA256=.*\$/ARG VERUS_SHA256=deadbeef/" \
    "$tree/examples/layers/rust-dev/Dockerfile"
rm -f "$tree/examples/layers/rust-dev/Dockerfile.bak"
output="$(expect_fail "$tree" 1)"
assert_contains "$output" "VERUS_SHA256 does not match"
assert_contains "$output" "verus.yml"

# Case 17: the Verus install script stops checking the digest. The ARG value
# still matches verus.yml, so only the usage check can catch this -- without it
# the verified "hard failure" property would be decorative.
tree="$(make_tree case17-layer-verus-sha-unused)"
delete_first_matching_line "$tree/examples/layers/rust-dev/install-verus.sh" 'sha256sum -c -'
output="$(expect_fail "$tree" 1)"
assert_contains "$output" "no longer verifies the Verus digest"

echo "rust-toolchain consistency seam tests passed"
