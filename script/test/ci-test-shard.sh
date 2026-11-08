#!/usr/bin/env bash
# Run one shard of the agent-vm test suite.
#
# `cargo test -p agent-vm` runs a package's test binaries one at a time, so the
# suite costs the *sum* of every binary's wall clock: 609s on a 4-vCPU runner,
# 243s of it in tests/config_launch_driven.rs alone. CI gives the suite several
# runners and this script deals the binaries between them.
#
# Usage: script/test/ci-test-shard.sh <shard-index> <shard-count>
#
# The plan comes from the filesystem, not a checked-in list: one
# `crates/agent-vm/tests/*.rs` file is one cargo test target (the crate declares
# no `[[test]]` sections), so a new test file joins a shard with no edit here.
# Targets are dealt greedily, heaviest first, to the lightest shard. The weight
# is the count of test functions, which is a proxy for cost, not the cost: a
# `config_launch_driven` case measured ~1.0s, a `config_mounts` case ~0.5s and a
# unit test in the binary ~0.04s. The binary's own unit tests are why the proxy
# is imperfect — 1907 of them cost 126s in total, so instead of being dealt like
# a 1907-case target they go to the shard with the fewest test functions.
set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
TESTS_DIR="crates/agent-vm/tests"

usage() {
    cat <<'EOF'
Usage: script/test/ci-test-shard.sh <shard-index> <shard-count>

Run one shard of the agent-vm test suite: the integration test files dealt to
this shard, plus — on the shard that owes them — the binary's own unit tests. A
failure in any of them stops the shard, as `cargo test` would.
EOF
}

if [[ $# -ne 2 ]]; then
    usage >&2
    exit 2
fi
shard="$1"
shards="$2"
if ! [[ "$shard" =~ ^[0-9]+$ && "$shards" =~ ^[1-9][0-9]*$ ]] || ((shard >= shards)); then
    echo "ci-test-shard: shard $shard is not an index below a shard count of $shards" >&2
    exit 2
fi

cd "$REPO_ROOT"

# One entry per integration target: "<test function count> <target name>". A
# file with no tests still belongs to a shard; it just weighs nothing.
weights=()
for file in "$TESTS_DIR"/*.rs; do
    [[ -f "$file" ]] || continue
    name="$(basename "$file" .rs)"
    count="$(grep -c -e '#\[test\]' -e '#\[tokio::test\]' "$file" || true)"
    weights+=("$count $name")
done
if ((${#weights[@]} == 0)); then
    echo "ci-test-shard: no test targets under $TESTS_DIR" >&2
    exit 1
fi

# Deal the targets, then name the shard that owes the binary's unit tests.
# Output is "T <shard> <weight> <name>" per target, in the same descending-weight
# order the targets were dealt, and a final "U <shard>".
deal="$(
    printf '%s\n' "${weights[@]}" |
        sort -k1,1nr -k2,2 |
        awk -v shards="$shards" '
            {
                weight = $1
                name = $2
                names[++n] = name
                weights[name] = weight
                lightest = 0
                for (s = 1; s < shards; s++) {
                    if (load[s] < load[lightest]) lightest = s
                }
                load[lightest] += weight
                owner[name] = lightest
            }
            END {
                units = 0
                for (s = 1; s < shards; s++) {
                    if (load[s] < load[units]) units = s
                }
                for (i = 1; i <= n; i++) {
                    print "T", owner[names[i]], weights[names[i]], names[i]
                }
                print "U", units
            }
        '
)"

targets=()
total=0
units_shard=""
while IFS= read -r line; do
    case "$line" in
        'T '*)
            read -r _ owner weight name <<<"$line"
            if ((owner == shard)); then
                targets+=("$name")
                total=$((total + weight))
            fi
            ;;
        'U '*) read -r _ units_shard <<<"$line" ;;
    esac
done <<<"$deal"

if ((${#targets[@]} == 0)) && ((units_shard != shard)); then
    echo "ci-test-shard: shard $shard owes nothing; use at most $((${#weights[@]} + 1)) shards" >&2
    exit 1
fi

echo "ci-test-shard: shard $shard/$shards, ${#targets[@]} integration target(s), $total test function(s)"
for target in "${targets[@]}"; do
    echo "  $target"
done

# The unit tests need no separate target name: `--bin` is the binary's own
# tests, exactly what `cargo test -p agent-vm` runs first. There are no doctests
# to run here — the crate is a bin, so `--doc` reports "no library targets
# found", and `cargo test -p agent-vm` runs none (the only Doc-tests target in
# the workspace belongs to msb-krun-compat-evidence, which `ci-contracts.sh`
# tests).
if ((units_shard == shard)); then
    echo "ci-test-shard: the binary's unit tests are shard $shard's"
    cargo test -p agent-vm --bin agent-vm
fi

if ((${#targets[@]} > 0)); then
    # One invocation so cargo builds only this shard's test binaries. Every
    # target is named with --test: a bare filter would also match the tests of
    # another shard, and `--test` is the only form that runs one binary.
    run_targets=()
    for target in "${targets[@]}"; do
        run_targets+=(--test "$target")
    done
    echo "ci-test-shard: cargo test -p agent-vm ${run_targets[*]}"
    cargo test -p agent-vm "${run_targets[@]}"
fi

echo "ci-test-shard: shard $shard/$shards passed"
