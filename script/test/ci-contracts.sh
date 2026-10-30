#!/usr/bin/env bash
# CI pre-build gate: runtime source provenance, harness contracts, and the shell
# guard rail for the scripts this workflow executes. This is the scriptified body
# of ci.yml's "Check runtime source provenance and harness contracts" step; the
# workflow now only invokes it. Runnable from any cwd -- every path is resolved
# against REPO_ROOT, derived from this script's own location.
set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# This script's own absolute path, plus its repo-relative form. The relative form
# is a member of both guard lists below, and the self-check asserts it stays
# there: a guard that silently stops covering a file is the bug issue #127 was.
self_path="$(cd "${BASH_SOURCE[0]%/*}" && pwd)/$(basename "${BASH_SOURCE[0]}")"
[[ "$self_path" == "$REPO_ROOT/"* ]] ||
    fail "this script ($self_path) is not under the repository root ($REPO_ROOT)"
self_relative="${self_path#"$REPO_ROOT"/}"

usage() {
    cat <<'EOF'
Usage: script/test/ci-contracts.sh [--guard-only]

Run the CI pre-build gate: runtime source provenance, harness contracts, and the
shell guard rail.

  --guard-only  Run only the shell guard rail (bash -n + shellcheck). Test seam
                for exercising the guard in a worktree without the
                vendor/microsandbox submodule, which the contract checks need.
EOF
}

guard_only=false
if (($#)); then
    [[ $# -eq 1 && "$1" == --guard-only ]] || {
        usage >&2
        exit 2
    }
    guard_only=true
fi

if [[ "$guard_only" == false ]]; then
    # --- Runtime source provenance and harness contracts ---------------------
    bash "$REPO_ROOT/script/test/runtime-provenance.sh"
    "$REPO_ROOT/script/check-runtime-provenance.sh"
    cargo test --locked --manifest-path "$REPO_ROOT/Cargo.toml" -p msb-krun-compat-evidence
    cargo clippy --locked --manifest-path "$REPO_ROOT/Cargo.toml" \
        -p msb-krun-compat-evidence --all-targets -- -D warnings
    "$REPO_ROOT/script/test/msb-krun-compat-contract.sh"
    bash "$REPO_ROOT/script/test/build-workflow.sh"
    bash "$REPO_ROOT/script/test/rust-toolchain-consistency.sh"
    bash "$REPO_ROOT/script/test/standard-release-pin.sh"
    bash "$REPO_ROOT/script/test/standard-release-pin-test.sh"
    bash "$REPO_ROOT/script/test/no-image-source-dependency.sh"
    bash "$REPO_ROOT/script/test/no-image-source-dependency-test.sh"
    bash "$REPO_ROOT/script/test/chrome-example-contract.sh"
    bash "$REPO_ROOT/script/test/chrome-example-contract-test.sh"
    # #400's native driver and guest probe: the boot-free controls prove the
    # exact-byte, resize and restoration oracles reject a broken stand-in, so a
    # later native run's evidence means something. Detached, like the other PTY
    # controls, so no ambient terminal can help a case pass.
    python3 "$REPO_ROOT/script/test/lib/detached-run.py" \
      python3 "$REPO_ROOT/script/test/lib/direct-terminal-contract.py"
    # #455's sweep contract is boot-free and cheap, so it goes first: the
    # released-image control below can hang on a host for a pre-existing reason
    # (its reentrant-sigterm teardown), and then a plain run of this script never
    # reaches it. CI runs the whole list either way.
    bash "$REPO_ROOT/script/test/e2e-image-cleanup-contract.sh"
    # #473: reclaiming the build cache is an operator step, so what CI guards is
    # that reporting prunes nothing, that `--prune` is one prune between two
    # reads, and that a failed observation never reads as an empty cache. Cheap
    # and boot-free, so it sits with #455's contract above.
    bash "$REPO_ROOT/script/test/reclaim-docker-cache-contract.sh"
    bash "$REPO_ROOT/script/test/e2e-release-contract.sh"
    bash "$REPO_ROOT/script/test/egress-default-deny-contract.sh"
    bash "$REPO_ROOT/script/test/config-dir-guard-contract.sh"
    bash "$REPO_ROOT/script/test/config-mounts-contract.sh"
    bash "$REPO_ROOT/script/test/build-provenance-contract.sh"
    bash "$REPO_ROOT/script/test/persisted-network-contract.sh"
    # Mutation anchors must still name lines that exist; otherwise the
    # mutation evidence is stale and only a hand-run would notice (#305 N9).
    python3 "$REPO_ROOT/script/test/egress-mutations.py" --check-anchors
    # #358 moved launch options before the tool verb; the manual migration sweep
    # found the last old-order caller (profiling/) only by reading, so pin it.
    python3 "$REPO_ROOT/script/test/launch-argv-order.py"

fi

# --- Shell guard rail --------------------------------------------------------
# Guard rail for the shell this workflow runs: every script the commands above
# execute, the scripts those invoke in turn, scripts other jobs in this workflow
# run, and the fixtures they use belong in both lists. Scripts only other
# workflows run are guarded there. The example image scripts (Chrome wrapper,
# Go/Rust installers) moved to agent-vm-images, whose
# script/test/example-layers.sh guards them.
syntax_check=(
    vendor/microsandbox/vendor/libkrunfw/build_in_docker.sh
    script/check-runtime-provenance.sh
    script/test/runtime-provenance.sh
    script/test/msb-krun-compat.sh
    script/test/msb-krun-compat-contract.sh
    script/build/macos.sh
    script/test/build-workflow.sh
    script/test/single-binary-contract.sh
    script/check-rust-toolchain.sh
    script/test/rust-toolchain-consistency.sh
    script/test/fixtures/fake-plutil.sh
    script/test/standard-release-pin.sh
    script/test/standard-release-pin-test.sh
    script/test/no-image-source-dependency.sh
    script/test/no-image-source-dependency-test.sh
    script/test/chrome-example-contract.sh
    script/test/chrome-example-contract-test.sh
    script/test/e2e-release-contract.sh
    script/test/e2e-image-cleanup-contract.sh
    script/test/reclaim-docker-cache.sh
    script/test/reclaim-docker-cache-contract.sh
    script/test/persisted-network-live.sh
    script/test/persisted-network-contract.sh
    script/test/build-provenance-contract.sh
    script/test/lib/persisted-network.sh
    script/test/fixtures/persisted-network/guest-pn4-write.sh
    script/test/fixtures/persisted-network/guest-pn-probe.sh
    script/test/config-dir-guard-live.sh
    script/test/config-dir-guard-contract.sh
    script/test/config-mounts-live.sh
    script/test/config-mounts-contract.sh
    script/test/fixtures/config-mounts/guest-cm-probe.sh
    script/test/fixtures/config-dir-guard/guest-n1a.sh
    script/test/fixtures/config-dir-guard/guest-n1b.sh
    script/test/fixtures/config-dir-guard/guest-n3.sh
    script/test/fixtures/config-dir-guard/guest-n4.sh
    script/test/fixtures/config-dir-guard/guest-n5.sh
    script/test/fixtures/config-dir-guard/guest-n7.sh
    script/test/lib/config-dir-guard.sh
    script/test/egress-default-deny.sh
    script/test/egress-default-deny-contract.sh
    script/test/fixtures/egress-probe.sh
    script/test/fixtures/direct-terminal/guest-probe.sh
    script/test/e2e-released-image.sh
    script/test/e2e.sh
    script/test/lib/released-image-checks.sh
    script/test/lib/e2e-image-cleanup.sh
    "$self_relative"
)

# The lint list below runs every guarded script plus the nested vendored script
# that `build_in_docker.sh` invokes; it is deliberately a superset-by-one of
# syntax_check rather than a divergence from the criterion above.
shellcheck_files=(
    vendor/microsandbox/vendor/libkrunfw/build_in_docker.sh
    vendor/microsandbox/vendor/libkrunfw/scripts/test-build-in-docker.sh
    script/check-runtime-provenance.sh
    script/test/runtime-provenance.sh
    script/test/msb-krun-compat.sh
    script/test/msb-krun-compat-contract.sh
    script/build/macos.sh
    script/test/build-workflow.sh
    script/test/single-binary-contract.sh
    script/check-rust-toolchain.sh
    script/test/rust-toolchain-consistency.sh
    script/test/fixtures/fake-plutil.sh
    script/test/standard-release-pin.sh
    script/test/standard-release-pin-test.sh
    script/test/no-image-source-dependency.sh
    script/test/no-image-source-dependency-test.sh
    script/test/chrome-example-contract.sh
    script/test/chrome-example-contract-test.sh
    script/test/e2e-release-contract.sh
    script/test/e2e-image-cleanup-contract.sh
    script/test/reclaim-docker-cache.sh
    script/test/reclaim-docker-cache-contract.sh
    script/test/persisted-network-live.sh
    script/test/persisted-network-contract.sh
    script/test/build-provenance-contract.sh
    script/test/lib/persisted-network.sh
    script/test/fixtures/persisted-network/guest-pn4-write.sh
    script/test/fixtures/persisted-network/guest-pn-probe.sh
    script/test/config-dir-guard-live.sh
    script/test/config-dir-guard-contract.sh
    script/test/config-mounts-live.sh
    script/test/config-mounts-contract.sh
    script/test/fixtures/config-mounts/guest-cm-probe.sh
    script/test/fixtures/config-dir-guard/guest-n1a.sh
    script/test/fixtures/config-dir-guard/guest-n1b.sh
    script/test/fixtures/config-dir-guard/guest-n3.sh
    script/test/fixtures/config-dir-guard/guest-n4.sh
    script/test/fixtures/config-dir-guard/guest-n5.sh
    script/test/fixtures/config-dir-guard/guest-n7.sh
    script/test/lib/config-dir-guard.sh
    script/test/egress-default-deny.sh
    script/test/egress-default-deny-contract.sh
    script/test/fixtures/egress-probe.sh
    script/test/fixtures/direct-terminal/guest-probe.sh
    script/test/e2e-released-image.sh
    script/test/e2e.sh
    script/test/lib/released-image-checks.sh
    script/test/lib/e2e-image-cleanup.sh
    "$self_relative"
)

# The guard guards itself (issue #127): both lists claim to describe the shell
# this workflow runs, so dropping this script from one fails loudly here.
assert_listed() {
    local list_name="$1" needle="$2" entry
    shift 2
    for entry in "$@"; do
        [[ "$entry" == "$needle" ]] && return 0
    done
    fail "script ($needle) is missing from the $list_name guard list"
}
assert_listed 'bash -n' "$self_relative" "${syntax_check[@]}"
assert_listed 'shellcheck' "$self_relative" "${shellcheck_files[@]}"

assert_listed 'bash -n' 'script/test/single-binary-contract.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/single-binary-contract.sh' "${shellcheck_files[@]}"
assert_listed 'bash -n' 'script/test/persisted-network-live.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/persisted-network-live.sh' "${shellcheck_files[@]}"
assert_listed 'bash -n' 'script/test/persisted-network-contract.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/persisted-network-contract.sh' "${shellcheck_files[@]}"
assert_listed 'bash -n' 'script/test/build-provenance-contract.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/build-provenance-contract.sh' "${shellcheck_files[@]}"
assert_listed 'bash -n' 'script/test/lib/persisted-network.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/lib/persisted-network.sh' "${shellcheck_files[@]}"
assert_listed 'bash -n' 'script/test/fixtures/persisted-network/guest-pn4-write.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/fixtures/persisted-network/guest-pn4-write.sh' "${shellcheck_files[@]}"
assert_listed 'bash -n' 'script/test/fixtures/direct-terminal/guest-probe.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/fixtures/direct-terminal/guest-probe.sh' "${shellcheck_files[@]}"
assert_listed 'bash -n' 'script/test/fixtures/persisted-network/guest-pn-probe.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/fixtures/persisted-network/guest-pn-probe.sh' "${shellcheck_files[@]}"

# These explicit checks are independent of the join's dispatch list: deleting
# a membership must fail even when only the guard seam is selected.
assert_listed 'bash -n' 'script/test/egress-default-deny.sh' "${syntax_check[@]}"
assert_listed 'bash -n' 'script/test/egress-default-deny-contract.sh' "${syntax_check[@]}"
assert_listed 'bash -n' 'script/test/fixtures/egress-probe.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/egress-default-deny.sh' "${shellcheck_files[@]}"
assert_listed 'shellcheck' 'script/test/egress-default-deny-contract.sh' "${shellcheck_files[@]}"
assert_listed 'shellcheck' 'script/test/fixtures/egress-probe.sh' "${shellcheck_files[@]}"
assert_listed 'bash -n' 'script/test/config-dir-guard-live.sh' "${syntax_check[@]}"
assert_listed 'bash -n' 'script/test/config-dir-guard-contract.sh' "${syntax_check[@]}"
assert_listed 'bash -n' 'script/test/lib/config-dir-guard.sh' "${syntax_check[@]}"
assert_listed 'bash -n' 'script/test/fixtures/config-dir-guard/guest-n1a.sh' "${syntax_check[@]}"
assert_listed 'bash -n' 'script/test/fixtures/config-dir-guard/guest-n1b.sh' "${syntax_check[@]}"
assert_listed 'bash -n' 'script/test/fixtures/config-dir-guard/guest-n3.sh' "${syntax_check[@]}"
assert_listed 'bash -n' 'script/test/fixtures/config-dir-guard/guest-n4.sh' "${syntax_check[@]}"
assert_listed 'bash -n' 'script/test/fixtures/config-dir-guard/guest-n5.sh' "${syntax_check[@]}"
assert_listed 'bash -n' 'script/test/fixtures/config-dir-guard/guest-n7.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/config-dir-guard-live.sh' "${shellcheck_files[@]}"
assert_listed 'shellcheck' 'script/test/config-dir-guard-contract.sh' "${shellcheck_files[@]}"
assert_listed 'shellcheck' 'script/test/lib/config-dir-guard.sh' "${shellcheck_files[@]}"
assert_listed 'shellcheck' 'script/test/fixtures/config-dir-guard/guest-n1a.sh' "${shellcheck_files[@]}"
assert_listed 'shellcheck' 'script/test/fixtures/config-dir-guard/guest-n1b.sh' "${shellcheck_files[@]}"
assert_listed 'shellcheck' 'script/test/fixtures/config-dir-guard/guest-n3.sh' "${shellcheck_files[@]}"
assert_listed 'shellcheck' 'script/test/fixtures/config-dir-guard/guest-n4.sh' "${shellcheck_files[@]}"
assert_listed 'shellcheck' 'script/test/fixtures/config-dir-guard/guest-n5.sh' "${shellcheck_files[@]}"
assert_listed 'shellcheck' 'script/test/fixtures/config-dir-guard/guest-n7.sh' "${shellcheck_files[@]}"
assert_listed 'bash -n' 'script/test/config-mounts-live.sh' "${syntax_check[@]}"
assert_listed 'bash -n' 'script/test/config-mounts-contract.sh' "${syntax_check[@]}"
assert_listed 'bash -n' 'script/test/fixtures/config-mounts/guest-cm-probe.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/config-mounts-live.sh' "${shellcheck_files[@]}"
assert_listed 'shellcheck' 'script/test/config-mounts-contract.sh' "${shellcheck_files[@]}"
assert_listed 'shellcheck' 'script/test/fixtures/config-mounts/guest-cm-probe.sh' "${shellcheck_files[@]}"
# #455's sweep lib is sourced by e2e.sh, so both guards need it as an input:
# the linter resolves a sourced file only when it is one of the inputs. Nothing
# scans script/test/, so the new contract needs its own pair as well.
assert_listed 'bash -n' 'script/test/lib/e2e-image-cleanup.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/lib/e2e-image-cleanup.sh' "${shellcheck_files[@]}"
assert_listed 'bash -n' 'script/test/e2e-image-cleanup-contract.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/e2e-image-cleanup-contract.sh' "${shellcheck_files[@]}"
# #473's operator reclaim tool is executed by its own contract, so both the tool
# and the contract are guard inputs.
assert_listed 'bash -n' 'script/test/reclaim-docker-cache.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/reclaim-docker-cache.sh' "${shellcheck_files[@]}"
assert_listed 'bash -n' 'script/test/reclaim-docker-cache-contract.sh' "${syntax_check[@]}"
assert_listed 'shellcheck' 'script/test/reclaim-docker-cache-contract.sh' "${shellcheck_files[@]}"

is_vendored() {
    [[ "$1" == vendor/microsandbox/* ]]
}

# Vendored entries exist only once the recursive submodule is initialized, which
# CI's checkout does. A bare worktree legitimately lacks them, so they are skipped
# with a notice instead of dying on a baffling ENOENT; this cannot weaken CI,
# because the provenance check above already fails loudly when the submodule is
# missing. A missing *non*-vendored entry is a hard failure: that means the guard
# list has drifted from the scripts the workflow actually runs.
for script_file in "${syntax_check[@]}"; do
    file="$REPO_ROOT/$script_file"
    if [[ ! -f "$file" ]]; then
        if is_vendored "$script_file"; then
            echo "notice: skipping bash -n for $script_file (submodule not initialized; run: git submodule update --init --recursive)" >&2
            continue
        fi
        fail "bash -n target missing: $script_file (guard list drifted?)"
    fi
    # Per-file on purpose: `bash -n a b c` parses only `a` -- the rest become
    # positional parameters -- so a single multi-file invocation would guard
    # exactly one entry (issue #127). Do not collapse this into one call.
    bash -n "$file" || fail "bash -n failed for $script_file"
done

if ! command -v shellcheck >/dev/null 2>&1; then
    fail "shellcheck is required but not on PATH (macOS: brew install shellcheck; Debian/Ubuntu: sudo apt-get install -y shellcheck)"
fi

present=()
for script_file in "${shellcheck_files[@]}"; do
    file="$REPO_ROOT/$script_file"
    if [[ ! -f "$file" ]]; then
        if is_vendored "$script_file"; then
            echo "notice: skipping shellcheck for $script_file (submodule not initialized; run: git submodule update --init --recursive)" >&2
            continue
        fi
        fail "shellcheck target missing: $script_file (guard list drifted?)"
    fi
    present+=("$file")
done
shellcheck "${present[@]}" || fail "shellcheck reported findings"

if [[ "$guard_only" == true ]]; then
    echo "shell guard passed"
else
    echo "ci provenance/contract checks and shell guard passed"
fi
