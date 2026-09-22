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
    bash "$REPO_ROOT/script/test/pi-wrapper.sh"
    bash "$REPO_ROOT/script/test/pi-install.sh"
    bash "$REPO_ROOT/script/test/dsh-verify.sh"
    bash "$REPO_ROOT/script/test/rust-toolchain-consistency.sh"
fi

# --- Shell guard rail --------------------------------------------------------
# Guard rail for the shell this workflow runs: every script the commands above
# execute, the scripts those invoke in turn, scripts other jobs in this workflow
# run, and the fixtures they use belong in both lists. Scripts only other
# workflows run are guarded there. The examples/layers/rust-dev and
# examples/layers/go-dev build scripts are guarded here too: no workflow runs
# them (they are bind-mounted into their layer's Dockerfile at image-build
# time), so this is their only shell guard.
syntax_check=(
    vendor/microsandbox/vendor/libkrunfw/build_in_docker.sh
    script/check-runtime-provenance.sh
    script/test/runtime-provenance.sh
    script/test/msb-krun-compat.sh
    script/test/msb-krun-compat-contract.sh
    script/build/macos.sh
    script/test/build-workflow.sh
    images/tools/pi/pi.sh
    images/tools/pi/install-pi.sh
    images/tools/pi/verify-pi.sh
    images/tools/dsh/verify-dsh.sh
    script/test/dsh-verify.sh
    script/test/pi-wrapper.sh
    script/test/pi-install.sh
    script/check-rust-toolchain.sh
    script/test/rust-toolchain-consistency.sh
    script/test/fixtures/fake-plutil.sh
    examples/layers/rust-dev/install-rust.sh
    examples/layers/rust-dev/install-verus.sh
    examples/layers/rust-dev/verify-toolchain.sh
    examples/layers/go-dev/install-go.sh
    examples/layers/go-dev/install-golangci-lint.sh
    examples/layers/go-dev/install-gopls.sh
    examples/layers/go-dev/verify-toolchain.sh
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
    images/tools/pi/pi.sh
    images/tools/pi/install-pi.sh
    images/tools/pi/verify-pi.sh
    images/tools/dsh/verify-dsh.sh
    script/test/dsh-verify.sh
    script/test/pi-wrapper.sh
    script/test/pi-install.sh
    script/check-rust-toolchain.sh
    script/test/rust-toolchain-consistency.sh
    script/test/fixtures/fake-plutil.sh
    examples/layers/rust-dev/install-rust.sh
    examples/layers/rust-dev/install-verus.sh
    examples/layers/rust-dev/verify-toolchain.sh
    examples/layers/go-dev/install-go.sh
    examples/layers/go-dev/install-golangci-lint.sh
    examples/layers/go-dev/install-gopls.sh
    examples/layers/go-dev/verify-toolchain.sh
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
    fail "this script ($needle) is missing from the $list_name guard list"
}
assert_listed 'bash -n' "$self_relative" "${syntax_check[@]}"
assert_listed 'shellcheck' "$self_relative" "${shellcheck_files[@]}"

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
