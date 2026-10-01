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
    bash "$REPO_ROOT/script/test/pi-prepare-lock.sh"
    bash "$REPO_ROOT/script/test/pi-verify.sh"
    bash "$REPO_ROOT/script/test/dsh-verify.sh"
    bash "$REPO_ROOT/script/test/dsh-prepare-lock.sh"
    bash "$REPO_ROOT/script/test/upgrade-scripts.sh"
    bash "$REPO_ROOT/script/test/agent-versions.sh"
    bash "$REPO_ROOT/script/test/rust-toolchain-consistency.sh"
    bash "$REPO_ROOT/script/test/tool-access.sh"
    bash "$REPO_ROOT/script/test/shipped-installer-contracts.sh"
    bash "$REPO_ROOT/script/test/copilot-verify.sh"
    bash "$REPO_ROOT/script/test/claude-installer.sh"
    bash "$REPO_ROOT/script/test/codex-installer.sh"
    bash "$REPO_ROOT/script/test/opencode-installer.sh"
    bash "$REPO_ROOT/script/test/vendored-installers.sh"
    bash "$REPO_ROOT/script/test/shipped-tool-recipes.sh" --self-test
    bash "$REPO_ROOT/script/test/sync-recipe-contracts.sh"
    "$REPO_ROOT/script/build/sync-recipe-contracts.sh" --check
    python3 -c 'import ast,sys;[ast.parse(open(p,encoding="utf-8").read(),p) for p in sys.argv[1:]]' \
        "$REPO_ROOT/images/recipe-contract/check-tool-access.py" \
        "$REPO_ROOT/images/recipe-contract/install-status.py" \
        "$REPO_ROOT"/images/tools/*/contract/check-tool-access.py \
        "$REPO_ROOT"/images/tools/*/contract/install-status.py \
        "$REPO_ROOT/script/test/fixtures/installer-egress/addon.py" \
        "$REPO_ROOT/script/test/host-watchdog.py"
    node --check "$REPO_ROOT/images/tools/dsh/check-lock-update.js"
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
    images/tools/dsh/install-dsh.sh
    images/tools/dsh/prepare-lock.sh
    images/tools/pi/prepare-lock.sh
    images/tools/pi/bridge/prepare-lock.sh
    script/build/dockerfile-label.sh
    script/test/dsh-prepare-lock.sh
    script/test/pi-prepare-lock.sh
    script/test/pi-verify.sh
    images/tools/claude/install-claude.sh
    images/tools/claude/verify-claude.sh
    images/tools/claude/vendor/install.sh
    script/test/claude-installer.sh
    images/tools/codex/install-codex.sh
    images/tools/codex/verify-codex.sh
    images/tools/codex/vendor/install.sh
    script/test/codex-installer.sh
    images/tools/opencode/install-opencode.sh
    images/tools/opencode/verify-opencode.sh
    images/tools/opencode/vendor/install.sh
    script/test/opencode-installer.sh
    script/test/vendored-installers.sh
    vendor/microsandbox/vendor/libkrunfw/build_in_docker.sh
    script/test/shipped-tool-recipes.sh
    script/check-runtime-provenance.sh
    script/test/runtime-provenance.sh
    script/test/msb-krun-compat.sh
    script/test/msb-krun-compat-contract.sh
    script/build/macos.sh
    script/build/agent-versions.sh
    script/build/npm-pin.sh
    images/build.sh
    script/test/build-workflow.sh
    images/tools/pi/pi.sh
    images/tools/pi/install-pi.sh
    images/tools/pi/install-pi-packages.sh
    images/tools/pi/verify-pi.sh
    images/tools/pi/seed-claude-bridge-config.sh
    images/tools/pi/upgrade-pi.sh
    images/tools/pi/bridge/upgrade-bridge.sh
    images/tools/dsh/verify-dsh.sh
    images/tools/copilot/install-copilot.sh
    images/tools/copilot/verify-copilot.sh
    script/test/copilot-verify.sh
    script/test/copilot-installer.sh
    images/tools/dsh/upgrade-dsh.sh
    script/test/dsh-verify.sh
    script/test/pi-wrapper.sh
    script/test/pi-install.sh
    script/test/upgrade-scripts.sh
    script/test/agent-versions.sh
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
    script/build/sync-recipe-contracts.sh
    script/test/tool-access.sh
    script/test/sync-recipe-contracts.sh
    script/test/host-watchdog.sh
    script/test/shipped-installer-contracts.sh
    script/test/shipped-installer-network.sh
    images/recipe-contract/download.sh
    images/recipe-contract/run-install.sh
    images/recipe-contract/run-npm.sh
    images/recipe-contract/run-report.sh
    images/tools/dsh/contract/download.sh
    images/tools/dsh/contract/run-install.sh
    images/tools/dsh/contract/run-npm.sh
    images/tools/dsh/contract/run-report.sh
    images/tools/pi/contract/download.sh
    images/tools/pi/contract/run-install.sh
    images/tools/pi/contract/run-npm.sh
    images/tools/pi/contract/run-report.sh
    images/tools/codex/contract/download.sh
    images/tools/codex/contract/run-install.sh
    images/tools/codex/contract/run-npm.sh
    images/tools/codex/contract/run-report.sh
    images/tools/opencode/contract/download.sh
    images/tools/opencode/contract/run-install.sh
    images/tools/opencode/contract/run-npm.sh
    images/tools/opencode/contract/run-report.sh
    images/tools/claude/contract/download.sh
    images/tools/claude/contract/run-install.sh
    images/tools/claude/contract/run-npm.sh
    images/tools/claude/contract/run-report.sh
    images/tools/copilot/contract/download.sh
    images/tools/copilot/contract/run-install.sh
    images/tools/copilot/contract/run-npm.sh
    images/tools/copilot/contract/run-report.sh
    "$self_relative"
)

# The lint list below runs every guarded script plus the nested vendored script
# that `build_in_docker.sh` invokes; it is deliberately a superset-by-one of
# syntax_check rather than a divergence from the criterion above.
shellcheck_files=(
    images/tools/dsh/install-dsh.sh
    images/tools/dsh/prepare-lock.sh
    images/tools/pi/prepare-lock.sh
    images/tools/pi/bridge/prepare-lock.sh
    script/build/dockerfile-label.sh
    script/test/dsh-prepare-lock.sh
    script/test/pi-prepare-lock.sh
    script/test/pi-verify.sh
    images/tools/claude/install-claude.sh
    images/tools/claude/verify-claude.sh
    images/tools/claude/vendor/install.sh
    script/test/claude-installer.sh
    images/tools/codex/install-codex.sh
    images/tools/codex/verify-codex.sh
    images/tools/codex/vendor/install.sh
    script/test/codex-installer.sh
    images/tools/opencode/install-opencode.sh
    images/tools/opencode/verify-opencode.sh
    images/tools/opencode/vendor/install.sh
    script/test/opencode-installer.sh
    script/test/vendored-installers.sh
    vendor/microsandbox/vendor/libkrunfw/build_in_docker.sh
    vendor/microsandbox/vendor/libkrunfw/scripts/test-build-in-docker.sh
    script/test/shipped-tool-recipes.sh
    script/check-runtime-provenance.sh
    script/test/runtime-provenance.sh
    script/test/msb-krun-compat.sh
    script/test/msb-krun-compat-contract.sh
    script/build/macos.sh
    script/build/agent-versions.sh
    script/build/npm-pin.sh
    images/build.sh
    script/test/build-workflow.sh
    images/tools/pi/pi.sh
    images/tools/pi/install-pi.sh
    images/tools/pi/install-pi-packages.sh
    images/tools/pi/verify-pi.sh
    images/tools/pi/seed-claude-bridge-config.sh
    images/tools/pi/upgrade-pi.sh
    images/tools/pi/bridge/upgrade-bridge.sh
    images/tools/dsh/verify-dsh.sh
    images/tools/copilot/install-copilot.sh
    images/tools/copilot/verify-copilot.sh
    script/test/copilot-verify.sh
    script/test/copilot-installer.sh
    images/tools/dsh/upgrade-dsh.sh
    script/test/dsh-verify.sh
    script/test/pi-wrapper.sh
    script/test/pi-install.sh
    script/test/upgrade-scripts.sh
    script/test/agent-versions.sh
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
    script/build/sync-recipe-contracts.sh
    script/test/tool-access.sh
    script/test/sync-recipe-contracts.sh
    script/test/host-watchdog.sh
    script/test/shipped-installer-contracts.sh
    script/test/shipped-installer-network.sh
    images/recipe-contract/download.sh
    images/recipe-contract/run-install.sh
    images/recipe-contract/run-npm.sh
    images/recipe-contract/run-report.sh
    images/tools/dsh/contract/download.sh
    images/tools/dsh/contract/run-install.sh
    images/tools/dsh/contract/run-npm.sh
    images/tools/dsh/contract/run-report.sh
    images/tools/pi/contract/download.sh
    images/tools/pi/contract/run-install.sh
    images/tools/pi/contract/run-npm.sh
    images/tools/pi/contract/run-report.sh
    images/tools/codex/contract/download.sh
    images/tools/codex/contract/run-install.sh
    images/tools/codex/contract/run-npm.sh
    images/tools/codex/contract/run-report.sh
    images/tools/opencode/contract/download.sh
    images/tools/opencode/contract/run-install.sh
    images/tools/opencode/contract/run-npm.sh
    images/tools/opencode/contract/run-report.sh
    images/tools/claude/contract/download.sh
    images/tools/claude/contract/run-install.sh
    images/tools/claude/contract/run-npm.sh
    images/tools/claude/contract/run-report.sh
    images/tools/copilot/contract/download.sh
    images/tools/copilot/contract/run-install.sh
    images/tools/copilot/contract/run-npm.sh
    images/tools/copilot/contract/run-report.sh
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
