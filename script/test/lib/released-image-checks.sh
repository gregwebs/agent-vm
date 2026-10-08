#!/usr/bin/env bash
# Shared boot-free predicates for the released-image native join.
#
# These are factored out of script/test/e2e-released-image.sh so the CI contract
# test (script/test/e2e-release-contract.sh) exercises the *same* assertion the
# native path uses, instead of a duplicated copy that could drift. This file is
# sourced, so it deliberately sets no shell options; callers use `set -euo pipefail`.

# Assert a selection record is byte-identical immediately after a launch that
# must not rewrite it. The comparison has to run BEFORE any manual
# overwrite/restore: a regression that rewrote the retained child to the
# recommended index during the launch would otherwise be masked by the restore.
released_image_assert_record_unchanged() {
    local record="$1" snapshot="$2" label="${3:-retained}"
    if ! cmp -s "$record" "$snapshot"; then
        echo "released-image: $label record changed during the launch" >&2
        echo "  snapshot: $(cat "$snapshot" 2>/dev/null || echo '<unreadable>')" >&2
        echo "  record:   $(cat "$record" 2>/dev/null || echo '<unreadable>')" >&2
        return 1
    fi
}

# Require the build checkout the operator declares for the candidate to be
# absent. This is a provenance *binding*, not detection: the helper only checks
# the declared path's canonical absence, so the operator must bind
# AGENT_VM_E2E_BUILD_SOURCE_DIR to the candidate through the reviewed build logs
# and record that correspondence. The path is canonicalized even when absent, and
# the helper never deletes or moves anything -- only the operator removes the
# disposable checkout after confirming relocation. On success it prints the
# canonical path that was verified absent.
released_image_require_absent_build_source() {
    local declared="${1:-}" canonical
    if [[ -z "$declared" ]]; then
        echo "released-image: set AGENT_VM_E2E_BUILD_SOURCE_DIR to the candidate's actual build checkout" >&2
        return 1
    fi
    if [[ "$declared" != /* ]]; then
        echo "released-image: AGENT_VM_E2E_BUILD_SOURCE_DIR must be an absolute path" >&2
        return 1
    fi
    canonical="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$declared")"
    if [[ -e "$canonical" ]]; then
        echo "released-image: build source still present at $canonical" >&2
        return 1
    fi
    printf '%s\n' "$canonical"
}

# Whether BIN is the installed npm/Node dispatcher rather than the native
# executable. The published package's bin entry is JS with a `#!/usr/bin/env
# node` shebang; the native release is a Mach-O/ELF binary.
released_image_is_node_candidate() {
    local bin="$1" prefix
    prefix="$(head -c 64 "$bin" 2>/dev/null || true)"
    [[ "$prefix" == '#!'*node* ]]
}

# Resolve the vetted Node interpreter used to invoke an installed npm
# dispatcher. AGENT_VM_E2E_NODE (absolute) wins; otherwise `node` is resolved
# from the caller PATH *before* environment isolation. Both are canonicalized.
# The caller must resolve this before isolation because the isolated PATH may not
# contain the host's Node prefix (nvm, /usr/local, ...).
released_image_resolve_node() {
    local declared="${1:-}" node_bin
    if [[ -n "$declared" ]]; then
        if [[ "$declared" != /* ]]; then
            echo "released-image: AGENT_VM_E2E_NODE must be an absolute path" >&2
            return 1
        fi
        if [[ ! -x "$declared" ]]; then
            echo "released-image: AGENT_VM_E2E_NODE is not executable: $declared" >&2
            return 1
        fi
        node_bin="$declared"
    else
        node_bin="$(command -v node || true)"
        if [[ -z "$node_bin" ]]; then
            echo "released-image: the installed npm dispatcher needs node; set AGENT_VM_E2E_NODE to a vetted absolute interpreter" >&2
            return 1
        fi
    fi
    python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$node_bin"
}
