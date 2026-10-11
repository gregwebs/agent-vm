#!/usr/bin/env bash
# Shared boot-free helpers for ADR-0038's config-dir guard evidence. Sourced by
# config-dir-guard-live.sh (native rows) and exercised by
# config-dir-guard-contract.sh (CI). No VM, no agent-vm binary, no side effects
# beyond the candidate directories avm_guard_select_case_variant_project creates.

# The vendored runtime derives a sandbox's canonical control socket as
#   <run_dir>/sandboxes/<24 hex>/control.sock
# (vendor/microsandbox/crates/runtime/lib/client/ipc.rs::sandbox_socket_paths,
# 2 * CANONICAL_SOCKET_HASH_BYTES). agent-vm's msb_home_dir() puts run_dir at
# <AGENT_VM_STATE_DIR>/msb-home/run when the state dir is overridden, so the
# whole path is:
#   <AGENT_VM_STATE_DIR>/msb-home/run/sandboxes/<24 hex>/control.sock
# The <24 hex> id is fixed length, so only the state-dir length varies.
# config-dir-guard-contract.sh checks source-shape sentinels plus independent
# fixed-shape budget controls. These are drift alarms, not execution of the
# runtime's actual path derivation; native rows remain necessary.
AVM_GUARD_SOCKET_SUFFIX="/msb-home/run/sandboxes/"
AVM_GUARD_SOCKET_HASH_BYTES=12
AVM_GUARD_SOCKET_LEAF="/control.sock"

# macOS sockaddr_un.sun_path is a 104-byte buffer including the NUL; Linux 108.
avm_sun_path_usable_len() {
    case "$(uname -s)" in
    Darwin) printf '103' ;;
    *) printf '107' ;;
    esac
}

# The canonical control-socket path a state dir at $1 produces, with the fixed
# 24-hex sandbox id spelled as a placeholder of the same length.
avm_guard_control_socket_path() {
    local state="$1" hex
    hex="$(printf '%*s' "$((AVM_GUARD_SOCKET_HASH_BYTES * 2))" ' ' | tr ' ' '0')"
    printf '%s%s%s%s\n' "$state" "$AVM_GUARD_SOCKET_SUFFIX" "$hex" "$AVM_GUARD_SOCKET_LEAF"
}

# Byte length, not character count: a multibyte state path (e.g. a UTF-8 home
# directory) occupies more bytes than its ${#path} length under a UTF-8 locale,
# and sockaddr_un is measured in bytes. `local LC_ALL=C` scopes the byte
# semantics to this expansion.
avm_guard_control_socket_len() {
    local path LC_ALL=C
    path="$(avm_guard_control_socket_path "$1")"
    printf '%s' "${#path}"
}

# 0 when a state dir at $1 keeps the control-socket path within the platform
# sockaddr_un limit; otherwise 1 and prints the over-limit length.
avm_guard_state_dir_fits() {
    local len limit
    len="$(avm_guard_control_socket_len "$1")"
    limit="$(avm_sun_path_usable_len)"
    if ((${#len} && len <= limit)); then
        return 0
    fi
    printf '%s' "$len"
    return 1
}

# The lower/upper spellings of a 12-hex project hash are distinct exactly when
# the hash contains an ASCII letter. When it does not (~0.36% of hashes), the
# case-variant rows would pass without exercising the case arm.
avm_guard_case_variant_is_distinct() {
    [[ "$1" == *[a-f]* ]]
}

# session.rs::hash_path: the first six SHA-256 bytes over the canonical path,
# as lowercase hex. This is the *project* hash, not the runtime sandbox id.
avm_guard_project_hash() {
    python3 - "$1" <<'PY'
import hashlib, os, sys
print(hashlib.sha256(os.fsencode(os.path.realpath(sys.argv[1]))).hexdigest()[:12])
PY
}

# Prints a directory under $1 whose project hash changes under ASCII
# uppercasing, creating deterministic candidates until one does.
#
# Return codes are distinguished because callers run this under `if`/`||`,
# where bash disables errexit inside the function and would otherwise swallow a
# failed mkdir or python invocation:
#   0  a distinct-case project was printed
#   1  every candidate was genuinely letterless (caller prints a skip reason)
#   2  an unexpected I/O or hash failure (caller must fail, never skip)
# Every fallible step is checked explicitly for exactly that reason.
avm_guard_select_case_variant_project() {
    local parent="$1" attempts="${2:-64}" i path hash upper
    mkdir -p "$parent" || return 2
    for ((i = 1; i <= attempts; i++)); do
        path="$parent/case-$i"
        mkdir -p "$path" || return 2
        hash="$(avm_guard_project_hash "$path")" || return 2
        [[ -n "$hash" ]] || return 2
        upper="$(printf '%s' "$hash" | tr '[:lower:]' '[:upper:]')" || return 2
        if avm_guard_case_variant_is_distinct "$hash" && [[ "$hash" != "$upper" ]]; then
            printf '%s\n' "$path"
            return 0
        fi
    done
    return 1
}
