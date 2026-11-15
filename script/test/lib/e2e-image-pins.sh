#!/usr/bin/env bash
# The pins environment every `script/test/e2e.sh` image-pin command runs under.
#
# Shared with `script/test/e2e-image-pins-contract.sh`, which executes these
# exact functions against a fake binary and its **actual child** environment, so
# the ambient-override wiring cannot rot unnoticed (#543, #455's pattern).
#
# Bash, sourced by `e2e.sh` and by the contract: it defines functions and a state
# array only. No `set -e` (a sourced fragment must not change its caller's
# options), and no command is run at source time.

# Consumed by the sourcing script's own helpers (`pins_store`, the registry
# counters, the observer), so "unused here" is expected.
# shellcheck disable=SC2034
PINS_HOME=""
PINS_STATE=""
PINS_BIN=""
PINS_ENV=()
PINS_OBSERVER_PID=""

# Every command here runs under one private HOME/state pair, with the inherited
# image/cache overrides cleared and the host decoys first on PATH.
pins_env() {
    local home="$1" state="$2"
    PINS_HOME="$home"
    PINS_STATE="$state"
    PINS_ENV=(env
        -u AGENT_VM_IMAGE_TAG -u AGENT_VM_ROOT -u AGENT_VM_SHARE_MSB_CACHE
        -u AGENT_VM_MSB_CACHE_DIR -u MSB_CONFIG_PATH -u AGENT_VM_TEST_DEFAULT_IMAGE
        HOME="$home" AGENT_VM_STATE_DIR="$state")
}

# Every explicit verb runs in the project whose approval it must read or write:
# a project is the command's working directory, so a verb run from the script's
# own cwd would act on a different project's records.
pins_avm() {
    local proj="$1"
    shift
    (cd "$proj" && "${PINS_ENV[@]}" "$PINS_BIN" "$@")
}

# The same command with one reference as the **ambient selection**.
#
# `image pull --image REF` is a target filter over references already in use
# (#543), so a first approval has to supply the reference as
# `AGENT_VM_IMAGE_TAG`. The assignment is an environment argument **after** every
# `-u` option in `PINS_ENV`: a shell prefix assignment would be erased by those
# `-u`s, and exporting it would leak a boot selection into later commands.
pins_avm_ambient() {
    local proj="$1" reference="$2"
    shift 2
    (cd "$proj" && "${PINS_ENV[@]}" AGENT_VM_IMAGE_TAG="$reference" "$PINS_BIN" "$@")
}
