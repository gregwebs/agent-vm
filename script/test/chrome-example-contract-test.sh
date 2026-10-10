#!/usr/bin/env bash
# Branch and negative controls for chrome-example-contract.sh through its --root
# seam (#293). Synthetic roots hold only the two constants, a gitlink and a
# minimal synthetic recipe, never a copy of the production example:
# agent-vm-images owns that and its content checks.
set -euo pipefail

REPO_ROOT="$(CDPATH='' cd -- "${BASH_SOURCE[0]%/*}/../.." && pwd)"
CHECK="$REPO_ROOT/script/test/chrome-example-contract.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/av-chrome.XXXXXX")"
WORK="$(CDPATH='' cd -- "$WORK" && pwd)"
trap 'rm -rf "$WORK"' EXIT

MARKER=/etc/agent-vm-capabilities/chrome-devtools-mcp
WRAPPER=/usr/local/bin/agent-vm-chrome-mcp
COPY_LINE="COPY --chmod=0755 agent-vm-chrome-mcp $WRAPPER"
MARKER_LINE=" && : > $MARKER"
PRE_MOVE=087f8bad3de624a5dad38f1669e7dea96996371a
LATER=1111111111111111111111111111111111111111
EXAMPLE_REL=vendor/agent-vm-images/examples/layers/chrome-devtools

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

write_constants() { # DIR MARKER WRAPPER
    printf 'pub const CHROME_MCP_CAPABILITY_PATH: &str = "%s";\npub const CHROME_MCP_WRAPPER_PATH: &str = "%s";\n' \
        "$2" "$3" >"$1/crates/agent-vm/src/defaults.rs"
}

# A checkout whose constants agree, recording GITLINK, submodule uninitialized.
make_root() { # NAME GITLINK
    local dir="$WORK/$1"
    mkdir -p "$dir/crates/agent-vm/src" "$dir/vendor/agent-vm-images"
    write_constants "$dir" "$MARKER" "$WRAPPER"
    git -C "$dir" init -q
    git -C "$dir" update-index --add --cacheinfo "160000,$2,vendor/agent-vm-images"
    printf '%s\n' "$dir"
}

initialize_submodule() { # DIR
    : >"$1/vendor/agent-vm-images/.git"
}

write_example() { # DIR COPY_LINE LAST_LINE
    local example="$1/$EXAMPLE_REL"
    initialize_submodule "$1"
    mkdir -p "$example"
    printf 'FROM scratch\n%s\nRUN true \\\n%s\n' "$2" "$3" >"$example/Dockerfile"
    printf '#!/bin/sh\n' >"$example/agent-vm-chrome-mcp"
}

expect() { # STATUS NEEDLE DESCRIPTION [CHECK ARGS...]
    local want="$1" needle="$2" description="$3" status=0
    shift 3
    bash "$CHECK" "$@" >"$WORK/out" 2>&1 || status=$?
    [[ "$status" == "$want" ]] || {
        cat "$WORK/out" >&2
        fail "$description: exit $status, expected $want"
    }
    grep -Fq -- "$needle" "$WORK/out" || {
        cat "$WORK/out" >&2
        fail "$description: output lacks: $needle"
    }
    echo "ok: $description (exit $status)"
}

expect 0 'Chrome launcher path contract passed' 'P1 real checkout, default root'
dir="$(make_root uninitialized "$LATER")"
expect 0 'uninitialized; skipping' 'P2 uninitialized submodule skips' --root "$dir"
dir="$(make_root pre-move "$PRE_MOVE")"; initialize_submodule "$dir"
expect 0 'example read deferred' 'P3 pre-move defers' --root "$dir"
dir="$(make_root agrees "$LATER")"; write_example "$dir" "$COPY_LINE" "$MARKER_LINE"
expect 0 'submodule example agrees' 'P4 present agrees' --root "$dir"
make_root relative "$LATER" >/dev/null
decoy="$(make_root cdpath/relative "$LATER")"
write_constants "$decoy" /etc/agent-vm-capabilities/other "$WRAPPER"
(cd "$WORK" && export CDPATH="$WORK/cdpath" && expect 0 'passed (example read skipped)' 'P5 relative root under inherited CDPATH' --root relative)
dir="$(make_root marker "$LATER")"; write_constants "$dir" /etc/agent-vm-capabilities/other "$WRAPPER"
expect 1 "CHROME_MCP_CAPABILITY_PATH is '/etc/agent-vm-capabilities/other'" 'N1 marker mismatch' --root "$dir"
dir="$(make_root wrapper "$LATER")"; write_constants "$dir" "$MARKER" /usr/bin/other
expect 1 "CHROME_MCP_WRAPPER_PATH is '/usr/bin/other'" 'N2 wrapper mismatch' --root "$dir"
dir="$(make_root selfcons "$LATER")"; write_constants "$dir" /etc/agent-vm-capabilities/other "$WRAPPER"; write_example "$dir" "$COPY_LINE" " && : > /etc/agent-vm-capabilities/other"
expect 1 "CHROME_MCP_CAPABILITY_PATH is" 'N3 self-consistent drift' --root "$dir"
dir="$(make_root missing "$LATER")"; printf 'pub const CHROME_MCP_WRAPPER_PATH: &str = "%s";\n' "$WRAPPER" >"$dir/crates/agent-vm/src/defaults.rs"
expect 1 "CHROME_MCP_CAPABILITY_PATH is ''" 'N4 missing constant' --root "$dir"
dir="$(make_root later-missing "$LATER")"; initialize_submodule "$dir"
expect 1 "at $LATER lacks" 'N5 later gitlink without example' --root "$dir"
dir="$(make_root badmarker "$LATER")"; write_example "$dir" "$COPY_LINE" " && : > /etc/agent-vm-capabilities/other"
expect 1 'must end with' 'N6 wrong marker' --root "$dir"
dir="$(make_root notlast "$LATER")"; write_example "$dir" "$COPY_LINE" "$MARKER_LINE"; printf 'RUN true\n' >>"$dir/$EXAMPLE_REL/Dockerfile"
expect 1 'must end with' 'N7 marker not last' --root "$dir"
dir="$(make_root mode "$LATER")"; write_example "$dir" "COPY --chmod=0644 agent-vm-chrome-mcp $WRAPPER" "$MARKER_LINE"
expect 1 "lacks the line 'COPY" 'N8 wrong mode' --root "$dir"
dir="$(make_root suffix "$LATER")"; write_example "$dir" "$COPY_LINE.old" "$MARKER_LINE"
expect 1 "lacks the line 'COPY" 'N9 substring copy' --root "$dir"
dir="$(make_root nowrap "$LATER")"; write_example "$dir" "$COPY_LINE" "$MARKER_LINE"; rm "$dir/$EXAMPLE_REL/agent-vm-chrome-mcp"
expect 1 'agent-vm-chrome-mcp is missing' 'N10 missing wrapper' --root "$dir"
dir="$(make_root premove-present "$PRE_MOVE")"; write_example "$dir" "$COPY_LINE" " && : > /etc/agent-vm-capabilities/other"
expect 1 'must end with' 'N11 pre-move present checked' --root "$dir"
dir="$(make_root no-defaults "$LATER")"; rm "$dir/crates/agent-vm/src/defaults.rs"
expect 1 'crates/agent-vm/src/defaults.rs is missing' 'N12 missing defaults.rs' --root "$dir"
dir="$(make_root sed-fails "$LATER")"
mkdir -p "$WORK/failing-sed"
printf '#!/bin/sh\necho '\''sed: injected read failure'\'' >&2\nexit 2\n' >"$WORK/failing-sed/sed"
chmod +x "$WORK/failing-sed/sed"
(export PATH="$WORK/failing-sed:$PATH" && expect 1 'chrome example contract: cannot read crates/agent-vm/src/defaults.rs' 'N13 defaults.rs read failure' --root "$dir")
expect 2 'usage:' 'U1 unknown' --bogus
expect 2 'usage:' 'U2 root no value' --root
expect 2 'not a directory' 'U3 nonexistent root' --root "$WORK/absent"
expect 2 'not a directory' 'U4 empty root' --root ''
echo 'chrome example contract branch and negative controls passed'
