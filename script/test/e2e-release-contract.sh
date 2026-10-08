#!/usr/bin/env bash
# Early dispatch must not silently preflight a builder or skip prerequisites.
set -euo pipefail
ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/av-release-contract.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/tools" "$WORK/home" "$WORK/config"
# Expose only the released-image gate's declared tool prerequisites to the
# isolated PATH. Link each file (not its directory), because a directory symlink
# would also leak unrelated host tools past the builder decoys.
for tool in jq shasum python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "contract test needs $tool on PATH" >&2; exit 1; }
    ln -s "$(command -v "$tool")" "$WORK/tools/$tool"
done
cat > "$WORK/bin/docker" <<'SH'
#!/bin/bash
set -euo pipefail
printf 'called\n' >> "$DOCKER_LOG"
exit 97
SH
chmod 755 "$WORK/bin/docker"
run() {
    env -i HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/config" \
        AGENT_VM_STATE_DIR="$WORK/state" AGENT_VM_SHARE_MSB_CACHE=0 \
        PATH="$WORK/bin:$WORK/tools:/usr/bin:/bin" DOCKER_LOG="$WORK/docker.log" \
        "$@"
}
status=0
run docker calibration || status=$?
[[ "$status" == 97 && -s "$WORK/docker.log" ]]
: > "$WORK/docker.log"
run bash "$ROOT/script/test/e2e.sh" --help > "$WORK/help"
grep -q released-image "$WORK/help"
status=0
run bash "$ROOT/script/test/e2e.sh" not-a-group > "$WORK/bad" 2>&1 || status=$?
[[ "$status" == 2 ]]
status=0
run bash "$ROOT/script/test/e2e.sh" released-image > "$WORK/missing" 2>&1 || status=$?
[[ "$status" != 0 ]]
grep -q AGENT_VM_RELEASE_BIN "$WORK/missing"
status=0
run env AGENT_VM_RELEASE_BIN=/missing/agent-vm bash "$ROOT/script/test/e2e.sh" released-image > "$WORK/assets" 2>&1 || status=$?
[[ "$status" != 0 ]]
grep -q AGENT_VM_E2E_RELEASE_ASSETS_DIR "$WORK/assets"
status=0
run env AGENT_VM_RELEASE_BIN=/missing/agent-vm \
    AGENT_VM_E2E_RELEASE_ASSETS_DIR="$WORK/native" AGENT_VM_E2E_OTHER_ASSETS_DIR="$WORK/other" \
    bash "$ROOT/script/test/e2e.sh" released-image > "$WORK/candidate" 2>&1 || status=$?
[[ "$status" != 0 ]]
grep -q 'absolute executable path' "$WORK/candidate"
if grep -q 'native join passed' "$WORK/missing" "$WORK/assets" "$WORK/candidate"; then
    echo 'failed prerequisites produced success' >&2; exit 1
fi

# ---------------------------------------------------------------------------
# Boot-free controls for the native join's factored predicates (F1-F4). The
# native path (e2e-released-image.sh) sources the SAME lib for F1/F2/F3, so these
# exercise the assertion it uses rather than a duplicated copy.
# ---------------------------------------------------------------------------
# shellcheck source=script/test/lib/released-image-checks.sh
. "$ROOT/script/test/lib/released-image-checks.sh"

# F1: the retained-record comparison must reject a record changed by a launch.
printf '{"version":1,"image":"child@sha256:aaa"}\n' > "$WORK/record.snapshot"
cp "$WORK/record.snapshot" "$WORK/record.live"
released_image_assert_record_unchanged "$WORK/record.live" "$WORK/record.snapshot" retained \
    || { echo 'F1: unchanged retained record rejected' >&2; exit 1; }
printf '{"version":1,"image":"index@sha256:bbb"}\n' > "$WORK/record.live"
if released_image_assert_record_unchanged "$WORK/record.live" "$WORK/record.snapshot" retained 2>/dev/null; then
    echo 'F1: changed retained record accepted at the boundary' >&2; exit 1
fi

# F2: canonical absent-build-source predicate (missing / present / absent).
mkdir -p "$WORK/present-source"
if released_image_require_absent_build_source "$WORK/present-source" >/dev/null 2>&1; then
    echo 'F2: present build source accepted' >&2; exit 1
fi
if released_image_require_absent_build_source "" >/dev/null 2>&1; then
    echo 'F2: unset build source accepted' >&2; exit 1
fi
if released_image_require_absent_build_source "relative/source" >/dev/null 2>&1; then
    echo 'F2: relative build source accepted' >&2; exit 1
fi
absent_canonical="$(released_image_require_absent_build_source "$WORK/absent-source")" \
    || { echo 'F2: absent build source rejected' >&2; exit 1; }
[[ "$absent_canonical" == "$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$WORK/absent-source")" ]] \
    || { echo 'F2: canonical absent path mismatch' >&2; exit 1; }

# F2 wiring: the dispatch must stop at the source prerequisite before any boot.
printf '#!/bin/sh\nexit 0\n' > "$WORK/bin/agent-vm"; chmod 755 "$WORK/bin/agent-vm"
status=0
run env AGENT_VM_RELEASE_BIN="$WORK/bin/agent-vm" AGENT_VM_E2E_RELEASE_ASSETS_DIR="$WORK/native" \
    AGENT_VM_E2E_OTHER_ASSETS_DIR="$WORK/other" \
    bash "$ROOT/script/test/e2e.sh" released-image > "$WORK/source-unset" 2>&1 || status=$?
[[ "$status" != 0 ]] || { echo 'F2: unset build source dispatch succeeded' >&2; exit 1; }
grep -q 'AGENT_VM_E2E_BUILD_SOURCE_DIR' "$WORK/source-unset"
status=0
run env AGENT_VM_RELEASE_BIN="$WORK/bin/agent-vm" AGENT_VM_E2E_RELEASE_ASSETS_DIR="$WORK/native" \
    AGENT_VM_E2E_OTHER_ASSETS_DIR="$WORK/other" AGENT_VM_E2E_BUILD_SOURCE_DIR="$WORK/present-source" \
    bash "$ROOT/script/test/e2e.sh" released-image > "$WORK/source-present" 2>&1 || status=$?
[[ "$status" != 0 ]] || { echo 'F2: present build source dispatch succeeded' >&2; exit 1; }
grep -q 'build source still present' "$WORK/source-present"
if grep -q 'native join passed' "$WORK/source-unset" "$WORK/source-present"; then
    echo 'F2: source prerequisite produced success' >&2; exit 1
fi

# F3: vetted Node resolution supports a non-system install and fails closed.
mkdir -p "$WORK/nonstd/bin"
printf '#!/bin/sh\nexit 0\n' > "$WORK/nonstd/bin/node"; chmod 755 "$WORK/nonstd/bin/node"
printf '#!/usr/bin/env node\n' > "$WORK/nonstd/agent-vm.js"; chmod 755 "$WORK/nonstd/agent-vm.js"
printf 'not executable\n' > "$WORK/nonstd/not-exec"
released_image_is_node_candidate "$WORK/nonstd/agent-vm.js" \
    || { echo 'F3: JS dispatcher not detected' >&2; exit 1; }
if released_image_is_node_candidate "$WORK/bin/agent-vm"; then
    echo 'F3: native binary misdetected as a Node dispatcher' >&2; exit 1
fi
node_canonical="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$WORK/nonstd/bin/node")"
resolved="$(PATH="$WORK/nonstd/bin:/usr/bin:/bin" released_image_resolve_node "")" \
    || { echo 'F3: non-system node not resolved' >&2; exit 1; }
[[ "$resolved" == "$node_canonical" ]] || { echo 'F3: resolved node is not canonical' >&2; exit 1; }
resolved="$(released_image_resolve_node "$WORK/nonstd/bin/node")" \
    || { echo 'F3: declared node not resolved' >&2; exit 1; }
[[ "$resolved" == "$node_canonical" ]] || { echo 'F3: declared node is not canonical' >&2; exit 1; }
if PATH=/nonexistent released_image_resolve_node "" >/dev/null 2>&1; then
    echo 'F3: missing Node accepted' >&2; exit 1
fi
if released_image_resolve_node "relative/node" >/dev/null 2>&1; then
    echo 'F3: relative Node accepted' >&2; exit 1
fi
if released_image_resolve_node "$WORK/nonstd/not-exec" >/dev/null 2>&1; then
    echo 'F3: non-executable Node accepted' >&2; exit 1
fi

# F3 invocation: run the real sanitized launch helper through a vetted
# interpreter that lives outside /usr/bin:/bin, and observe the forwarded argv,
# the isolated environment, the propagated status and that no builder ran. The
# interpreter records argv/env and exits 42; the candidate path need not be
# executable because the interpreter receives it as an argument.
cat > "$WORK/nonstd/bin/vetted-node" <<SH
#!/bin/sh
RECORD="$WORK/dispatch-record"
{ echo "interp=\$0"; for a in "\$@"; do echo "arg=\$a"; done; env | sort; } > "\$RECORD"
exit 42
SH
chmod 755 "$WORK/nonstd/bin/vetted-node"
: > "$WORK/builder.log"
status=0
INHERITED_SECRET=leak python3 -B "$ROOT/script/test/released-image-launch.py" \
    --root "$WORK/r" --shim "$WORK/shim" --log "$WORK/builder.log" \
    --binary "$WORK/nonstd/agent-vm.js" \
    --interpreter "$WORK/nonstd/bin/vetted-node" --timeout 30 --grace 2 \
    -- IMAGE_ENV=av265:test shell --no-git -- bash -c true || status=$?
[[ "$status" == 42 ]] || { echo "F3: dispatched status $status, expected 42" >&2; exit 1; }
grep -qx "arg=$WORK/nonstd/agent-vm.js" "$WORK/dispatch-record"
for forwarded in shell --no-git -- bash -c true; do
    grep -qx "arg=$forwarded" "$WORK/dispatch-record"
done
grep -qx "HOME=$WORK/r/home" "$WORK/dispatch-record"
grep -qx "XDG_CONFIG_HOME=$WORK/r/config" "$WORK/dispatch-record"
grep -qx "AGENT_VM_STATE_DIR=$WORK/r/state" "$WORK/dispatch-record"
grep -qx "AGENT_VM_IMAGE_TAG=av265:test" "$WORK/dispatch-record"
grep -qx "PATH=$WORK/shim:/usr/bin:/bin" "$WORK/dispatch-record"
grep -qx "LANG=C.UTF-8" "$WORK/dispatch-record"
grep -qx "BUILDER_LOG=$WORK/builder.log" "$WORK/dispatch-record"
if grep -q 'INHERITED_SECRET' "$WORK/dispatch-record"; then
    echo 'F3: inherited environment leaked into the dispatched launch' >&2; exit 1
fi
[[ ! -s "$WORK/builder.log" ]] || { echo 'F3: dispatched launch invoked a builder' >&2; exit 1; }

# F4: parse both helper files without writing bytecode, keep the tree free of
# tracked caches, then run the process-group timeout controls.
ROOT="$ROOT" python3 - <<'PY'
import ast, os, pathlib
root = pathlib.Path(os.environ["ROOT"])
for rel in ("script/test/released-image-launch.py", "script/test/released-image-launch-test.py"):
    ast.parse((root / rel).read_text())
PY
if git -C "$ROOT" ls-files | grep -Eq '(^|/)__pycache__/|\.pyc$'; then
    echo 'tracked Python bytecode cache present' >&2; exit 1
fi
python3 -B "$ROOT/script/test/released-image-launch-test.py"

[[ ! -s "$WORK/docker.log" ]] || { echo 'a decoy builder was invoked' >&2; exit 1; }
echo 'released-image early-dispatch and boot-free controls passed'
