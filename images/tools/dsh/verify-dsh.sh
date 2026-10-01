#!/bin/sh
# Build-time gate for the dsh tool layer. Bind-mounted into the layer's
# Dockerfile, not COPYed, so it never ships in the image.
#
# The version *string* is the assertion, not the exit code. dsh dispatches on
# `import.meta.main`, which Node only defines from 22.19 (and 24.x); on an older
# Node its bin.js loads, prints nothing and exits 0. A `dsh --version`
# exit-code check would therefore pass on an image that ships no working dsh --
# and `agent-vm setup`'s own `--version` probe would pass it too.
#
# Both slots are checked: the manifest pins dsh AND pnpm (dsh's plugin command
# execs pnpm), and the running binaries must match. Each report is captured
# bounded and its status is checked BEFORE parsing, so a command that prints the
# expected version and then exits nonzero, or hangs, fails the build.
#
# A supplied slot must equal the effective (prepared) manifest pin; if they
# differ the preparation did not take effect, and verifying the manifest would
# be verifying the wrong thing.
#
# dsh is deliberately never soft-failable, so a missing command is a hard
# failure regardless of AGENT_INSTALL_SOFT_FAIL. Only after both reports, the
# exact equality and the T5 command audit pass is the slot recorded
# `installed` (selection labels are not health).
set -eu

CONTRACT="${AGENT_VM_CONTRACT_DIR:-/tmp/recipe-contract}"
PREFIX="${AGENT_VM_DSH_PREFIX:-/opt/agent-vm/dsh}"
# `DSH_MANIFEST` is a test seam (the same shape as the pi installer's
# AGENT_VM_PI_PREFIX); production uses the default.
MANIFEST="${DSH_MANIFEST:-$PREFIX/package.json}"
status_dir="${AGENT_VM_INSTALL_STATUS_DIR:-/opt/agent-vm/install-status}"
status="$status_dir/dsh"

want_dsh=$(jq -r '.dependencies["@deepseek-ai/dsh"]' "$MANIFEST")
want_pnpm=$(jq -r '.dependencies.pnpm' "$MANIFEST")

# The supplied slot has already been validated for exact syntax by
# prepare-lock.sh. Here it must agree with what the manifest says will be
# installed; a mismatch means the preparation is not the one being verified.
if [ -n "${AGENT_VM_VERSION_DSH:-}" ] && [ "${AGENT_VM_VERSION_DSH}" != "$want_dsh" ]; then
    echo "  dsh: layer asked for ${AGENT_VM_VERSION_DSH} but the manifest pins ${want_dsh}" >&2
    exit 1
fi
if [ -n "${AGENT_VM_VERSION_PNPM:-}" ] && [ "${AGENT_VM_VERSION_PNPM}" != "$want_pnpm" ]; then
    echo "  pnpm: layer asked for ${AGENT_VM_VERSION_PNPM} but the manifest pins ${want_pnpm}" >&2
    exit 1
fi

if ! command -v dsh >/dev/null 2>&1; then
    echo "  dsh: MISSING — hard sanity failure" >&2
    exit 1
fi
if ! command -v pnpm >/dev/null 2>&1; then
    echo "  pnpm: MISSING — hard sanity failure ('dsh plugin' would fail)" >&2
    exit 1
fi

scratch=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf '$scratch'" EXIT INT TERM HUP

# report EXE OUTFILE ERRFILE -> echoes the single non-blank stdout line, or
# fails on a nonzero/signal/timeout status, empty output or extra lines. The
# exact mapping is a bare `<version>`; anything else is unrecognized.
report() {
    exe=$1
    out=$2
    err=$3
    rc=0
    sh "$CONTRACT/run-report.sh" 60 "$out" "$err" "$exe" --version || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "  $exe: --version exited $rc; refusing to accept the report" >&2
        sed -n '1,10p' "$err" >&2
        exit 1
    fi
    first=$(sed -n '1p' "$out")
    if [ -z "$first" ]; then
        if [ "$exe" = dsh ]; then
            echo "  dsh: empty --version output — hard sanity failure" >&2
            echo "  dsh needs Node >=22.19 ('import.meta.main'); an older Node makes" >&2
            echo "  its CLI exit 0 with no output, so this must fail the build." >&2
        else
            echo "  $exe: empty --version output — hard sanity failure" >&2
        fi
        exit 1
    fi
    lineno=0
    while IFS= read -r line || [ -n "$line" ]; do
        lineno=$((lineno + 1))
        [ "$lineno" -eq 1 ] && continue
        [ -z "$line" ] && continue
        echo "  $exe: unexpected --version output on line $lineno: '$line'" >&2
        exit 1
    done <"$out"
    printf '%s\n' "$first"
}

got_dsh=$(report dsh "$scratch/dsh.out" "$scratch/dsh.err")
if [ "$got_dsh" != "$want_dsh" ]; then
    echo "  dsh: installed $got_dsh but package.json pins $want_dsh" >&2
    exit 1
fi

got_pnpm=$(report pnpm "$scratch/pnpm.out" "$scratch/pnpm.err")
if [ "$got_pnpm" != "$want_pnpm" ]; then
    echo "  pnpm: installed $got_pnpm but package.json pins $want_pnpm" >&2
    exit 1
fi

echo "  dsh: $got_dsh (pnpm $got_pnpm)"

# T5: the resolved commands and every directory on their paths must be usable
# by an arbitrary uid. This follows the PATH symlinks into the private prefix
# and audits the targets and all ancestors; the install hook's chmod is what
# repairs them.
python3 "$CONTRACT/check-tool-access.py" dsh pnpm

mkdir -p "$status_dir"
printf 'installed\n' >"$status"
