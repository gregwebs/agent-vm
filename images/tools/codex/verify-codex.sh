#!/bin/sh
# Build-time gate for the codex layer. Bind-mounted, never COPYed.
#
# Reached after install-codex.sh: a hard failure already aborted the build, and
# a softened transport failure exited 0 having left an `absent-transport CODE`
# record and no command. The gate accepts that degraded state ONLY when the
# record is present; otherwise a missing command is a hard failure regardless of
# AGENT_INSTALL_SOFT_FAIL. On a real install it runs a bounded, status-checked
# `codex --version`, requires the exact `codex-cli <version>` report, audits T5,
# and only then records `installed` (selection labels are not health).
set -eu

CONTRACT="${AGENT_VM_CONTRACT_DIR:-/tmp/recipe-contract}"
# Production prefix is the installer's $HOME; the seam matches install-codex.sh.
prefix="${AGENT_VM_CODEX_PREFIX:-/opt/agent}"
codex_bin="$prefix/.local/bin/codex"
slot="${AGENT_VM_VERSION_CODEX:?verify-codex.sh needs AGENT_VM_VERSION_CODEX}"
status_dir="${AGENT_VM_INSTALL_STATUS_DIR:-/opt/agent-vm/install-status}"
status="$status_dir/codex"

# Path state via lstat: only a genuinely nonexistent command may be waved away
# by an absence record. A dangling symlink, a present-but-unusable file or a
# permission error on an ancestor is a contract violation, not an absence.
bin_state=0
python3 "$CONTRACT/install-status.py" path-state "$codex_bin" || bin_state=$?
if [ "$bin_state" -eq 0 ]; then
    if python3 "$CONTRACT/install-status.py" code "$status" >/dev/null 2>&1; then
        echo "  codex: ABSENT ($(cat "$status")); raw developer build only"
        exit 0
    fi
    echo "  codex: command missing with no valid absence record -- hard failure" >&2
    exit 1
fi
if [ "$bin_state" -eq 2 ]; then
    echo "  codex: cannot stat $codex_bin (permission/loop) -- hard failure" >&2
    exit 1
fi

scratch=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf '$scratch'" EXIT INT TERM HUP
out="$scratch/out"
err="$scratch/err"

status_code=0
sh "$CONTRACT/run-report.sh" 60 "$out" "$err" "$codex_bin" --version || status_code=$?
if [ "$status_code" -ne 0 ]; then
    echo "  codex: --version exited $status_code; refusing to accept the report" >&2
    sed -n '1,10p' "$err" >&2
    exit 1
fi
# The report is exact bytes; a NUL inside the banner would be erased by the
# command substitution below and canonicalize a corrupted report.
if [ "$(LC_ALL=C tr -d '\11\12\40-\176' <"$out" | wc -c | tr -d ' ')" != 0 ]; then
    echo "  codex: --version report contains non-printable bytes -- hard failure" >&2
    exit 1
fi
# A version banner on stderr is a contradictory/duplicate report; reject it.
if LC_ALL=C grep -Eq '^codex-cli [0-9A-Za-z.+-]+$' "$err"; then
    echo "  codex: --version printed a version report on stderr -- hard failure" >&2
    sed -n '1,10p' "$err" >&2
    exit 1
fi

# The recorded transcript is exactly `codex-cli <version>`. The first line must
# carry that banner; a later warning that merely embeds a version is rejected.
got=$(sed -n '1s/^codex-cli \(.*\)$/\1/p' "$out")
if [ -z "$got" ]; then
    echo "  codex: unrecognized --version output: $(sed -n '1p' "$out")" >&2
    exit 1
fi
want="${slot#rust-v}"
if [ "$got" != "$want" ]; then
    echo "  codex: installed $got, layer pinned $want" >&2
    exit 1
fi
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    [ "$lineno" -eq 1 ] && continue
    [ -z "$line" ] && continue
    echo "  codex: unexpected --version output on line $lineno: '$line'" >&2
    exit 1
done <"$out"
echo "  codex: codex-cli $got (pinned)"

python3 "$CONTRACT/check-tool-access.py" codex

mkdir -p "$status_dir"
printf 'installed\n' >"$status"
