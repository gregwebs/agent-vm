#!/bin/sh
# Build-time gate for the claude layer. Bind-mounted, never COPYed.
#
# Reached after install-claude.sh: a hard failure already aborted the build, and
# a softened transport failure exited 0 having left an `absent-transport CODE`
# record and no command. The gate accepts that degraded state ONLY when the
# record is present; otherwise a missing command is a hard failure regardless of
# AGENT_INSTALL_SOFT_FAIL. On a real install it runs a bounded, status-checked
# `claude --version`, requires the exact `<version> (Claude Code)` report, audits
# T5, and only then records `installed` (selection labels are not health).
set -eu

CONTRACT="${AGENT_VM_CONTRACT_DIR:-/tmp/recipe-contract}"
# Production prefix is the native installer's $HOME; the seam matches
# install-claude.sh and lets the host black-box test use a temp root.
prefix="${AGENT_VM_CLAUDE_PREFIX:-/opt/agent}"
claude_bin="$prefix/.local/bin/claude"
want="${AGENT_VM_VERSION_CLAUDE:?verify-claude.sh needs AGENT_VM_VERSION_CLAUDE}"
status_dir="${AGENT_VM_INSTALL_STATUS_DIR:-/opt/agent-vm/install-status}"
status="$status_dir/claude"

# Path state via lstat: only a genuinely nonexistent command may be waved away
# by an absence record. A dangling symlink, a present-but-unusable file or a
# permission error on an ancestor is a contract violation, not an absence.
bin_state=0
python3 "$CONTRACT/install-status.py" path-state "$claude_bin" || bin_state=$?
if [ "$bin_state" -eq 0 ]; then
    if python3 "$CONTRACT/install-status.py" code "$status" >/dev/null 2>&1; then
        echo "  claude: ABSENT ($(cat "$status")); raw developer build only"
        exit 0
    fi
    echo "  claude: command missing with no valid absence record -- hard failure" >&2
    exit 1
fi
if [ "$bin_state" -eq 2 ]; then
    echo "  claude: cannot stat $claude_bin (permission/loop) -- hard failure" >&2
    exit 1
fi

scratch=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf '$scratch'" EXIT INT TERM HUP
out="$scratch/out"
err="$scratch/err"

status_code=0
sh "$CONTRACT/run-report.sh" 60 "$out" "$err" "$claude_bin" --version || status_code=$?
if [ "$status_code" -ne 0 ]; then
    echo "  claude: --version exited $status_code; refusing to accept the report" >&2
    sed -n '1,10p' "$err" >&2
    exit 1
fi
# The report is exact bytes. An embedded NUL (or any other control byte) would
# be silently erased by the command substitution below, canonicalizing a
# corrupted report into an accepted one, so reject it before parsing.
if [ "$(LC_ALL=C tr -d '\11\12\40-\176' <"$out" | wc -c | tr -d ' ')" != 0 ]; then
    echo "  claude: --version report contains non-printable bytes -- hard failure" >&2
    exit 1
fi
# stderr is captured but not the report. A version-shaped banner there is a
# contradictory/duplicate report, not a harmless progress line, so reject it
# instead of discarding it on exit 0. Other diagnostics remain allowed.
if LC_ALL=C grep -Eq '^[0-9][0-9A-Za-z.+-]* \(Claude Code\)$' "$err"; then
    echo "  claude: --version printed a version report on stderr -- hard failure" >&2
    sed -n '1,10p' "$err" >&2
    exit 1
fi
got=$(sed -n '1s/^\(.*\) (Claude Code)$/\1/p' "$out")
if [ -z "$got" ]; then
    echo "  claude: unrecognized --version output: $(sed -n '1p' "$out")" >&2
    exit 1
fi
if [ "$got" != "$want" ]; then
    echo "  claude: installed $got, layer pinned $want" >&2
    exit 1
fi
# The recorded transcript is a single version line; any other non-blank output
# is an unrecognized format (e.g. a warning that merely embeds a version).
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    [ "$lineno" -eq 1 ] && continue
    [ -z "$line" ] && continue
    echo "  claude: unexpected --version output on line $lineno: '$line'" >&2
    exit 1
done <"$out"
echo "  claude: $got (Claude Code)"

python3 "$CONTRACT/check-tool-access.py" claude

mkdir -p "$status_dir"
printf 'installed\n' >"$status"
