#!/bin/sh
# Build-time gate for the copilot tool layer. Bind-mounted into the layer's
# Dockerfile, never COPYed, so it stays out of the shipped image.
#
# The version string is the assertion, not the exit code: a present-but-broken
# or wrong-version `copilot` must fail the build, and copilot keeps running (it
# even prints a version-shaped banner) when the install is subtly wrong. The
# report is bounded and its status is checked BEFORE parsing, so a command that
# prints the expected version and then exits nonzero, or hangs, fails.
#
# The exact output contract is a genuine transcript captured from
# @github/copilot@1.0.90 (see images/tools/copilot/README.md):
#
#   GitHub Copilot CLI 1.0.90.
#   Run 'copilot update' to check for updates.
#
# Only that first line -- the version with its sentence-final period -- plus
# that one known footer line is accepted. Anything else (an extra line, a
# warning that embeds a version, a different banner) fails rather than guessing,
# so a future format change is a reviewable failure instead of a silent
# mis-parse.
set -eu

CONTRACT="${AGENT_VM_CONTRACT_DIR:-/tmp/recipe-contract}"
want="${AGENT_VM_VERSION_COPILOT:?verify-copilot.sh needs AGENT_VM_VERSION_COPILOT}"

if [ -z "$want" ]; then
    echo "  copilot: the layer supplied no version to verify against" >&2
    exit 1
fi

scratch=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf '$scratch'" EXIT INT TERM HUP
out="$scratch/out"
err="$scratch/err"

status=0
sh "$CONTRACT/run-report.sh" 60 "$out" "$err" copilot --version || status=$?
if [ "$status" -ne 0 ]; then
    echo "  copilot: --version exited $status; refusing to accept the report" >&2
    sed -n '1,10p' "$err" >&2
    exit 1
fi
# The report is exact bytes; reject non-printable bytes (a NUL would be erased
# by command substitution and canonicalize a corrupted report).
if [ "$(LC_ALL=C tr -d '\11\12\40-\176' <"$out" | wc -c | tr -d ' ')" != 0 ]; then
    echo "  copilot: --version report contains non-printable bytes -- hard failure" >&2
    exit 1
fi
# A version banner on stderr is a contradictory/duplicate report, not a benign
# progress line; a captured but unparsed stderr must not certify the slot.
if LC_ALL=C grep -Eq '^GitHub Copilot CLI [0-9A-Za-z.+-]+\.$' "$err"; then
    echo "  copilot: --version printed a version report on stderr -- hard failure" >&2
    sed -n '1,10p' "$err" >&2
    exit 1
fi

first=$(sed -n '1p' "$out")
got=$(printf '%s\n' "$first" | sed -n 's/^GitHub Copilot CLI \(.*\)\.$/\1/p')
if [ -z "$got" ]; then
    echo "  copilot: unrecognized --version banner: '$first'" >&2
    exit 1
fi
if [ "$got" != "$want" ]; then
    echo "  copilot: installed $got, layer pinned $want" >&2
    exit 1
fi

# Every line after the banner must be the one documented footer.
footer="Run 'copilot update' to check for updates."
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    [ "$lineno" -eq 1 ] && continue
    [ -z "$line" ] && continue
    if [ "$line" != "$footer" ]; then
        echo "  copilot: unexpected --version output on line $lineno: '$line'" >&2
        exit 1
    fi
done <"$out"
echo "  copilot: $got (pinned)"

# T5: the resolved command and every directory on its path must be usable by an
# arbitrary uid. This follows the PATH symlink into the npm global prefix and
# audits the target and all ancestors; the chmod in the Dockerfile is what
# repairs a narrowed prefix.
python3 "$CONTRACT/check-tool-access.py" copilot

# Only now is the slot healthy: report, exact equality and T5 have all passed.
# Copilot is never soft-failable, but an external audit still reads this record
# (selection labels are not health).
status_dir="${AGENT_VM_INSTALL_STATUS_DIR:-/opt/agent-vm/install-status}"
mkdir -p "$status_dir"
printf 'installed\n' >"$status_dir/copilot"
