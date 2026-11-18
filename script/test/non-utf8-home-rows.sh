#!/usr/bin/env bash
# Run the two non-UTF-8 HOME rows uncaptured, and fail if either skipped (#626).
#
# libtest captures a test's stderr and reports a row that returned early as
# `ok`, so its `SKIPPED` line is invisible in a green job and the row proves
# nothing -- which is how #609 shipped an unproved promise behind a green run.
# The rows now fail rather than skip on Linux, where the filesystem accepts
# these names; macOS refuses them (`EILSEQ`, errno 92), so this runs on Linux
# only. It exists to put their execution, and what they asserted, in the job
# log, and to fail if either one stops running.
set -euo pipefail

# Nothing to prove off Linux: macOS refuses the name itself (`EILSEQ`), so both
# rows legitimately skip there. ci.yml runs this step on the Ubuntu shard.
if [[ "$(uname -s)" != Linux ]]; then
    echo "non-utf8-home-rows: not Linux; this filesystem cannot hold the name, so there is nothing to run"
    exit 0
fi

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
cd "$REPO_ROOT"

rows=(
    s14_an_invalid_utf8_home_path_is_escaped_bytewise
    pins_accepts_absolute_non_utf8_home_and_doctor_escapes_path
)
log="$(mktemp)"
trap 'rm -f "$log"' EXIT

status=0
cargo test -p agent-vm --test image_show -- --nocapture --exact "${rows[@]}" >"$log" 2>&1 ||
    status=$?
cat "$log"
if ((status != 0)); then
    echo "non-utf8-home-rows: cargo test failed (exit $status)" >&2
    exit 1
fi
if grep -q '^SKIPPED ' "$log"; then
    echo "non-utf8-home-rows: a row skipped instead of running" >&2
    exit 1
fi
# `--exact` names two rows, so a filter that matches nothing is not a failure of
# its own: without this count the step would pass having run zero rows.
grep -q 'test result: ok\. 2 passed' "$log" || {
    echo "non-utf8-home-rows: expected both rows to run, not only a subset" >&2
    exit 1
}
echo "non-utf8-home-rows: both non-UTF-8 HOME rows executed, no skip"
