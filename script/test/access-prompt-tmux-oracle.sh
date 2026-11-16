#!/usr/bin/env bash
# The access prompt's independent oracle: tmux 3.8 renders the frames
# `access_prompt::screen` builds, and every case is checked against the terminal
# state the guest had (ADR-0069, #501 slice 3 §10.3).
#
# The tests are `#[ignore]` in the crate because they need a `tmux` binary; this
# script is the one way to run them, so CI and a laptop agree.
set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"

if ! command -v tmux >/dev/null 2>&1; then
    echo "SKIP: access-prompt tmux oracle — tmux is not on PATH" >&2
    echo "      the oracle is the independent check of the prompt's byte frames;" >&2
    echo "      install tmux and re-run script/test/access-prompt-tmux-oracle.sh" >&2
    exit 0
fi

echo "access-prompt tmux oracle: $(tmux -V)"
cd "$REPO_ROOT"
exec cargo test -p agent-vm --bin agent-vm access_prompt::tmux_oracle -- --ignored --test-threads=1 "$@"
