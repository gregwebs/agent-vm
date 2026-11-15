#!/usr/bin/env bash
# The real `/usr/bin/security` contract for the keychain host credential
# location (#497, ADR-0056). macOS only: the test executes the system binary.
#
# Everything the test does is isolated — it creates a uniquely named keychain in
# a temporary directory, names it explicitly on every item operation, and deletes
# it — so this is runnable on a Mac that holds a real login item. Nothing it
# prints comes from a credential: the fixtures are canaries and the reader never
# renders item bytes.
set -euo pipefail

[[ "$(uname -s)" == Darwin ]] || {
    echo 'error: the keychain contract executes /usr/bin/security, so it runs on macOS only' >&2
    exit 1
}

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
cd "$REPO_ROOT"

export AGENT_VM_REAL_KEYCHAIN_CONTRACT=1
cargo test -p agent-vm --bin agent-vm real_security_contract -- --ignored --nocapture
