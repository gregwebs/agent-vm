#!/usr/bin/env bash
# Black-box tests for the copilot layer's install hook
# (images/tools/copilot/install-copilot.sh): the exact canonical version
# grammar is enforced BEFORE npm is invoked, and a canonical selection reaches
# npm.
#
# No Docker, no network, no real npm: `npm` is faked (logging every invocation)
# and `rm` is shadowed so the hook's `rm -rf /root/.npm` cannot touch a real
# host tree.
set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
INSTALL="$REPO_ROOT/images/tools/copilot/install-copilot.sh"

TEST_ROOT="$(mktemp -d /tmp/copilot-installer.XXXXXX)"
chmod 0755 "$TEST_ROOT"
trap 'rm -rf "$TEST_ROOT"' EXIT

REAL_RM="$(command -v rm)"
REAL_RMDIR="$(command -v rmdir)"
CASE=""

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

new_case() {
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/bin" "$CASE/global"
    chmod 0755 "$CASE" "$CASE/bin" "$CASE/global"
    # Fake npm: records every invocation and creates the (case-local) global
    # tree so the hook's `chmod -R` and `npm root -g` succeed.
    cat >"$CASE/bin/npm" <<'SH'
#!/bin/sh
printf 'npm %s\n' "$*" >>"$FAKE_NPM_LOG"
case "$1" in
    root) printf '%s\n' "$FAKE_NPM_ROOT" ;;
    install)
        mkdir -p "$FAKE_NPM_ROOT/@github/copilot"
        printf '{}\n' >"$FAKE_NPM_ROOT/@github/copilot/package.json"
        ;;
esac
exit 0
SH
    # Fake rm: the hook must never delete a real tree from this hermetic test.
    # It no-ops the known `/root/.npm` cleanup and runs the real rm otherwise.
    cat >"$CASE/bin/rm" <<SH
#!/bin/sh
case "\$*" in
    */root/.npm*) exit 0 ;;
esac
exec "$REAL_RM" "\$@"
SH
    # Fake rmdir/rm are not otherwise needed, but keep a real rmdir off the
    # shadowed name space to avoid surprises.
    cp "$REAL_RMDIR" "$CASE/bin/rmdir" 2>/dev/null || true
    chmod 0755 "$CASE/bin/npm" "$CASE/bin/rm"
    : >"$CASE/npm.log"
}

run_install() {
    set +e
    RUN_OUTPUT="$(
        env -i \
            "PATH=$CASE/bin:/usr/bin:/bin" \
            "AGENT_VM_VERSION_COPILOT=$1" \
            "FAKE_NPM_LOG=$CASE/npm.log" \
            "FAKE_NPM_ROOT=$CASE/global" \
            sh "$INSTALL" 2>&1
    )"
    RUN_STATUS=$?
    set -e
}

# Canonical selections reach npm.
for good in 1.0.90 1.0.0-beta.1 1.0.0+build.1; do
    new_case "accept-$(printf '%s' "$good" | tr -c 'A-Za-z0-9' '_')"
    run_install "$good"
    [[ $RUN_STATUS -eq 0 ]] || fail "canonical version '$good' must be accepted: $RUN_OUTPUT"
    [ -s "$CASE/npm.log" ] || fail "canonical version '$good' must reach npm"
    grep -q "@github/copilot@$good" "$CASE/npm.log" ||
        fail "canonical version '$good' must be handed to npm intact"
done

# Floating/noncanonical inputs are rejected BEFORE npm is invoked.
for bad in latest next '^1.0.0' '1.0' '1.0.0 2.0.0' 'https://x/1.0.90' '1.0.90 ' \
    '01.0.90' '1.00.90' '1.0.090' '1.0.0-01' '1.0.0-alpha.01'; do
    new_case "reject-$(printf '%s' "$bad" | tr -c 'A-Za-z0-9' '_')"
    run_install "$bad"
    [[ $RUN_STATUS -ne 0 ]] || fail "version '$bad' must be rejected"
    [ ! -s "$CASE/npm.log" ] ||
        fail "version '$bad' must be rejected before npm runs: $(cat "$CASE/npm.log")"
done

echo "copilot-installer black-box tests passed"
