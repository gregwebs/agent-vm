#!/usr/bin/env bash
# Run one macOS CI leg exactly as ci.yml runs it, and record the host facts that
# can change its result.
#
# Usage: script/test/ci-macos-legs.sh <leg> [--receipt FILE] [--compare FILE]
#   legs: build-script | keychain-contract
#
# The two macOS legs are the only gates a developer cannot reach through
# `cargo test`, so they used to run under whatever environment the caller had:
# a Homebrew bash 5 where CI has `/bin/bash` 3.2, a Homebrew `jq`, a rustup
# override, a `CARGO_TARGET_DIR`. A difference in any of those is a difference in
# what was tested, and nothing said so.
#
# This script owns the leg's definition -- ci.yml calls it, so local and CI
# cannot drift -- pins the environment the way `e2e-release-contract.sh` does,
# and ends with one receipt line:
#
#   ci-macos-leg leg=build-script host=Darwin arch=arm64 os=15.5 bash=3.2.57 result=pass
#
# `--compare FILE` reads the receipt line out of FILE (a saved receipt or a whole
# downloaded job log) and diffs it against this run's. A `result` difference is a
# failure: the leg did not behave the same on the two hosts. A host-fact
# difference is a note, because that is the risk the receipt exists to expose,
# not a thing the other host can fix.
#
# Written for bash 3.2, which is what `/bin/bash` is on a macOS runner.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: script/test/ci-macos-legs.sh <leg> [--receipt FILE] [--compare FILE]

Run a macOS CI leg under the environment ci.yml gives it, and print a receipt of
the host facts that can change its result.

  build-script        script/test/build-workflow.sh (no toolchain needed)
  keychain-contract   script/test/keychain-contract.sh (needs the pinned rustc)
  harness             the agent-vm-harness crate's checks (needs the pinned rustc)

  --receipt FILE      also write the receipt line to FILE
  --compare FILE      diff this run's receipt against the receipt line in FILE
                      (a saved receipt, or a whole CI job log); a `result`
                      difference fails, a host-fact difference is reported
EOF
}

fail() {
    echo "ci-macos-legs: $*" >&2
    exit 1
}

leg=""
receipt_file=""
compare_file=""
while (($#)); do
    case "$1" in
        build-script | keychain-contract | harness)
            leg="$1"
            shift
            ;;
        --receipt)
            (($# >= 2)) || { usage >&2; exit 2; }
            receipt_file="$2"
            shift 2
            ;;
        --compare)
            (($# >= 2)) || { usage >&2; exit 2; }
            compare_file="$2"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "ci-macos-legs: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done
[[ -n "$leg" ]] || { usage >&2; exit 2; }

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"

[[ "$(uname -s)" == Darwin ]] || fail "the macOS legs run on macOS only"

# The environment the leg gets, and nothing else. `env -i` keeps the caller's
# HOMEBREW_*, GITHUB_*, CARGO_TARGET_DIR, RUSTFLAGS and rustup override out of the
# result; a fixed PATH keeps a Homebrew tool from standing in for the system one;
# a fixed TMPDIR and locale keep temporary paths and sort order the same on both
# hosts. HOME is kept because rustup locates the toolchain under it, exactly as
# it does on a runner.
home="${HOME:?HOME must be set: the Rust toolchain lives under it}"
pinned_path="/usr/bin:/bin:/usr/sbin:/sbin"
have_rustup_cargo=0
if [[ -x "$home/.cargo/bin/cargo" ]]; then
    # CI installs dtolnay/rust-toolchain, so its cargo is this shim, and a
    # developer's version manager may shadow cargo in their own PATH. Keeping it
    # first tests the same cargo on both hosts.
    pinned_path="$home/.cargo/bin:$pinned_path"
    have_rustup_cargo=1
fi

pinned_bash=/bin/bash
# shellcheck disable=SC2016 # the expression expands in the child, which is the pinned bash.
pinned_bash_version="$("$pinned_bash" -c 'echo "${BASH_VERSION%%(*}"')"

run_pinned() {
    env -i \
        HOME="$home" \
        PATH="$pinned_path" \
        TMPDIR=/tmp \
        LC_ALL=C \
        LANG=C \
        TERM=dumb \
        "$@"
}

# bash's own version is the first input a leg has: CI runs it with /bin/bash 3.2,
# so a construct that only bash 4 has passes locally and fails there. Pin the
# interpreter (above) and say when the pinned one moved.
if [[ "$pinned_bash_version" != 3.2* ]]; then
    echo "ci-macos-legs: note: $pinned_bash is bash $pinned_bash_version, while CI's is 3.2.57" >&2
fi

rustc_version=""
# Both toolchain legs are contracts with compiled code, so the toolchain is part
# of the input: CI installs rust-toolchain.toml's channel, and a caller's rustup
# default or override is exactly the kind of difference a green local run would
# hide.
require_pinned_rustc() {
    if ((have_rustup_cargo == 0)); then
        command -v cargo >/dev/null 2>&1 ||
            fail "leg $leg builds Rust, so it needs cargo; install the pinned toolchain"
        pinned_path="$(cd "$(dirname "$(command -v cargo)")" && pwd):$pinned_path"
    fi
    local channel
    channel="$(awk -F'"' '/^channel[[:space:]]*=/ { print $2; exit }' "$REPO_ROOT/rust-toolchain.toml")"
    [[ -n "$channel" ]] || fail "cannot read the pinned channel from rust-toolchain.toml"
    rustc_version="$(run_pinned rustc --version | awk '{ print $2 }')"
    [[ "$rustc_version" == "$channel" ]] ||
        fail "leg $leg needs rustc $channel (rust-toolchain.toml) but this host resolves $rustc_version"
}

case "$leg" in
    build-script)
        # No toolchain step in this job: build-workflow.sh fakes rustc, cargo and
        # rustup, so the leg is logic plus the system tools.
        leg_command=("$pinned_bash" "$REPO_ROOT/script/test/build-workflow.sh")
        ;;
    keychain-contract)
        [[ -x /usr/bin/security ]] ||
            fail "the keychain contract executes /usr/bin/security, which this host lacks"
        require_pinned_rustc
        leg_command=("$pinned_bash" "$REPO_ROOT/script/test/keychain-contract.sh")
        ;;
    harness)
        # ADR-0072: the harness is Rust, so it has to build and pass on macOS and
        # not only on the Linux `contracts` job.
        require_pinned_rustc
        leg_command=(cargo test --locked -p agent-vm-harness)
        ;;
esac

receipt_line() {
    local result="$1" line
    line="ci-macos-leg leg=$leg host=$(uname -s) arch=$(uname -m)"
    line="$line os=$(sw_vers -productVersion) bash=$pinned_bash_version"
    [[ -z "$rustc_version" ]] || line="$line rustc=$rustc_version"
    printf '%s result=%s\n' "$line" "$result"
}

result=pass
if ! run_pinned "${leg_command[@]}"; then
    result=fail
fi
line="$(receipt_line "$result")"
printf '%s\n' "$line"
[[ -z "$receipt_file" ]] || printf '%s\n' "$line" >"$receipt_file"

if [[ -n "$compare_file" ]]; then
    # FILE may be a saved receipt or a whole job log: a runner's log carries
    # carriage returns and colour escapes, and the receipt has to survive both.
    esc="$(printf '\033')"
    theirs="$(tr -d '\r' <"$compare_file" |
        sed "s/$esc\[[0-9;]*[A-Za-z]//g" |
        grep -o 'ci-macos-leg leg=.*' |
        tail -n 1 |
        sed 's/[[:space:]]*$//')" || true
    [[ -n "$theirs" ]] || fail "no receipt line in $compare_file"

    field() { # field <key> <line>
        printf '%s\n' "$2" | tr ' ' '\n' | sed -n "s/^$1=//p"
    }
    [[ "$(field leg "$theirs")" == "$leg" ]] ||
        fail "$compare_file is a receipt for leg $(field leg "$theirs"), not $leg"

    host_diffs=""
    for key in host arch os bash rustc; do
        a="$(field "$key" "$theirs")"
        b="$(field "$key" "$line")"
        [[ -z "$a" && -z "$b" ]] && continue
        [[ "$a" == "$b" ]] || host_diffs="$host_diffs ${key}(ci=${a:-absent},local=${b:-absent})"
    done
    [[ -z "$host_diffs" ]] || echo "ci-macos-legs: host differs:$host_diffs"

    theirs_result="$(field result "$theirs")"
    if [[ "$theirs_result" != "$result" ]]; then
        echo "ci-macos-legs: result differs from $compare_file: result(ci=$theirs_result,local=$result)" >&2
        exit 1
    fi
    echo "ci-macos-legs: same result as $compare_file ($result)"
fi

[[ "$result" == pass ]] || fail "leg $leg failed"
echo "ci-macos-legs: leg $leg passed on this host"
