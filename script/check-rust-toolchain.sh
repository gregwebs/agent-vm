#!/usr/bin/env bash
# Assert every enforced consumer of the pinned Rust toolchain agrees with the
# canonical pin in rust-toolchain.toml's [toolchain].channel (see that file's
# header for why this is the owner). No consumer's value is changed here --
# this only enforces that the duplicated literals stay in lockstep, with an
# actionable diagnostic naming the file, the drifted value, and the fix.
#
# Enforced consumers and why each is a separate literal that can't just read
# rust-toolchain.toml directly:
#   - Cargo.toml rust-version (workspace.package): Cargo's declared MSRV,
#     kept in exact lockstep with the channel by policy (see its comment).
#   - .github/workflows/ci.yml: dtolnay/rust-toolchain's `toolchain:` input,
#     pinned explicitly rather than auto-read for CI-install auditability.
#   - .github/workflows/release-npm.yml: two explicit
#     `rustup toolchain install` legs, same reproducibility rationale.
#   - script/build/macos.sh: its own RUST_TOOLCHAIN copy (so the script never
#     depends on or changes the caller's global default toolchain), the
#     numeric floor guard, and the two hardcoded error messages.
#   - macos-build.md: contributor-facing copy-paste install/run commands. A
#     stale one actively misleads a contributor, so every occurrence of the
#     three anchor commands is checked, not merely their presence.
#
# Deliberately NOT enforced (see the implementation plan for issue #59):
#   - script/test/build-workflow.sh's fake rustc/cargo/rustup fixtures --
#     already fail-closed because a stale fixture makes the test's own
#     assertions fail when it runs; checking them here would be circular.
#   - docs/adr/0005's "Rust 1.94 pin" mentions -- a frozen historical record
#     of the pin at decision time, not a copy that should track future bumps.
#
# False-positive trap:
# Every pattern below is anchored to its surrounding keyword
# (RUST_TOOLCHAIN=, "minor < ", "Rust ... or newer", "rustup toolchain
# install ", "rustup run ", "rustup component add cargo --toolchain ") so a
# blanket version-token scan is never used and these tokens are never
# mistaken for the pin.
#
# Channel form: two-component MAJOR.MINOR (currently 1.94). An optional patch
# component (1.94.0) is tolerated by normalizing to MAJOR.MINOR for the
# numeric floor-guard comparison; the string-literal consumers require exact
# equality to the canonical channel string as written.
#
# Usage: script/check-rust-toolchain.sh [--root DIR] [--print]
#   --root DIR   Treat DIR as the repository root (default: this script's own
#                repo root). Test seam: script/test/rust-toolchain-consistency.sh
#                points this at a synthetic tree of copied, mutated files.
#   --print      Print only the canonical channel value to stdout and exit 0.
# Exit: 0 = all consumers agree (or --print). 1 = one or more drifted.
#       2 = usage error, or the canonical channel could not be read.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: script/check-rust-toolchain.sh [--root DIR] [--print]

Verify every enforced consumer of the pinned Rust toolchain agrees with the
canonical pin in rust-toolchain.toml's [toolchain].channel.

  --root DIR   Treat DIR as the repository root (default: this script's own
               repo root).
  --print      Print only the canonical channel value to stdout and exit 0.
EOF
}

failures=0

ok() {
    printf '  ok  %s\n' "$1"
}

fail() {
    printf '  FAIL %s\n' "$1"
    failures=$((failures + 1))
}

fail_missing_anchor() {
    local file="$1" description="$2"
    fail "could not locate the pin in $file ($description); the anchor may have been reworded -- update this script's pattern for it"
}

check_cargo_toml() {
    local file=Cargo.toml found
    found="$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' "$file")"
    if [[ -z "$found" ]]; then
        fail_missing_anchor "$file" 'rust-version = "..." under [workspace.package]'
        return
    fi
    if [[ "$found" == "$channel" ]]; then
        ok "$file rust-version = $found"
        return
    fi
    fail "$file rust-version is $found but canonical channel is $channel"
    printf '       fix: set rust-version = "%s" in %s (workspace.package), or update rust-toolchain.toml if %s was intended.\n' \
        "$channel" "$file" "$found"
}

check_ci_yml() {
    local file=.github/workflows/ci.yml found
    found="$(sed -n 's/^[[:space:]]*toolchain: "\(.*\)"$/\1/p' "$file")"
    if [[ -z "$found" ]]; then
        fail_missing_anchor "$file" 'toolchain: "..." (dtolnay/rust-toolchain input)'
        return
    fi
    if [[ "$found" == "$channel" ]]; then
        ok "$file toolchain = $found"
        return
    fi
    fail "$file toolchain is $found but canonical channel is $channel"
    printf '       fix: set toolchain: "%s" in %s, or update rust-toolchain.toml if %s was intended.\n' \
        "$channel" "$file" "$found"
}

check_release_npm() {
    local file=.github/workflows/release-npm.yml
    local -a occurrences=()
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] && occurrences+=("$line")
    done < <(grep -oE 'rustup toolchain install [0-9]+\.[0-9]+(\.[0-9]+)?' "$file" || true)

    if ((${#occurrences[@]} == 0)); then
        fail_missing_anchor "$file" 'rustup toolchain install <version>'
        return
    fi
    if ((${#occurrences[@]} != 2)); then
        fail "$file has ${#occurrences[@]} 'rustup toolchain install' occurrence(s) but expected 2 (one per release leg)"
        printf '       fix: restore exactly two "rustup toolchain install %s" legs in %s.\n' "$channel" "$file"
        return
    fi

    local occurrence version mismatch=false
    for occurrence in "${occurrences[@]}"; do
        version="${occurrence##* }"
        if [[ "$version" != "$channel" ]]; then
            mismatch=true
            fail "$file has \"$occurrence\" but canonical channel is $channel"
            printf '       fix: change this occurrence in %s to "rustup toolchain install %s", or update rust-toolchain.toml if %s was intended.\n' \
                "$file" "$channel" "$version"
        fi
    done
    [[ "$mismatch" == true ]] || ok "$file rustup toolchain install (2 occurrences) = $channel"
}

check_macos_rust_toolchain_var() {
    local file=script/build/macos.sh found
    found="$(sed -n 's/^RUST_TOOLCHAIN=\(.*\)$/\1/p' "$file")"
    if [[ -z "$found" ]]; then
        fail_missing_anchor "$file" 'RUST_TOOLCHAIN=...'
        return
    fi
    if [[ "$found" == "$channel" ]]; then
        ok "$file RUST_TOOLCHAIN = $found"
        return
    fi
    fail "$file RUST_TOOLCHAIN is $found but canonical channel is $channel"
    printf '       fix: set RUST_TOOLCHAIN=%s in %s, or update rust-toolchain.toml if %s was intended.\n' \
        "$channel" "$file" "$found"
}

check_macos_floor_guard() {
    local file=script/build/macos.sh found floor
    found="$(grep -oE 'minor < [0-9]+' "$file" | head -n1 || true)"
    if [[ -z "$found" ]]; then
        fail_missing_anchor "$file" 'the "minor < N" floor guard'
        return
    fi
    floor="${found##* }"
    if [[ "$floor" == "$channel_minor" ]]; then
        ok "$file floor guard minor = $floor"
        return
    fi
    fail "$file floor guard checks minor < $floor but canonical channel minor is $channel_minor"
    printf '       fix: change the floor guard in %s to minor < %s, or update rust-toolchain.toml if minor %s was intended.\n' \
        "$file" "$channel_minor" "$floor"
}

check_macos_build_md() {
    local file=macos-build.md
    local -a occurrences=()
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] && occurrences+=("$line")
    done < <(grep -oE \
        '(rustup toolchain install|rustup run|rustup component add cargo --toolchain) [0-9]+\.[0-9]+(\.[0-9]+)?' \
        "$file" || true)

    if ((${#occurrences[@]} == 0)); then
        fail_missing_anchor "$file" 'rustup toolchain install/run/component-add commands'
        return
    fi

    local occurrence version mismatch=false
    for occurrence in "${occurrences[@]}"; do
        version="${occurrence##* }"
        if [[ "$version" != "$channel" ]]; then
            mismatch=true
            fail "$file has the command \"$occurrence\" but canonical channel is $channel"
            printf '       fix: update this contributor-facing command in %s to use %s, or update rust-toolchain.toml if %s was intended.\n' \
                "$file" "$channel" "$version"
        fi
    done
    [[ "$mismatch" == true ]] || ok "$file install/run commands match $channel (${#occurrences[@]} occurrences)"
}

main() {
    local repo_root print_only=false
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    while (($#)); do
        case "$1" in
            --root)
                [[ $# -ge 2 ]] || { echo "usage: --root requires an argument" >&2; usage >&2; exit 2; }
                repo_root="$2"
                shift 2
                ;;
            --print)
                print_only=true
                shift
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                usage >&2
                exit 2
                ;;
        esac
    done

    cd "$repo_root" || {
        echo "error: --root $repo_root is not a directory" >&2
        exit 2
    }

    local toolchain_toml=rust-toolchain.toml
    [[ -f "$toolchain_toml" ]] || {
        echo "error: could not read [toolchain].channel from $toolchain_toml: file not found" >&2
        exit 2
    }

    channel="$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$toolchain_toml")"
    [[ -n "$channel" ]] || {
        echo "error: could not read [toolchain].channel from $toolchain_toml" >&2
        exit 2
    }

    local channel_major="${channel%%.*}" channel_rest="${channel#*.}"
    channel_minor="${channel_rest%%.*}"
    [[ "$channel_major" =~ ^[0-9]+$ && "$channel_minor" =~ ^[0-9]+$ ]] || {
        echo "error: could not parse a MAJOR.MINOR channel from $toolchain_toml: $channel" >&2
        exit 2
    }

    if [[ "$print_only" == true ]]; then
        printf '%s\n' "$channel"
        exit 0
    fi

    printf 'rust-toolchain: canonical channel %s (owner: %s [toolchain].channel)\n' "$channel" "$toolchain_toml"

    check_cargo_toml
    check_ci_yml
    check_release_npm
    check_macos_rust_toolchain_var
    check_macos_floor_guard
    check_macos_build_md

    if ((failures > 0)); then
        echo "error: $failures rust-toolchain consumer(s) drifted from $toolchain_toml" >&2
        exit 1
    fi
    echo "rust-toolchain: all consumers agree"
}

# channel/channel_minor are set by main() and read by the check_* functions
# above; deliberately not passed as arguments since every check needs both
# and this is a single-purpose script, not a library.
channel=
channel_minor=

main "$@"
