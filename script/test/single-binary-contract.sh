#!/usr/bin/env bash
# Boot-free single-binary release contracts. No real runtime or VM is needed.
# Backticks in diagnostic literals are intentional.
# shellcheck disable=SC2016
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/avm-single.XXXXXX")"
# macOS TMPDIR may use /var, while resolved executable siblings use /private/var.
tmp="$(cd "$tmp" && pwd -P)"
trap 'chmod -R u+w "$tmp"; rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "$1 PASS"; }
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' vendor/microsandbox/Cargo.toml | head -1)"
mkdir -p "$tmp/payload" "$tmp/dist" "$tmp/project"
cat >"$tmp/payload/msb" <<EOF
#!/bin/bash
case "\${1:-}" in
    --version) echo 'msb $version' ;;
    probe) printf 'MSB_PATH=%s LIB=%s SELF=%s\\n' "\${MSB_PATH:-}" "\${MSB_LIBKRUNFW_PATH:-}" "\$0" ;;
    *) exit 40 ;;
esac
# pad
EOF
chmod 755 "$tmp/payload/msb"
dd if=/dev/zero of="$tmp/payload/lib" bs=4096 count=1 2>/dev/null
export AGENT_VM_EMBED_MSB="$tmp/payload/msb" AGENT_VM_EMBED_LIBKRUNFW="$tmp/payload/lib"
export CARGO_TARGET_DIR="$REPO_ROOT/target/single-binary-contract"
cargo build --locked -p agent-vm --features embedded-runtime
cp "$CARGO_TARGET_DIR/debug/agent-vm" "$tmp/dist/agent-vm"
cargo clippy --locked -p agent-vm --features embedded-runtime -- -D warnings
binary="$tmp/dist/agent-vm"
new_case() {
    home="$tmp/$1/home"; state="$tmp/$1/state"
    mkdir -p "$home" "$state"
    cache="$home/.cache/agent-vm/runtime"
}
run() {
    env -u XDG_CACHE_HOME -u XDG_STATE_HOME -u MSB_PATH -u MSB_LIBKRUNFW_PATH \
        HOME="$home" AGENT_VM_STATE_DIR="$state" "$@"
}
expect_failure() {
    local status=0
    run "$@" >"$tmp/out" 2>"$tmp/err" || status=$?
    [[ "$status" == 1 ]] || fail "expected exit 1, got $status"
}
contains() { grep -F -- "$1" "$tmp/err" >/dev/null || fail "missing diagnostic: $1"; }
mode() {
    local result
    if result="$(stat -f '%Lp' "$1" 2>/dev/null)"; then :; else result="$(stat -c '%a' "$1")"; fi
    printf '%s' "$result"
}
new_case c1
[[ "$(run "$binary" msb --version)" == "msb $version" ]] || fail C1
pass C1
probe="$(run "$binary" msb probe)"
msbs=("$cache"/*/bin/msb)
[[ ${#msbs[@]} == 1 && -f "${msbs[0]}" ]] || fail "runtime count"
msb="${msbs[0]}"; dir="${msb%/bin/msb}"
libs=("$dir"/lib/*); lib="${libs[0]}"
[[ "${dir##*/}" =~ ^[0-9a-f]{16}$ ]] || fail "runtime id"
[[ "$probe" == "MSB_PATH=$msb LIB=$lib SELF=$msb" ]] || fail "$probe"
[[ "$(mode "$msb")/$(mode "$lib")/$(mode "$dir")" == 755/644/700 ]] || fail modes
pass C2
before="$(ls -i "$msb" "$lib")"
run "$binary" msb probe >/dev/null
[[ "$(ls -i "$msb" "$lib")" == "$before" ]] || fail "republished runtime"
pass C3
new_case c4
pids=()
for n in 1 2 3 4 5 6 7 8; do run "$binary" msb --version >"$tmp/parallel-$n" & pids+=("$!"); done
for pid in "${pids[@]}"; do wait "$pid" || fail concurrency; done
for n in 1 2 3 4 5 6 7 8; do [[ "$(cat "$tmp/parallel-$n")" == "msb $version" ]] || fail concurrency-output; done
entries=("$cache"/*); [[ ${#entries[@]} == 1 ]] || fail "multiple runtimes"
[[ -z "$(find "$cache" -name '.stage-*' -print)" ]] || fail "stage leaked"
pass C4
for which in msb lib; do
    new_case "c5-$which"
    run "$binary" msb --version >/dev/null
    dirs=("$cache"/*); dir="${dirs[0]}"
    files=("$dir"/lib/*)
    if [[ "$which" == msb ]]; then file="$dir/bin/msb"; else file="${files[0]}"; fi
    printf x >>"$file"
    expect_failure "$binary" msb --version
    contains 'does not match the runtime embedded in this binary'; contains "${file##*/}"; contains 'rm -rf'
    pass "C5-$which"
done
new_case c5c
run "$binary" msb --version >/dev/null
dirs=("$cache"/*); dir="${dirs[0]}"; files=("$dir"/lib/*); lib="${files[0]}"
length="$(wc -c <"$dir/bin/msb")"
printf X | dd of="$dir/bin/msb" bs=1 seek="$((length - 2))" conv=notrunc 2>/dev/null
printf X | dd of="$lib" bs=1 conv=notrunc 2>/dev/null
run "$binary" msb --version >/dev/null
rm -rf "$dir"
run "$binary" msb --version >/dev/null
cmp "$dir/bin/msb" "$tmp/payload/msb"; cmp "$lib" "$tmp/payload/lib"
pass C5c
new_case c6
printf occupied >"$home/.cache"
expect_failure "$binary" msb --version
contains 'could not unpack its embedded `msb` runtime'; contains XDG_CACHE_HOME
pass C6
new_case c7
if [[ "$(id -u)" == 0 ]]; then echo 'C7 SKIP: root'; else
    mkdir "$home/.cache"; chmod 555 "$home/.cache"
    expect_failure "$binary" msb --version
    contains 'could not unpack its embedded `msb` runtime'; contains XDG_CACHE_HOME
    chmod 755 "$home/.cache"; pass C7
fi
new_case c8
mkdir "$tmp/bundle"
cp "$binary" "$tmp/bundle/agent-vm"; cp "$tmp/payload/msb" "$tmp/bundle/msb"
[[ "$(run "$tmp/bundle/agent-vm" msb probe)" == "MSB_PATH=$tmp/bundle/msb LIB= SELF=$tmp/bundle/msb" ]] || fail C8
[[ ! -e "$home/.cache/agent-vm" ]] || fail "bundle unpacked"
pass C8
new_case c9
[[ "$(run env MSB_PATH="$tmp/payload/msb" "$binary" msb probe)" == "MSB_PATH=$tmp/payload/msb LIB= SELF=$tmp/payload/msb" ]] || fail C9
[[ ! -e "$home/.cache/agent-vm" ]] || fail "explicit unpacked"
pass C9
new_case c10
mkdir -p "$home/.config/agent-vm"
: >"$home/.config/agent-vm/config.toml"
status=0
(cd "$tmp/project" && run env GIT_CEILING_DIRECTORIES="$tmp" "$binary" --no-git --image localhost:1/does-not-exist:latest --mount "$home/.config" shell) >"$tmp/out" 2>"$tmp/err" || status=$?
[[ "$status" != 0 ]] || fail C10
contains 'would let the guest change'
[[ -z "$(find "$state" -mindepth 1 -print -quit)" ]] || fail 'rejected launch created state'
files=("$cache"/*/bin/msb); [[ -f "${files[0]}" ]] || fail 'C10 vacuous'
pass C10
new_case c11
expect_failure env -u HOME -u XDG_CACHE_HOME "$binary" msb --version
contains 'could not unpack its embedded `msb` runtime'; contains 'set XDG_CACHE_HOME or HOME'
pass C11
new_case c12
# `image show` must return before runtime discovery, so the embedded payload is
# never unpacked. Only this case's own home/state are asserted: the harness
# pre-creates both roots on purpose.
(
    cd "$tmp/project"
    env -u XDG_CACHE_HOME -u XDG_STATE_HOME -u MSB_PATH -u MSB_LIBKRUNFW_PATH \
        -u AGENT_VM_IMAGE_TAG -u AGENT_VM_TEST_DEFAULT_IMAGE \
        HOME="$home" AGENT_VM_STATE_DIR="$state" "$binary" image show
) >"$tmp/c12.out" 2>"$tmp/c12.err" || fail "C12: image show failed: $(cat "$tmp/c12.err")"
grep -q '^Image: ' "$tmp/c12.out" || fail "C12: missing Image line"
grep -qx 'Source: initial recommendation' "$tmp/c12.out" || fail "C12: wrong source: $(cat "$tmp/c12.out")"
grep -q '^File: ' "$tmp/c12.out" && fail "C12: an initial recommendation has no source file"
[[ ! -s "$tmp/c12.err" ]] || fail "C12: stderr not empty: $(cat "$tmp/c12.err")"
[[ ! -e "$home/.config/agent-vm" ]] || fail "C12: created a configuration directory"
[[ ! -e "$home/.cache/agent-vm" ]] || fail "C12: unpacked the embedded runtime"
[[ -z "$(ls -A "$state")" ]] || fail "C12: created runtime state"
pass C12
echo 'single-binary contracts passed'
