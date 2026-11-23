#!/usr/bin/env bash
# The real notification helper, built, signed and executed (issue #501 slice 4,
# S5/S6). macOS only: it compiles Swift and runs `plutil`, `lipo` and `codesign`.
#
# `script/build/macos.sh` is what produces the shipped helper, and
# `build-workflow.sh` already checks its sequencing against fake tools. This is the
# other half: the same source, compiled by the same compiler with the same flags,
# inside a throwaway bundle in a temp directory. Nothing here writes to a real
# install, and nothing registers a bundle with LaunchServices, so an operator's
# own `dev.agent-vm.notifier` and its notification permission are untouched.
#
# What it proves without a GUI session:
#
#   * the Swift source compiles for the target the shipped bundle uses;
#   * the stamped `Info.plist` is a valid property list;
#   * the binary is arm64-only, as the release artifact must be;
#   * an ad-hoc signature with the shared identifier verifies under
#     `--deep --strict`;
#   * `--version` answers without starting AppKit;
#   * `--check-bundle` exits 0 with a sibling `bin/agent-vm`, and non-zero
#     without one, which is the helper's one discovery rule (S4).
set -euo pipefail

[[ "$(uname -s)" == Darwin ]] || {
    echo 'error: notifier-contract.sh compiles and executes the macOS helper, so it runs on macOS only' >&2
    exit 1
}

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
cd "$REPO_ROOT"

APP_NAME=AgentVMNotifier
BUNDLE_ID=dev.agent-vm.notifier

fail() {
    echo "notifier-contract: $*" >&2
    exit 1
}

for tool in swiftc plutil lipo codesign; do
    command -v "$tool" >/dev/null 2>&1 ||
        fail "$tool was not found on PATH; install the Xcode Command Line Tools with 'xcode-select --install'"
done

# `[workspace.package] version` from Cargo.toml, read by hand for the same reason
# `script/build/macos.sh` reads it by hand: the only consumer is one plist string,
# and a `cargo` invocation would put a toolchain on a Swift-only leg.
workspace_version() {
    local line

    while IFS= read -r line; do
        case "$line" in
            'version = "'*'"')
                line="${line#version = \"}"
                printf '%s\n' "${line%\"}"
                return 0
                ;;
        esac
    done <Cargo.toml
    fail "Cargo.toml has no workspace version line to stamp the helper with"
}
version="$(workspace_version)"
[[ -n "$version" ]] || fail "the workspace version is empty"

work="$(mktemp -d "${TMPDIR:-/tmp}/notifier-contract.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# The bundle root holds `bin/` and `lib/`, which is the layout the helper's
# sibling-only discovery reads: `lib/AgentVMNotifier.app/../../bin/agent-vm`.
root="$work/root"
app="$root/lib/$APP_NAME.app"
contents="$app/Contents"
mkdir -p "$contents/MacOS" "$root/bin"

# A stub launcher: only existence and the executable bit are inspected here, and
# no click is ever played.
printf '#!/bin/sh\nexit 0\n' >"$root/bin/agent-vm"
chmod 0755 "$root/bin/agent-vm"

# macOS 12 is the floor because `interruptionLevel` is 12.0, and the language mode
# is pinned so a future compiler default cannot change the concurrency rules
# under this file. Both flags are the shipped build's (`script/build/macos.sh`).
swiftc -swift-version 5 -O -target arm64-apple-macosx12.0 \
    -o "$contents/MacOS/$APP_NAME" macos/notifier/Notifier.swift ||
    fail "swiftc could not compile macos/notifier/Notifier.swift"

# Silence is a promise the specification makes and no GUI session can observe: a
# banner may arrive every 3 s, so it must not be audible. `content.sound` is only
# reachable inside the helper's own process, so this pins the two source lines that
# decide it — the authorization request and the post — and names the ADR.
swift_source="$(cat macos/notifier/Notifier.swift)"
case "$swift_source" in
    *"requestAuthorization(options: [.alert, .sound])"*)
        fail "the helper asks for notification permission with sound; ADR-0073 keeps banners silent"
        ;;
    *"content.sound = "*)
        fail "the helper sets content.sound; ADR-0073 keeps banners silent"
        ;;
esac

# The template is stamped exactly as the shipped build stamps it, so a placeholder
# that survived substitution fails the version check below rather than a lint.
template="$(cat macos/notifier/Info.plist.in)"
[[ "$template" == *__AGENT_VM_VERSION__* ]] ||
    fail "macos/notifier/Info.plist.in has no __AGENT_VM_VERSION__ placeholder to stamp"
printf '%s\n' "${template//__AGENT_VM_VERSION__/$version}" >"$contents/Info.plist"

plutil -lint "$contents/Info.plist" >/dev/null ||
    fail "$contents/Info.plist is not a valid property list"
[[ "$(plutil -extract CFBundleIdentifier raw "$contents/Info.plist")" == "$BUNDLE_ID" ]] ||
    fail "the stamped plist does not carry CFBundleIdentifier $BUNDLE_ID"

archs="$(lipo -archs "$contents/MacOS/$APP_NAME")"
[[ "$archs" == arm64 ]] || fail "the helper must be arm64-only; found: $archs"

codesign --force --sign - --identifier "$BUNDLE_ID" "$app" ||
    fail "codesign could not sign $app ad-hoc"
codesign --verify --deep --strict "$app" ||
    fail "$app does not have a valid code signature"

reported="$("$contents/MacOS/$APP_NAME" --version)" ||
    fail "the helper failed to run with --version"
[[ "$reported" == "agent-vm-notifier $version" ]] ||
    fail "the helper reports '$reported'; expected 'agent-vm-notifier $version'"

# A positive `--check-bundle`: identifier and sibling launcher both resolve, so it
# answers with one JSON line and exits 0. The `type` is deliberately not a v1
# launcher event, which is what lets a launcher skip it.
checked="$("$contents/MacOS/$APP_NAME" --check-bundle)" ||
    fail "the helper refused a bundle that has a sibling bin/agent-vm: $checked"
case "$checked" in
    *'"ok":true'*) ;;
    *) fail "--check-bundle did not answer ok:true: $checked" ;;
esac
# The JSON escapes the separators, so the launcher is named as `bin\/agent-vm`.
case "$checked" in
    *'bin\/agent-vm'*) ;;
    *) fail "--check-bundle did not name the sibling launcher: $checked" ;;
esac

# And the negative control: the same bundle without a launcher must say so and
# fail, because a click that cannot open a session is not a working install.
rm -f "$root/bin/agent-vm"
status=0
checked="$("$contents/MacOS/$APP_NAME" --check-bundle)" || status=$?
((status != 0)) ||
    fail "--check-bundle exited 0 with no sibling bin/agent-vm (answer: $checked)"
case "$checked" in
    *'"ok":false'*) ;;
    *) fail "--check-bundle did not answer ok:false: $checked" ;;
esac
case "$checked" in
    *'no executable sibling at bin\/agent-vm'*) ;;
    *) fail "--check-bundle did not explain the missing launcher: $checked" ;;
esac

echo "notifier-contract: OK ($reported; $archs; $BUNDLE_ID; --check-bundle 0 with a launcher, $status without)"
