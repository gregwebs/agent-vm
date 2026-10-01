#!/usr/bin/env bash
# Developer write tool: resolve each single-slot installer layer's current
# upstream release and stage the reviewed exact default in its Dockerfile.
#
# Usage: script/build/agent-versions.sh --write [--repo-root DIR]
#        script/build/agent-versions.sh --help
#
# This is an EXPLICIT developer step, never a build or CI step. Orthogonal builds
# consume the committed exact `ARG AGENT_VERSION_*` defaults; nothing resolves
# "latest" at build time. After a run: review `git diff`, run the owning installer
# tests / the Docker audit, then commit -- the version bump and the rebuilt
# binary that embeds the Dockerfiles land together.
#
# It resolves exactly the four sources the single-slot installers install from:
#   - codex:    openai/codex releases/latest tag -> canonical `rust-v<semver>`
#   - opencode: anomalyco/opencode releases/latest tag -> canonical `v<semver>`
#   - claude:   downloads.claude.ai native channel `/latest` -> bare `<semver>`
#   - copilot:  npm `@github/copilot` latest -> bare `<semver>`
# dsh and pi are lock-backed layers with EMPTY version ARGs; their pins (and
# generated LABEL fallbacks) are bumped by images/tools/{dsh,pi}/upgrade-*.sh.
#
# GitHub API calls are authenticated with $GH_TOKEN when set; the token never
# appears in diagnostics. Rejected before any network call under GITHUB_ACTIONS,
# so an accidental workflow reintegration fails instead of silently restoring a
# build-time latest resolution.

set -euo pipefail

case "${BASH_SOURCE[0]}" in
    */*) script_dir_path="${BASH_SOURCE[0]%/*}" ;;
    *) script_dir_path=. ;;
esac
# shellcheck source=/dev/null
. "$script_dir_path/npm-pin.sh"

usage() {
    cat <<'EOF'
Usage: script/build/agent-versions.sh --write [--repo-root DIR]
       script/build/agent-versions.sh --help

Resolve the current upstream release of each single-slot installer layer and
stage the reviewed exact default in the owning Dockerfile. This is a developer
write tool: it performs no commit, build, or push, and it refuses to run under
GitHub Actions.
EOF
}

fail() {
    echo "error: $1" >&2
    exit 1
}

repo_root=
write=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        --write)
            write=true
            ;;
        --repo-root)
            [ "$#" -ge 2 ] || fail "--repo-root requires a directory"
            repo_root="$2"
            shift
            ;;
        --help | -h)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if [ "$write" != true ]; then
    usage >&2
    exit 2
fi

if [ "${GITHUB_ACTIONS:-}" = true ]; then
    fail "refusing to run under GitHub Actions: version bumps are an explicit developer step"
fi

if [ -z "$repo_root" ]; then
    repo_root="$(cd "$script_dir_path/../.." && pwd)"
fi
[ -d "$repo_root" ] || fail "--repo-root is not a directory: $repo_root"
repo_root="$(cd "$repo_root" && pwd -P)"

# Fail before a lookup so an HTTP-200-but-garbage response reports a per-tool
# message instead of this chokepoint.
require_tools curl jq npm

github_latest_tag() {
    local repo=$1 auth=()
    if [ -n "${GH_TOKEN:-}" ]; then
        auth=(-H "Authorization: Bearer ${GH_TOKEN}")
    fi
    # `${auth[@]+...}`: bash 3.2 (macOS) treats an empty array as unset under -u.
    curl -fsSL ${auth[@]+"${auth[@]}"} -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${repo}/releases/latest" | jq -r .tag_name
}

# Canonical semver 2.0.0 grammar (semver.org), as ERE components reused per
# tool below. Each anchor rejects multi-line/whitespace/HTML/interpolation, and
# every character class rejects a shell metacharacter before it can reach a
# Dockerfile ARG.
#   - version core numeric identifier: no leading zero  (0|[1-9][0-9]*)
#   - pre-release identifier: a numeric identifier (no leading zero) OR an
#     alphanumeric identifier (at least one letter or hyphen). A dot-separated
#     list of these, so empty/leading-zero-numeric ids are NOT exact.
#   - build identifier: digits (leading zeros allowed) OR an alphanumeric
#     identifier. A dot-separated list; empty ids are NOT exact.
numeric='(0|[1-9][0-9]*)'
pre_id='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
build_id='[0-9A-Za-z-]+'
semver_core="${numeric}\.${numeric}\.${numeric}"
semver_pre="(-${pre_id}(\.${pre_id})*)?"
semver_build="(\+${build_id}(\.${build_id})*)?"
# claude's owning hook ships no build metadata; opencode/copilot accept the full
# canonical grammar; codex permits only its alpha/beta subset. Each tool regex
# must be NO more permissive than its owning installer, or the bumper would
# commit a value the owning hook rejects (review E1).
claude_re="^${semver_core}${semver_pre}\$"
opencode_re="^${semver_core}${semver_pre}${semver_build}\$"
copilot_re="^${semver_core}${semver_pre}${semver_build}\$"
codex_re="^${semver_core}(-alpha(\.${numeric}){0,2}|-beta(\.${numeric})?)?\$"

canonicalize() { # $1 = tool, $2 = raw
    local tool=$1 raw=$2 body
    case "$raw" in
        "" | null)
            fail "${tool} version empty/null"
            ;;
        *[!0-9A-Za-z.+-]*)
            fail "${tool} version has unexpected characters: '${raw}'"
            ;;
    esac
    case "$tool" in
        codex)
            case "$raw" in
                rust-v*) body="${raw#rust-v}" ;;
                v*) body="${raw#v}" ;;
                *) fail "codex tag is not rust-v<semver>: '${raw}'" ;;
            esac
            printf '%s' "$body" | grep -Eq "$codex_re" ||
                fail "codex version is not exact semver: '${raw}'"
            printf 'rust-v%s\n' "$body"
            ;;
        opencode)
            case "$raw" in
                v*) body="${raw#v}" ;;
                *) fail "opencode tag is not v<semver>: '${raw}'" ;;
            esac
            printf '%s' "$body" | grep -Eq "$opencode_re" ||
                fail "opencode version is not exact semver: '${raw}'"
            printf 'v%s\n' "$body"
            ;;
        claude)
            printf '%s' "$raw" | grep -Eq "$claude_re" ||
                fail "${tool} version is not exact semver: '${raw}'"
            printf '%s\n' "$raw"
            ;;
        copilot)
            printf '%s' "$raw" | grep -Eq "$copilot_re" ||
                fail "${tool} version is not exact semver: '${raw}'"
            printf '%s\n' "$raw"
            ;;
        *)
            fail "unknown tool: ${tool}"
            ;;
    esac
}

raw_codex="$(github_latest_tag openai/codex)" \
    || fail "codex version lookup failed (openai/codex releases/latest)"
raw_opencode="$(github_latest_tag anomalyco/opencode)" \
    || fail "opencode version lookup failed (anomalyco/opencode releases/latest)"
raw_claude="$(curl -fsSL https://downloads.claude.ai/claude-code-releases/latest)" \
    || fail "claude version lookup failed (downloads.claude.ai/claude-code-releases/latest)"
raw_copilot="$(npm view @github/copilot dist-tags.latest)" \
    || fail "copilot version lookup failed (npm @github/copilot)"

# Resolve EVERY value before touching a file.
codex="$(canonicalize codex "$raw_codex")"
opencode="$(canonicalize opencode "$raw_opencode")"
claude="$(canonicalize claude "$raw_claude")"
copilot="$(canonicalize copilot "$raw_copilot")"

tool_file() { # $1 = tool -> Dockerfile path
    printf '%s/images/tools/%s/Dockerfile\n' "$repo_root" "$1"
}
tool_arg() { # $1 = tool -> ARG name
    case "$1" in
        codex) printf 'AGENT_VERSION_CODEX\n' ;;
        opencode) printf 'AGENT_VERSION_OPENCODE\n' ;;
        claude) printf 'AGENT_VERSION_CLAUDE\n' ;;
        copilot) printf 'AGENT_VERSION_COPILOT\n' ;;
    esac
}

staged=()
old_values=()
changed_paths=()

stage_one() { # $1 = tool, $2 = new value
    local tool=$1 value=$2 file arg file_count current staged_file
    file="$(tool_file "$tool")"
    arg="$(tool_arg "$tool")"
    [ -f "$file" ] || fail "missing Dockerfile: $file"
    file_count="$(grep -c "^ARG ${arg}=" "$file" || true)"
    [ "$file_count" -eq 1 ] \
        || fail "expected exactly one 'ARG ${arg}=' in ${file#"$repo_root"/}, found ${file_count}"
    current="$(sed -n "s/^ARG ${arg}=//p" "$file")"
    [ "$current" = "$value" ] && return 0

    staged_file="${file}.agent-versions.staged.$$"
    sed "s|^ARG ${arg}=.*\$|ARG ${arg}=${value}|" "$file" >"$staged_file"
    grep -q "^ARG ${arg}=${value}\$" "$staged_file" \
        || { rm -f "$staged_file"; fail "staged edit for ${arg} is not exact"; }

    staged+=("$staged_file")
    old_values+=("$tool ${current} -> ${value}")
    changed_paths+=("$file")
}

stage_one codex "$codex"
stage_one opencode "$opencode"
stage_one claude "$claude"
stage_one copilot "$copilot"

if [ "${#staged[@]}" -eq 0 ]; then
    echo "All single-slot defaults are already current:"
    printf '  %-10s %s\n' codex "$codex" opencode "$opencode" claude "$claude" copilot "$copilot"
    exit 0
fi

# Back up, then replace. A failure restoring leaves the originals in place rather
# than a half-applied four-tool bump.
backups=()
restore() {
    local i
    for i in "${!backups[@]}"; do
        if [ -e "${backups[$i]}" ]; then
            cp "${backups[$i]}" "${changed_paths[$i]}" 2>/dev/null || true
        fi
    done
}
trap 'restore' ERR INT TERM

i=0
while [ "$i" -lt "${#staged[@]}" ]; do
    backup="${changed_paths[$i]}.agent-versions.bak.$$"
    cp "${changed_paths[$i]}" "$backup"
    backups+=("$backup")
    mv "${staged[$i]}" "${changed_paths[$i]}"
    i=$((i + 1))
done
trap - ERR INT TERM
for backup in "${backups[@]}"; do
    rm -f "$backup"
done

echo "Staged version bumps:"
for line in "${old_values[@]}"; do
    printf '  %s\n' "$line"
done
echo
echo "Changed files:"
for path in "${changed_paths[@]}"; do
    printf '  %s\n' "${path#"$repo_root"/}"
done
echo
echo "Next: review 'git diff', run the owning installer tests / the Docker audit, then commit."
