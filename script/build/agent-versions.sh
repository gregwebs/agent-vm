#!/usr/bin/env bash
# Resolve each installer tool layer's current upstream version and print it as
# `tool=version` lines (codex, opencode, claude, copilot).
# Usage: ./script/build/agent-versions.sh
#
# The installer layers (images/tools/{codex,opencode,claude,copilot}) always
# install upstream's latest release; the version is fed in as the layer's
# `AGENT_VERSION_<TOOL>` build arg purely as a cache key, so a layer is rebuilt
# exactly when its agent released. This script is the one resolver for that key:
# .github/workflows/build-image.yml appends its output to $GITHUB_OUTPUT, and
# images/build.sh turns it into build args. Without the key a rebuild is a
# cache hit that silently keeps the old agent.
#
# Each source is the EXACT one the matching installer reads, so the key tracks
# what actually gets installed:
#   - codex:    openai/codex releases/latest tag -- install.sh's own resolver
#               hits the same endpoint.
#   - opencode: anomalyco/opencode releases/latest tag -- the repo
#               opencode.ai/install downloads from (renamed from sst/opencode;
#               sst/* only resolves via GitHub's rename redirect, so pin the
#               real repo).
#   - claude:   downloads.claude.ai native channel `/latest` (a plain version
#               string) -- what claude.ai/install.sh installs. NOT npm: the npm
#               dist-tags (@anthropic-ai/claude-code) move on a separate cadence
#               (e.g. stable != latest), so keying on npm would miss native
#               releases / rebuild for npm-only bumps.
#   - copilot:  npm `@github/copilot` latest -- the layer installs exactly this
#               version, so the key and the install cannot disagree.
# `dsh` and `pi` are deliberately absent: they are committed-lockfile layers,
# so their cache key is the lockfile's bytes, not a lookup.
#
# Any lookup failure exits non-zero (vs emitting a stale or garbage key that
# would skip a real agent update). Under GitHub Actions (GITHUB_ACTIONS=true)
# fail() also emits an `::error::` annotation, so the workflow shows the
# specific reason rather than a generic message -- on stderr, because stdout is
# the `tool=version` output callers capture. GitHub API calls are authenticated
# with $GH_TOKEN when set (CI); anonymous calls work locally within GitHub's
# unauthenticated rate limit.

set -euo pipefail

# require_tools is the shared prerequisite check (npm-pin.sh, same directory),
# not a second inline copy -- see that file's header. `case` rather than
# `dirname`: this script must run under a minimal PATH (script/test's missing-
# npm case) that may not carry the external `dirname`.
case "${BASH_SOURCE[0]}" in
    */*) script_dir_path="${BASH_SOURCE[0]%/*}" ;;
    *) script_dir_path=. ;;
esac
# shellcheck source=/dev/null
. "$script_dir_path/npm-pin.sh"

# Fail before a lookup so an HTTP-200-but-garbage response reports a per-tool
# message instead of this chokepoint.
require_tools curl jq npm

fail() {
    echo "error: $1" >&2
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        echo "::error::$1" >&2
    fi
    exit 1
}

github_latest_tag() {
    local repo=$1 auth=()
    if [ -n "${GH_TOKEN:-}" ]; then
        auth=(-H "Authorization: Bearer ${GH_TOKEN}")
    fi
    # `${auth[@]+...}`: bash 3.2 (macOS) treats an empty array as unset under -u.
    curl -fsSL ${auth[@]+"${auth[@]}"} -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${repo}/releases/latest" | jq -r .tag_name
}

codex=$(github_latest_tag openai/codex) \
    || fail "codex version lookup failed (openai/codex releases/latest)"
opencode=$(github_latest_tag anomalyco/opencode) \
    || fail "opencode version lookup failed (anomalyco/opencode releases/latest)"
claude=$(curl -fsSL https://downloads.claude.ai/claude-code-releases/latest) \
    || fail "claude version lookup failed (downloads.claude.ai/claude-code-releases/latest)"
copilot=$(npm view @github/copilot dist-tags.latest) \
    || fail "copilot version lookup failed (npm @github/copilot)"

# Guard against an HTTP-200-but-garbage response (empty body, jq 'null', or an
# HTML error page) silently becoming a key.
if [ -z "$codex" ] || [ "$codex" = null ]; then
    fail "codex version empty/null"
fi
if [ -z "$opencode" ] || [ "$opencode" = null ]; then
    fail "opencode version empty/null"
fi
case "$claude" in [0-9]*.[0-9]*.[0-9]*) : ;; *) fail "claude version implausible: '$claude'" ;; esac
case "$copilot" in [0-9]*.[0-9]*.[0-9]*) : ;; *) fail "copilot version implausible: '$copilot'" ;; esac

echo "codex=$codex"
echo "opencode=$opencode"
echo "claude=$claude"
echo "copilot=$copilot"
