#!/usr/bin/env bash
# Restricted-egress gate for the shipped vendored installers (#227, plan task 2).
#
# It runs the REAL patched vendored installers + owning hooks inside a container
# whose only route off the network is a digest-pinned mitmproxy sidecar. The
# proxy denies by default and forwards only requests that match a committed
# exact-selection rule, learning the signed CDN redirect target from the
# response to an already-allowed request -- never a whole CDN namespace. That is
# what makes "no ordinary latest lookup / no mutable bootstrap" an executable
# claim: a build that reached `latest`, a channel, a dist-tag or an unversioned
# installer URL is denied and the run fails, even if the surrounding code
# swallows the HTTP error.
#
# Usage: script/test/shipped-installer-network.sh BASE_IMAGE \
#            [--overrides] [--observe] [--tool TOOL] [--platform PLATFORM]
#
#   --overrides   also run the committed exact alternate selection per tool
#   --observe     capture mode: log every URL and forward it (builds the
#                 allowlist; not an acceptance run)
#   --tool TOOL   only codex|opencode|claude (repeatable)
#   --platform P  Docker platform (default: the host's)
#
# Tier: real Docker + real network. It downloads real release assets, so it is
# an explicit developer/dispatched-CI step, never part of the boot-free suite.

set -euo pipefail

# Digest-pinned mitmproxy sidecar (linux/arm64 + linux/amd64 multi-arch image).
# Reviewed/updated by a developer; there is deliberately no floating tag here.
MITM_IMAGE="mitmproxy/mitmproxy@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f"

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
FIXTURES="$REPO_ROOT/script/test/fixtures/installer-egress"
SELECTIONS="$FIXTURES/selections.tsv"

# Whole-gate watchdog (plan task 5). macOS has no guaranteed `timeout`, so the
# first invocation re-execs the ENTIRE gate under the shared Python3
# process-group watchdog. On timeout the whole group is signalled; the inner run
# still owns its cleanup traps. The marker stops the re-exec from recursing.
if [ "${SHIPPED_INSTALLER_NETWORK_WATCHED:-0}" != 1 ]; then
    command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
    export SHIPPED_INSTALLER_NETWORK_WATCHED=1
    exec python3 "$REPO_ROOT/script/test/host-watchdog.py" \
        "${SHIPPED_INSTALLER_NETWORK_GATE_WATCHDOG:-5400}" bash "$0" "$@"
fi

if [ "$#" -lt 1 ]; then
    echo "usage: $0 BASE_IMAGE [--overrides] [--observe] [--tool TOOL] [--platform PLATFORM]" >&2
    exit 2
fi
BASE_IMAGE="$1"
shift

overrides=false
observe=false
platform=""
tools=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --overrides) overrides=true ;;
        --observe) observe=true ;;
        --tool)
            [ "$#" -ge 2 ] || { echo "--tool needs a value" >&2; exit 2; }
            tools+=("$2")
            shift
            ;;
        --platform)
            [ "$#" -ge 2 ] || { echo "--platform needs a value" >&2; exit 2; }
            platform="$2"
            shift
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
    shift
done

if [ -z "$platform" ]; then
    case "$(uname -m)" in
        arm64 | aarch64) platform="linux/arm64" ;;
        x86_64 | amd64) platform="linux/amd64" ;;
        *) echo "unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
    esac
fi

case "$platform" in
    linux/arm64) arch="aarch64" ;;
    linux/amd64) arch="x86_64" ;;
    *) echo "unsupported platform: $platform" >&2; exit 1 ;;
esac

if [ "${#tools[@]}" -eq 0 ]; then
    tools=(codex opencode claude)
fi

for required in docker jq python3; do
    command -v "$required" >/dev/null 2>&1 || { echo "$required is required" >&2; exit 1; }
done

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# run_with_watchdog SECONDS CMD... -> the command's own status, or 124 on
# timeout (the whole process group is signalled so no container is orphaned).
run_with_watchdog() {
    python3 "$REPO_ROOT/script/test/host-watchdog.py" "$@"
}

# Per-runtime-probe budget for the network installer container (plan task 5).
NETWORK_CONTAINER_WATCHDOG_SECONDS="${SHIPPED_INSTALLER_NETWORK_CONTAINER_WATCHDOG:-360}"

mode=strict
$observe && mode=observe

RUN_ID="installer-egress-$$"
NET_INTERNAL="$RUN_ID-internal"
NET_EXTERNAL="$RUN_ID-external"
PROXY="$RUN_ID-proxy"
# `target/` is gitignored and absent on a fresh CI checkout with no Rust build,
# so create it before mktemp (which does not create parent directories).
mkdir -p "$REPO_ROOT/target"
TMP="$(mktemp -d "$REPO_ROOT/target/installer-egress.XXXXXX")"
mkdir -p "$TMP/certs" "$TMP/logs"

cleanup() {
    # Force-remove every container we named, including the proxy and any
    # installer whose `docker run` client was killed by a watchdog (`--rm` only
    # fires once the container exits, not when its client dies). Never a global
    # prune: the filter is namescoped to this run.
    local cids
    cids="$(docker ps -aq --filter "name=^${RUN_ID}-" 2>/dev/null || true)"
    if [ -n "$cids" ]; then
        # shellcheck disable=SC2086  # word-splitting over the id list is intended
        docker rm -f $cids >/dev/null 2>&1 || true
    fi
    docker network rm "$NET_INTERNAL" "$NET_EXTERNAL" >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

# The internal network is `--internal`: containers on it get NO default route to
# the internet. The proxy is the only member with a second, external network.
docker network create --internal "$NET_INTERNAL" >/dev/null
docker network create "$NET_EXTERNAL" >/dev/null

# `--forward` of the selection table. `codex|default|alternate`.
selection_for() { # $1 = tool, $2 = column (2=default, 3=alternate)
    awk -F '\t' -v t="$1" -v c="$2" '$1 == t { print $c }' "$SELECTIONS"
}

selection_versions() { # $1 = tool -> newline-separated versions to run
    printf '%s\n' "$(selection_for "$1" 2)"
    $overrides && printf '%s\n' "$(selection_for "$1" 3)"
    return 0
}

# The selections.tsv default column must equal the committed Dockerfile ARG
# default. Otherwise a developer bump could leave this gate validating an old
# native binary while the shipped recipe ships a newer one.
assert_selection_defaults_match_dockerfiles() {
    local tool arg arg_default tsv_default
    for tool in codex opencode claude; do
        case "$tool" in
            codex) arg=AGENT_VERSION_CODEX ;;
            opencode) arg=AGENT_VERSION_OPENCODE ;;
            claude) arg=AGENT_VERSION_CLAUDE ;;
        esac
        arg_default="$(sed -n "s/^ARG ${arg}=//p" "$REPO_ROOT/images/tools/$tool/Dockerfile")"
        tsv_default="$(selection_for "$tool" 2)"
        [ -n "$arg_default" ] || fail "$tool Dockerfile has no $arg default"
        [ "$tsv_default" = "$arg_default" ] ||
            fail "selections.tsv default for $tool is '$tsv_default' but the Dockerfile default is '$arg_default'"
    done
    echo "  selections.tsv defaults match the committed Dockerfile ARGs"
}
assert_selection_defaults_match_dockerfiles

# Escape a version for use INSIDE an ERE before it is interpolated into a
# jq-built allowlist path (review F4): an unescaped `.` made the exact selection
# `2.1.286` also match `/2/1/286/...` (and `2a1b286`).
escape_re() { # $1 raw -> ERE-safe literal
    printf '%s' "$1" | sed 's/[][\\.^$*+?(){}|]/\\&/g'
}

# Build the addon config for one tool+version. GitHub release downloads redirect
# to a signed CDN URL, which the addon learns from the allowed response.
write_config() { # $1 = tool, $2 = version, $3 = out file
    local tool="$1" version="$2" out="$3" numeric
    case "$tool" in
        codex)
            numeric="$(escape_re "${version#rust-v}")"
            jq -n --arg v "$numeric" --arg arch "$arch" '{
                allow: [
                    {host: "api.github.com",
                     path: ("^/repos/openai/codex/releases/tags/rust-v" + $v + "$")},
                    {host: "github.com",
                     path: ("^/openai/codex/releases/download/rust-v" + $v
                            + "/codex-package-" + $arch + "-unknown-linux-musl\\.tar\\.gz$")},
                    {host: "github.com",
                     path: ("^/openai/codex/releases/download/rust-v" + $v
                            + "/codex-package_SHA256SUMS$")}
                ],
                deny: ["/latest", "releases/latest", "releases/tags/latest",
                       "channel", "/install\\.sh$", "releases/download/latest"]
            }' >"$out"
            ;;
        opencode)
            numeric="$(escape_re "${version#v}")"
            local oc_target
            case "$arch" in
                aarch64) oc_target="linux-arm64" ;;
                x86_64) oc_target="linux-x64" ;;
            esac
            jq -n --arg v "$numeric" --arg t "$oc_target" '{
                allow: [
                    {host: "github.com",
                     path: ("^/anomalyco/opencode/releases/download/v" + $v
                            + "/opencode-" + $t + "\\.tar\\.gz$")}
                ],
                deny: ["/latest", "releases/latest", "opencode\\.ai/install",
                       "releases/download/latest", "channel"]
            }' >"$out"
            ;;
        claude)
            numeric="$(escape_re "$version")"
            local cl_arch cl_platform
            case "$arch" in
                aarch64) cl_arch="arm64" ;;
                x86_64) cl_arch="x64" ;;
            esac
            cl_platform="linux-$cl_arch"
            jq -n --arg v "$numeric" --arg p "$cl_platform" '{
                allow: [
                    {host: "downloads.claude.ai",
                     path: ("^/claude-code-releases/" + $v + "/manifest\\.json$")},
                    {host: "downloads.claude.ai",
                     path: ("^/claude-code-releases/" + $v + "/manifest\\.json\\.raw-sig\\.json$")},
                    {host: "downloads.claude.ai",
                     path: ("^/claude-code-releases/" + $v + "/manifest\\.zst\\.json$")},
                    {host: "downloads.claude.ai",
                     path: ("^/claude-code-releases/" + $v + "/" + $p + "/claude(\\.zst)?$")}
                ],
                deny: ["/latest", "claude-code-releases/latest", "claude\\.ai/install\\.sh",
                       "channel", "/api/event_logging/", "/api/claude_code/"]
            }' >"$out"
            ;;
        *) fail "unknown tool: $tool" ;;
    esac
}

# Allowlist exactness (review F4): the committed config must allow ONLY the
# exact selected version path, never an adjacent version, a path-separator
# variant, or a prefix extension that an unescaped-dot regex would accept. This
# drives the REAL addon module in the pinned mitmproxy image with synthetic
# requests (no network) and fails on any mismatch.
run_allowlist_negatives() { # $1 tool, $2 version
    local tool="$1" version="$2" numeric sep adjacent cfg="$TMP/allow-$1-$2.json"
    local cases="$TMP/allow-cases-$1-$2.tsv" oc_target cl_platform rc=0
    write_config "$tool" "$version" "$cfg"
    : >"$cases"
    mkdir -p "$TMP/allowlog"
    : >"$TMP/allowlog/egress.log"
    case "$tool" in
        codex)
            numeric="${version#rust-v}"
            sep="${numeric//./\/}"
            adjacent="${numeric%.*}.$(( ${numeric##*.} + 1 ))"
            local asset="codex-package-$arch-unknown-linux-musl.tar.gz"
            printf '%s\t1\n' "https://api.github.com/repos/openai/codex/releases/tags/rust-v$numeric" >>"$cases"
            printf '%s\t1\n' "https://github.com/openai/codex/releases/download/rust-v$numeric/$asset" >>"$cases"
            printf '%s\t1\n' "https://github.com/openai/codex/releases/download/rust-v$numeric/codex-package_SHA256SUMS" >>"$cases"
            printf '%s\t0\n' "https://api.github.com/repos/openai/codex/releases/tags/rust-v$sep" >>"$cases"
            printf '%s\t0\n' "https://api.github.com/repos/openai/codex/releases/tags/rust-v$adjacent" >>"$cases"
            printf '%s\t0\n' "https://github.com/openai/codex/releases/download/rust-v$sep/$asset" >>"$cases"
            printf '%s\t0\n' "https://api.github.com/repos/openai/codex/releases/tags/rust-v$numeric?sig=REVIEW-SIGNED-SECRET&token=REVIEW-TOKEN" >>"$cases" ;;
        opencode)
            numeric="${version#v}"
            sep="${numeric//./\/}"
            adjacent="${numeric%.*}.$(( ${numeric##*.} + 1 ))"
            case "$arch" in
                aarch64) oc_target="linux-arm64" ;;
                x86_64) oc_target="linux-x64" ;;
            esac
            printf '%s\t1\n' "https://github.com/anomalyco/opencode/releases/download/v$numeric/opencode-$oc_target.tar.gz" >>"$cases"
            printf '%s\t0\n' "https://github.com/anomalyco/opencode/releases/download/v$sep/opencode-$oc_target.tar.gz" >>"$cases"
            printf '%s\t0\n' "https://github.com/anomalyco/opencode/releases/download/v$adjacent/opencode-$oc_target.tar.gz" >>"$cases"
            printf '%s\t0\n' "https://github.com/anomalyco/opencode/releases/download/v$numeric/opencode-$oc_target.tar.gz?sig=REVIEW-SIGNED-SECRET&token=REVIEW-TOKEN" >>"$cases" ;;
        claude)
            numeric="$version"
            sep="${numeric//./\/}"
            adjacent="${numeric%.*}.$(( ${numeric##*.} + 1 ))"
            case "$arch" in
                aarch64) cl_platform="linux-arm64" ;;
                x86_64) cl_platform="linux-x64" ;;
            esac
            printf '%s\t1\n' "https://downloads.claude.ai/claude-code-releases/$numeric/manifest.json" >>"$cases"
            printf '%s\t1\n' "https://downloads.claude.ai/claude-code-releases/$numeric/$cl_platform/claude" >>"$cases"
            printf '%s\t0\n' "https://downloads.claude.ai/claude-code-releases/$sep/manifest.json" >>"$cases"
            printf '%s\t0\n' "https://downloads.claude.ai/claude-code-releases/$adjacent/manifest.json" >>"$cases"
            printf '%s\t0\n' "https://downloads.claude.ai/claude-code-releases/$numeric/$cl_platform/claudex" >>"$cases"
            printf '%s\t0\n' "https://downloads.claude.ai/claude-code-releases/$numeric/manifest.json?sig=REVIEW-SIGNED-SECRET&token=REVIEW-TOKEN" >>"$cases" ;;
    esac
    docker run --rm -i --platform "$platform" \
        -v "$FIXTURES/addon.py:/addon/addon.py:ro" \
        -v "$cfg:/addon/config.json:ro" \
        -v "$cases:/addon/cases.tsv:ro" \
        -v "$TMP/allowlog:/addon/log" \
        -e EGRESS_CONFIG=/addon/config.json -e EGRESS_LOG=/addon/log/egress.log \
        --entrypoint python3 "$MITM_IMAGE" - <<'PY' || rc=$?
import importlib.util
import sys
from urllib.parse import urlsplit

spec = importlib.util.spec_from_file_location("egress_addon", "/addon/addon.py")
addon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(addon)


class Req:
    def __init__(self, url):
        parts = urlsplit(url)
        self.pretty_url = url
        self.pretty_host = parts.hostname
        self.path = parts.path + (("?" + parts.query) if parts.query else "")
        self.method = "GET"


class Flow:
    def __init__(self, url):
        self.request = Req(url)
        self.response = None


bad = 0
with open("/addon/cases.tsv", encoding="utf-8") as handle:
    for line in handle:
        line = line.rstrip("\n")
        if not line:
            continue
        url, expect = line.rsplit("\t", 1)
        flow = Flow(url)
        addon.request(flow)
        allowed = flow.response is None
        if allowed != (expect == "1"):
            print("MISMATCH %s expected allowed=%s got %s" % (url, expect, allowed), file=sys.stderr)
            bad = 1

# F5: the addon must redact every query value from the log, so a signed CDN URL
# never persists a bearer-style secret.
redacted = addon._redact(
    "https://cdn.example.invalid/asset?sig=REVIEW-SIGNED-SECRET&token=REVIEW-TOKEN"
)
if "REVIEW-SIGNED-SECRET" in redacted or "REVIEW-TOKEN" in redacted:
    print("redaction failed: %s" % redacted, file=sys.stderr)
    bad = 1
try:
    with open("/addon/log/egress.log", encoding="utf-8") as handle:
        logtext = handle.read()
except OSError:
    logtext = ""
if "REVIEW-SIGNED-SECRET" in logtext or "REVIEW-TOKEN" in logtext:
    print("egress log leaked a query secret:\n%s" % logtext, file=sys.stderr)
    bad = 1
sys.exit(bad)
PY
    [ "$rc" -eq 0 ] || fail "$tool $version allowlist exactness failed (rc=$rc)"
    echo "  $tool $version: allowlist exactness ok (separator/adjacent/prefix negatives)"
}

start_proxy() { # $1 = config file
    : >"$TMP/logs/egress.log"
    docker rm -f "$PROXY" >/dev/null 2>&1 || true
    docker run -d --name "$PROXY" \
        --network "$NET_EXTERNAL" \
        --cap-drop ALL --security-opt no-new-privileges \
        --user 0:0 \
        -v "$TMP/certs:/certs" \
        -v "$1:/addon/config.json:ro" \
        -v "$FIXTURES/addon.py:/addon/addon.py:ro" \
        -v "$TMP/logs:/logs" \
        -e EGRESS_CONFIG=/addon/config.json \
        -e EGRESS_LOG=/logs/egress.log \
        -e EGRESS_MODE="$mode" \
        --entrypoint mitmdump \
        "$MITM_IMAGE" \
        --set confdir=/certs --listen-host 0.0.0.0 --listen-port 8080 \
        -s /addon/addon.py --set console_eventlog_verbosity=error >/dev/null
    docker network connect "$NET_INTERNAL" "$PROXY"

    local counter=0
    while [ "$counter" -lt 120 ]; do
        [ -s "$TMP/certs/mitmproxy-ca-cert.pem" ] && return 0
        sleep 0.5
        counter=$((counter + 1))
    done
    echo "proxy container log:" >&2
    docker logs "$PROXY" >&2 || true
    fail "mitmproxy did not produce a CA certificate"
}

stop_proxy() {
    docker rm -f "$PROXY" >/dev/null 2>&1 || true
}

# The proxy log since a marker line, so each tool+version is judged alone.
mark_log() { wc -l <"$TMP/logs/egress.log"; }
since_marker() { # $1 = marker line count
    tail -n "+$(( $1 + 1 ))" "$TMP/logs/egress.log" 2>/dev/null || true
}

hook_for() { # $1 = tool
    case "$1" in
        codex) printf '%s\n' install-codex.sh ;;
        opencode) printf '%s\n' install-opencode.sh ;;
        claude) printf '%s\n' install-claude.sh ;;
        *) fail "unknown tool: $1" ;;
    esac
}

version_var_for() { # $1 = tool
    case "$1" in
        codex) printf '%s\n' AGENT_VM_VERSION_CODEX ;;
        opencode) printf '%s\n' AGENT_VM_VERSION_OPENCODE ;;
        claude) printf '%s\n' AGENT_VM_VERSION_CLAUDE ;;
        *) fail "unknown tool: $1" ;;
    esac
}

inner_script() { # $1 = tool  (paths are already mounted)
    cat <<'INNER'
set -eu
if command -v update-ca-certificates >/dev/null 2>&1; then
    cp /mitm/ca.pem /usr/local/share/ca-certificates/installer-egress.crt
    update-ca-certificates >/dev/null 2>&1 || true
fi
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
    cat /mitm/ca.pem >>/etc/ssl/certs/ca-certificates.crt
fi
export CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export NODE_EXTRA_CA_CERTS=/mitm/ca.pem
# A build must not phone home; the native installer honours this and it is the
# reason the gate can keep api.anthropic.com out of the allowlist entirely.
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export HOME=/opt/agent
sh /hook
INNER
}

report_script() { # $1 = tool
    case "$1" in
        codex) printf '%s\n' '/opt/agent/.local/bin/codex --version' ;;
        opencode) printf '%s\n' '/usr/local/bin/opencode --version' ;;
        claude) printf '%s\n' 'if [ -x /opt/agent/.local/bin/claude ]; then /opt/agent/.local/bin/claude --version; else find /opt/agent/.local/bin -name claude -type f -exec {} --version \; 2>/dev/null; fi' ;;
    esac
}

# The installed command lives in the container's own filesystem, discarded with
# --rm, so the version report is read in the SAME container that installed it
# (the internal network has no internet route anyway, so the run is offline).
run_one_combined() { # $1 = tool, $2 = version
    local tool="$1" version="$2" cfg="$TMP/config.json" marker run_status out
    local hook var
    hook="$(hook_for "$tool")"
    var="$(version_var_for "$tool")"
    local extra_env=()
    [ "$tool" = opencode ] && extra_env+=(-e "AGENT_VM_OPENCODE_LINK=/usr/local/bin/opencode")

    write_config "$tool" "$version" "$cfg"
    marker="$(mark_log)"

    echo "--- $tool $version"
    out="$TMP/run.out"
    set +e
    run_with_watchdog "$NETWORK_CONTAINER_WATCHDOG_SECONDS" \
        docker run --rm --name "$RUN_ID-inst-$RANDOM" --platform "$platform" --network "$NET_INTERNAL" \
        -v "$TMP/certs/mitmproxy-ca-cert.pem:/mitm/ca.pem:ro" \
        -v "$REPO_ROOT/images/tools/$tool/vendor:/vendor:ro" \
        -v "$REPO_ROOT/images/tools/$tool/contract:/contract:ro" \
        -v "$REPO_ROOT/images/tools/$tool/$hook:/hook:ro" \
        -e "HTTP_PROXY=http://$PROXY:8080" -e "HTTPS_PROXY=http://$PROXY:8080" \
        -e "http_proxy=http://$PROXY:8080" -e "https_proxy=http://$PROXY:8080" \
        -e "ALL_PROXY=http://$PROXY:8080" -e "NO_PROXY=" \
        -e "AGENT_VM_CONTRACT_DIR=/contract" \
        -e "AGENT_VM_VENDOR_DIR=/vendor" \
        -e "AGENT_VM_TRANSPORT_RECEIPT=/tmp/receipt" \
        -e "AGENT_VM_INSTALL_STATUS_DIR=/tmp/status" \
        -e "$var=$version" \
        "${extra_env[@]}" \
        "$BASE_IMAGE" \
        sh -c "$(inner_script "$tool")
echo '--- REPORT ---'
$(report_script "$tool")" >"$out" 2>&1
    run_status=$?
    set -e

    sed -n '1,60p' "$out" | sed 's/^/    /'

    if grep -q '^DENY ' <(since_marker "$marker"); then
        echo "    egress log:" >&2
        since_marker "$marker" | sed 's/^/      /' >&2
        fail "$tool $version reached a denied URL"
    fi
    if $observe; then
        echo "    (observe mode: not asserting install success)"
        return 0
    fi
    [ "$run_status" -eq 0 ] || fail "$tool $version installer failed (exit $run_status)"

    local report expect
    report="$(sed -n '/^--- REPORT ---$/,$p' "$out" | tail -n +2 | head -n 1)"
    case "$tool" in
        codex) expect="codex-cli ${version#rust-v}" ;;
        opencode) expect="${version#v}" ;;
        claude) expect="$version" ;;
    esac
    case "$report" in
        *"$expect"*) echo "    report ok: $report" ;;
        *) fail "$tool report '$report' does not contain '$expect'" ;;
    esac
}

# The proxy must forward claude's native `install` traffic too; observe mode is
# how the allowlist is captured, strict mode is how it is enforced.
#
# Mutation check: the plan requires that a build which reached `latest` is
# DENIED, not merely that the installed version happened to match. This rewrites
# the vendored codex metadata URL to `/releases/latest` and requires the run to
# fail with a logged denial.
run_denial_mutation() {
    local mutdir="$TMP/mutated-codex" out="$TMP/mutation.out" marker status
    mkdir -p "$mutdir"
    sed 's#releases/tags/rust-v%s#releases/latest#' \
        "$REPO_ROOT/images/tools/codex/vendor/install.sh" >"$mutdir/install.sh"
    write_config codex "$(selection_for codex 2)" "$TMP/config.json"
    start_proxy "$TMP/config.json"
    marker="$(mark_log)"
    echo "--- mutation: codex metadata URL forced to /releases/latest"
    set +e
    run_with_watchdog "$NETWORK_CONTAINER_WATCHDOG_SECONDS" \
        docker run --rm --name "$RUN_ID-mut-$RANDOM" --platform "$platform" --network "$NET_INTERNAL" \
        -v "$TMP/certs/mitmproxy-ca-cert.pem:/mitm/ca.pem:ro" \
        -v "$mutdir:/vendor:ro" \
        -v "$REPO_ROOT/images/tools/codex/contract:/contract:ro" \
        -v "$REPO_ROOT/images/tools/codex/install-codex.sh:/hook:ro" \
        -e "HTTP_PROXY=http://$PROXY:8080" -e "HTTPS_PROXY=http://$PROXY:8080" \
        -e "http_proxy=http://$PROXY:8080" -e "https_proxy=http://$PROXY:8080" \
        -e "ALL_PROXY=http://$PROXY:8080" -e "NO_PROXY=" \
        -e "AGENT_VM_CONTRACT_DIR=/contract" \
        -e "AGENT_VM_VENDOR_DIR=/vendor" \
        -e "AGENT_VM_TRANSPORT_RECEIPT=/tmp/receipt" \
        -e "AGENT_VM_INSTALL_STATUS_DIR=/tmp/status" \
        -e "AGENT_VM_VERSION_CODEX=$(selection_for codex 2)" \
        "$BASE_IMAGE" \
        sh -c "$(inner_script codex)" >"$out" 2>&1
    status=$?
    set -e
    since_marker "$marker" >"$TMP/mutation.log"
    sed 's/^/    /' "$TMP/mutation.log"
    [ "$status" -ne 0 ] || fail "the /releases/latest mutation unexpectedly succeeded"
    grep -q '^DENY ' "$TMP/mutation.log" \
        || fail "the /releases/latest mutation was not denied and logged"
    echo "    mutation denied and logged as required"
}

status=0
for tool in "${tools[@]}"; do
    while IFS= read -r version; do
        [ -n "$version" ] || continue
        write_config "$tool" "$version" "$TMP/config.json"
        # F4: the committed config must reject separator/adjacent variants of the
        # exact selection over the REAL addon, before the run.
        run_allowlist_negatives "$tool" "$version" || status=1
        # Restart the proxy so the addon reloads the new config file contents.
        start_proxy "$TMP/config.json"
        run_one_combined "$tool" "$version" || status=1
    done < <(selection_versions "$tool")
done

stop_proxy
[ "$observe" = true ] || run_denial_mutation
# Publish run-scoped, already-redacted evidence instead of an unscoped plaintext
# file shared by every run (review F5).
EVIDENCE="${TMPDIR:-/tmp}/installer-egress-$RUN_ID.log"
cp "$TMP/logs/egress.log" "$EVIDENCE" 2>/dev/null || true
echo "egress evidence: $EVIDENCE"

[ "$status" -eq 0 ] || fail "restricted-egress gate failed"
echo 'shipped-installer-network gate: OK'
