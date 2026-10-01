#!/usr/bin/env bash
# Independent, T5-audited acceptance audit for the six shipped tool recipes
# (#227, plan task 5).
#
# It builds each recipe INDEPENDENTLY from a supplied tool-free base image and
# audits the RESULT as an arbitrary numeric uid, so an inherited CLI on the base
# can never mask a failed install. It then inspects every
# `org.agent-vm.version.*` label and replays those exact values back as explicit
# build ARGs onto a SECOND, distinct tool-free base, proving that the labels are
# a usable selection surface and that an empty slot's committed locks survive.
#
# Usage: script/test/shipped-tool-recipes.sh BASE_IMAGE \
#            [--overrides] [--chain] [--platform PLATFORM] [--keep] \
#            [--min-free-gib N]
#
#   BASE_IMAGE        a tool-free base image (e.g. agent-vm-base:227-pre-pr)
#   --overrides       also build the committed exact alternate selection for
#                     every slot (never resolved from `latest`) plus the
#                     mixed-empty dsh/Pi cases, and replay them
#   --chain           additionally build the committed six-layer chain once and
#                     audit all eight slots on the final image
#   --platform P      Docker platform (default: the host's native platform)
#   --keep            keep the per-run images after the run (debugging)
#   --min-free-gib N  required free Docker storage (default 25)
#   --self-test       certify the oracle predicates AND the build/audit wiring
#                     without Docker: seed every rejected state (dropped override
#                     arg, lock drift, missing/stale/degraded status,
#                     non-registering bridge) and drive the real
#                     build_recipe/build_and_audit/replay_check/audit_image
#                     call sites with fake adapters, requiring a reasoned
#                     rejection. Runs in ci-contracts.
#
# Tier: real Docker + real network. It downloads real release assets, so it is
# an explicit developer/dispatched-CI step, never part of the boot-free suite.
# No test value is ever resolved from `latest`: the defaults come from the
# Dockerfiles and the alternates are the committed exact selections below.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
FIXTURE_DOCKERFILE="$REPO_ROOT/script/test/fixtures/t5-negative/Dockerfile"
# The committed status-record validator; the external oracle validates the exact
# status bytes with it rather than a first-line key/value extraction (review F2).
STATUS_VALIDATOR="$REPO_ROOT/images/recipe-contract/install-status.py"

usage() {
    echo "usage: $0 BASE_IMAGE [--overrides] [--chain] [--platform PLATFORM] [--keep] [--min-free-gib N]" >&2
    echo "       $0 --self-test   # certify the oracle predicates (no Docker)" >&2
}

self_test=false
BASE_IMAGE=""
overrides=false
chain=false
keep=false
platform=""
min_free_gib=25
if [ "$#" -ge 1 ] && [ "$1" != "--self-test" ]; then
    case "$1" in
        -*) usage; exit 2 ;;
        *) BASE_IMAGE="$1"; shift ;;
    esac
fi
while [ "$#" -gt 0 ]; do
    case "$1" in
        --self-test) self_test=true ;;
        --overrides) overrides=true ;;
        --chain) chain=true ;;
        --keep) keep=true ;;
        --platform)
            [ "$#" -ge 2 ] || { echo "--platform needs a value" >&2; exit 2; }
            platform="$2"
            shift
            ;;
        --min-free-gib)
            [ "$#" -ge 2 ] || { echo "--min-free-gib needs a value" >&2; exit 2; }
            min_free_gib="$2"
            shift
            ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
if [ "$self_test" = false ] && [ -z "$BASE_IMAGE" ]; then
    usage
    exit 2
fi

if [ -z "$platform" ]; then
    case "$(uname -m)" in
        arm64 | aarch64) platform="linux/arm64" ;;
        x86_64 | amd64) platform="linux/amd64" ;;
        *) echo "unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
    esac
fi

if [ "$self_test" = false ]; then
    for required in docker jq python3; do
        command -v "$required" >/dev/null 2>&1 || { echo "$required is required" >&2; exit 1; }
    done
fi

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# run_with_watchdog SECONDS CMD... -> the command's own status, or 124 on
# timeout. macOS has no guaranteed `timeout`, so host watchdogs use the shared
# Python3 process-group helper (script/test/host-watchdog.py); on timeout the
# whole group is signalled so no buildx builder, container or daemon client is
# orphaned.
run_with_watchdog() {
    python3 "$REPO_ROOT/script/test/host-watchdog.py" "$@"
}

# --- byte-exact report/status capture (review F2) ----------------------------
# The container audit emits each tool's COMPLETE stdout report and the exact
# status bytes base64-encoded, so a first-line key/value extraction can never
# hide a contradictory trailing report line or a multi-line status record.
# `b64file` runs in the container (injected via `declare -f`); `MISSING` marks
# an absent/unreadable file -- base64 output is always a multiple of four
# characters, so the sentinel can never collide with a real value.
b64file() { # $1 path -> base64 of its bytes, or MISSING
    if [ -r "$1" ]; then
        python3 -c 'import base64,sys; sys.stdout.write(base64.b64encode(open(sys.argv[1],"rb").read()).decode())' "$1"
    else
        printf 'MISSING'
    fi
}

# decode_b64 BLOB FILE -> write the decoded bytes to FILE; 1 when the blob is
# the MISSING sentinel.
decode_b64() { # $1 blob, $2 out file
    [ "$1" != MISSING ] || return 1
    printf '%s' "$1" | python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' >"$2"
}

# blob -> base64 of stdin (host helpers seed the self-test with exact bytes).
blob() {
    python3 -c 'import base64,sys; sys.stdout.write(base64.b64encode(sys.stdin.buffer.read()).decode())'
}

# sblob RECORD -> base64 of `RECORD` plus its trailing newline.
sblob() {
    printf '%s\n' "$1" | blob
}

# Per-build / per-runtime-probe budgets (plan task 5). Overridable only for
# targeted testing; the production values are the plan's 20 min / 3 min.
BUILD_WATCHDOG_SECONDS="${SHIPPED_TOOL_RECIPES_BUILD_WATCHDOG:-1200}"
RUNTIME_WATCHDOG_SECONDS="${SHIPPED_TOOL_RECIPES_RUNTIME_WATCHDOG:-180}"

# --- the committed exact alternate selections (never `latest`) ---------------
# Sources: /tmp/agent-vm-227/{initial-pin-candidates.txt,alternate-selection-capture.json}
# during the #227 revision. The defaults come from the Dockerfiles themselves.
ALT_CODEX="rust-v0.159.2"
ALT_OPENCODE="v1.18.33"
ALT_CLAUDE="2.1.285"
ALT_COPILOT="1.0.89"
ALT_DSH="0.1.5-rc.1"
ALT_PNPM="11.10.0"
ALT_PI="0.87.0"
ALT_BRIDGE="0.7.0"

# --- per-run names -----------------------------------------------------------
RUN_ID="agent-vm-227-$$"
# `target/` is gitignored and absent on a fresh CI checkout with no Rust build,
# so create it before mktemp (which does not create parent directories).
mkdir -p "$REPO_ROOT/target"
TMP="$(mktemp -d "$REPO_ROOT/target/shipped-tool-recipes.XXXXXX")"

prefix_images() {
    docker images --format '{{.Repository}}:{{.Tag}}' | grep "^${RUN_ID}-" || true
}

# Every probe container is given a run-scoped name so cleanup can force-remove
# one whose `docker run` client was killed by a watchdog. `--rm` only removes a
# container after it exits, not after its client dies; the name is what makes a
# leaked container findable on a shared daemon (we never prune globally).
#
# `docker_run` is an executable wrapper, not a shell function: the Python host
# watchdog execs argv directly (script/test/host-watchdog.py), so a shell
# function would fail with ENOENT/EACCES. `$TMP/bin` is put on PATH for both the
# harness and the watchdog child.
mkdir -p "$TMP/bin"
cat >"$TMP/bin/docker_run" <<'SH'
#!/bin/sh
exec docker run --name "${RUN_ID}-probe-$$" "$@"
SH
chmod 0755 "$TMP/bin/docker_run"
export RUN_ID
PATH="$TMP/bin:$PATH"
export PATH

cleanup() {
    local cids
    cids="$(docker ps -aq --filter "name=^${RUN_ID}-" 2>/dev/null || true)"
    if [ -n "$cids" ]; then
        # shellcheck disable=SC2086  # word-splitting over the id list is intended
        docker rm -f $cids >/dev/null 2>&1 || true
    fi
    if [ "$keep" = false ]; then
        if [ -n "$(prefix_images)" ]; then
            # shellcheck disable=SC2046  # word-splitting over the image list is intended
            docker rmi $(prefix_images) >/dev/null 2>&1 || true
        fi
    else
        echo "kept images matching ${RUN_ID} (--keep)" >&2
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

# --- helpers -----------------------------------------------------------------
labels_json() {
    docker image inspect "$1" --format '{{json .Config.Labels}}' 2>/dev/null || echo '{}'
}

label_value() { # $1 image, $2 full label key
    labels_json "$1" | jq -r --arg k "$2" 'if . == null then "" else (.[$k] // "") end'
}

version_keys() { # $1 image -> sorted org.agent-vm.version.* keys
    labels_json "$1" | jq -r 'if . == null then "" else . end
        | keys[] | select(startswith("org.agent-vm.version."))' | sort
}

valid_semver() {
    printf '%s' "$1" | grep -Eq \
        '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
}

recipe_keys() { # $1 recipe -> label suffixes
    case "$1" in
        codex) printf '%s\n' codex ;;
        opencode) printf '%s\n' opencode ;;
        claude) printf '%s\n' claude ;;
        copilot) printf '%s\n' copilot ;;
        dsh) printf '%s\n' dsh pnpm ;;
        pi) printf '%s\n' pi pi-claude-bridge ;;
        *) fail "unknown recipe: $1" ;;
    esac
}

suffix_arg() { # $1 label suffix -> build ARG name
    case "$1" in
        codex) printf '%s\n' AGENT_VERSION_CODEX ;;
        opencode) printf '%s\n' AGENT_VERSION_OPENCODE ;;
        claude) printf '%s\n' AGENT_VERSION_CLAUDE ;;
        copilot) printf '%s\n' AGENT_VERSION_COPILOT ;;
        dsh) printf '%s\n' AGENT_VERSION_DSH ;;
        pnpm) printf '%s\n' AGENT_VERSION_PNPM ;;
        pi) printf '%s\n' AGENT_VERSION_PI ;;
        pi-claude-bridge) printf '%s\n' AGENT_VERSION_PI_CLAUDE_BRIDGE ;;
        *) fail "unknown label suffix: $1" ;;
    esac
}

suffix_for_arg() { # $1 build ARG name -> label suffix
    case "$1" in
        AGENT_VERSION_CODEX) printf '%s\n' codex ;;
        AGENT_VERSION_OPENCODE) printf '%s\n' opencode ;;
        AGENT_VERSION_CLAUDE) printf '%s\n' claude ;;
        AGENT_VERSION_COPILOT) printf '%s\n' copilot ;;
        AGENT_VERSION_DSH) printf '%s\n' dsh ;;
        AGENT_VERSION_PNPM) printf '%s\n' pnpm ;;
        AGENT_VERSION_PI) printf '%s\n' pi ;;
        AGENT_VERSION_PI_CLAUDE_BRIDGE) printf '%s\n' pi-claude-bridge ;;
        *) fail "unknown build ARG name: $1" ;;
    esac
}

# The committed defaults, asserted independently of the image's own labels so an
# ignored or mistyped build ARG cannot pass by matching the image to itself.
DEFAULT_CODEX="rust-v0.159.3"
DEFAULT_OPENCODE="v1.18.34"
DEFAULT_CLAUDE="2.1.286"
DEFAULT_COPILOT="1.0.90"
DEFAULT_DSH="0.1.5-rc.2"
DEFAULT_PNPM="11.11.0"
DEFAULT_PI="0.87.1"
DEFAULT_BRIDGE="0.8.0"

default_selection() { # $1 recipe -> newline-separated suffix=value
    case "$1" in
        codex) printf '%s\n' "codex=$DEFAULT_CODEX" ;;
        opencode) printf '%s\n' "opencode=$DEFAULT_OPENCODE" ;;
        claude) printf '%s\n' "claude=$DEFAULT_CLAUDE" ;;
        copilot) printf '%s\n' "copilot=$DEFAULT_COPILOT" ;;
        dsh) printf '%s\n' "dsh=$DEFAULT_DSH" "pnpm=$DEFAULT_PNPM" ;;
        pi) printf '%s\n' "pi=$DEFAULT_PI" "pi-claude-bridge=$DEFAULT_BRIDGE" ;;
        *) fail "unknown recipe: $1" ;;
    esac
}

# assert_expected_selection IMG 'suffix=value'... -- the label must equal the
# INDEPENDENTLY-supplied selection, not merely agree with the image's report.
assert_expected_selection() { # $1 image, $2 newline-separated suffix=value
    local img="$1" lines="$2" line suffix value got reason
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        suffix="${line%%=*}"
        value="${line#*=}"
        got="$(label_value "$img" "org.agent-vm.version.$suffix")"
        reason="$(expect_label "$img" "$suffix" "$value" "$got")" || fail "$reason"
    done <<<"$lines"
}

# assert_recipe_labels IMG RECIPE [EXPECTED_LABELS_FILE] [STRICT]
# Validates presence, spelling and syntax, and exact equality when given. With
# STRICT=0 (the chained image, which carries every recipe) extra labels from the
# other recipes are allowed.
assert_recipe_labels() { # $1 image, $2 recipe, $3 expected file, $4 strict
    local img="$1" recipe="$2" expected_file="${3:-}" strict="${4:-1}" keys want got suffix full value
    keys="$(recipe_keys "$recipe")"
    if [ "$strict" = 1 ]; then
        want="$(for suffix in $keys; do echo "org.agent-vm.version.$suffix"; done | sort)"
        got="$(version_keys "$img")"
        [ "$got" = "$want" ] ||
            fail "$recipe labels: expected exactly [$want], got [$(echo "$got" | tr '\n' ' ')]"
    fi
    while IFS= read -r suffix; do
        [ -n "$suffix" ] || continue
        full="org.agent-vm.version.$suffix"
        value="$(label_value "$img" "$full")"
        [ -n "$value" ] || fail "$recipe label $full is empty"
        case "$suffix" in
            codex)
                if [ "${value#rust-v}" = "$value" ] || ! valid_semver "${value#rust-v}"; then
                    fail "$recipe label $full='$value' is not rust-v<semver>"
                fi ;;
            opencode)
                if [ "${value#v}" = "$value" ] || ! valid_semver "${value#v}"; then
                    fail "$recipe label $full='$value' is not v<semver>"
                fi ;;
            *)
                if ! valid_semver "$value"; then
                    fail "$recipe label $full='$value' is not canonical semver"
                fi ;;
        esac
        if [ -n "$expected_file" ]; then
            expected="$(sed -n "s/^$suffix=//p" "$expected_file")"
            [ "$value" = "$expected" ] ||
                fail "$recipe label $full changed across replay: '$value' != '$expected'"
        fi
    done <<<"$keys"
}

# assert_base_labels IMG -> every base OCI label is present with the same value.
assert_base_labels() { # $1 image
    local img="$1" base_key base_value
    while IFS= read -r base_key; do
        [ -n "$base_key" ] || continue
        base_value="$(label_value "$BASE_IMAGE" "$base_key")"
        [ "$(label_value "$img" "$base_key")" = "$base_value" ] ||
            fail "$img dropped or changed base label $base_key"
    done <<<"$(labels_json "$BASE_IMAGE" | jq -r 'keys[]' 2>/dev/null)"
}

# --- container audit ---------------------------------------------------------
# Emits `rcN=`, `lineN=`, `t5rc=`, `status=`, `warn=`, ... lines the harness
# asserts. Runs as an arbitrary numeric uid with no capabilities and no network.
container_script() { # $1 recipe
    # Inject the byte-exact capture helper: every report and status record is
    # emitted base64-encoded so a first-line extraction cannot hide a
    # contradictory trailing line or a multi-line record (review F2).
    printf '%s\n' "$(declare -f b64file)"
    case "$1" in
        codex)
            cat <<'EOS'
printf '=== RUN ===\n'
codex --version >/tmp/o 2>/tmp/e
printf 'rc0=%s\n' "$?"
printf 'report_b64=%s\n' "$(b64file /tmp/o)"
printf 'stderr_b64=%s\n' "$(b64file /tmp/e)"
printf '=== T5 ===\n'
python3 /contract/check-tool-access.py codex
printf 't5rc=%s\n' "$?"
printf '=== STATUS ===\n'
printf 'status_b64=%s\n' "$(b64file /opt/agent-vm/install-status/codex)"
EOS
            ;;
        opencode)
            cat <<'EOS'
printf '=== RUN ===\n'
opencode --version >/tmp/o 2>/tmp/e
printf 'rc0=%s\n' "$?"
printf 'report_b64=%s\n' "$(b64file /tmp/o)"
printf 'stderr_b64=%s\n' "$(b64file /tmp/e)"
printf '=== T5 ===\n'
python3 /contract/check-tool-access.py opencode
printf 't5rc=%s\n' "$?"
printf '=== STATUS ===\n'
printf 'status_b64=%s\n' "$(b64file /opt/agent-vm/install-status/opencode)"
EOS
            ;;
        claude)
            cat <<'EOS'
printf '=== RUN ===\n'
claude --version >/tmp/o 2>/tmp/e
printf 'rc0=%s\n' "$?"
printf 'report_b64=%s\n' "$(b64file /tmp/o)"
printf 'stderr_b64=%s\n' "$(b64file /tmp/e)"
printf '=== T5 ===\n'
python3 /contract/check-tool-access.py claude
printf 't5rc=%s\n' "$?"
printf '=== STATUS ===\n'
printf 'status_b64=%s\n' "$(b64file /opt/agent-vm/install-status/claude)"
EOS
            ;;
        copilot)
            cat <<'EOS'
printf '=== RUN ===\n'
copilot --version >/tmp/o 2>/tmp/e
printf 'rc0=%s\n' "$?"
printf 'report_b64=%s\n' "$(b64file /tmp/o)"
printf 'stderr_b64=%s\n' "$(b64file /tmp/e)"
printf '=== T5 ===\n'
python3 /contract/check-tool-access.py copilot
printf 't5rc=%s\n' "$?"
printf '=== STATUS ===\n'
printf 'status_b64=%s\n' "$(b64file /opt/agent-vm/install-status/copilot)"
EOS
            ;;
        dsh)
            cat <<'EOS'
printf '=== RUN ===\n'
dsh --version >/tmp/o 2>/tmp/e
printf 'rc0=%s\n' "$?"
printf 'report_b64=%s\n' "$(b64file /tmp/o)"
printf 'stderr_b64=%s\n' "$(b64file /tmp/e)"
pnpm --version >/tmp/o1 2>/tmp/e1
printf 'rc1=%s\n' "$?"
printf 'report1_b64=%s\n' "$(b64file /tmp/o1)"
printf 'stderr1_b64=%s\n' "$(b64file /tmp/e1)"
printf '=== T5 ===\n'
python3 /contract/check-tool-access.py dsh pnpm
printf 't5rc=%s\n' "$?"
printf '=== STATUS ===\n'
printf 'status_b64=%s\n' "$(b64file /opt/agent-vm/install-status/dsh)"
EOS
            ;;
        pi)
            # bridge_marks is the ONE raw-output parser; inject its exact bytes
            # so the container audit cannot drift from the parser oracle_self_test
            # certifies against real probe text.
            printf '%s\n' "$(declare -f bridge_marks)"
            cat <<'EOS'
printf '=== RUN ===\n'
PI_TELEMETRY=0 pi --version >/tmp/o 2>/tmp/e
printf 'rc0=%s\n' "$?"
printf 'report_b64=%s\n' "$(b64file /tmp/o)"
printf 'stderr_b64=%s\n' "$(b64file /tmp/e)"
printf '=== WARN ===\n'
PI_TELEMETRY=0 pi --mode rpc --no-session --no-approve </dev/null >/tmp/w.out 2>/tmp/w.err
printf 'warn_rc=%s\n' "$?"
printf 'warn=%s\n' "$(grep -c 'agent-vm: signing in here' /tmp/w.out || true)"
printf 'bridgever=%s\n' \
    "$(jq -r .version /opt/agent-vm/pi-packages/node_modules/pi-claude-bridge/package.json 2>/dev/null || echo MISSING)"
printf '=== BRIDGE PROBE ===\n'
cat > /tmp/probe.js <<'PROBE'
export default function (pi) {
  pi.on("session_start", (_event, ctx) => {
    const p = ctx.modelRegistry.getProvider("claude-bridge");
    const n = p && typeof p.getModels === "function" ? p.getModels().length
            : p && Array.isArray(p.models) ? p.models.length : 0;
    ctx.ui.notify(p ? `AGENT-VM-BRIDGE-REGISTERED models=${n}` : "AGENT-VM-BRIDGE-MISSING",
                  "warning");
  });
}
PROBE
PI_TELEMETRY=0 pi -e /tmp/probe.js --mode rpc --no-session --no-approve </dev/null >/tmp/p.out 2>/tmp/p.err
printf 'probe_rc=%s\n' "$?"
# The registration result: bridge_marks emits exactly one line per
# registration-bearing probe output line (or an AGENT-VM-BRIDGE-MALFORMED
# sentinel for a malformed one) and NEVER truncates or drops a marker, so a
# positive contradicted by a missing/malformed one is visible as probes>1 and
# `models=12"garbage` does not survive as `models=12`. The parser is defined once
# in bridge_marks() (host) and injected above.
bridge_marks </tmp/p.out >/tmp/p.marks
printf 'probe=%s\n' "$(head -n 1 /tmp/p.marks)"
printf 'probes=%s\n' "$(wc -l </tmp/p.marks | tr -d ' ')"
printf '=== T5 ===\n'
python3 /contract/check-tool-access.py pi
printf 't5rc=%s\n' "$?"
printf '=== STATUS ===\n'
printf 'status_b64=%s\n' "$(b64file /opt/agent-vm/install-status/pi)"
printf 'bridgestatus_b64=%s\n' "$(b64file /opt/agent-vm/install-status/pi-claude-bridge)"
EOS
            ;;
        *) fail "unknown recipe: $1" ;;
    esac
}

# run_container IMG RECIPE UID -> stdout+stderr of the audit script
run_container() { # $1 image, $2 recipe, $3 uid:gid
    local img="$1" recipe="$2" uid="$3" rc=0
    run_with_watchdog "$RUNTIME_WATCHDOG_SECONDS" \
        docker_run --rm --platform "$platform" --user "$uid" \
        --cap-drop ALL --network none --tmpfs /tmp:rw,exec \
        -e HOME=/tmp \
        -v "$REPO_ROOT/images/tools/$recipe/contract:/contract:ro" \
        --entrypoint sh "$img" -c "$(container_script "$recipe")" 2>&1 || rc=$?
    [ "$rc" -ne 124 ] ||
        fail "$recipe ($uid) runtime probe timed out after ${RUNTIME_WATCHDOG_SECONDS}s"
}

kv() { # $1 output, $2 key -> first matching value
    printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n 1
}

# --- oracle predicates -------------------------------------------------------
# These are the value-level verdicts the acceptance oracle applies. They are
# deliberately pure (no docker) so `--self-test` can seed every rejected state
# and prove the oracle REPORTS the failure, not merely that the assertion text
# exists. Each prints a one-line reason on stdout and returns 1 on rejection, so
# a caller surfaces it with `reason="$(predicate ...)" || fail "$reason"`.

# exact_report FILE EXPECTED -- the COMPLETE report must be exactly EXPECTED,
# optionally followed by one trailing newline. A contradictory trailing line, a
# second line, or extra blank lines are rejected (review F2).
exact_report() { # $1 file, $2 expected single line (no newline)
    python3 - "$1" "$2" <<'PY'
import sys

data = open(sys.argv[1], "rb").read()
expected = sys.argv[2].encode()
sys.exit(0 if data in (expected, expected + b"\n") else 1)
PY
}

# copilot_report FILE VERSION -- copilot's genuine --version output is the
# banner followed by the documented update footer; the owning gate accepts the
# footer on every line after the banner. Mirror that exact record rather than
# demanding a single line, while still rejecting any other extra line (F2).
copilot_report() { # $1 file, $2 installed version (no prefix)
    python3 - "$1" "$2" <<'PY'
import sys

data = open(sys.argv[1], "rb").read()
version = sys.argv[2].encode()
# Reject non-printable bytes: a NUL would be erased by command substitution.
if any(not (b in (9, 10) or 32 <= b <= 126) for b in data):
    sys.exit(1)
lines = data.split(b"\n")
if lines and lines[-1] == b"":
    lines.pop()
banner = b"GitHub Copilot CLI " + version + b"."
footer = b"Run 'copilot update' to check for updates."
if not lines or lines[0] != banner:
    sys.exit(1)
sys.exit(0 if all(line in (b"", footer) for line in lines[1:]) else 1)
PY
}

# check_report RECIPE LABEL0 LABEL1 CONTAINER_OUTPUT -- the COMPLETE stdout
# report, decoded from its base64 capture, must be exactly each tool's allowed
# record; the whole report is validated, never just its first line (review F2).
check_report() { # $1 recipe, $2 label0 value, $3 label1 value, $4 output
    local recipe="$1" v0="$2" v1="$3" out="$4" expected file
    file="$TMP/report-check.$$"
    decode_b64 "$(kv "$out" report_b64)" "$file" ||
        { printf '%s report is missing' "$recipe"; return 1; }
    if [ "$recipe" = copilot ]; then
        copilot_report "$file" "$v0" || {
            printf '%s report is not the exact copilot record for %s: %s' \
                "$recipe" "$v0" "$(tr -d '\0' <"$file" | head -c 200)"
            return 1
        }
    else
        case "$recipe" in
            codex) expected="codex-cli ${v0#rust-v}" ;;
            opencode) expected="${v0#v}" ;;
            claude) expected="$v0 (Claude Code)" ;;
            dsh | pi) expected="$v0" ;;
            *) printf 'unknown recipe %s' "$recipe"; return 1 ;;
        esac
        exact_report "$file" "$expected" || {
            printf '%s report is not the exact record "%s": %s' \
                "$recipe" "$expected" "$(tr -d '\0' <"$file" | head -c 200)"
            return 1
        }
    fi
    case "$recipe" in
        dsh)
            [ "$(kv "$out" rc1)" = 0 ] || { printf 'dsh pnpm exited %s' "$(kv "$out" rc1)"; return 1; }
            file="$TMP/report-check-pnpm.$$"
            decode_b64 "$(kv "$out" report1_b64)" "$file" ||
                { printf 'dsh pnpm report is missing'; return 1; }
            exact_report "$file" "$v1" || {
                printf 'pnpm report is not the exact record "%s": %s' \
                    "$v1" "$(tr -d '\0' <"$file" | head -c 200)"
                return 1
            } ;;
    esac
    return 0
}

# check_status RECIPE CONTAINER_OUTPUT -- decode the exact status bytes and
# validate them with the committed install-status.py record predicate, so a
# multi-line or unterminated record is rejected rather than truncated to its
# first line (review F2). Pi's separate bridge record is validated too.
check_status() { # $1 recipe, $2 output
    local recipe="$1" out="$2" file got
    file="$TMP/status-check.$$"
    decode_b64 "$(kv "$out" status_b64)" "$file" ||
        { printf '%s status record is missing' "$recipe"; return 1; }
    got="$(python3 "$STATUS_VALIDATOR" record "$file" 2>/dev/null)" || {
        printf '%s status record is not a valid record: %s' \
            "$recipe" "$(tr -d '\0' <"$file" | head -c 200)"
        return 1
    }
    [ "$got" = installed ] || { printf '%s status is not "installed": %s' "$recipe" "$got"; return 1; }
    if [ "$recipe" = pi ]; then
        file="$TMP/status-check-bridge.$$"
        decode_b64 "$(kv "$out" bridgestatus_b64)" "$file" ||
            { printf 'pi bridge status record is missing'; return 1; }
        got="$(python3 "$STATUS_VALIDATOR" record "$file" 2>/dev/null)" || {
            printf 'pi bridge status record is not a valid record: %s' \
                "$(tr -d '\0' <"$file" | head -c 200)"
            return 1
        }
        [ "$got" = installed ] || { printf 'pi bridge status is not "installed": %s' "$got"; return 1; }
    fi
    return 0
}

# bridge_marks -- parse the bridge probe's raw stdout (one notification per line)
# into one registration result per output line. A result is a COMPLETE plain
# marker line (`AGENT-VM-BRIDGE-REGISTERED models=<digits>` or
# `AGENT-VM-BRIDGE-MISSING`) or the `.message` of a valid single-line JSON
# notification. A marker-bearing line that is neither -- truncated/invalid JSON,
# a non-numeric or zero-padded count, trailing garbage -- is emitted as
# `AGENT-VM-BRIDGE-MALFORMED`, so a malformed result can never be truncated into
# a well-formed-looking count (`models=12"garbage`) nor erased (a positive
# contradicted by an unparseable MISSING that `jq ... || true` swallowed).
#
# Defined ONCE here and injected verbatim (via `declare -f`) into the container
# audit in container_script(), so the parser the real build runs is exactly the
# bytes oracle_self_test certifies against RAW probe output.
bridge_marks() {
    local line msg n
    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        msg="$line"
        case "$line" in
            '{'*)
                # Whole-notification parsing: a JSON line that does not parse
                # as one value is not a trustworthy result.
                if msg="$(printf '%s\n' "$line" | jq -r \
                    'if type == "object" and (.message | type) == "string" then .message else empty end' \
                    2>/dev/null)"; then
                    :
                else
                    case "$line" in
                        *AGENT-VM-BRIDGE-REGISTERED* | *AGENT-VM-BRIDGE-MISSING*)
                            printf 'AGENT-VM-BRIDGE-MALFORMED\n' ;;
                    esac
                    continue
                fi ;;
        esac
        case "$msg" in
            AGENT-VM-BRIDGE-MISSING)
                printf 'AGENT-VM-BRIDGE-MISSING\n' ;;
            'AGENT-VM-BRIDGE-REGISTERED models='*)
                n="${msg#AGENT-VM-BRIDGE-REGISTERED models=}"
                case "$n" in
                    '' | *[!0-9]*)
                        printf 'AGENT-VM-BRIDGE-MALFORMED\n' ;;
                    *)
                        printf 'AGENT-VM-BRIDGE-REGISTERED models=%s\n' "$n" ;;
                esac ;;
            *AGENT-VM-BRIDGE-REGISTERED* | *AGENT-VM-BRIDGE-MISSING*)
                printf 'AGENT-VM-BRIDGE-MALFORMED\n' ;;
        esac
    done
}

# check_bridge CONTAINER_OUTPUT EXPECTED_BRIDGE_VERSION -- the behavioral probe
# must report EXACTLY ONE registration result with a canonical strictly-positive
# model count; metadata and a stale record are not proof. The probe/probes pair
# is what the container audit emits, so the oracle validates the external result
# independently of verify-pi.sh.
check_bridge() { # $1 output, $2 expected bridge version
    local out="$1" v1="$2" probe probes n
    [ "$(kv "$out" warn_rc)" = 0 ] || { printf 'pi rpc invocation exited %s' "$(kv "$out" warn_rc)"; return 1; }
    [ "$(kv "$out" warn)" != 0 ] || { printf 'pi does not load the mandatory warning extension'; return 1; }
    [ "$(kv "$out" bridgever)" = "$v1" ] ||
        { printf 'installed bridge %s != %s' "$(kv "$out" bridgever)" "$v1"; return 1; }
    [ "$(kv "$out" probe_rc)" = 0 ] || { printf 'bridge probe exited %s' "$(kv "$out" probe_rc)"; return 1; }
    probes="$(kv "$out" probes)"
    probe="$(kv "$out" probe)"
    [ "$probes" = 1 ] || {
        if [ "$probes" = 0 ]; then
            printf 'bridge did not register its provider: "%s"' "$probe"
        else
            printf 'bridge emitted %s conflicting registration results' "$probes"
        fi
        return 1
    }
    case "$probe" in
        AGENT-VM-BRIDGE-MISSING)
            printf 'bridge did not register its provider'; return 1 ;;
        'AGENT-VM-BRIDGE-REGISTERED models='*)
            n="${probe#AGENT-VM-BRIDGE-REGISTERED models=}"
            case "$n" in
                '' | *[!0-9]*) printf 'bridge reported a non-numeric model count "%s"' "$n"; return 1 ;;
                0 | 0*) printf 'bridge registered an empty model catalog'; return 1 ;;
            esac
            return 0 ;;
        *) printf 'bridge did not register its provider: "%s"' "$probe"; return 1 ;;
    esac
}

# expect_label IMG SUFFIX EXPECTED GOT -- a label must equal the
# INDEPENDENTLY-supplied selection; this is what catches a dropped override arg.
expect_label() { # $1 image, $2 suffix, $3 expected, $4 got
    [ "$4" = "$3" ] || { printf '%s ignored the requested %s=%s (label is %s)' "$1" "$2" "$3" "$4"; return 1; }
    return 0
}

# assert_files_identical A B MESSAGE -- byte identity, used for the
# committed-unchanged lock preservation check; a drift must fail.
assert_files_identical() { # $1 a, $2 b, $3 message
    cmp -s "$1" "$2" || { printf '%s' "$3"; return 1; }
    return 0
}

# oracle_self_test -- negative/positive CERTIFICATION of the predicates above.
# Every state the review named (a dropped override arg, lock drift, a
# missing/stale/degraded status, a non-registering bridge) must be rejected,
# and the matching good state must pass. Run with `--self-test`.
oracle_self_test() {
    local reason

    check_report codex rust-v0.159.3 "" "report_b64=$(printf 'codex-cli 0.159.3\n' | blob)" >/dev/null ||
        fail "self-test: a matching codex report was rejected"
    reason="$(check_report codex rust-v0.159.3 "" "report_b64=$(printf 'codex-cli 0.159.2\n' | blob)")" &&
        fail "self-test: a mismatched codex report was accepted"
    [ -n "$reason" ] || fail "self-test: a rejected report must carry a reason"
    # F2: a correct first line contradicted by a trailing line must be rejected
    # (the old `head -n 1` capture certified it).
    reason="$(check_report codex rust-v0.159.3 "" "report_b64=$(printf 'codex-cli 0.159.3\n9.9.9\n' | blob)")" &&
        fail "self-test: a contradictory trailing report line was accepted"
    [ -n "$reason" ] || fail "self-test: contradictory report rejection needs a reason"
    reason="$(check_report codex rust-v0.159.3 "" 'report_b64=MISSING')" &&
        fail "self-test: a missing codex report was accepted"
    reason="$(check_report dsh 0.1.5-rc.2 11.11.0 "$(printf 'report_b64=%s\nreport1_b64=%s\nrc1=0\n' \
        "$(printf '0.1.5-rc.2\n' | blob)" "$(printf '11.10.0\n' | blob)")")" &&
        fail "self-test: a wrong pnpm report was accepted"

    check_status codex "status_b64=$(sblob installed)" >/dev/null ||
        fail "self-test: an installed codex status was rejected"
    check_status pi "$(printf 'status_b64=%s\nbridgestatus_b64=%s\n' "$(sblob installed)" "$(sblob installed)")" >/dev/null ||
        fail "self-test: an installed pi + bridge status was rejected"
    local bad_status
    for bad_status in pending 'absent-transport 6' FAILED; do
        reason="$(check_status codex "status_b64=$(sblob "$bad_status")")" &&
            fail "self-test: codex status '$bad_status' was accepted"
        [ -n "$reason" ] || fail "self-test: status '$bad_status' rejection needs a reason"
    done
    reason="$(check_status codex 'status_b64=MISSING')" &&
        fail "self-test: a missing codex status was accepted"
    # F2: a valid first line followed by a contradictory record, and a record
    # with no trailing newline, must both be rejected by the byte-exact
    # validator (the old first-line extraction certified the former).
    reason="$(check_status codex "status_b64=$(printf 'installed\nabsent-transport 6\n' | blob)")" &&
        fail "self-test: a multi-line installed+absence status was accepted"
    [ -n "$reason" ] || fail "self-test: multi-line status rejection needs a reason"
    reason="$(check_status codex "status_b64=$(printf 'installed' | blob)")" &&
        fail "self-test: an unterminated installed status was accepted"
    reason="$(check_status pi "$(printf 'status_b64=%s\nbridgestatus_b64=%s\n' "$(sblob installed)" "$(sblob 'absent-transport 6')")")" &&
        fail "self-test: a degraded (absent) bridge status was accepted"
    reason="$(check_status pi "$(printf 'status_b64=%s\nbridgestatus_b64=MISSING\n' "$(sblob installed)")")" &&
        fail "self-test: a missing bridge status was accepted"

    check_bridge $'warn_rc=0\nwarn=1\nbridgever=0.8.0\nprobe_rc=0\nprobe=AGENT-VM-BRIDGE-REGISTERED models=3\nprobes=1' 0.8.0 >/dev/null ||
        fail "self-test: a registering bridge was rejected"
    local bad_probe probe_prefix=$'warn_rc=0\nwarn=1\nbridgever=0.8.0\nprobe_rc=0\nprobes=1\nprobe='
    for bad_probe in 'AGENT-VM-BRIDGE-MISSING' 'AGENT-VM-BRIDGE-REGISTERED models=0' \
        'AGENT-VM-BRIDGE-REGISTERED models=' 'AGENT-VM-BRIDGE-REGISTERED models=00' \
        'AGENT-VM-BRIDGE-REGISTERED models=garbage' 'AGENT-VM-BRIDGE-REGISTERED models=-1'; do
        reason="$(check_bridge "$probe_prefix$bad_probe" 0.8.0)" &&
            fail "self-test: a non-registering bridge ('$bad_probe') was accepted"
        [ -n "$reason" ] || fail "self-test: bridge '$bad_probe' rejection needs a reason"
    done
    # A positive marker contradicted by a missing one is ambiguous: the raw
    # count of registration results must be exactly one.
    reason="$(check_bridge $'warn_rc=0\nwarn=1\nbridgever=0.8.0\nprobe_rc=0\nprobe=AGENT-VM-BRIDGE-REGISTERED models=12\nprobes=2' 0.8.0)" &&
        fail "self-test: a contradictory bridge report was accepted"
    [ "$reason" = 'bridge emitted 2 conflicting registration results' ] ||
        fail "self-test: contradictory bridge rejection lost its reason: $reason"
    reason="$(check_bridge $'warn_rc=0\nwarn=1\nbridgever=0.8.0\nprobe_rc=0\nprobe=AGENT-VM-BRIDGE-REGISTERED models=3\nprobes=0' 0.8.0)" &&
        fail "self-test: an empty registration result set was accepted"
    reason="$(check_bridge $'warn_rc=0\nwarn=1\nbridgever=0.7.0\nprobe_rc=0\nprobe=AGENT-VM-BRIDGE-REGISTERED models=3\nprobes=1' 0.8.0)" &&
        fail "self-test: a stale bridge version was accepted"
    reason="$(check_bridge $'warn_rc=0\nwarn=1\nbridgever=0.8.0\nprobe_rc=1\nprobe=AGENT-VM-BRIDGE-REGISTERED models=3\nprobes=1' 0.8.0)" &&
        fail "self-test: a nonzero bridge probe was accepted"

    # --- bridge extraction: the REAL parser over RAW probe output -----------
    # The container audit pipes the bridge's raw stdout through bridge_marks and
    # feeds the marks to check_bridge. Seed RAW text (never a sanitized predicate
    # value) and require the pair to accept the valid forms and reject the
    # review's exact `models=12"garbage` counterexample, a positive contradicted
    # by a malformed JSON MISSING, and a plain contradiction. A regression that
    # truncates (`grep -oE '...models=[^" ]*'`) or drops (`jq ... || true`) a
    # malformed marker therefore fails HERE, through the same bytes the build
    # ships.
    command -v jq >/dev/null 2>&1 || fail "self-test: jq is required for the bridge extraction tier"
    local rawfile="$TMP/self-bridge-raw"
    check_raw_bridge() { # $1 raw probe stdout, $2 expect pass (1) / reject (0)
        printf '%s\n' "$1" >"$rawfile"
        bridge_marks <"$rawfile" >"$rawfile.marks"
        local fields reason accepted=0
        fields="$(printf 'probe=%s\nprobes=%s\n' \
            "$(head -n 1 "$rawfile.marks")" \
            "$(wc -l <"$rawfile.marks" | tr -d ' ')")"
        if reason="$(check_bridge "$(printf 'warn_rc=0\nwarn=1\nbridgever=0.8.0\nprobe_rc=0\n%s\n' "$fields")" 0.8.0)"; then
            accepted=1
        fi
        if [ "$2" = 1 ]; then
            [ "$accepted" = 1 ] || fail "self-test: a valid raw bridge report was rejected: $reason"
        else
            [ "$accepted" = 0 ] || fail "self-test: a malformed raw bridge report was accepted: '$1'"
            [ -n "$reason" ] || fail "self-test: raw bridge rejection lost its reason: '$1'"
        fi
    }
    check_raw_bridge 'AGENT-VM-BRIDGE-REGISTERED models=12' 1
    check_raw_bridge '{"type":"notification","message":"AGENT-VM-BRIDGE-REGISTERED models=12","notifyType":"warning"}' 1
    check_raw_bridge 'AGENT-VM-BRIDGE-REGISTERED models=12"garbage' 0
    check_raw_bridge '{"message":"AGENT-VM-BRIDGE-REGISTERED models=12"' 0
    check_raw_bridge "$(printf 'AGENT-VM-BRIDGE-REGISTERED models=12\n{"message":"AGENT-VM-BRIDGE-MISSING"')" 0
    check_raw_bridge "$(printf 'AGENT-VM-BRIDGE-REGISTERED models=12\nAGENT-VM-BRIDGE-MISSING')" 0

    expect_label img codex rust-v0.159.2 rust-v0.159.2 >/dev/null ||
        fail "self-test: a matching override label was rejected"
    reason="$(expect_label img codex rust-v0.159.2 rust-v0.159.3)" &&
        fail "self-test: a dropped override arg (default label) was accepted"

    local a="$TMP/self-lock-a" b="$TMP/self-lock-b"
    printf 'lock-a\n' >"$a"
    cp "$a" "$b"
    assert_files_identical "$a" "$b" "self-test" >/dev/null ||
        fail "self-test: identical locks were rejected"
    printf 'drift\n' >"$b"
    reason="$(assert_files_identical "$a" "$b" 'pi lock drifted')" &&
        fail "self-test: a drifted lock was accepted"
    [ "$reason" = 'pi lock drifted' ] || fail "self-test: lock drift rejection lost its reason"

    echo "oracle self-test: every rejected state failed with a reason"
    oracle_wiring_self_test
}

# oracle_wiring_self_test -- deterministic INTEGRATION certification of the
# build/audit call sites, complementing the value-level predicates above. It
# drives the REAL build_recipe -> build_and_audit -> assert_expected_selection
# chain and the REAL replay_check/audit_image wiring with fake build/run
# adapters. The original review mutation (dropping `"$@"` from build_recipe, or
# not calling check_dsh_lock/image_file/check_status/check_bridge) therefore
# fails THIS test, not merely a predicate seeded in isolation.
oracle_wiring_self_test() {
    local reason real_audit_image
    # audit_image is defined later in the file; keep the real one to restore
    # after the forwarding block overrides it.
    real_audit_image="$(declare -f audit_image)"

    # --- forwarding: a requested ARG must reach the produced label -----------
    # The fake build adapter derives the produced label from the build ARGs,
    # exactly as a real build does; build_recipe must forward its trailing "$@"
    # for the adapter to see them.
    run_with_watchdog() {
        local arg
        WIRING_LABEL="$DEFAULT_CODEX"
        for arg in "$@"; do
            case "$arg" in
                AGENT_VERSION_CODEX=*) WIRING_LABEL="${arg#*=}" ;;
            esac
        done
        return 0
    }
    label_value() { printf '%s\n' "${WIRING_LABEL:-}"; }
    audit_image() { return 0; }

    EXPECT_SELECTIONS="codex=$ALT_CODEX"
    build_and_audit codex wiring --build-arg "AGENT_VERSION_CODEX=$ALT_CODEX"
    [ "$WIRING_LABEL" = "$ALT_CODEX" ] ||
        fail "self-test: the build adapter never saw the forwarded override ARG"

    # If build_recipe drops its trailing "$@", the adapter keeps the default
    # label and the SAME chain rejects it.
    WIRING_LABEL="$DEFAULT_CODEX"
    if ( assert_expected_selection img "$EXPECT_SELECTIONS" ) >/dev/null 2>&1; then
        fail "self-test: a dropped override ARG was accepted through the wiring"
    fi

    # --- mixed-empty companion drift (review F1) ----------------------------
    # A mixed-empty build requests ONE slot; the committed companion must stay
    # put. Asserting only the changed slot let an implementation silently move
    # the companion through both selection and replay. The expectation now
    # names BOTH effective slots, so a drifted companion fails here.
    EXPECT_SELECTIONS="$(printf 'dsh=%s\npnpm=%s' "$ALT_DSH" "$DEFAULT_PNPM")"
    label_value() {
        case "$2" in
            *version.dsh) printf '%s\n' "$ALT_DSH" ;;
            *version.pnpm) printf '%s\n' "$DEFAULT_PNPM" ;;
        esac
    }
    assert_expected_selection img "$EXPECT_SELECTIONS" >/dev/null ||
        fail "self-test: a preserved mixed-empty companion was rejected"
    label_value() {
        case "$2" in
            *version.dsh) printf '%s\n' "$ALT_DSH" ;;
            *version.pnpm) printf '%s\n' "$ALT_PNPM" ;;  # silently moved companion
        esac
    }
    if ( assert_expected_selection img "$EXPECT_SELECTIONS" ) >/dev/null 2>&1; then
        fail "self-test: a drifted companion slot on a mixed-empty selection was accepted"
    fi

    # --- status/probe: the real audit_image must consult the container output -
    eval "$real_audit_image"
    # shellcheck disable=SC2317,SC2329  # invoked indirectly by the real audit_image
    label_value() {
        case "$2" in
            *version.codex) printf 'rust-v0.159.3\n' ;;
            *version.pi) printf '0.87.1\n' ;;
            *version.pi-claude-bridge) printf '0.8.0\n' ;;
            *) printf '\n' ;;
        esac
    }
    # shellcheck disable=SC2317,SC2329  # invoked indirectly by the real audit_image
    assert_recipe_labels() { return 0; }
    # shellcheck disable=SC2317,SC2329  # invoked indirectly by the real audit_image
    assert_base_labels() { return 0; }
    # shellcheck disable=SC2317,SC2329  # invoked indirectly by the real audit_image
    run_container() { printf '%s\n' "$WIRING_OUT"; }

    WIRING_OUT="$(printf 'rc0=0\nreport_b64=%s\nt5rc=0\nstatus_b64=%s\n' \
        "$(printf 'codex-cli 0.159.3\n' | blob)" "$(sblob installed)")"
    audit_image img codex >/dev/null || fail "self-test: a healthy codex audit was rejected"
    WIRING_OUT="$(printf 'rc0=0\nreport_b64=%s\nt5rc=0\nstatus_b64=%s\n' \
        "$(printf 'codex-cli 0.159.3\n' | blob)" "$(sblob pending)")"
    if ( audit_image img codex ) >/dev/null 2>&1; then
        fail "self-test: audit_image accepted a non-installed status"
    fi

    local pi_ok
    pi_ok="$(printf 'rc0=0\nreport_b64=%s\nt5rc=0\nstatus_b64=%s\nwarn_rc=0\nwarn=1\nbridgever=0.8.0\nprobe_rc=0\nprobes=1\nbridgestatus_b64=%s\n' \
        "$(printf '0.87.1\n' | blob)" "$(sblob installed)" "$(sblob installed)")"
    WIRING_OUT="$pi_ok"$'\nprobe=AGENT-VM-BRIDGE-REGISTERED models=12'
    audit_image img pi >/dev/null || fail "self-test: a healthy pi audit was rejected"
    WIRING_OUT="$pi_ok"$'\nprobe=AGENT-VM-BRIDGE-MISSING'
    if ( audit_image img pi ) >/dev/null 2>&1; then
        fail "self-test: audit_image accepted a non-registering bridge"
    fi
    WIRING_OUT="$(printf 'rc0=0\nreport_b64=%s\nt5rc=0\nstatus_b64=%s\nwarn_rc=0\nwarn=1\nbridgever=0.8.0\nprobe_rc=0\nprobe=AGENT-VM-BRIDGE-REGISTERED models=12\nprobes=1\nbridgestatus_b64=%s\n' \
        "$(printf '0.87.1\n' | blob)" "$(sblob installed)" "$(sblob 'absent-transport 6')")"
    if ( audit_image img pi ) >/dev/null 2>&1; then
        fail "self-test: audit_image accepted a degraded bridge status"
    fi

    # --- lock preservation: replay_check must act on the lock call sites -----
    build_recipe() { return 0; }
    label_value() {
        case "$2" in
            *version.dsh) printf '0.1.5-rc.2\n' ;;
            *version.pnpm) printf '11.11.0\n' ;;
            *version.pi) printf '0.87.1\n' ;;
            *version.pi-claude-bridge) printf '0.8.0\n' ;;
        esac
    }
    assert_recipe_labels() { return 0; }
    assert_base_labels() { return 0; }
    audit_image() { return 0; }

    check_dsh_lock() { return "$WIRING_LOCK_RC"; }
    WIRING_LOCK_RC=1
    ( replay_check img dsh tag ) >/dev/null 2>&1 &&
        fail "self-test: replay_check accepted a rejected dsh lock record"
    WIRING_LOCK_RC=0
    ( replay_check img dsh tag ) >/dev/null 2>&1 ||
        fail "self-test: replay_check rejected a preserved dsh lock record"

    # pi: replay_check must compare the committed lock to BOTH images; a drifted
    # replay lock must fail. The fake image_file copies the correct committed
    # lock for pi vs. pi-packages; the drifted variant overrides it below.
    image_file() { # $1 image, $2 path, $3 out
        local committed
        case "$2" in
            *pi-packages*) committed="$REPO_ROOT/images/tools/pi/bridge/package-lock.json" ;;
            *) committed="$REPO_ROOT/images/tools/pi/package-lock.json" ;;
        esac
        cp "$committed" "$3"
    }
    ( replay_check src pi replay-good ) >/dev/null 2>&1 ||
        fail "self-test: replay_check rejected a preserved pi lock"
    image_file() { # drifted replay image: the comparison must fail
        local committed
        case "$2" in
            *pi-packages*) committed="$REPO_ROOT/images/tools/pi/bridge/package-lock.json" ;;
            *) committed="$REPO_ROOT/images/tools/pi/package-lock.json" ;;
        esac
        case "$1" in
            *replay*) printf 'drifted\n' >"$3" ;;
            *) cp "$committed" "$3" ;;
        esac
    }
    ( replay_check src pi replay-drifted ) >/dev/null 2>&1 &&
        fail "self-test: replay_check accepted a drifted pi replay lock"

    echo "oracle wiring self-test: forwarding, status/probe and lock call sites exercised"
}

# audit_image IMG RECIPE [STRICT_LABELS] -> labels + reports + T5 + status.
audit_image() { # $1 image, $2 recipe, $3 strict-label-exactness (default 1)
    local img="$1" recipe="$2" strict="${3:-1}" out v0 v1 k0 k1 reason
    assert_recipe_labels "$img" "$recipe" "" "$strict"
    assert_base_labels "$img"

    case "$recipe" in
        codex) k0=codex ;;
        opencode) k0=opencode ;;
        claude) k0=claude ;;
        copilot) k0=copilot ;;
        dsh) k0=dsh; k1=pnpm ;;
        pi) k0=pi; k1=pi-claude-bridge ;;
        *) fail "unknown recipe: $recipe" ;;
    esac
    v0="$(label_value "$img" "org.agent-vm.version.$k0")"
    v1=""
    [ -n "${k1:-}" ] && v1="$(label_value "$img" "org.agent-vm.version.$k1")"

    for uid in 12345:23456 54321:45678; do
        out="$(run_container "$img" "$recipe" "$uid")"
        [ "$(kv "$out" rc0)" = 0 ] ||
            fail "$recipe ($uid) report exited $(kv "$out" rc0); output: $(printf '%s' "$out" | head -c 400)"
        [ "$(kv "$out" t5rc)" = 0 ] ||
            fail "$recipe ($uid) T5 audit failed: $out"
        reason="$(check_report "$recipe" "$v0" "$v1" "$out")" ||
            fail "$recipe ($uid) report mismatch: $reason"
        reason="$(check_status "$recipe" "$out")" ||
            fail "$recipe ($uid) $reason"
        if [ "$recipe" = pi ]; then
            # The behavioral probe must run under a numeric uid too: metadata
            # and a stale `installed` record are not proof a working extension.
            reason="$(check_bridge "$out" "$v1")" || fail "pi ($uid) $reason"
        fi
    done
    echo "  $recipe: labels ok; reports/T5/status ok as 12345:23456 and 54321:45678"
}

# --- builds ------------------------------------------------------------------
build_recipe() { # $1 base, $2 recipe, $3 tag, rest: --build-arg k=v ...
    local base="$1" recipe="$2" tag="$3" rc=0
    shift 3
    run_with_watchdog "$BUILD_WATCHDOG_SECONDS" \
        docker buildx build --platform "$platform" --load -t "$tag" \
        -f "$REPO_ROOT/images/tools/$recipe/Dockerfile" \
        --build-arg BASE_IMAGE="$base" "$@" \
        "$REPO_ROOT/images/tools/$recipe" >"$TMP/build-$tag.log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        sed -n '1,80p' "$TMP/build-$tag.log" >&2
        [ "$rc" -ne 124 ] ||
            fail "$recipe build ($tag) timed out after ${BUILD_WATCHDOG_SECONDS}s (process group killed)"
        fail "$recipe build ($tag) failed (exit $rc)"
    fi
}

# --- lock preservation on replay --------------------------------------------
# dsh shares one lock across both slots: the committed location-freeze checker
# proves only the selected root moved and every other record stayed.
check_dsh_lock() { # $1 image (has DSH_PIN/PNPM_PIN env), $2 dsh pin, $3 pnpm pin
    # shellcheck disable=SC2016  # $DSH_PIN/$PNPM_PIN must expand in the container
    run_with_watchdog "$RUNTIME_WATCHDOG_SECONDS" \
        docker_run --rm --platform "$platform" \
        -v "$REPO_ROOT/images/tools/dsh/check-lock-update.js:/cmp/check-lock-update.js:ro" \
        -v "$REPO_ROOT/images/tools/dsh/package.json:/cmp/package.json:ro" \
        -v "$REPO_ROOT/images/tools/dsh/package-lock.json:/cmp/package-lock.json:ro" \
        -e DSH_PIN="$2" -e PNPM_PIN="$3" \
        --entrypoint sh "$1" -c \
        'node /cmp/check-lock-update.js /cmp/package.json /cmp/package-lock.json /opt/agent-vm/dsh/package.json /opt/agent-vm/dsh/package-lock.json "$DSH_PIN" "$PNPM_PIN"'
}

image_file() { # $1 image, $2 absolute path in image, $3 out file
    local rc=0
    run_with_watchdog "$RUNTIME_WATCHDOG_SECONDS" \
        docker_run --rm --platform "$platform" --entrypoint cat "$1" "$2" >"$3" 2>/dev/null || rc=$?
    [ "$rc" -ne 124 ] || fail "$1: timed out reading $2"
    [ "$rc" -eq 0 ] || fail "$1: cannot read $2"
}

# Replay acceptance: read the exact version labels of $1, feed them back as
# explicit ARGs onto the second tool-free base, and require the same normalized
# reports, labels, statuses and preserved base labels. The previously-empty
# project's committed lock must survive byte-for-byte.
#
# $4 (optional) is the REQUESTED selection the source was built with. Preserving
# a committed lock is decided from that request, not the image's own label, so a
# mixed-empty build that silently moved the companion slot cannot disable the
# preservation check by giving the companion a nondefault label (review F1).
requested_value() { # $1 requested selection, $2 suffix -> value (or empty)
    printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n 1
}

replay_check() { # $1 source image, $2 recipe, $3 replay tag, [$4 requested selection]
    local src="$1" recipe="$2" tag="$3" requested="${4:-}" args suffix value
    args=()
    while IFS= read -r suffix; do
        [ -n "$suffix" ] || continue
        value="$(label_value "$src" "org.agent-vm.version.$suffix")"
        args+=("--build-arg" "$(suffix_arg "$suffix")=$value")
    done <<<"$(recipe_keys "$recipe")"
    build_recipe "$RUN_ID-replay-base" "$recipe" "$tag" "${args[@]}"

    local expected="$TMP/expect-$recipe.tsv"
    : >"$expected"
    while IFS= read -r suffix; do
        [ -n "$suffix" ] || continue
        printf '%s=%s\n' "$suffix" "$(label_value "$src" "org.agent-vm.version.$suffix")" >>"$expected"
    done <<<"$(recipe_keys "$recipe")"

    assert_recipe_labels "$tag" "$recipe" "$expected"
    assert_base_labels "$tag"
    audit_image "$tag" "$recipe"

    case "$recipe" in
        dsh)
            check_dsh_lock "$tag" \
                "$(label_value "$src" org.agent-vm.version.dsh)" \
                "$(label_value "$src" org.agent-vm.version.pnpm)" ||
                fail "dsh replay moved a frozen lock record" ;;
        pi)
            # A project whose REQUESTED value is its committed default was NOT
            # regenerated: its lock must be byte-identical to the committed lock
            # in BOTH the source image and the replay, checked UNCONDITIONALLY
            # (not only when the source happened to already match). The decision
            # uses the requested selection, not the image's own label.
            local proj committed pin reason request
            for proj in pi pi-packages; do
                case "$proj" in
                    pi) committed="$REPO_ROOT/images/tools/pi/package-lock.json"
                        pin="$DEFAULT_PI"; suffix=pi ;;
                    pi-packages) committed="$REPO_ROOT/images/tools/pi/bridge/package-lock.json"
                        pin="$DEFAULT_BRIDGE"; suffix=pi-claude-bridge ;;
                esac
                request="$(requested_value "$requested" "$suffix")"
                # Fall back to the source label only when no request was
                # threaded (the wiring self-test calls this directly).
                [ -n "$request" ] || request="$(label_value "$src" "org.agent-vm.version.$suffix")"
                [ "$request" = "$pin" ] || continue
                image_file "$src" "/opt/agent-vm/$proj/package-lock.json" "$TMP/src-$proj.lock"
                image_file "$tag" "/opt/agent-vm/$proj/package-lock.json" "$TMP/rep-$proj.lock"
                reason="$(assert_files_identical "$committed" "$TMP/src-$proj.lock" \
                    "pi $proj lock in the source is not the committed lock despite requested pin $request")" || fail "$reason"
                reason="$(assert_files_identical "$committed" "$TMP/rep-$proj.lock" \
                    "pi replay changed the committed-unchanged $proj lock")" || fail "$reason"
            done ;;
    esac
    echo "  replay $recipe: labels/reports/statuses preserved on the second base"
}

# --- T5 built-image negatives ------------------------------------------------
t5_negatives() {
    local img="$RUN_ID-t5" status out rc=0
    run_with_watchdog "$BUILD_WATCHDOG_SECONDS" \
        docker buildx build --platform "$platform" --load -t "$img" \
        -f "$FIXTURE_DOCKERFILE" --build-arg BASE_IMAGE="$BASE_IMAGE" \
        "$REPO_ROOT/images/tools/codex" >"$TMP/build-t5.log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        sed -n '1,60p' "$TMP/build-t5.log" >&2
        [ "$rc" -ne 124 ] || fail "T5 fixture build timed out after ${BUILD_WATCHDOG_SECONDS}s"
        fail "T5 fixture build failed"
    fi

    # expect_fail UID TARGET [PATH_OVERRIDE] NEEDLE [WORKDIR]
    expect_fail() {
        local uid="$1" target="$2" pathov="$3" needle="$4" workdir="${5:-}" out status
        local args=(--rm --platform "$platform" --user "$uid" --cap-drop ALL --network none)
        if [ -n "$pathov" ]; then
            args=(-e "PATH=$pathov" "${args[@]}")
        fi
        if [ -n "$workdir" ]; then
            args=(--workdir "$workdir" "${args[@]}")
        fi
        args+=(-v "$REPO_ROOT/images/tools/codex/contract:/contract:ro"
            --entrypoint /usr/bin/python3 "$img" /contract/check-tool-access.py "$target")
        set +e
        out="$(run_with_watchdog "$RUNTIME_WATCHDOG_SECONDS" docker_run "${args[@]}" 2>&1)"
        status=$?
        set -e
        [ "$status" -ne 124 ] ||
            fail "T5 negative '$target' ($uid) timed out after ${RUNTIME_WATCHDOG_SECONDS}s"
        [ "$status" -ne 0 ] || fail "T5 negative '$target' ($uid) unexpectedly passed"
        case "$out" in
            *"$needle"*) : ;;
            *) fail "T5 negative '$target' ($uid) failed without '$needle': $out" ;;
        esac
    }

    expect_fail 12345:23456 /t5/neg/symlink0700/bin/link "" "not traversable by all"
    expect_fail 12345:23456 tool "/t5/neg/dir0700/bin:/usr/bin:/bin" "not traversable by all"
    expect_fail 12345:23456 /t5/neg/root0700/cmd "" "not executable by all"
    expect_fail 12345:23456 /t5/neg/gid0701/bin/cmd "" "not traversable by all"
    # F6: the 0701 group-match DENIAL fixture is owned root:23456, so the group
    # class denies the audited 12345:23456 identity and the checker fails closed.
    # Assert execution is denied before repair and allowed after.
    expect_fail 12345:23456 /t5/neg/gid0701-deny/bin/cmd "" "does not exist"
    local gid_rc=0
    run_with_watchdog "$RUNTIME_WATCHDOG_SECONDS" \
        docker_run --rm --platform "$platform" --user 0:0 \
        --cap-drop ALL --cap-add SETUID --cap-add SETGID --network none \
        --entrypoint sh "$img" -c '
        set -eu
        if setpriv --reuid 12345 --regid 23456 --clear-groups /t5/neg/gid0701-deny/bin/cmd >/dev/null 2>&1; then
            echo "gid0701-deny executed before repair" >&2
            exit 10
        fi
        chmod 0755 /t5/neg/gid0701-deny
        setpriv --reuid 12345 --regid 23456 --clear-groups /t5/neg/gid0701-deny/bin/cmd >/dev/null 2>&1 || {
            echo "gid0701-deny still denied after repair" >&2
            exit 11
        }
        echo "gid0701-deny: denied before repair, allowed after"
        ' || gid_rc=$?
    [ "$gid_rc" -ne 124 ] || fail "the gid0701-deny execution fixture timed out"
    [ "$gid_rc" -eq 0 ] || fail "the gid0701-deny execution fixture failed (rc=$gid_rc)"
    expect_fail 12345:45678 /t5/neg/owner0001/cmd "" "not executable by all"
    expect_fail 12345:23456 /t5/neg/script0111/cmd "" "cannot read"
    expect_fail 12345:23456 /t5/neg/dangling/bin/link "" "does not exist"
    expect_fail 12345:23456 /t5/neg/cycle/bin/a "" "symlink chain exceeds"
    # SP1: the `#!/usr/bin/env NAME` shebang must audit NAME on PATH...
    expect_fail 12345:23456 /t5/neg/env0700/bin/tool \
        "/t5/neg/env0700/interp:/usr/bin:/bin" "not executable by all"
    # ...and a PATH-changing `-S` shebang must audit NAME under the EFFECTIVE
    # PATH its own assignment selects, not the auditor's (which here holds a
    # good interpreter).
    expect_fail 12345:23456 /t5/neg/envpath/bin/tool \
        "/t5/neg/envpath/good:/usr/bin:/bin" "not executable by all"
    # ...and a NESTED env interpreter that sets no PATH of its own inherits the
    # effective PATH its ancestor selected; resolving it on the auditor's PATH
    # would certify a tool the kernel cannot execute.
    expect_fail 12345:23456 /t5/neg/envnested/bin/tool \
        "/t5/neg/envnested/good:/usr/bin:/bin" "not executable by all"
    # ...and a relative command path must still audit the directory `..` leaves.
    expect_fail 12345:23456 private/../bin/tool "" "not traversable by all" \
        /t5/neg/lexical0700
    echo "  T5 negatives: all twelve rejected with the offending path"

    # The repaired tree passes under two unrelated numeric gids.
    local ok_uid
    for ok_uid in 12345:54321 54321:12345; do
        rc=0
        run_with_watchdog "$RUNTIME_WATCHDOG_SECONDS" \
            docker_run --rm --platform "$platform" --user "$ok_uid" \
            --cap-drop ALL --network none \
            -v "$REPO_ROOT/images/tools/codex/contract:/contract:ro" \
            --entrypoint /usr/bin/python3 "$img" \
            /contract/check-tool-access.py /t5/pass/one/two/cmd /t5/pass/multi/two \
            >"$TMP/t5-pass-$ok_uid.out" 2>&1 || rc=$?
        [ "$rc" -ne 124 ] ||
            fail "T5 repaired fixture timed out under uid $ok_uid after ${RUNTIME_WATCHDOG_SECONDS}s"
        [ "$rc" -eq 0 ] ||
            fail "T5 repaired fixture failed under uid $ok_uid: $(cat "$TMP/t5-pass-$ok_uid.out")"
        # The repaired `#!/usr/bin/env NAME` command passes once NAME is 0755.
        rc=0
        run_with_watchdog "$RUNTIME_WATCHDOG_SECONDS" \
            docker_run --rm --platform "$platform" --user "$ok_uid" \
            --cap-drop ALL --network none -e "PATH=/t5/pass/env/interp:/usr/bin:/bin" \
            -v "$REPO_ROOT/images/tools/codex/contract:/contract:ro" \
            --entrypoint /usr/bin/python3 "$img" \
            /contract/check-tool-access.py /t5/pass/env/bin/tool \
            >"$TMP/t5-pass-env-$ok_uid.out" 2>&1 || rc=$?
        [ "$rc" -ne 124 ] ||
            fail "T5 repaired env fixture timed out under uid $ok_uid after ${RUNTIME_WATCHDOG_SECONDS}s"
        [ "$rc" -eq 0 ] ||
            fail "T5 repaired env fixture failed under uid $ok_uid: $(cat "$TMP/t5-pass-env-$ok_uid.out")"
        # The repaired PATH-changing `-S` command passes once NAME is 0755.
        rc=0
        run_with_watchdog "$RUNTIME_WATCHDOG_SECONDS" \
            docker_run --rm --platform "$platform" --user "$ok_uid" \
            --cap-drop ALL --network none -e "PATH=/t5/pass/envpath/good:/usr/bin:/bin" \
            -v "$REPO_ROOT/images/tools/codex/contract:/contract:ro" \
            --entrypoint /usr/bin/python3 "$img" \
            /contract/check-tool-access.py /t5/pass/envpath/bin/tool \
            >"$TMP/t5-pass-envpath-$ok_uid.out" 2>&1 || rc=$?
        [ "$rc" -ne 124 ] ||
            fail "T5 repaired envpath fixture timed out under uid $ok_uid after ${RUNTIME_WATCHDOG_SECONDS}s"
        [ "$rc" -eq 0 ] ||
            fail "T5 repaired envpath fixture failed under uid $ok_uid: $(cat "$TMP/t5-pass-envpath-$ok_uid.out")"
        # The repaired nested inherited-PATH command passes once NAME is 0755.
        rc=0
        run_with_watchdog "$RUNTIME_WATCHDOG_SECONDS" \
            docker_run --rm --platform "$platform" --user "$ok_uid" \
            --cap-drop ALL --network none -e "PATH=/t5/pass/envnested/bad:/usr/bin:/bin" \
            -v "$REPO_ROOT/images/tools/codex/contract:/contract:ro" \
            --entrypoint /usr/bin/python3 "$img" \
            /contract/check-tool-access.py /t5/pass/envnested/bin/tool \
            >"$TMP/t5-pass-envnested-$ok_uid.out" 2>&1 || rc=$?
        [ "$rc" -ne 124 ] ||
            fail "T5 repaired nested-env fixture timed out under uid $ok_uid after ${RUNTIME_WATCHDOG_SECONDS}s"
        [ "$rc" -eq 0 ] ||
            fail "T5 repaired nested-env fixture failed under uid $ok_uid: $(cat "$TMP/t5-pass-envnested-$ok_uid.out")"
    done
    echo "  T5 repaired fixture: passes under 12345:54321 and 54321:12345"
}

# --- chain -------------------------------------------------------------------
chain_check() {
    local order=(dsh pi codex opencode claude copilot) prev recipe tag
    prev="$BASE_IMAGE"
    for recipe in "${order[@]}"; do
        tag="$RUN_ID-chain-$recipe"
        build_recipe "$prev" "$recipe" "$tag"
        if [ "$keep" = false ] && [ "$prev" != "$BASE_IMAGE" ]; then
            docker rmi "$prev" >/dev/null 2>&1 || true
        fi
        prev="$tag"
    done
    # The final image carries all six recipes: audit each recipe's slots on it,
    # allowing the other recipes' labels to be present.
    for recipe in "${order[@]}"; do
        audit_image "$prev" "$recipe" 0
    done
    echo "  chain: six committed layers built and all eight slots audited"
}

# --- the build/audit driver --------------------------------------------------
# Defined before the self-test handler so the deterministic wiring self-test can
# exercise the REAL forward/audit chain (a fake build adapter derives a label
# from the requested ARGs, exactly as a real build does).
built=()
# Parallel to `built`: the REQUESTED selection each image was built with, used
# to decide committed-lock preservation independently of the image's labels
# (review F1).
built_requested=()
# EXPECT_SELECTIONS is the independently-supplied `suffix=value` set for the
# build about to be audited; when set, the image labels MUST equal it, so an
# ignored/mistyped ARG cannot pass by matching the image to itself.
EXPECT_SELECTIONS=""
build_and_audit() { # $1 recipe, $2 tag suffix, rest args
    local recipe="$1" suffix="$2"
    shift 2
    local tag="$RUN_ID-$suffix"
    build_recipe "$BASE_IMAGE" "$recipe" "$tag" "$@"
    audit_image "$tag" "$recipe"
    if [ -n "$EXPECT_SELECTIONS" ]; then
        assert_expected_selection "$tag" "$EXPECT_SELECTIONS"
    fi
    built+=("$tag:$recipe")
    built_requested+=("$EXPECT_SELECTIONS")
}

# --- main --------------------------------------------------------------------
# --self-test certifies the oracle predicates without Docker: it seeds every
# state the review named as a surviving mutation and requires a rejection.
if [ "$self_test" = true ]; then
    oracle_self_test
    echo "shipped-tool-recipes --self-test: OK"
    exit 0
fi

echo "shipped-tool-recipes: base=$BASE_IMAGE platform=$platform"
peak_kb=$(run_with_watchdog "$RUNTIME_WATCHDOG_SECONDS" \
    docker_run --rm --platform "$platform" "$BASE_IMAGE" df -Pk / | awk 'NR==2 {print $4}' || echo 0)
case "$peak_kb" in '' | *[!0-9]*) peak_kb=0 ;; esac
free_gib=$((peak_kb / 1024 / 1024))
if [ "$free_gib" -lt "$min_free_gib" ]; then
    echo "WARNING: only ${free_gib} GiB free Docker storage (< ${min_free_gib} GiB budget)" >&2
    if [ "${SHIPPED_TOOL_RECIPES_ALLOW_LOW_DISK:-0}" != 1 ]; then
        fail "insufficient Docker storage (${free_gib} GiB); free space or set SHIPPED_TOOL_RECIPES_ALLOW_LOW_DISK=1"
    fi
fi

# A distinct second tool-free base: the supplied base plus only an unrelated
# marker. Nothing installed, so a replayed build cannot inherit a CLI.
cat >"$TMP/replay.Dockerfile" <<'EOS'
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN mkdir -p /opt/agent-vm && printf 'replay-base-marker\n' > /opt/agent-vm/replay-base-marker
EOS
rc=0
run_with_watchdog "$BUILD_WATCHDOG_SECONDS" \
    docker buildx build --platform "$platform" --load -t "$RUN_ID-replay-base" \
    -f "$TMP/replay.Dockerfile" --build-arg BASE_IMAGE="$BASE_IMAGE" "$TMP" \
    >"$TMP/build-replay-base.log" 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then
    sed -n '1,40p' "$TMP/build-replay-base.log" >&2
    [ "$rc" -ne 124 ] || fail "replay base build timed out after ${BUILD_WATCHDOG_SECONDS}s"
    fail "replay base build failed"
fi
# shellcheck disable=SC2016  # $c must expand in the container, not here
run_with_watchdog "$RUNTIME_WATCHDOG_SECONDS" \
    docker_run --rm --platform "$platform" --entrypoint sh "$RUN_ID-replay-base" -c '
    [ -f /opt/agent-vm/replay-base-marker ] || { echo "replay marker missing" >&2; exit 1; }
    for c in codex opencode claude copilot dsh pnpm pi; do
        if command -v "$c" >/dev/null 2>&1; then echo "replay base ships $c" >&2; exit 1; fi
    done' ||
    fail "the second tool-free base is not tool-free"
echo "replay base: ${RUN_ID}-replay-base is tool-free and marked"

echo "== default builds =="
for recipe in codex opencode claude copilot dsh pi; do
    EXPECT_SELECTIONS="$(default_selection "$recipe")"
    build_and_audit "$recipe" "$recipe"
done

if $overrides; then
    echo "== override builds =="
    EXPECT_SELECTIONS="codex=$ALT_CODEX" \
        build_and_audit codex codex-alt    --build-arg "AGENT_VERSION_CODEX=$ALT_CODEX"
    EXPECT_SELECTIONS="opencode=$ALT_OPENCODE" \
        build_and_audit opencode opencode-alt --build-arg "AGENT_VERSION_OPENCODE=$ALT_OPENCODE"
    EXPECT_SELECTIONS="claude=$ALT_CLAUDE" \
        build_and_audit claude claude-alt  --build-arg "AGENT_VERSION_CLAUDE=$ALT_CLAUDE"
    EXPECT_SELECTIONS="copilot=$ALT_COPILOT" \
        build_and_audit copilot copilot-alt --build-arg "AGENT_VERSION_COPILOT=$ALT_COPILOT"
    EXPECT_SELECTIONS="$(printf 'dsh=%s\npnpm=%s' "$ALT_DSH" "$DEFAULT_PNPM")" \
        build_and_audit dsh dsh-only       --build-arg "AGENT_VERSION_DSH=$ALT_DSH"
    EXPECT_SELECTIONS="$(printf 'dsh=%s\npnpm=%s' "$DEFAULT_DSH" "$ALT_PNPM")" \
        build_and_audit dsh pnpm-only      --build-arg "AGENT_VERSION_PNPM=$ALT_PNPM"
    EXPECT_SELECTIONS="$(printf 'dsh=%s\npnpm=%s' "$ALT_DSH" "$ALT_PNPM")" \
        build_and_audit dsh dsh-both       --build-arg "AGENT_VERSION_DSH=$ALT_DSH" --build-arg "AGENT_VERSION_PNPM=$ALT_PNPM"
    EXPECT_SELECTIONS="$(printf 'pi=%s\npi-claude-bridge=%s' "$ALT_PI" "$DEFAULT_BRIDGE")" \
        build_and_audit pi pi-only         --build-arg "AGENT_VERSION_PI=$ALT_PI"
    EXPECT_SELECTIONS="$(printf 'pi=%s\npi-claude-bridge=%s' "$DEFAULT_PI" "$ALT_BRIDGE")" \
        build_and_audit pi bridge-only     --build-arg "AGENT_VERSION_PI_CLAUDE_BRIDGE=$ALT_BRIDGE"
    EXPECT_SELECTIONS="$(printf 'pi=%s\npi-claude-bridge=%s' "$ALT_PI" "$ALT_BRIDGE")" \
        build_and_audit pi pi-both         --build-arg "AGENT_VERSION_PI=$ALT_PI" --build-arg "AGENT_VERSION_PI_CLAUDE_BRIDGE=$ALT_BRIDGE"
fi

echo "== label replay onto the second tool-free base =="
index=0
for i in "${!built[@]}"; do
    record="${built[$i]}"
    requested="${built_requested[$i]}"
    src="${record%%:*}"
    recipe="${record##*:}"
    index=$((index + 1))
    replay_tag="$RUN_ID-replay-$index-$recipe"
    replay_check "$src" "$recipe" "$replay_tag" "$requested"
    if [ "$keep" = false ]; then
        docker rmi "$src" "$replay_tag" >/dev/null 2>&1 || true
    fi
done

echo "== T5 built-image negatives =="
t5_negatives

if $chain; then
    echo "== committed six-layer chain =="
    chain_check
fi

echo 'shipped-tool-recipes: OK'
