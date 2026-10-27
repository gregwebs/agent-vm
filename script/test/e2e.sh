#!/usr/bin/env bash
# shellcheck disable=SC2016  # guest-side commands deliberately single-quote `$(...)`
# shellcheck disable=SC2030,SC2031  # the boot-free self-test stubs CAPTURE_STATUS inside a subshell on purpose
#
# Native VM verification; CI runs only the boot-free harness contracts.
#
# Groups:
#   released-image  installed release, registry + corresponding archive, native
#                   amd64/arm64; no Docker or image sources needed by launcher
#   custom-image    existing marker-free regression suite; Apple Silicon only,
#                   Docker/buildx, validated debug and release bundles required
#   all             (default) released-image followed by custom-image
#
# Released-image inputs (required):
#   AGENT_VM_RELEASE_BIN            absolute relocated installed release binary
#   AGENT_VM_E2E_RELEASE_ASSETS_DIR  verified native v0.1.3 assets directory
#   AGENT_VM_E2E_OTHER_ASSETS_DIR    verified opposite-architecture assets directory
#   AGENT_VM_E2E_BUILD_SOURCE_DIR    the candidate's ACTUAL build checkout, which
#                                   must be absent after relocation (operator records
#                                   its correspondence to the candidate)
# Released-image inputs (optional):
#   AGENT_VM_E2E_NODE               vetted absolute Node interpreter for an
#                                   installed npm dispatcher candidate; defaults to
#                                   `node` resolved from the caller PATH
# Gate prerequisites: jq, shasum, python3 (and node for an npm dispatcher).
#
# Custom-image inputs:
#   AGENT_VM_BIN / AGENT_VM_DEV_BIN  validated debug launcher
#   AGENT_VM_RELEASE_BIN            validated release launcher
#   AGENT_VM_E2E_BUILDER            optional existing docker-container builder
# Custom-image selection (optional):
#   AGENT_VM_E2E_ONLY_ROWS          space-separated exact run_check names to run;
#                                   every other row is skipped without a result.
#                                   Fixture builds/imports run only when a
#                                   selected name starts with `custom-image-`.
#
# Custom-image runtime selection (**required for every launch of this group,**
# including the boot-free "harness-negative" controls): the group runs the
# vendored runtime this checkout pins — vendor/microsandbox/build/msb,
# libkrunfw.5.dylib and the bundle's agentd artifact — with inherited
# MSB_PATH/MSB_LIBKRUNFW_PATH/MSB_AGENTD_PATH cleared, so the runtime hashes in
# every evidence line describe the runtime that actually ran. This is a
# *testing* selection with a real cost: an installation that would have supplied
# its own bundle `msb` (or an external agentd) still needs these vendored files
# on disk, and the group dies before any work when one is missing. Naming the
# prerequisite here is deliberate — the identity receipts are worthless if the
# pinned runtime silently came from somewhere else.
#
# All launches use owned private HOME/state/cache. Real native joins remain
# manual; see CONTRIBUTING.md. No debug recommendation seam in released-image.

set -euo pipefail

CALLER_CWD="$PWD"
OPERATOR_HOME="$HOME"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

FIXTURE_DIR="$REPO_ROOT/script/test/fixtures/marker-free-image"

usage() {
  # Print the header comment (lines after the shebang) as the help text.
  awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "${BASH_SOURCE[0]}"
}

GROUP=all
case "${1:-}" in
  -h | --help)
    usage
    exit 0
    ;;
  "") ;;
  all | custom-image | released-image)
    GROUP="$1"
    ;;
  *)
    echo "e2e: unknown argument: $1" >&2
    usage >&2
    exit 2
    ;;
esac

die() {
  echo "e2e: $*" >&2
  exit 1
}

[[ $# -le 1 ]] || die "expected at most one group"
# Targeted evidence runs: exact row names, space separated. A run with a filter
# is reproducible from its own log because the argv and filter are echoed below.
E2E_ONLY_ROWS="${AGENT_VM_E2E_ONLY_ROWS:-}"
row_selected() {
  local row
  for row in $E2E_ONLY_ROWS; do
    [ "$row" = "$1" ] && return 0
  done
  return 1
}
rows_need_fixtures() {
  [ -z "$E2E_ONLY_ROWS" ] && return 0
  local row
  for row in $E2E_ONLY_ROWS; do
    case "$row" in custom-image-*) return 0 ;; esac
  done
  return 1
}

if [[ "$GROUP" == released-image || "$GROUP" == all ]]; then
  bash "$REPO_ROOT/script/test/e2e-released-image.sh"
  [[ "$GROUP" != released-image ]] || exit 0
fi
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || die "custom-image/all requires Apple Silicon"

# ---------------------------------------------------------------- inputs ----

if [[ -n "${AGENT_VM_BIN:-}" ]]; then
  AGENT_VM="$(cd "$(dirname "$AGENT_VM_BIN")" && pwd)/$(basename "$AGENT_VM_BIN")"
elif [[ -x "$REPO_ROOT/target/macos-dev/bin/agent-vm" ]]; then
  AGENT_VM="$REPO_ROOT/target/macos-dev/bin/agent-vm"
else
  AGENT_VM="$REPO_ROOT/target/macos/bin/agent-vm"
fi

# The retained-default check needs *two* launchers: a debug build (the
# AGENT_VM_TEST_DEFAULT_IMAGE recommendation seam is compiled out of release)
# and a release build (to prove the seam is not an override). Respect the
# advertised AGENT_VM_BIN as the debug candidate; both are validated where used.
AGENT_VM_DEV_BIN="${AGENT_VM_DEV_BIN:-$AGENT_VM}"
AGENT_VM_RELEASE_BIN="${AGENT_VM_RELEASE_BIN:-$REPO_ROOT/target/macos/bin/agent-vm}"


# Save native connection/plugin configuration before disposable HOME isolation.
absolute_override() {
  case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s/%s\n' "$CALLER_CWD" "$1" ;; esac
}
REAL_DOCKER="$(command -v docker)" || die "docker missing"
REAL_DOCKER="$(absolute_override "$REAL_DOCKER")"
BUILD_DOCKER_CONFIG="$(absolute_override "${DOCKER_CONFIG:-$OPERATOR_HOME/.docker}")"
BUILD_BUILDX_CONFIG="$(absolute_override "${BUILDX_CONFIG:-$BUILD_DOCKER_CONFIG/buildx}")"
BUILD_XDG_CONFIG="$(absolute_override "${XDG_CONFIG_HOME:-$OPERATOR_HOME/.config}")"
BUILD_ENV=(env DOCKER_CONFIG="$BUILD_DOCKER_CONFIG" BUILDX_CONFIG="$BUILD_BUILDX_CONFIG" XDG_CONFIG_HOME="$BUILD_XDG_CONFIG")
OFFLINE_ENV=(env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH -u DOCKER_API_VERSION -u DOCKER_CONFIG -u BUILDX_CONFIG -u BUILDX_BUILDER)
docker() { "${BUILD_ENV[@]}" "$REAL_DOCKER" "$@"; }
OWNED_BUILDER=""

# ----------------------------------------------------------- preconditions --

[[ -x "$AGENT_VM" ]] || die "launcher not found at $AGENT_VM; build it with
  ./script/build/macos.sh --dev
or point AGENT_VM_BIN at one."

command -v docker >/dev/null 2>&1 || die "docker is required but not on PATH"
docker info >/dev/null 2>&1 || die "the docker daemon is unreachable; start colima or Docker Desktop"

# The custom-image group is a serial native-VM run. Concurrent agent-vm/msb
# sessions on this host would make the process/catalog absence observations
# meaningless, so record the prerequisite rather than guessing.
if [[ "$GROUP" == custom-image ]]; then
  echo "e2e: custom-image group requires a dedicated serial native host (no concurrent agent-vm/msb VMs)"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/agent-vm-e2e.XXXXXX")"
# The work dir holds the only copies of the launch output, PTY recordings and
# process snapshots, so a failed run preserves them instead of deleting the
# evidence along with the VMs it was collected from. `rm` is ever only applied
# to this run's own $WORK.
cleanup_work() {
  local status=$?
  # Only the run's own shell may clean up. A helper subshell — a FIFO writer, an
  # RSS sampler, a command substitution — inherits this trap, and its exit must
  # never delete $WORK or report the run as failed when the row killed it on
  # purpose (#399). BASH_SUBSHELL exists in bash 3.2, where BASHPID does not and
  # a subshell's `$$` is the parent's, so the former BASHPID guard could never
  # reject a worker on the native 3.2 leg (#399 N2).
  if [ "${BASH_SUBSHELL:-0}" -ne 0 ]; then
    return 0
  fi
  # A failed row must not leave a row-owned FIFO writer, a live capture or an
  # RSS sampler behind: any of them can keep a pipe open and turn a failure
  # into an unbounded wait (#399 F2). A helper that fails is itself a failure.
  if ! cleanup_row_helpers; then
    [ "$status" -ne 0 ] || status=1
  fi
  if [ -n "$OWNED_BUILDER" ]; then
    if ! docker buildx rm "$OWNED_BUILDER"; then
      [ "$status" -ne 0 ] || status=1
    fi
  fi
  if [ "$status" -ne 0 ]; then
    echo "e2e: preserving $WORK for failure evidence (exit $status)" >&2
    exit "$status"
  fi
  rm -rf "$WORK"
}
# The row helpers are defined below; cleanup_work runs only at exit, when bash
# has already parsed them. `declare -F` keeps an early exit (before the helper
# block) from turning cleanup into a `command not found`.
cleanup_row_helpers() {
  local fn status=0
  for fn in stdin_writer_stop stdin_producer_stop stdin_capture_stop rss_sampler_stop; do
    if declare -F "$fn" >/dev/null 2>&1; then
      # A helper that cannot stop its worker is a real failure: the run's own
      # evidence (and the exit status) must say so rather than deleting $WORK
      # over a leftover writer or a capture that never exited.
      if ! "$fn" >/dev/null 2>&1; then
        echo "    FAIL: cleanup helper $fn failed" >&2
        status=1
      fi
    fi
  done
  return "$status"
}
trap cleanup_work EXIT
# A fresh basename per run keeps the per-run custom-image fixture refs (and the
# locally published registry refs) distinct, so a check cannot silently reuse an
# earlier run's tag. Docker repository names and the local-registry refs must be
# lowercase, and mktemp's suffix is mixed-case, so normalize it once here.
RUN_ID="$(printf '%s' "${WORK##*.}" | tr '[:upper:]' '[:lower:]')"

# A fresh, short, isolated state root for every custom-image boot. Never the
# shared dev state dir above: these checks must not see dev-image refs.
# An override is allowed only when it is absent or empty: a populated override
# could already carry a one-way `paths.cache` redirect (USAGE "The shared-cache
# trap"), so it would measure a stale cache rather than this run's.
CUSTOM_STATE="${AGENT_VM_E2E_CUSTOM_STATE_DIR:-$WORK/state}"
if [ -n "${AGENT_VM_E2E_CUSTOM_STATE_DIR:-}" ] && [ -e "$CUSTOM_STATE" ]; then
  remaining="$(ls -A "$CUSTOM_STATE" 2>/dev/null)" ||
    die "cannot inspect AGENT_VM_E2E_CUSTOM_STATE_DIR=$CUSTOM_STATE"
  [ -z "$remaining" ] ||
    die "AGENT_VM_E2E_CUSTOM_STATE_DIR=$CUSTOM_STATE is not empty; the custom-image group needs a fresh state root"
fi
CUSTOM_HOME="$WORK/home"
# The synthetic host credential for the file-backed Anthropic provider check
# (#258). It lives ONLY under this private launcher HOME, is read by the
# credential resolver, and is never mounted into the guest; the check that owns
# it removes it again so no other check can observe it. The tokens are
# deliberately non-secret sentinels, so their (non-)appearance in guest output
# is itself the leakage oracle.
CUSTOM_CREDENTIAL_SEED="$CUSTOM_HOME/.claude/.credentials.json"
CUSTOM_CREDENTIAL_ACCESS='sk-ant-synthetic-e2e-258-access'
CUSTOM_CREDENTIAL_REFRESH='sk-ant-synthetic-e2e-258-refresh'
# The runtime this group pins for every launch. `msb_install.rs` prefers an
# inherited MSB_PATH and a candidate's sibling `msb` over the vendored source
# build, and the pinned SDK honours MSB_PATH / MSB_LIBKRUNFW_PATH /
# MSB_AGENTD_PATH directly (vendor SDK `PathsConfigPatch::from_env_or_sdk`). An
# inherited value would therefore run a different runtime than the one the
# evidence lines hash (#399 R2-5). This checkout has no `target/debug/msb`, so
# the pinned paths are exactly what the launcher's own ladder resolves.
#
# MSB_AGENTD_PATH is cleared but deliberately *not* pinned: setting it makes
# the vendored runtime load an external agentd and log an INFO override line on
# every launch, which is a different runtime shape from the bundle's embedded
# agentd. Clearing it keeps the embedded payload while still refusing a
# caller's injection.
#
# This is a deliberate side effect on the whole group, not a free one: the check
# below makes every launch — `harness-negative` included, which boots nothing —
# require the vendor-built msb, agentd and firmware, even on a host whose
# candidate would have supplied a complete bundle runtime of its own. That
# trade is taken so the evidence can bind the runtime that ran (#399 R2-5); a
# bundle-only installation needs `vendor/microsandbox` built first.
CUSTOM_RUNTIME_DIR="$REPO_ROOT/vendor/microsandbox/build"
CUSTOM_MSB="$CUSTOM_RUNTIME_DIR/msb"
CUSTOM_AGENTD="$CUSTOM_RUNTIME_DIR/agentd"
CUSTOM_LIBKRUNFW="$CUSTOM_RUNTIME_DIR/libkrunfw.5.dylib"
for pinned in "$CUSTOM_MSB" "$CUSTOM_AGENTD" "$CUSTOM_LIBKRUNFW"; do
  [ -f "$pinned" ] || die "the vendored runtime is incomplete: no $pinned"
done

# The one environment every command that touches the custom root runs under.
# The host may export AGENT_VM_SHARE_MSB_CACHE, and the pinned SDK reads
# MSB_CONFIG_PATH instead of MSB_HOME/config.json when it is set (a loaded
# paths.cache overrides the private default). Leaving either in place lets an
# isolated import write one cache while a launch reads another and falls
# through to a registry pull, so neutralise both here: the private
# $CUSTOM_STATE/msb-home/cache is the only store this group exercises.
#
# The runtime paths are cleared and then pinned for the same reason (#399
# R2-5): the identity receipts must describe the runtime that actually ran, so
# the rows cannot inherit a caller's MSB_PATH.
CUSTOM_ENV=(env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_ROOT -u AGENT_VM_SHARE_MSB_CACHE -u AGENT_VM_MSB_CACHE_DIR -u MSB_CONFIG_PATH -u MSB_PATH -u MSB_LIBKRUNFW_PATH -u MSB_AGENTD_PATH MSB_PATH="$CUSTOM_MSB" MSB_LIBKRUNFW_PATH="$CUSTOM_LIBKRUNFW" AGENT_VM_STATE_DIR="$CUSTOM_STATE")
if [ -n "${AGENT_VM_SHARE_MSB_CACHE:-}" ]; then
  echo "e2e: neutralized inherited AGENT_VM_SHARE_MSB_CACHE=$AGENT_VM_SHARE_MSB_CACHE for the isolated custom root"
fi
if [ -n "${MSB_CONFIG_PATH:-}" ]; then
  echo "e2e: unset inherited MSB_CONFIG_PATH=$MSB_CONFIG_PATH for the isolated custom root"
fi
for runtime_var in MSB_PATH MSB_LIBKRUNFW_PATH MSB_AGENTD_PATH; do
  if [ -n "${!runtime_var:-}" ]; then
    echo "e2e: replaced inherited $runtime_var=${!runtime_var} with the vendored $CUSTOM_RUNTIME_DIR runtime"
  fi
done

# Valid only with MSB_CONFIG_PATH unset (then the SDK's config path is
# $CUSTOM_STATE/msb-home/config.json). A config.json there means a cache/state
# redirect was written; a .microsandbox in the launch HOME means the same. Once
# the fixtures are imported the private cache dir must exist. Every failure is a
# FAIL, never a tolerated redirect.
assert_custom_cache_isolated() {
  local desc="$1" require_cache="${2:-no}" rc=0
  if [ -e "$CUSTOM_STATE/msb-home/config.json" ]; then
    echo "    FAIL: $desc: $CUSTOM_STATE/msb-home/config.json exists (msb config redirect written)"
    jq -c . "$CUSTOM_STATE/msb-home/config.json" 2>/dev/null || true
    rc=1
  fi
  if [ -e "$CUSTOM_HOME/.microsandbox" ]; then
    echo "    FAIL: $desc: launch HOME $CUSTOM_HOME carries a .microsandbox redirect"
    rc=1
  fi
  if [ "$require_cache" = yes ] && [ ! -d "$CUSTOM_STATE/msb-home/cache" ]; then
    echo "    FAIL: $desc: private $CUSTOM_STATE/msb-home/cache is absent after the imports"
    rc=1
  fi
  return "$rc"
}

mkdir -p "$CUSTOM_STATE/msb-home" "$CUSTOM_HOME"
# ------------------------------------------------------------- host helpers --

# agent-vm against the isolated custom state root (only ever used off the shim).
avm_custom_state() {
  "${CUSTOM_ENV[@]}" "$AGENT_VM" "$@"
}

import_image() {
  local source="$1" dest="${2:-$1}" state="${3:?custom state required}"
  echo "==> Importing $source as $dest"
  local archive
  archive="$(mktemp "$WORK/docker-save.XXXXXX")" || return 1
  docker image save --output "$archive" "$source" || return 1
  if [ "$state" = "$CUSTOM_STATE" ]; then
    "${CUSTOM_ENV[@]}" "$AGENT_VM" msb image load --input "$archive" --tag "$dest" >/dev/null
  else
    AGENT_VM_STATE_DIR="$state" "$AGENT_VM" msb image load --input "$archive" --tag "$dest" >/dev/null
  fi
}

# ------------------------------------------------------------- assertions ---

assert_match() {
  local desc="$1" re="$2" hay="$3"
  grep -qE -- "$re" <<<"$hay" || {
    echo "    FAIL: $desc (no match for /$re/)"
    return 1
  }
}

# grep exits 0 (match), 1 (no match) or 2 (error). Only 1 is proof of absence;
# an error (unreadable/invalid pattern) is a failure, never a pass.
assert_no_match() {
  local desc="$1" re="$2" hay="$3" status=0
  grep -qE -- "$re" <<<"$hay" || status=$?
  case "$status" in
    0)
      echo "    FAIL: $desc (unexpected /$re/ in output)"
      return 1
      ;;
    1) return 0 ;;
    *)
      echo "    FAIL: $desc (grep error $status; absence not proven)"
      return 1
      ;;
  esac
}

# #258: the credential checks emit synthetic tokens that must never reach the
# guest. A raw `grep A || grep B` pair silently passes when grep itself errors
# (status 2), so each token is checked separately through assert_no_match,
# which treats an error as failure rather than proven absence.
assert_no_credential_leak() {
  local desc="$1" hay="$2"
  assert_no_match "$desc: synthetic access token" "$CUSTOM_CREDENTIAL_ACCESS" "$hay" || return 1
  assert_no_match "$desc: synthetic refresh token" "$CUSTOM_CREDENTIAL_REFRESH" "$hay" || return 1
}

assert_eq() {
  local desc="$1" want="$2" got="$3"
  [[ "$want" == "$got" ]] || {
    echo "    FAIL: $desc (want [$want], got [$got])"
    return 1
  }
}

# #258: the `(full logs: …)` suffix has exactly one owner (`finish_failed_exec`),
# so a failed launch must name the directory once, never once per diagnostic stage.
# `grep -o` counts occurrences, not matching lines: the pre-fix duplicate landed
# twice on the same diagnostic line, so `grep -c` would have missed it.
assert_single_logs_ref() {
  local desc="$1" out="$2" count status=0
  count="$(grep -oF -- "(full logs:" <<<"$out" | wc -l | tr -d '[:space:]')" || status=$?
  case "$status" in
    0) ;;
    1) count=0 ;;
    *)
      echo "    FAIL: $desc (grep error $status; occurrence not counted)"
      return 1
      ;;
  esac
  if [ "$count" -ne 1 ]; then
    echo "    FAIL: $desc (want exactly one '(full logs:' occurrence, got $count)"
    return 1
  fi
}

# #258: the boot must select the expected ref, and only it. A fallback or
# substituted image prints its own "Booting sandbox from <ref>" line, so the
# single counted line naming `ref` is the acquisition observation, not merely
# the absence of install/build/pull text.
assert_single_boot_ref() {
  local desc="$1" ref="$2" out="$3" boots count status=0
  boots="$(grep 'Booting sandbox from ' <<<"$out")" || status=$?
  case "$status" in
    0) ;;
    1)
      echo "    FAIL: $desc (no boot line for the selected image)"
      return 1
      ;;
    *)
      echo "    FAIL: $desc (could not read boot lines, grep status $status)"
      return 1
      ;;
  esac
  count="$(printf '%s\n' "$boots" | wc -l | tr -d '[:space:]')"
  if [ "$count" -ne 1 ]; then
    echo "    FAIL: $desc (want exactly one boot, got $count)"
    printf '%s\n' "$boots"
    return 1
  fi
  if ! grep -qF -- "from $ref " <<<"$boots"; then
    echo "    FAIL: $desc (the boot line does not name $ref)"
    printf '%s\n' "$boots"
    return 1
  fi
}

PASSED=0
FAILED=0
SKIPPED=0

run_check() {
  local name="$1"
  shift
  # `negative/*` rows are the harness self-test's deliberate failures; they
  # belong to whichever selected row invoked them, never to the filter.
  if [ -n "$E2E_ONLY_ROWS" ] && [[ "$name" != negative/* ]] && ! row_selected "$name"; then
    return 0
  fi
  echo
  echo "==> $name"
  # Decoy calls accumulate across every launch inside one check, so the
  # trailing assert_no_host_calls covers each boot rather than only the last.
  if [ -n "${HOST_SHIM_LOG:-}" ] && ! reset_host_shim_log; then
    echo "    FAIL: could not reset the host decoy log"
    FAILED=$((FAILED + 1))
    return 1
  fi
  if "$@"; then
    echo "    PASS: $name"
    PASSED=$((PASSED + 1))
  else
    echo "    FAIL: $name"
    FAILED=$((FAILED + 1))
  fi
}

run_optional() {
  local name="$1" var="$2"
  shift 2
  if [ -n "$E2E_ONLY_ROWS" ] && ! row_selected "$name"; then
    return 0
  fi
  echo
  echo "==> $name"
  if [[ -n "${!var:-}" ]]; then
    run_check "$name" "$@"
  else
    echo "    SKIP: set $var to enable"
    SKIPPED=$((SKIPPED + 1))
  fi
}

# ------------------------------------------------- custom-image host shims ---

# Every decoy appends its invocation to $HOST_SHIM_LOG and fails. The launches
# run with `PATH="$SHIM_DIR:/usr/bin:/bin"`, so a launcher that shells out to a
# package manager, Docker, or the *host* copy of the selected program is caught
# instead of silently succeeding through the real binary.
make_host_shims() {
  SHIM_DIR="$WORK/shim"
  HOST_SHIM_LOG="$WORK/host-shim.log"
  mkdir -p "$SHIM_DIR" || return 1
  local tool
  for tool in docker buildx hello-258 not-installed-258 npx npm pip apk apt-get dnf yum cargo claude; do
    cat >"$SHIM_DIR/$tool" <<'SHIM'
#!/usr/bin/env bash
echo "HOST-SHIM-CALLED: $(basename "$0") $*" >>"$HOST_SHIM_LOG"
exit 1
SHIM
    chmod +x "$SHIM_DIR/$tool" || return 1
  done
}

reset_host_shim_log() {
  : >"$HOST_SHIM_LOG" || return 1
}

assert_no_host_calls() {
  local log="${1:-$HOST_SHIM_LOG}"
  # A missing or unreadable log is a failed observation, not a vacuous zero: the
  # run's log is created (and emptied) by run_check before every check.
  if [[ ! -e "$log" ]]; then
    echo "    FAIL: host decoy log $log is missing; absence not proven"
    return 1
  fi
  if [[ ! -r "$log" ]]; then
    echo "    FAIL: host decoy log $log is unreadable; absence not proven"
    return 1
  fi
  if [[ -s "$log" ]]; then
    echo "    FAIL: a host decoy was invoked:"
    cat "$log"
    return 1
  fi
}

# Zero docker/buildx invocations: the log must exist, be readable and be empty.
# A missing or unreadable log is a failure, never a vacuous zero (Spec S2).
assert_no_builder_calls() {
  local desc="$1" log="$2"
  if [ ! -e "$log" ]; then
    echo "    FAIL: $desc: builder log $log is missing; absence not proven"
    return 1
  fi
  if [ ! -r "$log" ]; then
    echo "    FAIL: $desc: builder log $log is unreadable; absence not proven"
    return 1
  fi
  if [ -s "$log" ]; then
    echo "    FAIL: $desc: docker/buildx was invoked:"
    cat "$log"
    return 1
  fi
}

# Create executable docker/buildx decoys in `$1` that log `basename argv` to `$2`
# and exit 97, then prove the wiring: invoke each through the same child PATH the
# launch uses and require exit 97 plus the two exact log entries before
# truncating. A decoy that is unreachable, silent or successful would make every
# later zero-builder observation vacuous, so the control is part of the setup
# (Spec S2 / plan 7.2).
make_builder_shims() {
  local dir="$1" log="$2" tool status want got
  mkdir -p "$dir" || return 1
  for tool in docker buildx; do
    cat >"$dir/$tool" <<'SHIM'
#!/usr/bin/env bash
printf '%s %s\n' "$(basename "$0")" "$*" >>"$DOCKER_SHIM_LOG"
exit 97
SHIM
    chmod +x "$dir/$tool" || return 1
  done
  : >"$log" || return 1
  for tool in docker buildx; do
    status=0
    env PATH="$dir:/usr/bin:/bin" DOCKER_SHIM_LOG="$log" "$tool" wiring-probe >/dev/null 2>&1 ||
      status=$?
    if [ "$status" -ne 97 ]; then
      echo "    FAIL: the $tool decoy did not exit 97 (got $status); the zero-builder evidence is void"
      return 1
    fi
  done
  want=$'docker wiring-probe\nbuildx wiring-probe'
  got="$(cat "$log")"
  if [ "$got" != "$want" ]; then
    echo "    FAIL: the decoy wiring log does not match the two exact invocations:"
    printf '%s\n' "$got"
    return 1
  fi
  : >"$log" || return 1
}

# -------------------------------------------------- custom fixture images ----

build_custom_fixtures() {
  local tag="$1" target="$2" platform
  echo "==> Building fixture target $target as $tag"
  docker buildx build --platform linux/arm64 --load \
    --build-arg "ALPINE=alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8" \
    -t "$tag" --target "$target" "$FIXTURE_DIR" >/dev/null || return 1
  platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$tag")" || return 1
  [ "$platform" = linux/arm64 ] || {
    echo "    FAIL: $tag is $platform, not linux/arm64"
    return 1
  }
}

CUSTOM_MARKER="agent-vm-e2e-258-$RUN_ID:marker-free"
CUSTOM_NO_BASH="agent-vm-e2e-258-$RUN_ID:no-bash"
CUSTOM_WRAPPER="agent-vm-e2e-258-$RUN_ID:wrapper-provided"
CUSTOM_INTEGRATIONS="agent-vm-e2e-258-$RUN_ID:with-integrations"
CUSTOM_SCRIPT="agent-vm-e2e-258-$RUN_ID:script-provided"
CUSTOM_USER_HOME="agent-vm-e2e-258-$RUN_ID:user-home-set"
CUSTOM_NONSTANDARD="agent-vm-e2e-258-$RUN_ID:nonstandard-path"
CUSTOM_STAMP="agent-vm-e2e-258-$RUN_ID:stamp-present"
# #399: the direct-stdin `hook-read` row's image (a seed hook that reports EOF).
CUSTOM_STDIN_SEED="agent-vm-e2e-258-$RUN_ID:stdin-seed-399"
# The exact body the `stamp-present` fixture target writes to
# `/etc/agent-vm-image-version`; the e2e check asserts the guest observes this
# literal. Keep in sync with that target in the fixture Dockerfile.
CUSTOM_STAMP_LITERAL='garbage-not-a-version-258'

# ── effective guest PATH literals (two independent sources) ────────────────
# microsandbox's agentd prepends its scripts dir to every per-exec PATH that
# does not already contain it as a colon-delimited segment
# (vendor/microsandbox/crates/agentd/lib/config.rs `scripts_path`, pinned
# microsandbox 4246606a; SCRIPTS_PATH in
# vendor/microsandbox/crates/protocol/lib/lib.rs). The launcher never adds it.
MSB_SCRIPTS_PREFIX=/.msb/scripts
# The nonstandard-path fixture Dockerfile's `ENV PATH`. It is cross-checked
# against the built image config (the input acquired by import and push, not the
# runtime under test) before any launch uses it.
NONSTANDARD_OCI_PATH=/opt/e2e-258/bin:/usr/bin:/bin

# One complete controlled oracle output: every non-PATH line is byte-identical
# across rows by construction, so a rejection table built from it varies only
# PATH. `$1` is the single value printed on `path=`.
path_oracle_row() {
  printf 'uid=%s\n' "$(id -u)"
  printf 'path=%s\n' "$1"
  printf 'bash=/opt/e2e-258/bin/bash\n'
  printf 'hello=/opt/e2e-258/bin/hello-258\n'
  printf 'fallback_bin_bash=absent\n'
  printf 'fallback_usr_bin_bash=absent\n'
  printf 'fallback_hello=absent\n'
}

# The strict effective-PATH oracle used by every nonstandard-path launch:
# exactly one path= line, string-equal to the runtime prefix composed with the
# exact OCI PATH, plus the Bash/program resolutions and the absent fallback
# probes. Equality only — never a suffix/prefix/substring/regex acceptance, so
# a lost or reordered OCI PATH, a fallback-prefix success or a runtime shadow
# all stay red.
expect_effective_path() {
  local desc="$1" out="$2" want="path=$MSB_SCRIPTS_PREFIX:$NONSTANDARD_OCI_PATH" count line
  count="$(grep -c '^path=' <<<"$out")" || {
    echo "    FAIL: $desc: could not count the path= lines"
    return 1
  }
  if [ "$count" -ne 1 ]; then
    echo "    FAIL: $desc: expected exactly one path= line, got $count"
    return 1
  fi
  line="$(grep '^path=' <<<"$out")" || return 1
  assert_eq "$desc: effective PATH" "$want" "$line" || return 1
  assert_eq "$desc: bash resolution" "bash=/opt/e2e-258/bin/bash" \
    "$(grep '^bash=' <<<"$out")" || return 1
  assert_eq "$desc: program resolution" "hello=/opt/e2e-258/bin/hello-258" \
    "$(grep '^hello=' <<<"$out")" || return 1
  assert_eq "$desc: no fallback /bin/bash" "fallback_bin_bash=absent" \
    "$(grep '^fallback_bin_bash=' <<<"$out")" || return 1
  assert_eq "$desc: no fallback /usr/bin/bash" "fallback_usr_bin_bash=absent" \
    "$(grep '^fallback_usr_bin_bash=' <<<"$out")" || return 1
  assert_eq "$desc: no fallback program" "fallback_hello=absent" \
    "$(grep '^fallback_hello=' <<<"$out")" || return 1
}

# The custom root must stay private: no msb config redirect, no launch-HOME
# .microsandbox, and (once the fixtures are imported) a real private cache.
check_custom_cache_isolation() {
  assert_custom_cache_isolated "custom root" yes
}

# Static audit: every write to the custom root goes through the one
# CUSTOM_ENV helper, and that helper neutralizes the inherited shared-cache
# opt-ins and the SDK config redirect. The needle is split so this audit's own
# source does not count as a second writer.
check_custom_env_isolation() {
  local def count needle
  def="$(grep -F 'CUSTOM_ENV=(env' "$REPO_ROOT/script/test/e2e.sh")" || {
    echo "    FAIL: no CUSTOM_ENV definition in the harness"
    return 1
  }
  local need
  for need in '-u MSB_CONFIG_PATH' '-u AGENT_VM_SHARE_MSB_CACHE' '-u AGENT_VM_MSB_CACHE_DIR'; do
    grep -qF -- "$need" <<<"$def" || {
      echo "    FAIL: CUSTOM_ENV does not neutralize $need"
      return 1
    }
  done
  needle='AGENT_VM_STATE_DIR="$CUSTOM'
  needle+='_STATE"'
  count="$(grep -cF -- "$needle" "$REPO_ROOT/script/test/e2e.sh")" || count=0
  if [ "$count" -ne 1 ]; then
    echo "    FAIL: $count writers of AGENT_VM_STATE_DIR=\"\$CUSTOM_STATE\" (want exactly 1, inside CUSTOM_ENV)"
    return 1
  fi
}

# Build every exact target and import that same ref into the isolated custom
# cache the launches use. Building only a target and importing a differently
# named ref (or importing into the shared dev state) would make the VM checks
# observe an image other than the one this run built.
prepare_custom_fixtures() {
  local tag target
  while read -r tag target; do
    [ -n "$tag" ] || continue
    build_custom_fixtures "$tag" "$target" || return 1
    import_image "$tag" "$tag" "$CUSTOM_STATE" || return 1
  done <<EOF
$CUSTOM_MARKER marker-free
$CUSTOM_NO_BASH no-bash
$CUSTOM_WRAPPER wrapper-provided
$CUSTOM_INTEGRATIONS with-integrations
$CUSTOM_SCRIPT script-provided
$CUSTOM_USER_HOME user-home-set
$CUSTOM_NONSTANDARD nonstandard-path
$CUSTOM_STAMP stamp-present
$CUSTOM_STDIN_SEED stdin-seed-399
EOF
}

# Before any VM boots, every imported fixture ref must be present in the custom
# image catalog. Otherwise a launch could appear to succeed by acquiring the
# ref from elsewhere, and the isolated-cache assertions would be inferred from a
# cache directory rather than the acquisition the launches actually use.
check_custom_fixtures_imported() {
  local ref
  for ref in "$CUSTOM_MARKER" "$CUSTOM_NO_BASH" "$CUSTOM_WRAPPER" \
    "$CUSTOM_INTEGRATIONS" "$CUSTOM_SCRIPT" "$CUSTOM_USER_HOME" \
    "$CUSTOM_NONSTANDARD" "$CUSTOM_STAMP" "$CUSTOM_STDIN_SEED"; do
    image_catalog_has "$ref" "$ref" present || return 1
  done
}

write_custom_tools_config() {
  local dir="$1"
  mkdir -p "$dir/.agent-vm" || return 1
  cat >"$dir/.agent-vm/config.toml" <<'EOF' || return 1
[[tools]]
name = "hello-258"
command = "hello-258"
persist = [".hello-258.state"]

[[tools]]
name = "missing-258"
command = "not-installed-258"
EOF
}

# The file-backed Anthropic credential probe project: the marker-free fixture
# has no `claude`, so the declaring tool runs `bash ./guestprobe.sh` and only
# observes the documented guest placeholder. `command = "bash"` + a project
# script avoids the nested TOML/JSON/shell quoting an inline `-c` would need.
write_custom_credential_probe() {
  local dir="$1"
  mkdir -p "$dir/.agent-vm" || return 1
  cat >"$dir/guestprobe.sh" <<'PROBE' || return 1
#!/bin/sh
set -eu
f="$HOME/.claude/.credentials.json"
printf 'home=%s\n' "$HOME"
[ -f "$f" ] || { printf 'creds_file=missing\n'; exit 4; }
link=$(readlink "$HOME/.claude") || { printf 'creds_link_read=missing\n'; exit 6; }
printf 'creds_link=%s\n' "$link"
mode=$(stat -c %a "$f") || { printf 'creds_mode_read=missing\n'; exit 6; }
printf 'creds_mode=%s\n' "$mode"
grep -qF 'msb-anthropic-placeholder-a-v2' "$f" || { printf 'guest_placeholder_access=missing\n'; exit 5; }
grep -qF 'msb-anthropic-placeholder-r-v2' "$f" || { printf 'guest_placeholder_refresh=missing\n'; exit 5; }
printf 'guest_placeholder_access=present\n'
printf 'guest_placeholder_refresh=present\n'
printf 'credsprobe=ok\n'
PROBE
  chmod 0755 "$dir/guestprobe.sh" || return 1
  cat >"$dir/.agent-vm/config.toml" <<'EOF' || return 1
[[tools]]
name = "credsprobe"
command = "bash"
credentials = ["anthropic"]
args = ['./guestprobe.sh']
EOF
}

# Synthetic far-future OAuth credential, private launcher HOME only.
write_custom_credential_seed() {
  mkdir -p "$CUSTOM_HOME/.claude" || return 1
  cat >"$CUSTOM_CREDENTIAL_SEED" <<EOF || return 1
{"claudeAiOauth":{"accessToken":"$CUSTOM_CREDENTIAL_ACCESS","refreshToken":"$CUSTOM_CREDENTIAL_REFRESH","expiresAt":9999999999999,"scopes":["user:inference"],"subscriptionType":"synthetic","rateLimitTier":"synthetic"}}
EOF
  chmod 600 "$CUSTOM_CREDENTIAL_SEED"
}

# Remove ONLY this check's seed and the host-only captured token for its two
# projects, so no other check can be affected. Removal is best-effort across
# the whole set, but any resolution or removal failure is reported, never
# ignored: the check must not claim success while the synthetic seed survives.
remove_custom_credential_material() {
  local failed=0 proj state
  rm -f "$CUSTOM_CREDENTIAL_SEED" || failed=1
  for proj in "$WORK/custom-cred" "$WORK/custom-cred-missing"; do
    if ! state="$(host_state_dir "$proj" 2>/dev/null)"; then
      echo "    cleanup: could not resolve the state dir for $proj" >&2
      failed=1
      continue
    fi
    if [ -z "$state" ]; then
      echo "    cleanup: resolved an empty state dir for $proj; not removing" >&2
      failed=1
      continue
    fi
    rm -f "$state.secrets/anthropic" || failed=1
  done
  return "$failed"
}

# ------------------------------------------- bounded launch + observation ----

# Persistent process observer state, valid only while a launch is in flight.
LAUNCH_DESCENDANTS=""
CAPTURE_STATUS=0

# The host-side per-project state dir agent-vm derives (session::hash_path is
# the first 12 hex chars of sha256 of the canonical project path). Reading the
# guest-visible state JSON from here lets the integration checks use host jq
# without a second guest probe.
host_state_dir() {
  local proj="$1" canon hash
  canon="$(cd "$proj" && pwd -P)" || return 1
  hash="$(printf '%s' "$canon" | shasum -a 256 | cut -c1-12)" || return 1
  printf '%s' "$CUSTOM_STATE/$hash"
}

# PIDs whose executable name looks like an agent-vm/msb microVM runtime.
runtime_pids() {
  ps -axo pid=,comm= | awk '{ n=$2; sub(/.*\//,"",n); if (n ~ /^(agent-vm|msb|microsandbox|.*krun.*)$/) print $1 }'
}

# Transitive descendants of $1 (bounded depth), one `pid:comm` per line. The
# comm is the **whole** `ps -o comm=` field, not its first whitespace-separated
# word: an executable path may contain a space, and a comm that was truncated
# can never be matched again by `signal_inventory`, which compares the whole
# field, so such a descendant escaped both the TERM and the KILL pass (#399
# R3-2).
descendants_of() {
  local root="$1"
  ps -axo pid=,ppid=,comm= | awk -v root="$root" '
    { p[$1]=$2; line=$0; sub(/^[ \t]*[0-9]+[ \t]+[0-9]+[ \t]+/, "", line); c[$1]=line }
    END {
      for (i in p) {
        x=i
        for (n=0; n<32 && x+0 != 0; n++) {
          if (p[x]+0 == root+0) { print i":"c[i]; break }
          x=p[x]
        }
      }
    }'
}

# Signal one recorded launcher PID, but only while `ps -o comm=` still names the
# executable the receipt bound it to. The comm comparison is a guard, not a birth
# identity (#399 R3-2); with no expected executable there is nothing to verify,
# so nothing is signalled and the caller's descendant inventory is the only
# record used.
signal_launcher_pid() { # pid signal expected_executable
  local pid="$1" sig="$2" expected="$3"
  case "$pid" in '' | *[!0-9]*) return 0 ;; esac
  [ -n "$expected" ] || return 0
  same_executable "$(ps -p "$pid" -o comm= 2>/dev/null)" "$expected" || return 0
  kill "-$sig" "$pid" 2>/dev/null || true
}

# Stop one launch this shell owns, bounded, together with every process in its
# descendant tree. The launch *job* PID is only the launcher when no
# `/usr/bin/time` wrapper was added: with the wrapper the launcher is a child of
# the job, so stopping the job alone leaves the real launcher (and its VM)
# running with no record left to reap it (#399 R3-1). Both passes use the
# inventory taken before the first TERM, so a reparented child cannot escape the
# KILL.
stop_owned_launch_tree() { # job_pid [exec_pid] [expected_executable]
  local job="$1" exec_pid="${2:-}" expected="${3:-}" inventory i=0
  inventory="$(descendants_of "$job")" || inventory=""
  signal_inventory "$inventory" TERM
  signal_launcher_pid "$exec_pid" TERM "$expected"
  kill -TERM "$job" 2>/dev/null || true
  sleep 1
  signal_inventory "$inventory" KILL
  signal_launcher_pid "$exec_pid" KILL "$expected"
  kill -KILL "$job" 2>/dev/null || true
  while [ "$i" -lt 5 ]; do
    kill -0 "$job" 2>/dev/null || break
    sleep 1
    i=$((i + 1))
  done
  wait "$job" 2>/dev/null || true
}

# Bounded teardown of an in-flight observed launch: the watchdog is stopped
# first so it cannot later signal a recycled PID, then the owned launch tree is
# torn down. `exec_pid` is the PID the launch receipt named (the real launcher
# when the job is a wrapper); it is signalled only while its comm still matches
# `expected_executable`. The job is reaped so a failed observation cannot return
# while a VM process is still starting. A signal delivered to this harness from
# outside is not covered here: the EXIT trap's row-helper cleanup is a separate,
# separately controlled path.
stop_observed_launch() { # job_pid watchdog [exec_pid] [expected_executable]
  local pid="$1" watchdog="$2" exec_pid="${3:-}" expected="${4:-}"
  kill -TERM "$watchdog" 2>/dev/null || true
  stop_owned_launch_tree "$pid" "$exec_pid" "$expected"
  wait "$watchdog" 2>/dev/null || true
}

# The launcher PID a launch receipt names, best effort: empty when there is no
# receipt (yet) or its pid field is absent or non-numeric.
launch_receipt_pid() { # receipt
  local pid
  pid="$(sed -n 's/^pid=//p' "$1" 2>/dev/null || true)"
  case "$pid" in '' | *[!0-9]*) pid="" ;; esac
  printf '%s' "$pid"
}

# The one teardown every failure path inside `observe_launch` uses: the launch
# tree plus, when this observation sampled RSS, the PID its receipt named.
observe_launch_teardown() { # job_pid watchdog
  local receipt_pid=""
  if [ -n "${OBSERVE_RSS_FILE:-}" ]; then
    receipt_pid="$(launch_receipt_pid "$OBSERVE_RSS_FILE.receipt")"
  fi
  stop_observed_launch "$1" "$2" "$receipt_pid" "${OBSERVE_LAUNCHER_EXE:-$AGENT_VM}"
}

# Run `command` (after `--`) as a background launch under a 120s watchdog and a
# process observer. Sets CAPTURE_STATUS. Returns 0 only
# when the capture and the *observations* completed; a timeout is always a
# failure, and a surviving descendant/new runtime PID is a failure, so a
# wedged or leaked VM can never be reported as a pass.
observe_launch() {
  local name="$1" proj="$2" out="$3"
  shift 3
  [ "${1:-}" = "--" ] && shift
  CAPTURE_STATUS=0
  LAUNCH_DESCENDANTS=""
  rm -f "$WORK/$name.timeout" || return 1

  ps -axo pid=,ppid=,comm= >/dev/null || { echo "    FAIL: ps snapshot failed"; return 1; }
  local before
  before="$(runtime_pids)" || return 1

  # Opt-in split capture (#398): a caller that needs guest stdout bytes apart
  # from the launcher's stderr sets OBSERVE_STDOUT_FILE for its own call. Every
  # other row keeps the merged stream it has always read.
  #
  # Opt-in stdin (#399): OBSERVE_STDIN_FILE replaces the /dev/null redirect, so
  # a stdin row hands the launcher a file or its own FIFO. A FIFO open blocks
  # until the row's writer opens the other end, which is why this stays inside
  # the backgrounded subshell.
  local stdin_file="${OBSERVE_STDIN_FILE:-/dev/null}"
  # Opt-in corroborating `/usr/bin/time -l -o` report (#399 B1). It is evidence
  # only: on macOS the maximum RSS includes waited-for descendants, so the RSS
  # oracle stays the launcher-only sampler.
  local -a launch_cmd=("$@")
  if [ -n "${OBSERVE_RSS_FILE:-}" ]; then
    # The sampler cannot sample `$!` when `/usr/bin/time` wraps the launch: `$!`
    # is then the time wrapper, a constant few hundred KiB (#399 R2-1). The
    # wrapper records the PID it is about to exec into, and the sampler
    # verifies that PID's comm before measuring it.
    ensure_launch_wrapper || { echo "    FAIL: could not write the launch wrapper"; return 1; }
    # Clear this launch's sampler files **before** the child exists. The
    # wrapper writes its one-shot receipt as its first act, so a legal
    # child-first schedule can publish it before the sampler is even started;
    # a delete inside the sampler would then discard a live identity record and
    # wait forever for one that is never rewritten (#399 R3-1).
    reset_launcher_rss_files "$OBSERVE_RSS_FILE" || {
      echo "    FAIL: could not clear the launcher-RSS files for $OBSERVE_RSS_FILE"
      return 1
    }
    launch_cmd=("$LAUNCH_WRAPPER" "$OBSERVE_RSS_FILE.receipt" "${launch_cmd[@]}")
  fi
  if [ -n "${OBSERVE_TIME_FILE:-}" ]; then
    launch_cmd=(/usr/bin/time -l -o "$OBSERVE_TIME_FILE" "${launch_cmd[@]}")
  fi
  if [ -n "${OBSERVE_STDOUT_FILE:-}" ]; then
    (cd "$proj" || exit 1; exec "${launch_cmd[@]}") >"$OBSERVE_STDOUT_FILE" 2>"$out" <"$stdin_file" &
  else
    (cd "$proj" || exit 1; exec "${launch_cmd[@]}") >"$out" 2>&1 <"$stdin_file" &
  fi
  local pid=$!
  # Opt-in launcher RSS sampling (#399): the PID exists only here, so the
  # sampler is started and bounded inside the observation. If it cannot start,
  # the launcher must not be left running while this returns — and the launcher
  # is the receipt's PID (a child of the job when `/usr/bin/time` wraps it), not
  # the job PID (#399 R3-1).
  if [ -n "${OBSERVE_RSS_FILE:-}" ]; then
    if ! sample_launcher_rss "$pid" "$OBSERVE_RSS_FILE" "${OBSERVE_LAUNCHER_EXE:-$AGENT_VM}"; then
      echo "    FAIL: could not start the launcher RSS sampler"
      observe_launch_teardown "$pid" ""
      return 1
    fi
  fi
  (
    local i=0
    while [ "$i" -lt 120 ]; do
      sleep 1
      kill -0 "$pid" 2>/dev/null || exit 0
      i=$((i + 1))
    done
    : >"$WORK/$name.timeout"
    kill -TERM "$pid" 2>/dev/null || true
    sleep 5
    kill -KILL "$pid" 2>/dev/null || true
  ) &
  local watchdog=$!

  # An observation that errors must never leave the launcher or its watchdog
  # running, so both `ps`-observation failure paths below go through the same
  # bounded teardown (as does the sampler-start failure above). A signal
  # delivered to the harness from outside is a different path with its own
  # control (#399 h16-trap).
  local start elapsed snap
  start=$(date +%s)
  while kill -0 "$pid" 2>/dev/null; do
    if ! ps -axo pid=,ppid=,comm= >/dev/null; then
      echo "    FAIL: ps snapshot failed"
      observe_launch_teardown "$pid" "$watchdog"
      return 1
    fi
    if ! snap="$(descendants_of "$pid")"; then
      echo "    FAIL: descendant observation failed"
      observe_launch_teardown "$pid" "$watchdog"
      return 1
    fi
    LAUNCH_DESCENDANTS+="$snap"$'\n'
    elapsed=$(( $(date +%s) - start ))
    [ "$elapsed" -ge 125 ] && break
    sleep 1
  done
  wait "$pid" || CAPTURE_STATUS=$?
  wait "$watchdog" || { echo "    FAIL: launch watchdog did not exit cleanly"; return 1; }

  if [ -f "$WORK/$name.timeout" ]; then
    echo "    FAIL: launch $name timed out after 120s"
    local killline killpid
    while IFS= read -r killline; do
      [ -n "$killline" ] || continue
      killpid="${killline%%:*}"
      kill -KILL "$killpid" 2>/dev/null || true
    done <<<"$LAUNCH_DESCENDANTS"
    return 1
  fi

  # Any recorded descendant that is still alive is a leak. `ps` exits 0 when the
  # process exists and 1 when it does not; any other status is an observation
  # error and a failure, never treated as absence.
  local line pid2 status
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    pid2="${line%%:*}"
    ps -p "$pid2" >/dev/null 2>&1
    status=$?
    case "$status" in
    0)
      echo "    FAIL: descendant $line survived the launch"
      return 1
      ;;
    1) : ;;
    *)
      echo "    FAIL: could not observe descendant $line (ps status $status)"
      return 1
      ;;
    esac
  done <<<"$LAUNCH_DESCENDANTS"

  # New runtime PIDs (relative to the pre-launch snapshot) must not survive.
  local after
  after="$(runtime_pids)" || return 1
  local leaked="" candidate
  for candidate in $after; do
    if ! grep -qx "$candidate" <<<"$before"; then
      leaked+="$candidate "
    fi
  done
  if [ -n "$leaked" ]; then
    echo "    FAIL: runtime process(es) survived the launch: $leaked"
    # shellcheck disable=SC2086  # $leaked is a deliberate space-separated pid list
    ps -p ${leaked} -o pid=,comm= 2>/dev/null || true
    return 1
  fi
  return 0
}

# Streaming (no host TTY) launch used by every custom-image check except the
# explicit attach checks. stdin is /dev/null so agent-vm takes its no-TTY exec
# stream path.
capture_custom_launch() {
  local name="$1" proj="$2"
  shift 2
  observe_launch "$name" "$proj" "$WORK/$name.out" -- \
    "${CUSTOM_ENV[@]}" "${OFFLINE_ENV[@]}" \
    XDG_CONFIG_HOME="$WORK/offline-config" PATH="$SHIM_DIR:/usr/bin:/bin" \
    HOME="$CUSTOM_HOME" \
    HOST_SHIM_LOG="$HOST_SHIM_LOG" \
    "$AGENT_VM" "$@"
}

# Extra host environment for one direct capture (#398): a row that needs it sets
# `K=V` words here for the duration of its own capture calls (e.g.
# `AGENT_VM_DEBUG_CONFIG=1`) and clears them immediately after. Empty otherwise,
# so no other row's launches change.
DIRECT_CAPTURE_ENV=()

# Direct-launch capture (#398): guest stdout goes to its own file so byte-exact
# argv evidence is never mixed with launcher notices, and the launcher's stderr
# stays in the row log. The split is scoped to this call only.
capture_custom_direct() {
  local name="$1" proj="$2"
  shift 2
  local OBSERVE_STDOUT_FILE="$WORK/$name.stdout"
  : >"$OBSERVE_STDOUT_FILE" || return 1
  observe_launch "$name" "$proj" "$WORK/$name.out" -- \
    "${CUSTOM_ENV[@]}" "${OFFLINE_ENV[@]}" \
    XDG_CONFIG_HOME="$WORK/offline-config" PATH="$SHIM_DIR:/usr/bin:/bin" \
    HOME="$CUSTOM_HOME" \
    HOST_SHIM_LOG="$HOST_SHIM_LOG" \
    ${DIRECT_CAPTURE_ENV[@]+"${DIRECT_CAPTURE_ENV[@]}"} \
    "$AGENT_VM" "$@"
}

# A direct capture whose stdin the row owns (#399): the same split stdout
# capture as capture_custom_direct, plus OBSERVE_STDIN_FILE. A missing or
# unreadable input is a failed observation, never an empty stream.
capture_custom_direct_input() {
  local name="$1" proj="$2" input="$3"
  shift 3
  [ "${1:-}" = "--" ] && shift
  if [ ! -e "$input" ]; then
    echo "    FAIL: no stdin input for $name: $input"
    return 1
  fi
  local OBSERVE_STDOUT_FILE="$WORK/$name.stdout" OBSERVE_STDIN_FILE="$input" arg
  : >"$OBSERVE_STDOUT_FILE" || return 1
  # The exact launcher argv, so a row log binds its evidence to a command rather
  # than a row name (#399 evidence discipline). This is the one place every
  # stdin row -- including `shell-unchanged`, which does not use stdin_capture --
  # passes through.
  printf '    exec: %q' "$AGENT_VM"
  for arg in "$@"; do printf ' %q' "$arg"; done
  printf '\n'
  observe_launch "$name" "$proj" "$WORK/$name.out" -- \
    "${CUSTOM_ENV[@]}" "${OFFLINE_ENV[@]}" \
    XDG_CONFIG_HOME="$WORK/offline-config" PATH="$SHIM_DIR:/usr/bin:/bin" \
    HOME="$CUSTOM_HOME" \
    HOST_SHIM_LOG="$HOST_SHIM_LOG" \
    ${DIRECT_CAPTURE_ENV[@]+"${DIRECT_CAPTURE_ENV[@]}"} \
    "$AGENT_VM" "$@"
}

# Path of a direct capture's guest stdout.
direct_stdout_file() {
  local name="$1"
  [ -f "$WORK/$name.stdout" ] ||
    { echo "    FAIL: no guest stdout capture for $name"; return 1; }
  printf '%s' "$WORK/$name.stdout"
}

# Guest stdout decoded with NUL as newline for line-oriented assertions only.
# A missing or unreadable capture is a failure, never empty evidence; the
# byte-exact checks read the file itself (see assert_direct_stdout_bytes).
# shellcheck disable=SC2317,SC2329  # invoked indirectly from the direct rows,
# which run_check dispatches by name; 0.9 (the Ubuntu CI version) reports the
# function as unreachable instead.
direct_stdout() {
  local name="$1" out
  direct_stdout_file "$name" >/dev/null || return 1
  if ! out="$(tr '\0' '\n' <"$WORK/$name.stdout")"; then
    echo "    FAIL: could not read the guest stdout capture for $name"
    return 1
  fi
  printf '%s' "$out"
}

# Byte-exact comparison of a capture's guest stdout with an expected string.
# `$(cat file)` would strip trailing newlines and hide a read error, so the
# expected bytes go into their own file and `cmp` decides.
assert_direct_stdout_bytes() {
  local desc="$1" name="$2" expected="$3" expected_file result=0
  direct_stdout_file "$name" >/dev/null || return 1
  expected_file="$WORK/$name.expected"
  printf '%s' "$expected" >"$expected_file" || return 1
  if ! cmp -s "$expected_file" "$WORK/$name.stdout"; then
    echo "    FAIL: $desc (guest stdout bytes differ)"
    cmp -l "$expected_file" "$WORK/$name.stdout" | head -5 || true
    od -c "$WORK/$name.stdout" | head -5 || result=1
    result=1
  fi
  return "$result"
}

# Exactly zero bytes on guest stdout. Existence is checked first, so a missing
# capture is never "empty".
assert_direct_stdout_empty() {
  local desc="$1" name="$2"
  direct_stdout_file "$name" >/dev/null || return 1
  if [ -s "$WORK/$name.stdout" ]; then
    echo "    FAIL: $desc (expected an empty guest stdout)"
    od -c "$WORK/$name.stdout" | head -5 || true
    return 1
  fi
}

# ── #399: streamed stdin for direct launches ──────────────────────────────
#
# A stdin row needs what the rest of the harness never did: a capture whose
# stdin the *row* owns (a file, or a FIFO whose write end only the row can
# close), a way to observe a capture while the launcher still runs, and
# launcher-RSS samples. Each helper is defined once and has its own negative
# control in check_harness_negative, so a helper that silently stops observing
# is caught without a VM.

# The row-owned FIFO writer. `close` writes the payload and closes the write end
# at once (the guest sees EOF); `hold` keeps it open until the row closes it, so
# a guest that must observe a *live* stdin really does. The PID is recorded
# because each path that returns from a row has to kill and wait for it: a
# forgotten writer keeps a guest's stdin open forever and turns the row into a
# timeout. The controls cover the helper's stop path and the EXIT trap, not a
# signal delivered to the harness mid-row.
#
# Two properties keep a *failed* row from blocking (#399 F2):
# * the worker opens the FIFO `O_WRONLY|O_NONBLOCK` and retries ENXIO under a
#   deadline, so it never blocks in `open` waiting for a launcher that already
#   died. A launcher arriving later still completes the FIFO handshake.
# * a readiness file records that the worker has cleared the inherited EXIT
#   trap; the row proceeds only after that receipt, never on a `sleep` race
#   (bash 3.2 has no BASHPID; #399 N2).
STDIN_WRITER_PID=""
STDIN_WRITER_FIFO=""
# Seconds a row-side producer may stay in open/write before it is a failure.
STDIN_WRITER_TIMEOUT="${STDIN_WRITER_TIMEOUT:-30}"

stdin_writer_start() {
  local fifo="$1" payload="$2" mode="$3" ready i=0
  [ -p "$fifo" ] || { echo "    FAIL: $fifo is not a FIFO"; return 1; }
  case "$mode" in
  hold | close) ;;
  *)
    echo "    FAIL: unknown stdin writer mode: $mode"
    return 1
    ;;
  esac
  ready="$fifo.ready"
  rm -f "$ready"
  (
    # A background writer must not inherit the run's EXIT trap: that trap
    # deletes $WORK and reports a failure status, so a reaped writer would look
    # like a failed run (and racing it with bash's own job bookkeeping prints
    # `wait_for: No record of process`).
    trap - EXIT
    # Hold nothing the caller may be reading from: the launcher keeps the row's
    # stdout, and a command substitution would never return while this holds it.
    exec >/dev/null 2>&1
    # Opening a FIFO for writing blocks until a reader appears, so a launcher
    # that failed before opening stdin would block this worker (and any cleanup
    # that waited for it) forever. `O_NONBLOCK` turns that into ENXIO, retried
    # under a deadline; the first readiness receipt proves the inherited EXIT
    # trap is already gone, which is the ownership protocol bash 3.2 can give
    # (no BASHPID; #399 F2/N2).
    exec python3 - "$fifo" "$mode" "$payload" "$ready" "$STDIN_WRITER_TIMEOUT" <<'PY'
import errno, os, sys, time

fifo, mode, payload, ready, timeout = sys.argv[1:6]
deadline = time.monotonic() + float(timeout)

with open(ready, "w", encoding="utf-8") as receipt:
    receipt.write("ready")

fd = None
while time.monotonic() < deadline:
    try:
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        break
    except OSError as error:
        if error.errno != errno.ENXIO:
            raise
        time.sleep(0.05)

if fd is None:
    print("no launcher opened the FIFO's read end", file=sys.stderr)
    sys.exit(1)

os.set_blocking(fd, True)
if payload:
    with os.fdopen(os.dup(fd), "wb", closefd=True) as stream:
        stream.write(payload.encode())

if mode == "close":
    os.close(fd)
else:
    while True:
        time.sleep(3600)
PY
  ) &
  STDIN_WRITER_PID=$!
  STDIN_WRITER_FIFO="$fifo"
  while [ "$i" -lt 50 ]; do
    if [ -e "$ready" ]; then
      rm -f "$ready"
      return 0
    fi
    kill -0 "$STDIN_WRITER_PID" 2>/dev/null || break
    sleep 0.1
    i=$((i + 1))
  done
  echo "    FAIL: the stdin writer did not open $fifo"
  stdin_writer_stop
  return 1
}

# Feed a FIFO with a deadline. A guest that stopped reading fills the pipe and
# then blocks the producer; the row must fail bounded rather than sit in that
# write forever (#399 F2).
# `exec cat`, not `cat`: the subshell running the file producer must *become*
# `cat`, because the timeout below can only signal the PID it recorded. Bash
# does not exec a `case` branch on its own, so the old shape left `cat` alive
# after the subshell was killed, still holding the FIFO's write end (#399 R2-3).
STDIN_PRODUCER_PID=""

# Reap a producer this shell started, bounded. EXIT cleanup calls it; the
# synchronous helper below calls it before returning too, so ownership is never
# left pointing at a reaped PID.
stdin_producer_stop() {
  [ -n "$STDIN_PRODUCER_PID" ] || return 0
  local pid="$STDIN_PRODUCER_PID" i=0
  STDIN_PRODUCER_PID=""
  kill -TERM "$pid" 2>/dev/null || true
  kill -KILL "$pid" 2>/dev/null || true
  while [ "$i" -lt 50 ]; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
    i=$((i + 1))
  done
  wait "$pid" 2>/dev/null || true
}

stdin_writer_write_bounded() {
  local fifo="$1" kind="$2" data="$3" pid status i=0 limit
  case "$kind" in
  string | file) ;;
  *)
    echo "    FAIL: unknown stdin producer kind: $kind"
    return 1
    ;;
  esac
  [ -p "$fifo" ] || { echo "    FAIL: $fifo is not a FIFO"; return 1; }
  limit=$((STDIN_WRITER_TIMEOUT * 5))
  (
    trap - EXIT
    exec >/dev/null 2>&1
    case "$kind" in
    string) printf '%s' "$data" >"$fifo" ;;
    file) exec cat "$data" >"$fifo" ;;
    esac
  ) &
  pid=$!
  STDIN_PRODUCER_PID="$pid"
  while [ "$i" -lt "$limit" ]; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
    i=$((i + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    stdin_producer_stop
    echo "    FAIL: the stdin producer for $fifo blocked for ${STDIN_WRITER_TIMEOUT}s"
    return 1
  fi
  wait "$pid"
  status=$?
  STDIN_PRODUCER_PID=""
  [ "$status" -eq 0 ] || {
    echo "    FAIL: writing stdin to $fifo failed (exit $status)"
    return 1
  }
}

# Write more bytes through the FIFO this row holds open.
stdin_writer_send() {
  local fifo="$1" payload="$2"
  [ -n "$STDIN_WRITER_PID" ] || { echo "    FAIL: no stdin writer is running"; return 1; }
  stdin_writer_write_bounded "$fifo" string "$payload"
}

# Close the held writer (this is the guest's EOF); the writer is reaped later.
stdin_writer_close() {
  [ -n "$STDIN_WRITER_PID" ] || return 0
  kill -TERM "$STDIN_WRITER_PID" 2>/dev/null || true
}

# Reap the writer, bounded. Safe to call twice, and every returning path that
# owns a writer calls it (the EXIT trap is the backstop; h16-trap checks it).
stdin_writer_stop() {
  [ -n "$STDIN_WRITER_PID" ] || return 0
  local pid="$STDIN_WRITER_PID" i=0
  STDIN_WRITER_PID=""
  [ -n "$STDIN_WRITER_FIFO" ] && rm -f "$STDIN_WRITER_FIFO.ready"
  STDIN_WRITER_FIFO=""
  kill -TERM "$pid" 2>/dev/null || true
  while [ "$i" -lt 50 ]; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
    i=$((i + 1))
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

# A fresh FIFO already written with `payload` and closed by the row. The path
# lands in `STDIN_FIFO`, **not** on stdout: a command substitution would wait for
# the background writer to close its inherited stdout, and a held writer never
# does. One FIFO per launch: a FIFO is consumed by the reader that opens it.
STDIN_FIFO=""

stdin_fifo_closed() {
  local name="$1" payload="$2"
  STDIN_FIFO="$WORK/$name.fifo"
  rm -f "$STDIN_FIFO" || return 1
  mkfifo "$STDIN_FIFO" || return 1
  stdin_writer_start "$STDIN_FIFO" "$payload" close || return 1
}

# Poll a capture file for a marker (`grep -q`, 0.2 s steps). A deadline miss is
# a failure, never a pass: this is the oracle for "output arrived *before*
# input ended", which only a live observation can answer.
wait_for_marker() {
  local file="$1" pattern="$2" seconds="$3" waited=0 steps
  steps=$((seconds * 5))
  # The capture file appears when the background launch starts observing, so a
  # missing file is "not yet", never an immediate failure; it fails at the
  # deadline with the same message as a missing marker.
  while [ "$waited" -lt "$steps" ]; do
    if grep -qE -- "$pattern" "$file" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
    waited=$((waited + 1))
  done
  echo "    FAIL: $(printf '%q' "$pattern") did not appear in $file within ${seconds}s"
  return 1
}

# ── launcher-RSS oracle (#399 R2-1) ────────────────────────────────────────
#
# A launch may be wrapped in `/usr/bin/time -l -o …`, which forks the command
# and waits: the backgrounded job's `$!` is then the *wrapper*, a constant few
# hundred KiB. Sampling that PID measures nothing about the launcher and would
# accept a launcher that buffered the whole stream (the first version of this
# oracle did exactly that). The wrapper below writes an identity receipt: its
# own PID, which `exec` preserves for the launcher, plus the argv it is about to
# execute. The sampler measures the receipt's PID only after `ps -o comm=` names
# the expected launcher, and every sample re-checks the same comm, so the
# receipt claims the process that was measured rather than the job that was
# started. The `/usr/bin/time` report stays as corroboration only.
LAUNCH_WRAPPER=""

ensure_launch_wrapper() {
  [ -n "$LAUNCH_WRAPPER" ] && [ -x "$LAUNCH_WRAPPER" ] && return 0
  LAUNCH_WRAPPER="$WORK/launch-wrapper.sh"
  cat >"$LAUNCH_WRAPPER" <<'WRAPPER' || return 1
#!/bin/bash
# $1 is the receipt path, the rest is the launch argv. `$$` is this bash
# process, and `exec` keeps that PID for the launcher, so the receipt names the
# exact process the RSS sampler must measure. It is written before the exec, so
# the sampler also verifies the comm it finds.
receipt=$1
shift
printf 'pid=%s\nbefore_comm=%s\nexec_argv0=%s\n' \
  "$$" "$(ps -p $$ -o comm=)" "$1" >"$receipt" || exit 1
exec "$@"
WRAPPER
  chmod +x "$LAUNCH_WRAPPER"
}

# Print the launch receipt's field $2. Missing or empty is a failure: an
# identity claim that cannot be read is not an identity claim.
launch_receipt_field() {
  local receipt="$1" field="$2" value
  value="$(sed -n "s/^$field=//p" "$receipt" 2>/dev/null)" || {
    echo "    FAIL: cannot read $field from the launch receipt $receipt" >&2
    return 1
  }
  if [ -z "$value" ]; then
    echo "    FAIL: the launch receipt $receipt has no $field" >&2
    return 1
  fi
  printf '%s' "$value"
}

# Two paths name the same executable. `comm` reports the path the kernel kept
# for the exec, which can differ from the caller's spelling only through a
# symlinked directory, so compare the resolved directories.
same_executable() {
  local left="$1" right="$2" left_dir right_dir
  [ -n "$left" ] && [ -n "$right" ] || return 1
  [ "$left" = "$right" ] && return 0
  left_dir="$(cd "$(dirname "$left")" 2>/dev/null && pwd -P)" || return 1
  right_dir="$(cd "$(dirname "$right")" 2>/dev/null && pwd -P)" || return 1
  [ "$left_dir/$(basename "$left")" = "$right_dir/$(basename "$right")" ]
}

# Sample `pid`'s RSS until it exits, writing one Kibibyte value per line to
# `out` (the `max_rss_kib` contract) and a receipt to `meta`. A comm change or a
# non-numeric `ps` line is recorded as a mismatch and stops the sampler rather
# than being averaged into the result. `expected_comm` is checked on the first
# sample, so a recycled or wrong PID can never be reported as the launcher.
# Is one `ps -o rss=,comm=` reading a placeholder for **our own** target
# finishing? macOS reports a process that is tearing down with `<defunct>` once
# it is a zombie, or `(<pbi_comm>)` while the kernel has already dropped its
# argument area, and reports 0 KiB of RSS for it. Such a reading is the launch
# ending, not a different process — the sampler has already matched every
# earlier sample — so it stops the loop instead of recording a mismatch. The
# rule stays narrow: a placeholder for a *different* name, or any comm change
# with a live RSS, is still a mismatch. h23 is the control.
rss_exit_transition() { # comm rss expected_name
  case "$1:$2" in
  "<defunct>:0") return 0 ;;
  "($3):0")
    [ -n "$3" ] || return 1
    return 0
    ;;
  esac
  return 1
}

rss_sample_until_exit() { # pid out meta [expected_comm]
  local pid="$1" out="$2" meta="$3" expected_comm="${4:-}" expected_name=""
  [ -n "$expected_comm" ] && expected_name="${expected_comm##*/}"
  : >"$out" || return 1
  (
    trap - EXIT
    local line rss comm samples=0 started ended mismatch="" comm0="" exit_seen=no
    started="$(date +%s)"
    while kill -0 "$pid" 2>/dev/null; do
      line="$(ps -p "$pid" -o rss=,comm= 2>/dev/null)" || break
      read -r rss comm <<<"$line"
      case "$rss" in
      '' | *[!0-9]*)
        mismatch="nonnumeric ps line '$line'"
        break
        ;;
      esac
      if [ -z "$comm0" ]; then
        comm0="$comm"
        if [ -n "$expected_comm" ] && [ "$comm" != "$expected_comm" ]; then
          mismatch="sampled comm '$comm' is not '$expected_comm'"
          break
        fi
      elif [ "$comm" = "$comm0" ]; then
        :
      elif rss_exit_transition "$comm" "$rss" "$expected_name"; then
        # The strict comparison failed a healthy `large` launch whose last read
        # raced its exit (post3 native sweep); a comm change to anything else,
        # or with a live RSS, still fails.
        exit_seen=yes
        break
      else
        mismatch="sampled comm changed '$comm0' -> '$comm'"
        break
      fi
      printf '%s\n' "$rss" >>"$out" || {
        mismatch="could not append to $out"
        break
      }
      samples=$((samples + 1))
      sleep "$RSS_SAMPLE_INTERVAL"
    done
    ended="$(date +%s)"
    {
      printf 'samples=%s\n' "$samples"
      printf 'sampled_comm=%s\n' "$comm0"
      printf 'sampling_started_ts=%s\n' "$started"
      printf 'sampling_ended_ts=%s\n' "$ended"
      printf 'sampling_exit_transition=%s\n' "$exit_seen"
      printf 'sampling_mismatch=%s\n' "$mismatch"
    } >>"$meta"
  ) &
  STDIN_RSS_PID=$!
}

# Clear one launch's sampler files (samples, receipt, meta) **before** the child
# starts. The wrapper writes its one-shot identity receipt as its first act, so a
# legal child-first schedule can publish it before the sampler is started; a
# delete inside the sampler would discard the live receipt and then wait for one
# that is never rewritten (#399 R3-1). Called by every caller that spawns a
# launch this sampler is going to measure.
reset_launcher_rss_files() { # out
  local out="$1"
  rm -f -- "$out" "$out.receipt" "$out.meta"
}

# Start the launcher sampler: wait for the launch receipt, verify the named
# process is the expected launcher, then sample it at $RSS_SAMPLE_INTERVAL
# across the whole run (the receipt is written before the launcher opens stdin,
# so the window covers the transfer, not just its end). `$STDIN_RSS_PID` is the
# sampler; the shell that started it must reap it (`rss_sampler_stop`), because
# a command substitution cannot `wait` for another shell's child (#399 N3).
STDIN_RSS_PID=""
RSS_SAMPLE_INTERVAL="${RSS_SAMPLE_INTERVAL:-0.05}"
RSS_RECEIPT_WAIT_SECONDS="${RSS_RECEIPT_WAIT_SECONDS:-20}"
RSS_MIN_SAMPLES="${RSS_MIN_SAMPLES:-3}"

# Resolve the expected launcher comm to the path form `ps -o comm=` reports.
absolute_executable() {
  local path="$1" dir
  dir="$(cd "$(dirname "$path")" 2>/dev/null && pwd -P)" || return 1
  [ -x "$dir/$(basename "$path")" ] || return 1
  printf '%s' "$dir/$(basename "$path")"
}

sample_launcher_rss() { # launch_job_pid out expected_executable
  local launch_job_pid="$1" out="$2" expected="$3"
  local receipt="$out.receipt" meta="$out.meta" steps waited pid target current job_comm
  # The receipt/meta/sample files are cleared by `reset_launcher_rss_files`
  # *before* the child starts, never here: a child-first schedule can publish
  # the receipt before this function runs, and deleting it would drop the live
  # identity record and then wait for a rewrite that never comes (#399 R3-1).
  if ! expected="$(absolute_executable "$expected")"; then
    echo "    FAIL: the expected launcher $3 is not an executable file" >&2
    return 1
  fi
  steps=$((RSS_RECEIPT_WAIT_SECONDS * 50))
  waited=0
  while [ "$waited" -lt "$steps" ]; do
    [ -s "$receipt" ] && break
    kill -0 "$launch_job_pid" 2>/dev/null || break
    sleep 0.02
    waited=$((waited + 1))
  done
  if [ ! -s "$receipt" ]; then
    echo "    FAIL: the launch wrote no identity receipt at $receipt" >&2
    return 1
  fi
  pid="$(launch_receipt_field "$receipt" pid)" || return 1
  target="$(launch_receipt_field "$receipt" before_comm)" || return 1
  case "$pid" in
  '' | *[!0-9]*)
    echo "    FAIL: the launch receipt names a non-numeric PID '$pid'" >&2
    return 1
    ;;
  esac
  job_comm="$(ps -p "$launch_job_pid" -o comm= 2>/dev/null)"
  # The receipt is written before the exec, so wait (bounded) for the named PID
  # to *be* the launcher: the sampler must never measure the pre-exec shell.
  waited=0
  current=""
  while [ "$waited" -lt "$steps" ]; do
    current="$(ps -p "$pid" -o comm= 2>/dev/null)" || {
      echo "    FAIL: the launcher PID $pid exited before it could be sampled" >&2
      return 1
    }
    same_executable "$current" "$expected" && break
    sleep 0.02
    waited=$((waited + 1))
  done
  if ! same_executable "$current" "$expected"; then
    echo "    FAIL: PID $pid never became $expected (last comm '$current', receipt comm '$target')" >&2
    return 1
  fi
  {
    printf 'sampled_pid=%s\n' "$pid"
    printf 'sampled_expected_comm=%s\n' "$expected"
    printf 'sampled_receipt_before_comm=%s\n' "$target"
    printf 'launch_job_pid=%s\n' "$launch_job_pid"
    printf 'launch_job_comm=%s\n' "$job_comm"
    printf 'sampling_interval_seconds=%s\n' "$RSS_SAMPLE_INTERVAL"
  } >"$meta" || return 1
  rss_sample_until_exit "$pid" "$out" "$meta" "$expected"
}

# Print one launcher-RSS sample receipt as `key=value` words, for the row log,
# and assert that the comm the sampler **observed** is the expected launcher's.
# Printing only `sampled_expected_comm` let a native receipt look identity-bound
# while the observed field was never shown (#399 review 3, observation 1).
launcher_rss_receipt() { # out
  local meta="$1.meta" field observed expected
  [ -f "$meta" ] || {
    echo "    FAIL: no launcher-RSS receipt at $meta" >&2
    return 1
  }
  for field in sampled_pid sampled_expected_comm sampled_comm \
    sampled_receipt_before_comm launch_job_pid launch_job_comm \
    sampling_interval_seconds samples sampling_started_ts sampling_ended_ts \
    sampling_exit_transition sampling_mismatch; do
    printf '%s=%s ' "$field" "$(sed -n "s/^$field=//p" "$meta")"
  done
  printf '\n'
  observed="$(sed -n 's/^sampled_comm=//p' "$meta")"
  expected="$(sed -n 's/^sampled_expected_comm=//p' "$meta")"
  if [ -z "$observed" ]; then
    echo "    FAIL: the launcher-RSS receipt $meta records no observed sampled_comm" >&2
    return 1
  fi
  if [ "$observed" != "$expected" ]; then
    echo "    FAIL: the launcher-RSS receipt observed comm '$observed' is not the expected launcher '$expected'" >&2
    return 1
  fi
  return 0
}

# Fail unless the receipt proves the sampler measured the launcher itself: a
# numeric sampled PID, the expected comm observed on every sample, enough
# samples to have covered the run, no mismatch, and — when the launch job was
# `/usr/bin/time` — a sampled PID distinct from that wrapper. The originals
# this replaces passed a constant 1056 KiB with growth 0 (#399 R2-1).
assert_launcher_rss_identity() { # out
  local out="$1" meta="$1.meta" desc="$2"
  local sampled launch_job expected observed samples mismatch launch_comm rc=0
  [ -s "$meta" ] || {
    echo "    FAIL: $desc: no launcher-RSS receipt at $meta"
    return 1
  }
  sampled="$(sed -n 's/^sampled_pid=//p' "$meta")"
  launch_job="$(sed -n 's/^launch_job_pid=//p' "$meta")"
  launch_comm="$(sed -n 's/^launch_job_comm=//p' "$meta")"
  expected="$(sed -n 's/^sampled_expected_comm=//p' "$meta")"
  observed="$(sed -n 's/^sampled_comm=//p' "$meta")"
  samples="$(sed -n 's/^samples=//p' "$meta")"
  mismatch="$(sed -n 's/^sampling_mismatch=//p' "$meta")"
  case "$sampled" in
  '' | *[!0-9]*)
    echo "    FAIL: $desc: the RSS receipt names no sampled PID ('$sampled')"
    rc=1
    ;;
  esac
  case "$expected" in
  '' | /*) ;;
  *)
    echo "    FAIL: $desc: the RSS receipt's expected comm is not an absolute path ('$expected')"
    rc=1
    ;;
  esac
  # The comm the sampler observed must be recorded and must be the launcher: the
  # receipt claims the process that was measured, not just the one intended.
  case "$observed" in
  '')
    echo "    FAIL: $desc: the RSS receipt records no observed sampled_comm"
    rc=1
    ;;
  "$expected") ;;
  *)
    echo "    FAIL: $desc: the RSS sampler observed comm '$observed', not the expected launcher '$expected'"
    rc=1
    ;;
  esac
  case "$samples" in
  '' | *[!0-9]*)
    echo "    FAIL: $desc: the RSS sampler recorded no sample count ('$samples')"
    rc=1
    ;;
  *)
    if [ "$samples" -lt "$RSS_MIN_SAMPLES" ]; then
      echo "    FAIL: $desc: only $samples RSS sample(s) (need $RSS_MIN_SAMPLES) — the window did not cover the run"
      rc=1
    fi
    ;;
  esac
  if [ -n "$mismatch" ]; then
    echo "    FAIL: $desc: the RSS sampler rejected its own samples: $mismatch"
    rc=1
  fi
  case "$launch_comm" in
  */time)
    if [ "$sampled" = "$launch_job" ]; then
      echo "    FAIL: $desc: the RSS oracle sampled the $launch_comm wrapper, not the launcher"
      rc=1
    fi
    ;;
  esac
  return "$rc"
}

# Reap the sampler in the shell that started it, bounded. Safe twice; a failed
# row's cleanup calls it on the way out.
rss_sampler_stop() {
  [ -n "$STDIN_RSS_PID" ] || return 0
  local pid="$STDIN_RSS_PID" i=0
  STDIN_RSS_PID=""
  while [ "$i" -lt 100 ]; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
    i=$((i + 1))
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

# Print the largest launcher RSS sample, in KiB. Pure parser: it neither waits
# for nor clears the sampler (that is `rss_sampler_stop`, #399 N3), so a command
# substitution can call it safely.
#
# Fails closed (#399 F3): a nonempty file is not enough. Every sample must be a
# decimal number after trimming only the padding `ps -o rss=` emits; an
# unterminated final line counts (the former `while read` skipped it, so a JSON
# file without a newline returned 0), and at least one sample must validate.
max_rss_kib() {
  local out="$1" max=0 line saw=0
  if [ ! -f "$out" ] || [ ! -s "$out" ]; then
    echo "    FAIL: no RSS samples in $out" >&2
    return 1
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    # `ps` pads on the left (and can pad on the right); internal whitespace is
    # never legitimate and must stay visible to the numeric check.
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    case "$line" in
    '' | *[!0-9]*)
      echo "    FAIL: non-numeric RSS sample '$line' in $out" >&2
      return 1
      ;;
    esac
    if [ "$line" -gt "$max" ]; then
      max="$line"
    fi
    saw=1
  done <"$out"
  if [ "$saw" -ne 1 ]; then
    echo "    FAIL: no validated RSS sample in $out" >&2
    return 1
  fi
  printf '%s' "$max"
}

# Plan §6.5's memory criterion in one place, so the `large` row and the
# sensitivity control cannot drift apart. Prints the growth in KiB and returns
# success only when it is under the limit. The 64 MiB limit is not a guess: on
# this host the debug launcher peaks at ~80 MB on both a 1 MiB and a 256 MiB
# input (growth ~5 MB), while a 256 MiB whole-stream buffer adds 256 MiB, four
# times the limit — the measured separation is recorded in verifications.md.
RSS_GROWTH_LIMIT_KIB="${RSS_GROWTH_LIMIT_KIB:-65536}"

rss_growth_verdict() { # baseline_median_kib measured_median_kib
  local growth
  growth=$(( $2 - $1 ))
  printf '%s' "$growth"
  [ "$growth" -lt "$RSS_GROWTH_LIMIT_KIB" ]
}

# Count one byte value, given as a C-style octal escape, in a file. LC_ALL=C so
# multibyte decoding cannot change what "a byte" means.
count_byte() {
  local file="$1" escape="$2"
  [ -f "$file" ] || { echo "    FAIL: no capture file $file" >&2; return 1; }
  LC_ALL=C tr -dc -- "$escape" <"$file" | wc -c | tr -d ' '
}

# The concurrent-streams oracle, over captured files only, so the harness
# self-test can run a mock launcher through the very same checks.
#
# Guest bytes are channel-distinct and non-ASCII on purpose: the launcher's own
# `==> …` notices contain ASCII letters, so counting ASCII in a capture cannot
# distinguish guest output from diagnostics.
assert_concurrent_stdout() {
  local desc="$1" expected="$2" actual="$3" stray
  if ! cmp -s "$expected" "$actual"; then
    echo "    FAIL: $desc (stdout is not the exact guest bytes)"
    cmp -l "$expected" "$actual" | head -5 || true
    return 1
  fi
  stray="$(count_byte "$actual" '\361')" || return 1
  assert_eq "$desc: no stderr byte on stdout" "0" "$stray" || return 1
}

# The launcher's complete progress-notice vocabulary for one direct launch. A
# `==>` line outside this set is either guest-byte contamination or a changed
# launcher, and both must fail rather than be accepted as "some notice"
# (#399 N1). Guest bytes cannot match: they are 0xE9/0xF1.
CONCURRENT_NOTICE_PATTERNS=(
  '^==> agent-vm-[0-9a-f]+-[0-9]+ in .+ [(]state: .+[)]$'
  '^==> Agent credentials: .+$'
  '^==> Git author identity: .+$'
  '^==> GitHub repo scope: .+$'
  '^==> GitHub repo scope [(][0-9]+[)]: .+$'
  '^==> Boot image: .+$'
  '^==> Booting sandbox from .+$'
  '^==> Project path .+$'
  '^==> --no-git skips .+$'
  '^==> Mounting .+$'
  '^==> Config mounts: .+$'
  '^==> Egress authority: .+$'
  '^==> Egress policy: .+$'
  '^==> TLS interception: .+$'
  '^==> Egress DNS: .+$'
  '^==> Tool network requests .+$'
  '^==>   (unmet|to grant): .+$'
  '^==>   … and [0-9]+ more not shown$'
  '^==> WARNING: potentially sensitive guest-managed Pi credentials .+$'
  '^==> Running .+ in sandbox [(]no TTY; streaming output[)]$'
  '^==> Stopping sandbox$'
)

# A notice is the launcher's own diagnostic: printable ASCII plus the three
# punctuation characters its vocabulary uses (`…`, `—`, `→`). Any other byte on
# a notice line — the guest's 0xE9/0xF1, a control byte, DEL — is contamination.
# This check is deliberately independent of the vocabulary: in C locale `.`
# matches any byte, so `^==> GitHub repo scope: .+$` accepts
# `owner/<0xF1>repo`. The vocabulary alone can therefore never carry the
# no-guest-byte property (#399 R2-2).
notice_bytes_clean() {
  local line="$1"
  local LC_ALL=C
  line="${line//$'\342\200\246'/}" # …
  line="${line//$'\342\200\224'/}" # —
  line="${line//$'\342\206\222'/}" # →
  case "$line" in
  *[$'\001'-$'\037']* | *[$'\177'-$'\377']*) return 1 ;;
  esac
  return 0
}

# Does one line match the launcher's stated notice vocabulary? Kept separate
# from `assert_expected_notices` so a control can show that a wildcard-injected
# notice is *accepted* by the vocabulary and rejected by the byte rule above.
notice_vocabulary_matches() {
  local line="$1" pattern
  local LC_ALL=C
  for pattern in "${CONCURRENT_NOTICE_PATTERNS[@]}"; do
    if [[ "$line" =~ $pattern ]]; then
      return 0
    fi
  done
  return 1
}

assert_expected_notices() {
  # A UTF-8 locale makes bash 5.2's `read` fail on a line holding a non-UTF-8
  # byte and silently skip its body -- that would make this oracle green for
  # exactly the contamination it exists to catch (#399 N1). Scan bytes.
  local desc="$1" stderr="$2" line
  local LC_ALL=C
  [ -f "$stderr" ] || {
    echo "    FAIL: $desc: no stderr capture"
    return 1
  }
  # `|| [ -n "$line" ]` also scans an unterminated final line: a guest byte in a
  # last line without a newline must not be skipped (#399 R2-2).
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in '==> '*) ;; *) continue ;; esac
    if ! notice_bytes_clean "$line"; then
      echo "    FAIL: $desc: guest byte or control byte on a launcher notice: $line"
      printf '    notice bytes:'
      printf '%s' "$line" | LC_ALL=C od -An -tx1 | head -2 || true
      return 1
    fi
    if ! notice_vocabulary_matches "$line"; then
      echo "    FAIL: $desc: unexpected launcher notice: $line"
      return 1
    fi
  done <"$stderr"
}

# Bytes above 0x7F on this capture that the notice oracle already vetted: the
# launcher's own `…`/`—`/`→` on lines that are accepted notices. `notice_bytes_clean`
# removes those three sequences and then rejects every remaining byte above
# 0x7F, so *all* high bytes on an accepted notice line are that punctuation. The
# allowance is line-scoped: a high byte on any other line (guest output, a
# rejected notice, a stray sequence) is never subtracted here.
notice_punctuation_bytes() { # file
  local file="$1" line count total=0
  local LC_ALL=C
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in '==> '*) ;; *) continue ;; esac
    notice_bytes_clean "$line" || continue
    notice_vocabulary_matches "$line" || continue
    count="$(printf '%s' "$line" | LC_ALL=C tr -cd '\200-\377' | wc -c | tr -d ' ')"
    total=$((total + count))
  done <"$file"
  printf '%s' "$total"
}

assert_concurrent_stderr() {
  local desc="$1" stderr="$2" total="$3" count stray allowed
  count="$(count_byte "$stderr" '\361')" || return 1
  assert_eq "$desc: guest stderr bytes" "$total" "$count" || return 1
  count="$(count_byte "$stderr" '\351')" || return 1
  assert_eq "$desc: no stdout byte on stderr" "0" "$count" || return 1
  # Only 0xF1 may be non-ASCII: remove it, then nothing above 0x7F may remain —
  # except the launcher's own notice punctuation (`…`, `—`, `→`) on lines the
  # notice oracle below accepts. Without that allowance this rule rejected a
  # valid `TLS interception: … — global` notice before the notice check ran, so
  # the punctuation allowance lived only inside `notice_bytes_clean` while the
  # whole-stream rule refused the same bytes (#399 review 3, observation 3).
  # `notice_punctuation_bytes` is line-scoped: punctuation on any line that is
  # not an accepted notice stays countable, so no guest byte can ride along.
  stray="$(LC_ALL=C tr -d '\361' <"$stderr" | LC_ALL=C tr -cd '\200-\377' | wc -c |
    tr -d ' ')" || return 1
  allowed="$(notice_punctuation_bytes "$stderr")" || return 1
  stray=$((stray - allowed))
  assert_eq "$desc: no other non-ASCII byte on stderr" "0" "$stray" || return 1
  # Guest bytes never ride on a notice, and only the launcher's known notices
  # are allowed at all.
  assert_expected_notices "$desc: notices" "$stderr" || return 1
  # Counts alone accept an arbitrarily long ASCII injection on a line the notice
  # oracle skips: every byte that is not part of an accepted notice must be the
  # guest's own flood byte, so the remaining lines are checked, not just counted.
  assert_stderr_is_notices_and_flood "$desc" "$stderr" || return 1
}

# Every stderr line is either a launcher notice the oracle accepts, or nothing
# but the guest's 0xF1 flood (#399 review: byte counts alone let an injected
# ASCII line through).
assert_stderr_is_notices_and_flood() {
  local desc="$1" stderr="$2" line rest
  local LC_ALL=C
  [ -f "$stderr" ] || {
    echo "    FAIL: $desc: no stderr capture"
    return 1
  }
  while IFS= read -r line || [ -n "$line" ]; do
    # The guest flood carries no line structure, so a launcher notice can be
    # glued to its tail (`0xF1 × 4 MiB` then `==> Stopping sandbox` with no
    # newline between them). Remove the flood bytes first and judge what is
    # left: an accepted notice line, or nothing.
    rest="$(printf '%s' "$line" | LC_ALL=C tr -d '\361')" || return 1
    [ -n "$rest" ] || continue
    if [[ "$rest" == '==> '* ]] && notice_bytes_clean "$rest" &&
      notice_vocabulary_matches "$rest"; then
      continue
    fi
    echo "    FAIL: $desc: stderr line is neither a launcher notice nor the guest flood"
    printf '    remaining bytes:'
    printf '%s' "$rest" | LC_ALL=C od -An -tx1 | head -2 || true
    printf '    text:'
    printf '%s' "$rest" | LC_ALL=C head -c 200 || true
    printf '\n'
    return 1
  done <"$stderr"
}

# One stdin capture in one direct syntax form: `$1` capture name, `$2` project,
# `$3` input path, `$4` form (`run` or `dash`), rest: the program's literal argv.
stdin_capture() {
  local capture="$1" proj="$2" input="$3" form="$4" status=0
  shift 4
  case "$form" in
  run | dash) ;;
  *)
    echo "    FAIL: unknown direct form: $form"
    return 1
    ;;
  esac
  case "$form" in
  run) capture_custom_direct_input "$capture" "$proj" "$input" -- run "$@" || status=$? ;;
  dash) capture_custom_direct_input "$capture" "$proj" "$input" -- -- "$@" || status=$? ;;
  esac
  printf '    observed: form=%s observation=%s launcher_status=%s\n' \
    "$form" "$status" "${CAPTURE_STATUS:-unset}"
  return "$status"
}

# The same capture in the background, so a row can observe the guest while the
# launcher still runs. Two independent outcomes are recorded (#399 F1):
# * `<capture>.observed` — did the *observation* succeed?
# * `<capture>.status` — the launcher's own exit status, kept in CAPTURE_STATUS
#   by observe_launch. The old wrapper wrote `$?` (observation success) here, so
#   a launcher that emitted every expected byte and exited 7 was recorded as 0.
stdin_capture_async() {
  local capture="$1" proj="$2" input="$3" form="$4"
  shift 4
  : >"$WORK/$capture.observed" || return 1
  (
    trap - EXIT
    local observation=0
    CAPTURE_STATUS=""
    stdin_capture "$capture" "$proj" "$input" "$form" "$@" || observation=$?
    printf '%s' "$observation" >"$WORK/$capture.observed"
    printf '%s' "${CAPTURE_STATUS:-}" >"$WORK/$capture.status"
  ) &
  STDIN_CAPTURE_PID=$!
}

# Background capture PID, for the row's bounded `wait`.
STDIN_CAPTURE_PID=""

# How long a background capture may take to finish. The launch itself has a
# 120 s watchdog, so this is a backstop, never the primary deadline (#399 F2).
STDIN_CAPTURE_WAIT_SECONDS="${STDIN_CAPTURE_WAIT_SECONDS:-130}"

# Signal one recorded `pid:comm` inventory. Every PID is re-checked against the
# comm recorded *before* the first signal. That comm match is a reuse *guard*,
# not a process birth identity: another process can reuse the PID with the same
# comm, and the check-to-kill window is a race, so this narrows — it does not
# eliminate — the chance of signalling a stranger. The inventory is the caller's
# snapshot: recomputing descendants after a TERM cannot find a child that was
# reparented when its parent died (#399 R2-4).
signal_inventory() { # inventory signal
  local inventory="$1" sig="$2" line pid comm current
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    pid="${line%%:*}"
    comm="${line#*:}"
    current="$(ps -p "$pid" -o comm= 2>/dev/null)" || continue
    [ "$current" = "$comm" ] || continue
    kill "-$sig" "$pid" 2>/dev/null || true
  done <<<"$inventory"
}

# Wait for an async capture, bounded, and reap it. A capture still running at
# the deadline is killed together with its descendants so a failed row cannot
# leave a launcher behind. The descendant inventory is taken once, before the
# TERM pass: a TERM-resistant child is reparented to init as soon as its capture
# parent dies, so rediscovering descendants after the TERM would miss exactly
# the process that needs the KILL and leave it unreachable from EXIT cleanup
# (#399 R2-4).
wait_capture_bounded() {
  local capture="$1" i=0 inventory
  [ -n "$STDIN_CAPTURE_PID" ] || return 0
  while [ "$i" -lt "$STDIN_CAPTURE_WAIT_SECONDS" ]; do
    kill -0 "$STDIN_CAPTURE_PID" 2>/dev/null || break
    sleep 1
    i=$((i + 1))
  done
  if kill -0 "$STDIN_CAPTURE_PID" 2>/dev/null; then
    echo "    FAIL: the background capture $capture did not finish within ${STDIN_CAPTURE_WAIT_SECONDS}s"
    inventory="$(descendants_of "$STDIN_CAPTURE_PID")" || inventory=""
    signal_inventory "$inventory" TERM
    kill -TERM "$STDIN_CAPTURE_PID" 2>/dev/null || true
    sleep 1
    signal_inventory "$inventory" KILL
    kill -KILL "$STDIN_CAPTURE_PID" 2>/dev/null || true
    wait "$STDIN_CAPTURE_PID" 2>/dev/null || true
    STDIN_CAPTURE_PID=""
    return 1
  fi
  wait "$STDIN_CAPTURE_PID" 2>/dev/null || true
  STDIN_CAPTURE_PID=""
}

# How long a control that killed a process waits for it to disappear. A
# SIGKILLed process is not absent on the next instruction: it can be
# mid-teardown or an unreaped zombie, and `kill -0` reports both as alive
# (#399 verification 4, h19). Ten seconds is far beyond observed teardown and
# still finite, so a descendant the KILL pass never reached (the control's child
# ignores TERM and loops forever) still fails it.
KILL_GRACE_SECONDS="${KILL_GRACE_SECONDS:-10}"

# Poll, bounded, for `pid` to be gone. Success means the process no longer
# exists or is an unreaped zombie — a process that was killed, not a survivor.
# A PID still carrying a live comm at the deadline returns 1.
wait_pid_absent() { # pid [seconds]
  local pid="$1" seconds="${2:-$KILL_GRACE_SECONDS}" steps waited=0 comm
  steps=$((seconds * 10))
  while :; do
    if ! kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
    comm="$(ps -p "$pid" -o comm= 2>/dev/null)"
    if [ "$comm" = "<defunct>" ]; then
      return 0
    fi
    [ "$waited" -lt "$steps" ] || return 1
    sleep 0.1
    waited=$((waited + 1))
  done
}

# Backstop for cleanup_work: stop a capture a failed row left running.
stdin_capture_stop() {
  [ -n "$STDIN_CAPTURE_PID" ] || return 0
  wait_capture_bounded "background capture"
}

# Abort a live row whose readiness deadline was missed. It closes its writer and
# reaps the capture; it never opens the FIFO for another synchronous write,
# which is what used to block a failed row forever (#399 F2).
abort_live_capture() {
  local capture="$1" status=0
  stdin_writer_close
  stdin_writer_stop || status=1
  wait_capture_bounded "$capture" || status=1
  return "$status"
}

# Poll until a capture file has at least one byte (a live guest is producing).
wait_for_nonempty() {
  local file="$1" seconds="$2" waited=0 steps
  steps=$((seconds * 5))
  while [ "$waited" -lt "$steps" ]; do
    [ -s "$file" ] && return 0
    sleep 0.2
    waited=$((waited + 1))
  done
  echo "    FAIL: $file stayed empty for ${seconds}s"
  return 1
}

# Byte-exact comparison of a capture's guest stdout with an **expected file**,
# for expectations that carry bytes a shell string cannot (random bytes, a
# trailing newline a `$(...)` would strip).
assert_direct_stdout_file() {
  local desc="$1" name="$2" expected_file="$3"
  direct_stdout_file "$name" >/dev/null || return 1
  if ! cmp -s "$expected_file" "$WORK/$name.stdout"; then
    echo "    FAIL: $desc (guest stdout bytes differ)"
    cmp -l "$expected_file" "$WORK/$name.stdout" | head -5 || true
    return 1
  fi
}

# The observation outcome of a capture started with stdin_capture_async: 0
# only when observe_launch completed, never the launcher's own status (#399
# F1). A missing receipt is a failure, not an assumed success.
stdin_capture_observation() {
  local capture="$1" observed
  observed="$(cat "$WORK/$capture.observed" 2>/dev/null)" || {
    echo "    FAIL: the background capture $capture never reported its observation"
    return 1
  }
  case "$observed" in
  '' | *[!0-9]*)
    echo "    FAIL: the background capture $capture reported a non-numeric observation '$observed'"
    return 1
    ;;
  esac
  printf '%s' "$observed"
}

# The launcher's own exit status, valid only when the observation succeeded.
# The previous helper returned the observation status here, so a launcher that
# exited 7 was reported as 0 whenever its bytes looked right (#399 F1).
stdin_capture_launcher_status() {
  local capture="$1" observed status
  observed="$(stdin_capture_observation "$capture")" || return 1
  if [ "$observed" -ne 0 ]; then
    echo "    FAIL: $capture: the observation itself failed (exit $observed); the launcher status is unknown"
    return 1
  fi
  status="$(cat "$WORK/$capture.status" 2>/dev/null)" || {
    echo "    FAIL: the background capture $capture never reported a launcher status"
    return 1
  }
  case "$status" in
  '' | *[!0-9]*)
    echo "    FAIL: the background capture $capture reported a non-numeric launcher status '$status'"
    return 1
    ;;
  esac
  printf '%s' "$status"
}

# Assert both halves of an async capture: the observation completed and the
# launcher exited with `want`.
assert_async_launcher_status() {
  local desc="$1" capture="$2" want="$3" status
  status="$(stdin_capture_launcher_status "$capture")" || return 1
  assert_eq "$desc" "$want" "$status"
}

# ── evidence receipts (#399 follow-up) ─────────────────────────────────────
#
# A row PASS label is not evidence. Every stdin row logs the exact launcher
# argv (in stdin_capture), then one receipt per form naming the candidate and
# the runtime this group pinned. Hashes are computed once and reused.
#
# The runtime receipt covers the paths the **rows actually launch with**
# (#399 R2-5): `CUSTOM_ENV` clears an inherited MSB_PATH / MSB_LIBKRUNFW_PATH /
# MSB_AGENTD_PATH and pins these exact files, so a caller's environment cannot
# make a launch execute a different runtime than the one recorded here. The
# version comes from the pinned binary itself, never from `agent-vm msb
# --version`, which resolves MSB_HOME and can create or read the caller's DB.
STDIN_EVIDENCE_CANDIDATE=""
STDIN_EVIDENCE_RUNTIME=""
STDIN_EVIDENCE_READY=""

# A Git object id, as the probes below must see it. A probe that succeeds while
# printing nothing, and the literal `unknown` some Git commands print for an
# unresolved revision, are failures here: neither may reach a receipt as an
# identity (#399 review).
stdin_object_id() {
  case "$1" in
  '' | unknown | *[!0-9a-f]*) return 1 ;;
  esac
  [ "${#1}" -eq 40 ] || [ "${#1}" -eq 64 ]
}

# The commit the pinned runtime's own `vendor/libkrunfw` gitlink names: the
# source the firmware receipt must match. The `ls-tree` status is checked before
# its output is parsed, so a failed or empty resolution cannot compare equal to
# a failed or empty receipt (#399 review).
stdin_firmware_gitlink() {
  local tree mode type link path
  tree="$(git -C "$REPO_ROOT/vendor/microsandbox" ls-tree HEAD vendor/libkrunfw)" || return 1
  read -r mode type link path <<<"$tree"
  if [ "$mode" != 160000 ] || [ "$type" != commit ] || [ "$path" != vendor/libkrunfw ]; then
    echo "    evidence: no vendor/libkrunfw gitlink in the pinned runtime: [$tree]" >&2
    return 1
  fi
  stdin_object_id "$link" || {
    echo "    evidence: the pinned runtime's vendor/libkrunfw gitlink is not an object id: [$link]" >&2
    return 1
  }
  printf '%s' "$link"
}

# A named object id, or a failure that says which probe answered wrongly.
require_object_id() {
  stdin_object_id "$2" && return 0
  echo "    evidence: $1 is not a Git object id: [$2]" >&2
  return 1
}

stdin_identity_init() {
  [ -z "$STDIN_EVIDENCE_READY" ] || return 0
  local cand_sha version head runtime_source firmware_source firmware_gitlink
  local runtime_msb runtime_agentd runtime_fw msb_version
  # The rows call this under `if`/`||`, where implicit errexit is ineffective, so
  # every probe carries its own `|| return 1` and its value is validated rather
  # than interpolated. An empty or `unknown` answer is a failed probe (#399 review).
  cand_sha="$(shasum -a 256 "$AGENT_VM" | cut -d' ' -f1)" || return 1
  version="$("$AGENT_VM" --version 2>&1)" || return 1
  head="$(git -C "$REPO_ROOT" rev-parse HEAD)" || return 1
  runtime_source="$(git -C "$REPO_ROOT/vendor/microsandbox" rev-parse --verify HEAD)" || return 1
  firmware_source="$(cat "$CUSTOM_RUNTIME_DIR/libkrunfw.5.dylib.source-sha")" || return 1
  firmware_gitlink="$(stdin_firmware_gitlink)" || return 1
  require_object_id "the candidate HEAD" "$head" || return 1
  require_object_id "the pinned runtime HEAD" "$runtime_source" || return 1
  require_object_id "the firmware source receipt" "$firmware_source" || return 1
  [ "$firmware_source" = "$firmware_gitlink" ] || {
    echo "    evidence: firmware source $firmware_source is not the pinned runtime gitlink $firmware_gitlink" >&2
    return 1
  }
  STDIN_EVIDENCE_CANDIDATE="path=$AGENT_VM version=[$version] sha256=$cand_sha commit=$head"
  runtime_msb="$(shasum -a 256 "$CUSTOM_MSB" | cut -d' ' -f1)" || return 1
  runtime_agentd="$(shasum -a 256 "$CUSTOM_AGENTD" | cut -d' ' -f1)" || return 1
  runtime_fw="$(shasum -a 256 "$CUSTOM_LIBKRUNFW" | cut -d' ' -f1)" || return 1
  msb_version="$("$CUSTOM_MSB" --version 2>&1)" || return 1
  STDIN_EVIDENCE_RUNTIME="msb_path=$CUSTOM_MSB (pinned) sha256=$runtime_msb version=[$msb_version]; agentd=embedded in the pinned msb (MSB_AGENTD_PATH cleared; the bundle ships $CUSTOM_AGENTD sha256=$runtime_agentd); libkrunfw_path=$CUSTOM_LIBKRUNFW (pinned) sha256=$runtime_fw; microsandbox=$runtime_source; firmware-source=$firmware_source (the pinned vendor/libkrunfw gitlink)"
  STDIN_EVIDENCE_READY=1
}

# One per-form receipt: command form, observed status, candidate/runtime
# identities, and the checks that ran.
stdin_form_evidence() {
  local form="$1" status="$2" assertions="$3"
  stdin_identity_init || return 1
  printf '    evidence: form=%s launcher_status=%s assertions=[%s]\n' \
    "$form" "$status" "$assertions"
  printf '    evidence: candidate=%s\n' "$STDIN_EVIDENCE_CANDIDATE"
  printf '    evidence: runtime=%s\n' "$STDIN_EVIDENCE_RUNTIME"
}

# A project pinned to one image, for a stdin row.
stdin_row_project() {
  local name="$1" image="$2" proj="$WORK/$1"
  mkdir -p "$proj/.agent-vm" || return 1
  printf 'image = "%s"\n' "$image" >"$proj/.agent-vm/config.toml" || return 1
  printf '%s' "$proj"
}

# The single state directory this run owns for `proj`: exactly one 12-hex child
# of the private state root (session::hash_path's first 12 hex chars). A
# resolution surprise (a parent, `..`, a nested or non-hex name) is reported and
# never becomes a delete target, so the guard enforces what it advertises.
direct_state_child() {
  local proj="$1" state child
  if ! state="$(host_state_dir "$proj")"; then
    echo "    cleanup: could not resolve the state dir for $proj" >&2
    return 1
  fi
  case "$state" in
  "$CUSTOM_STATE"/*) child="${state#"$CUSTOM_STATE"/}" ;;
  *)
    echo "    cleanup: $state is outside $CUSTOM_STATE; not removing" >&2
    return 1
    ;;
  esac
  case "$child" in
  '' | */* | . | ..)
    echo "    cleanup: $state is not one child of $CUSTOM_STATE; not removing" >&2
    return 1
    ;;
  esac
  if [ "${#child}" -ne 12 ]; then
    echo "    cleanup: $state has a ${#child}-character name, not 12 hex; not removing" >&2
    return 1
  fi
  case "$child" in
  *[!0-9a-f]*)
    echo "    cleanup: $state is not a 12-hex state child; not removing" >&2
    return 1
    ;;
  esac
  printf '%s' "$state"
}

# Finalize one direct row. `ref` is the image the row launched and `outcome` the
# row body's own status. A row that failed, or that cannot prove its owned
# runtime and catalog record are gone, removes NOTHING: the captured stdout, the
# launcher log and the state it was diagnosed from stay for the
# failure-preservation trap to report. Only once that proof holds does a passing
# row remove its own state child and the sibling host-only `.secrets`
# directory. Any cleanup failure fails the row.
direct_cleanup() {
  local name="$1" proj="$2" ref="$3" outcome="$4" state result=0
  if ! state="$(direct_state_child "$proj")"; then
    echo "    cleanup: keeping $name evidence (state identity unresolved)"
    return 1
  fi
  if [ "$outcome" -ne 0 ]; then
    echo "    cleanup: keeping $name evidence: $WORK/$name.stdout $WORK/$name.out $state"
    return 1
  fi
  # No owned sandbox may survive before its state is deleted: process absence
  # alone is not catalog absence. A survivor is itself the failure being
  # diagnosed, so its state stays.
  if ! assert_no_catalog_entry "$ref"; then
    echo "    cleanup: keeping $name evidence: a sandbox for $ref survives; $state"
    return 1
  fi
  if [ -e "$state" ]; then
    rm -rf "$state" || { echo "    cleanup: could not remove $state"; result=1; }
  fi
  if [ -e "$state.secrets" ]; then
    rm -rf "$state.secrets" || { echo "    cleanup: could not remove $state.secrets"; result=1; }
  fi
  rm -f "$WORK/$name.stdout" "$WORK/$name.expected" || result=1
  return "$result"
}

# Proof that none of the named state entries exists, distinguishing absence from
# a failed observation: only ENOENT is evidence.
assert_state_entries_absent() {
  local desc="$1" state="$2"
  shift 2
  python3 - "$desc" "$state" "$@" <<'ABSENT'
import os
import sys

desc, state = sys.argv[1], sys.argv[2]
failed = False
for relative in sys.argv[3:]:
    path = os.path.join(state, relative)
    try:
        os.lstat(path)
    except FileNotFoundError:
        continue
    except OSError as error:
        print(f"    FAIL: {desc}: could not observe {path}: {error}", file=sys.stderr)
        failed = True
    else:
        print(f"    FAIL: {desc}: {path} must not exist", file=sys.stderr)
        failed = True
raise SystemExit(1 if failed else 0)
ABSENT
}

# The exact generic guest-HOME furniture: `name<TAB>target`, sorted. Compared as
# a whole set so an unexpected link (a catalog `persist` declaration, or a
# provider link this oracle does not know) fails rather than passing as "some
# path under the state root".
direct_home_links() {
  python3 - "$1" <<'LINKS'
import os
import sys

root = os.path.join(sys.argv[1], "home")
rows = []
try:
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            if os.path.islink(path):
                rows.append(f"{os.path.relpath(path, root)}\t{os.readlink(path)}")
except OSError as error:
    print(f"    FAIL: could not walk {root}: {error}", file=sys.stderr)
    raise SystemExit(1)
for row in sorted(rows):
    print(row)
LINKS
}

assert_direct_state_furniture() {
  local desc="$1" state="$2" expected actual
  expected="$(printf '%s\t%s\n' \
    .bash_history /agent-vm-state/bash_history \
    .claude /agent-vm-state/claude \
    .claude.json /agent-vm-state/claude.json \
    .config/gh /agent-vm-state/gh-config \
    .config/opencode /agent-vm-state/opencode-config \
    .copilot /agent-vm-state/copilot \
    .gitconfig /agent-vm-state/gitconfig \
    .local/share/opencode /agent-vm-state/opencode \
    .pi /agent-vm-state/pi | LC_ALL=C sort)" || return 1
  if ! actual="$(direct_home_links "$state" | LC_ALL=C sort)"; then
    echo "    FAIL: $desc: could not read the guest HOME links"
    return 1
  fi
  if [ "$actual" != "$expected" ]; then
    echo "    FAIL: $desc: guest HOME links are not exactly the generic furniture"
    printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual"
    return 1
  fi
}

# The sandbox config the launcher actually handed the SDK, from its own
# `[debug] sandbox config JSON` record. A missing, unreadable or malformed record
# is a failure, never an empty observation.
direct_debug_config() {
  local name="$1"
  [ -r "$WORK/$name.out" ] ||
    { echo "    FAIL: no launcher log for $name"; return 1; }
  python3 - "$WORK/$name.out" <<'CONFIG'
import json
import sys

marker = "[debug] sandbox config JSON: "
try:
    with open(sys.argv[1], encoding="utf-8", errors="surrogateescape") as handle:
        text = handle.read()
except OSError as error:
    print(f"    FAIL: could not read {sys.argv[1]}: {error}", file=sys.stderr)
    raise SystemExit(1)
index = text.find(marker)
if index < 0:
    print("    FAIL: the launch emitted no sandbox config dump", file=sys.stderr)
    raise SystemExit(1)
try:
    config, _ = json.JSONDecoder().raw_decode(text[index + len(marker):].lstrip())
except ValueError as error:
    print(f"    FAIL: the sandbox config dump is not JSON: {error}", file=sys.stderr)
    raise SystemExit(1)
json.dump(config, sys.stdout)
CONFIG
}

# Default-deny authority with an empty grant, asserted on the config the native
# launch really used: no declared request rule, secret, intercept route or TLS
# intercept, and no catalog tool/shell environment.
assert_direct_default_deny() {
  local desc="$1" name="$2" config
  config="$(direct_debug_config "$name")" || return 1
  if ! jq -e '
      (.network.policy.default_egress == "deny")
      and (.network.policy.default_ingress == "allow")
      and ((.network.policy.rules | length) == 0)
      and ((.network.secrets.secrets | length) == 0)
      and ((.network.intercept.rules | length) == 0)
      and (.network.intercept.hook == null)
      and (.network.tls.enabled == false)
      and ([.env[].key] | index("PROBE_CATALOG_ENV") == null)
      and ([.env[].key] | index("SHELL_CATALOG_ENV") == null)
      and ([.env[].key] | index("CODEX_HOME") == null)
      and ([.env[].key] | index("COPILOT_GITHUB_TOKEN") == null)
    ' <<<"$config" >/dev/null; then
    echo "    FAIL: $desc: the launch config is not the empty default-deny grant"
    printf '%s\n' "$config" | jq -c '{policy: .network.policy, secrets: .network.secrets, intercept: .network.intercept.rules, env: [.env[].key]}' ||
      true
    return 1
  fi
}

# Attach-branch launch under a real PTY (macOS BSD `script`). `script`'s exit
# status is not assumed to equal the guest's; callers inspect the recorded PTY
# output. The watchdog and observer are identical to the streaming path.
capture_custom_attach() {
  local name="$1" proj="$2" pty="$WORK/$1.pty" log="$WORK/$1.pty.log"
  shift 2
  rm -f "$pty" "$log" || return 1
  observe_launch "$name" "$proj" "$log" -- \
    "${CUSTOM_ENV[@]}" "${OFFLINE_ENV[@]}" \
    XDG_CONFIG_HOME="$WORK/offline-config" PATH="$SHIM_DIR:/usr/bin:/bin" \
    HOME="$CUSTOM_HOME" \
    HOST_SHIM_LOG="$HOST_SHIM_LOG" \
    /usr/bin/script -q "$pty" "$AGENT_VM" "$@"
}

# The recorded PTY stream with CRs removed (PTY output is CRLF-terminated).
attach_output() {
  tr -d '\r' <"$WORK/$1.pty"
}

# Require no catalog entry for the fixture ref/session. `avm msb list` is the
# supported baseline JSON surface. A malformed document, an unexpected shape, a
# jq runtime error and a jq `false` are all distinguished: only a validated
# zero-length selection proves absence.
assert_no_catalog_entry() {
  local ref="$1" json count
  json="$(avm_custom_state msb list --format json)" ||
    { echo "    FAIL: could not list the sandbox catalog"; return 1; }
  if ! printf '%s' "$json" | jq -e \
      'type == "array" and all(.[]; type == "object" and (.image | type == "string"))' \
      >/dev/null; then
    echo "    FAIL: msb list --format json is not a validated array of {image: string}"
    printf '%s\n' "$json"
    return 1
  fi
  if ! count="$(printf '%s' "$json" | jq --arg ref "$ref" 'map(select(.image == $ref)) | length')"; then
    echo "    FAIL: could not select catalog entries for $ref"
    return 1
  fi
  if [ "$count" -ne 0 ]; then
    echo "    FAIL: the catalog still has $count entry/entries for $ref"
    printf '%s\n' "$json"
    return 1
  fi
}

# The msb *image* catalog is a different store from the sandbox catalog: the
# cold/warm check must prove the reference was absent before acquisition and
# present after it. `reference` may be stored exactly as pushed or canonically
# normalized, so accept an exact match or a normalized `<repo>:<tag>` suffix,
# never an arbitrary substring. Shape/type errors and jq runtime errors are
# failures, not absence.
image_catalog_has() {
  local ref="$1" suffix="/$2" want_present="$3" json count
  json="$(avm_custom_state msb image list --format json)" ||
    { echo "    FAIL: could not list the msb image catalog"; return 1; }
  if ! printf '%s' "$json" | jq -e \
      'type == "array" and all(.[]; type == "object" and (.reference | type == "string"))' \
      >/dev/null; then
    echo "    FAIL: msb image list --format json is not a validated array of {reference: string}"
    printf '%s\n' "$json"
    return 1
  fi
  if ! count="$(printf '%s' "$json" | jq --arg ref "$ref" --arg suffix "$suffix" \
      'map(select(.reference == $ref or (.reference | endswith($suffix)))) | length')"; then
    echo "    FAIL: could not select image catalog entries for $ref"
    return 1
  fi
  if [ "$count" -ne 0 ]; then
    if [ "$want_present" = present ]; then return 0; fi
    echo "    FAIL: image catalog already has an entry for $ref (not cold)"
    return 1
  fi
  if [ "$want_present" = absent ]; then return 0; fi
  echo "    FAIL: image catalog has no entry for $ref after acquisition"
  printf '%s\n' "$json"
  return 1
}

# Emergency cleanup: only this run's captured refs, only inside the isolated
# state root. Every failure is reported; the caller's check is already FAIL, so
# this can never turn a failure into a pass.
emergency_sandbox_cleanup() {
  local ref="$1" json names name failed=0
  if ! json="$(avm_custom_state msb list --format json 2>/dev/null)"; then
    echo "    cleanup: could not list the sandbox catalog"
    return 1
  fi
  if ! names="$(printf '%s' "$json" | jq -r --arg ref "$ref" '.[] | select(.image == $ref) | .name')"; then
    echo "    cleanup: could not select catalog names for $ref"
    return 1
  fi
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    echo "    cleanup: stopping $name"
    avm_custom_state msb stop --force "$name" >/dev/null 2>&1 ||
      { echo "    cleanup: stop failed for $name"; failed=1; }
    avm_custom_state msb remove "$name" >/dev/null 2>&1 ||
      { echo "    cleanup: remove failed for $name"; failed=1; }
  done <<<"$names"
  return "$failed"
}

launch_output() {
  local name="$1"
  cat "$WORK/$name.out"
}

# #258: a capture file can be readable and still incomplete, and a reader can
# print expected-looking lines and then fail. The credential/stamp checks read
# observed evidence through this guard so printed output is never treated as
# success on its own.
read_launch_evidence() {
  local name="$1" out
  if ! out="$(launch_output "$name")"; then
    echo "    FAIL: could not read the launch evidence for $name"
    return 1
  fi
  printf '%s' "$out"
}

# One required line from captured evidence. A missing line or a grep error is a
# check failure, never an empty argument that could be compared as if it were a
# real observation. Diagnostics go to stderr because stdout is captured by the
# caller's command substitution.
evidence_line() {
  local desc="$1" re="$2" hay="$3" status=0 line
  line="$(grep -E -- "$re" <<<"$hay")" || status=$?
  case "$status" in
    0) printf '%s' "$line" ;;
    1)
      echo "    FAIL: $desc (no evidence line matching /$re/)" >&2
      return 1
      ;;
    *)
      echo "    FAIL: $desc (grep error $status reading evidence)" >&2
      return 1
      ;;
  esac
}

# --------------------------------------------------------- harness negative --

# A controlled negative for the harness itself: a check whose guarded capture
# deliberately exits 37 and a check whose guarded assertion fails must BOTH be
# counted as FAIL, and each one's trailing no-host-calls assertion must still
# run. Removing either `|| return 1` turns that function into a PASS, which this
# check then observes (0 pass / 2 fail required).
check_harness_negative() {
  local saved_passed="$PASSED" saved_failed="$FAILED"
  local log="$WORK/harness-negative.log"
  PASSED=0
  FAILED=0
  reset_host_shim_log || return 1
  : >"$log" || return 1
  # Every control logs its own outcome, so the log binds each claimed property
  # to an observation instead of one aggregate `PASS: harness-negative` line.
  local ctl_before=""
  # `result` is a monotonic failure count inside this check, so a control that
  # fails *after* an earlier one cannot compare equal and be reported ok. The
  # old shared 0/1 flag did exactly that once any control had failed.
  control_report() {
    local name="$1" before="$2"
    if [ "$result" -eq "$before" ]; then
      echo "    control $name: ok"
    else
      echo "    control $name: FAILED"
    fi
  }

  # shellcheck disable=SC2317,SC2329  # invoked indirectly through run_check;
  # 0.9 (the Ubuntu CI version) reports the body as unreachable instead.
  failing_capture() {
    local out
    out="$(exit 37)" || return 1
    : "$out"
    assert_no_host_calls
  }
  # shellcheck disable=SC2317,SC2329  # invoked indirectly through run_check;
  # 0.9 (the Ubuntu CI version) reports the body as unreachable instead.
  failing_assert() {
    assert_eq "deliberately wrong" "a" "b" || return 1
    assert_no_host_calls
  }

  run_check "negative/capture-37" failing_capture >>"$log" 2>&1
  run_check "negative/assert-fails" failing_assert >>"$log" 2>&1

  # #258: the production effective-PATH oracle must accept the composed
  # accepted row and reject every controlled row that varies only PATH. These
  # are complete outputs, so a mutated suffix-matching oracle accepts a rejected
  # row here and turns this check red.
  local result=0 accepted="$MSB_SCRIPTS_PREFIX:$NONSTANDARD_OCI_PATH" bad_path
  if ! expect_effective_path "oracle-accepted" "$(path_oracle_row "$accepted")" >/dev/null 2>&1; then
    echo "    FAIL: PATH oracle rejected the accepted row"
    result=$((result + 1))
  fi
  for bad_path in \
    "$NONSTANDARD_OCI_PATH" \
    "$MSB_SCRIPTS_PREFIX:/usr/local/bin:/usr/bin:/usr/sbin:/bin" \
    "/usr/bin:$NONSTANDARD_OCI_PATH" \
    "/opt/e2e-258/bin:/bin" \
    "$MSB_SCRIPTS_PREFIX:$MSB_SCRIPTS_PREFIX:$NONSTANDARD_OCI_PATH" \
    "$NONSTANDARD_OCI_PATH:$MSB_SCRIPTS_PREFIX" \
    "$NONSTANDARD_OCI_PATH:/extra"; do
    if expect_effective_path "oracle-negative" "$(path_oracle_row "$bad_path")" >/dev/null 2>&1; then
      echo "    FAIL: PATH oracle accepted a rejected row: path=$bad_path"
      result=$((result + 1))
    fi
  done
  if expect_effective_path "oracle-two-lines" "$(path_oracle_row "$accepted")"$'\n'"path=$accepted" >/dev/null 2>&1; then
    echo "    FAIL: PATH oracle accepted two path= lines"
    result=$((result + 1))
  fi

  # #258: the real corrected subjects, probed in isolated subshells with stub
  # subprocesses. No VM is booted and no host filesystem path is removed: the
  # stubs substitute the readers/removers, so only the wiring is exercised.
  local probe_dir="$WORK/harness-negative-probes"
  local removed_state37 removed_rm38 probe_target
  if ! mkdir -p "$probe_dir"; then
    echo "    FAIL: could not create the harness-negative probe dir"
    result=$((result + 1))
  fi

  # (a) An evidence reader that prints complete, expected-looking lines and then
  # exits nonzero must fail the guarded read, never pass on its printed output.
  ctl_before="$result"
  if (
    launch_output() { printf 'credsprobe=ok\nhome=/x\nuid=1 gid=1\n'; return 37; }
    read_launch_evidence "probe" >/dev/null 2>&1
  ); then
    echo "    FAIL: guarded evidence read accepted a reader that failed after printing"
    result=$((result + 1))
  fi
  control_report "a evidence-read-guard" "$ctl_before"


  # (b) A grep error (status 2) must not be treated as proof that a synthetic
  # token is absent from guest output.
  ctl_before="$result"
  if (
    # shellcheck disable=SC2317,SC2329  # invoked indirectly by assert_no_match;
    # 0.9 (the Ubuntu CI version) reports the stub as unreachable instead.
    grep() { return 2; }
    assert_no_credential_leak "grep2 probe" "haystack with no tokens" >/dev/null 2>&1
  ); then
    echo "    FAIL: grep status 2 was treated as proven absence"
    result=$((result + 1))
  fi
  control_report "b grep-error-is-not-absence" "$ctl_before"


  # (c) A state-dir resolution failure must fail cleanup while the other
  # project's private token is still attempted.
  ctl_before="$result"
  removed_state37="$probe_dir/removed-state37.txt"
  : >"$removed_state37" || result=$((result + 1))
  if (
    host_state_dir() {
      if [ "$1" = "$WORK/custom-cred" ]; then return 37; fi
      printf '%s' "$probe_dir/state-missing"
    }
    rm() { printf '%s\n' "$*" >>"$removed_state37"; return 0; }
    remove_custom_credential_material
  ) >/dev/null 2>&1; then
    echo "    FAIL: cleanup succeeded despite a state-dir resolution failure"
    result=$((result + 1))
  fi
  if ! grep -qF -- "$probe_dir/state-missing.secrets/anthropic" "$removed_state37"; then
    echo "    FAIL: cleanup skipped the other project after a resolution failure"
    result=$((result + 1))
  fi
  control_report "c state-dir-resolution-failure" "$ctl_before"


  # (d) An rm failure must fail cleanup while other removals are attempted.
  ctl_before="$result"
  removed_rm38="$probe_dir/removed-rm38.txt"
  : >"$removed_rm38" || result=$((result + 1))
  if (
    host_state_dir() { printf '%s' "$probe_dir/state-ok"; }
    rm() { printf '%s\n' "$*" >>"$removed_rm38"; return 38; }
    remove_custom_credential_material
  ) >/dev/null 2>&1; then
    echo "    FAIL: cleanup succeeded despite an rm failure"
    result=$((result + 1))
  fi
  for probe_target in "$CUSTOM_CREDENTIAL_SEED" "$probe_dir/state-ok.secrets/anthropic"; do
    if ! grep -qF -- "$probe_target" "$removed_rm38"; then
      echo "    FAIL: rm-failure cleanup did not attempt removing $probe_target"
      result=$((result + 1))
    fi
  done
  control_report "d rm-failure" "$ctl_before"


  # (e) The real stamp subject: an evidence reader that prints the complete
  # expected lines and then exits nonzero must make custom_image_stamp_present
  # FAIL. Each capture is guarded in its own assignment, so a reverted nested
  # capture would accept the printed output, return success, and turn this
  # probe red. No VM boots and no host path is removed: the launcher and reader
  # are stubbed inside the subshell.
  ctl_before="$result"
  if (
    custom_project() { printf '%s' "$probe_dir/proj"; }
    capture_custom_launch() { return 0; }
    require_launch_ok() { return 0; }
    assert_no_host_calls() { return 0; }
    read_launch_evidence() { printf '%s' 'hello-258=ok'; }
    evidence_line() {
      case "$2" in
        '^hello-258=ok$') printf '%s' 'hello-258=ok' ;;
        '^stamp=') printf '%s' 'stamp=present' ;;
        '^image_stamp=') printf 'image_stamp=%s' "$CUSTOM_STAMP_LITERAL" ;;
      esac
      return 37
    }
    custom_image_stamp_present
  ) >/dev/null 2>&1; then
    echo "    FAIL: stamp subject accepted a reader that failed after printing expected lines"
    result=$((result + 1))
  fi
  control_report "e stamp-reader-failure" "$ctl_before"


  # (f) The acquisition-dump oracle and the zero-builder absence oracle. The
  # accepted capture passes; every malformed capture fails. This is the
  # permanent negative control for the substring-false-pass class (Standards S1)
  # and the missing/unreadable-log class (Spec S2).
  ctl_before="$result"
  local acquire_name='native-image-acquire' verify_name='agent-vm-setup-verify'
  local ref='localhost:1/project:latest'
  local good=$'native-image-acquire\tlocalhost:1/project:latest\nagent-vm-setup-verify\tlocalhost:1/project:latest'
  if ! assert_dump "$good" "$acquire_name" "$ref" >/dev/null 2>&1; then
    echo "    FAIL: assert_dump rejected the accepted capture"
    result=$((result + 1))
  fi
  if ! assert_dump "$good" "$verify_name" "$ref" >/dev/null 2>&1; then
    echo "    FAIL: assert_dump rejected the accepted capture (verify name)"
    result=$((result + 1))
  fi
  local -a bad_dumps=(
    $'native-image-acquire\tlocalhost:1/project:latest-WRONG\nagent-vm-setup-verify\tlocalhost:1/project:latest-WRONG'
    $'native-image-acquire\tlocalhost:1/project:latest\nnative-image-acquire\tlocalhost:1/other:latest\nagent-vm-setup-verify\tlocalhost:1/project:latest'
    $'native-image-acquire\tlocalhost:1/project:latest'
    $'native-image-acquire\tlocalhost:1/project:latest\nagent-vm-setup-verify\tlocalhost:1/project:latest\nextra\tlocalhost:1/project:latest'
    $'native-image-acquire\tlocalhost:1/other:latest\nagent-vm-setup-verify\tlocalhost:1/project:latest'
    $'agent-vm-pull\tlocalhost:1/project:latest\nagent-vm-setup-verify\tlocalhost:1/project:latest'
  )
  local bad
  for bad in "${bad_dumps[@]}"; do
    if assert_dump "$bad" "$acquire_name" "$ref" >/dev/null 2>&1; then
      echo "    FAIL: assert_dump accepted a malformed capture:"
      printf '%s\n' "$bad"
      result=$((result + 1))
    fi
  done

  # The split form: the acquisition carries the selection, while the
  # verification config carries the immutable child the acquisition validated.
  # The stale expectation (the selected tag in both records) and a swap between
  # the two records must both fail, so the two-reference form cannot degrade
  # into "any entry".
  local acquired='localhost:1/project@sha256:0000000000000000000000000000000000000000000000000000000000000000'
  local split=$'native-image-acquire\tlocalhost:1/project:latest\nagent-vm-setup-verify\tlocalhost:1/project@sha256:0000000000000000000000000000000000000000000000000000000000000000'
  if ! assert_dump "$split" "$verify_name" "$ref" "$acquired" >/dev/null 2>&1; then
    echo "    FAIL: assert_dump rejected the split accepted capture"
    result=$((result + 1))
  fi
  for bad in "$good" \
      $'native-image-acquire\tlocalhost:1/project@sha256:0000000000000000000000000000000000000000000000000000000000000000\nagent-vm-setup-verify\tlocalhost:1/project:latest'; do
    if assert_dump "$bad" "$verify_name" "$ref" "$acquired" >/dev/null 2>&1; then
      echo "    FAIL: assert_dump accepted a stale or swapped two-reference capture:"
      printf '%s\n' "$bad"
      result=$((result + 1))
    fi
  done

  # The zero-builder oracle must reject a missing, unreadable and non-empty log,
  # and accept a readable empty one.
  local oracle_log="$probe_dir/builder.log"
  : >"$oracle_log" || result=$((result + 1))
  if ! assert_no_builder_calls "probe-empty" "$oracle_log" >/dev/null 2>&1; then
    echo "    FAIL: assert_no_builder_calls rejected an empty readable log"
    result=$((result + 1))
  fi
  rm -f "$oracle_log" || result=$((result + 1))
  if assert_no_builder_calls "probe-missing" "$oracle_log" >/dev/null 2>&1; then
    echo "    FAIL: assert_no_builder_calls accepted a missing log"
    result=$((result + 1))
  fi
  printf 'docker build\n' >"$oracle_log" || result=$((result + 1))
  if assert_no_builder_calls "probe-nonempty" "$oracle_log" >/dev/null 2>&1; then
    echo "    FAIL: assert_no_builder_calls accepted a non-empty log"
    result=$((result + 1))
  fi
  # Unreadable (skip as root, where the permission check is bypassed).
  if [ "$(id -u)" -ne 0 ]; then
    : >"$oracle_log" || result=$((result + 1))
    chmod 000 "$oracle_log" || result=$((result + 1))
    if assert_no_builder_calls "probe-unreadable" "$oracle_log" >/dev/null 2>&1; then
      echo "    FAIL: assert_no_builder_calls accepted an unreadable log"
      result=$((result + 1))
    fi
    chmod 600 "$oracle_log" || result=$((result + 1))
  fi
  rm -f "$oracle_log" || result=$((result + 1))
  control_report "f acquisition-dump-oracle" "$ctl_before"


  # (g) The #262 registry access-record oracle. A genuine access record counts
  # once; a duplicate telemetry span naming the same path does not; an
  # unrecognized format is a legitimate zero; and a grep observation error
  # (status 2) is a failure, never a zero. Without the last case a matcher that
  # stopped matching would make "warm default makes zero registry reads" pass
  # vacuously.
  ctl_before="$result"
  local access_record telemetry_span oracle_status=0
  access_record='10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] "GET /v2/lib/manifests/tag HTTP/1.1" 200 3 "-" "docker/1"'
  telemetry_span='time="2025-01-01T00:00:00Z" level=info msg="GET /v2/lib/manifests/tag" span=abc'
  assert_eq "access-record oracle counts a real record" "1" \
    "$(upgrade_access_record_count "$access_record")" || result=$((result + 1))
  assert_eq "access-record oracle ignores a telemetry-only span" "0" \
    "$(upgrade_access_record_count "$telemetry_span")" || result=$((result + 1))
  assert_eq "access-record oracle counts a mixed log once" "1" \
    "$(upgrade_access_record_count "$access_record"$'\n'"$telemetry_span")" || result=$((result + 1))
  assert_eq "access-record oracle treats an unmatched format as a legitimate zero" "0" \
    "$(upgrade_access_record_count 'unrecognized log format')" || result=$((result + 1))
  (
    # shellcheck disable=SC2329  # invoked indirectly by upgrade_access_record_count
    grep() { return 2; }
    upgrade_access_record_count "$access_record"
  ) >/dev/null 2>&1 || oracle_status=$?
  assert_eq "access-record oracle propagates a matcher error" "2" "$oracle_status" || result=$((result + 1))

  # (h) #398: the direct-row helpers own their own negative controls.
  #
  control_report "g registry-record-oracle" "$ctl_before"

  # (h1) `direct_state_child` accepts exactly one 12-hex child of the private
  # state root and refuses every other resolution, so the delete target cannot
  # widen from a resolution surprise.
  ctl_before="$result"
  local state_case stub accepted_state
  for state_case in \
    'outside:$CUSTOM_STATE/../escape' \
    'root:$CUSTOM_STATE' \
    'short:$CUSTOM_STATE/abc' \
    'nested:$CUSTOM_STATE/0123456789ab/child' \
    'nonhex:$CUSTOM_STATE/0123456789az'; do
    stub="${state_case#*:}"
    if (
      host_state_dir() { printf '%s' "$stub"; }
      direct_state_child "/proj"
    ) >/dev/null 2>&1; then
      echo "    FAIL: direct_state_child accepted ${state_case%%:*} path $stub"
      result=$((result + 1))
    fi
  done
  if ! accepted_state="$(
    host_state_dir() { printf '%s' "$CUSTOM_STATE/0123456789ab"; }
    direct_state_child "/proj"
  )" || [ "$accepted_state" != "$CUSTOM_STATE/0123456789ab" ]; then
    echo "    FAIL: direct_state_child rejected a valid 12-hex state child"
    result=$((result + 1))
  fi
  control_report "h1 direct-state-child" "$ctl_before"


  # (h2) A failed row keeps its evidence: `rm` must not be called at all. A
  # passed row removes exactly the verified child and its sibling `.secrets`.
  # A fake child of the *real* private state root, created and removed here: the
  # helper resolves through host_state_dir, and nothing global is reassigned in a
  # subshell.
  ctl_before="$result"
  local fake_state="$CUSTOM_STATE/0123456789ab" removals="$probe_dir/direct-removals.txt"
  mkdir -p "$fake_state" "$fake_state.secrets" || result=$((result + 1))
  : >"$removals" || result=$((result + 1))
  if (
    # shellcheck disable=SC2317,SC2329  # stubs invoked indirectly; see the notes
    # on direct_stdout above.
    host_state_dir() { printf '%s' "$CUSTOM_STATE/0123456789ab"; }
    assert_no_catalog_entry() { return 0; }
    rm() { printf '%s\n' "$*" >>"$removals"; }
    direct_cleanup "probe" "/proj" "ref" 1
  ) >/dev/null 2>&1; then
    echo "    FAIL: direct_cleanup reported success for a failed row"
    result=$((result + 1))
  fi
  if [ -s "$removals" ]; then
    echo "    FAIL: direct_cleanup removed a failed row's evidence:"
    cat "$removals"
    result=$((result + 1))
  fi
  if ! (
    # shellcheck disable=SC2317,SC2329  # stubs invoked indirectly
    host_state_dir() { printf '%s' "$CUSTOM_STATE/0123456789ab"; }
    assert_no_catalog_entry() { return 0; }
    rm() { printf '%s\n' "$*" >>"$removals"; }
    direct_cleanup "probe" "/proj" "ref" 0
  ) >/dev/null 2>&1; then
    echo "    FAIL: direct_cleanup failed for a passed row"
    result=$((result + 1))
  fi
  for expected_removal in \
    "-rf $fake_state" \
    "-rf $fake_state.secrets"; do
    if ! grep -qxF -- "$expected_removal" "$removals"; then
      echo "    FAIL: direct_cleanup did not remove exactly $expected_removal"
      cat "$removals"
      result=$((result + 1))
    fi
  done
  rm -rf "$fake_state" "$fake_state.secrets" || result=$((result + 1))
  control_report "h2 cleanup-keeps-failure-evidence" "$ctl_before"


  # (h3) A surviving catalog record fails cleanup and removes nothing: the state
  # is the evidence for the leak, so the status alone is not the observation.
  ctl_before="$result"
  mkdir -p "$fake_state" || result=$((result + 1))
  : >"$removals" || result=$((result + 1))
  if (
    # shellcheck disable=SC2317,SC2329  # stubs invoked indirectly
    host_state_dir() { printf '%s' "$CUSTOM_STATE/0123456789ab"; }
    assert_no_catalog_entry() { return 1; }
    rm() { printf '%s\n' "$*" >>"$removals"; }
    direct_cleanup "probe" "/proj" "ref" 0
  ) >/dev/null 2>&1; then
    echo "    FAIL: direct_cleanup ignored a surviving catalog record"
    result=$((result + 1))
  fi
  if [ -s "$removals" ]; then
    echo "    FAIL: direct_cleanup removed state despite a surviving catalog record:"
    cat "$removals"
    result=$((result + 1))
  fi
  rm -rf "$fake_state" || result=$((result + 1))
  control_report "h3 surviving-catalog" "$ctl_before"


  # (h4) The absence oracle fails on an existing entry and passes on a missing
  # one; only ENOENT counts as evidence.
  ctl_before="$result"
  mkdir -p "$probe_dir/absent-probe" || result=$((result + 1))
  : >"$probe_dir/absent-probe/exists" || result=$((result + 1))
  if assert_state_entries_absent "probe-existing" "$probe_dir/absent-probe" \
    "exists" >/dev/null 2>&1; then
    echo "    FAIL: assert_state_entries_absent accepted an existing entry"
    result=$((result + 1))
  fi
  if ! assert_state_entries_absent "probe-missing" "$probe_dir/absent-probe" \
    "missing" >/dev/null 2>&1; then
    echo "    FAIL: assert_state_entries_absent rejected a missing entry"
    result=$((result + 1))
  fi
  control_report "h4 absence-oracle" "$ctl_before"


  # (h5) The byte-exact stdout oracle rejects a trailing-newline difference that
  # `$(cat …)` would have hidden.
  ctl_before="$result"
  printf '%s' '$HOME' >"$WORK/probe-bytes.stdout" || result=$((result + 1))
  if assert_direct_stdout_bytes "probe-bytes" "probe-bytes" $'$HOME\n' >/dev/null 2>&1; then
    echo "    FAIL: the byte-exact oracle accepted a missing trailing newline"
    result=$((result + 1))
  fi
  if ! assert_direct_stdout_bytes "probe-bytes" "probe-bytes" '$HOME' >/dev/null 2>&1; then
    echo "    FAIL: the byte-exact oracle rejected the exact bytes"
    result=$((result + 1))
  fi
  rm -f "$WORK/probe-bytes.stdout" "$WORK/probe-bytes.expected" || result=$((result + 1))
  control_report "h5 byte-exact-stdout" "$ctl_before"


  # (h6) A missing host-decoy log is a failed observation, not a vacuous zero.
  ctl_before="$result"
  rm -f "$probe_dir/missing-shim.log" || result=$((result + 1))
  if assert_no_host_calls "$probe_dir/missing-shim.log" >/dev/null 2>&1; then
    echo "    FAIL: assert_no_host_calls accepted a missing decoy log"
    result=$((result + 1))
  fi
  : >"$probe_dir/present-shim.log" || result=$((result + 1))
  if ! assert_no_host_calls "$probe_dir/present-shim.log" >/dev/null 2>&1; then
    echo "    FAIL: assert_no_host_calls rejected a readable empty decoy log"
    result=$((result + 1))
  fi
  control_report "h6 missing-decoy-log" "$ctl_before"


  # (h7) #399: the stdin-row helpers and the two live oracles, each against the
  # defect it exists to catch. These run without a VM: a helper that silently
  # stopped observing would otherwise turn a native row green for free.
  ctl_before="$result"
  if [ -e "$probe_dir/absent-stdin" ]; then
    # A precondition that silently skips the control would report it ok without
    # running it, which is the same false green the control exists to prevent.
    echo "    FAIL: h7 probe path already exists; the missing-input control cannot run"
    result=$((result + 1))
  elif capture_custom_direct_input "probe-missing-stdin" "$probe_dir" \
    "$probe_dir/absent-stdin" -- run true >/dev/null 2>&1; then
    echo "    FAIL: the stdin capture accepted a missing input file"
    result=$((result + 1))
  fi
  control_report "h7 missing-stdin-refused" "$ctl_before"


  # (h8) The FIFO writer this shell owns is reaped after stop: its pid is gone.
  # A helper that leaked it would keep a guest's stdin open forever. This is the
  # helper's own stop path; `every possible way a row can end` is not what these
  # controls claim (a signal to the harness while a writer is held is a separate,
  # uncovered path; h16-trap covers the EXIT trap).
  ctl_before="$result"
  local probe_fifo="$WORK/probe-stdin.fifo" writer_pid
  rm -f "$probe_fifo" || result=$((result + 1))
  mkfifo "$probe_fifo" || result=$((result + 1))
  stdin_writer_start "$probe_fifo" "" hold || result=$((result + 1))
  writer_pid="$STDIN_WRITER_PID"
  if [ -z "$writer_pid" ]; then
    echo "    FAIL: stdin_writer_start recorded no pid"
    result=$((result + 1))
  fi
  stdin_writer_stop
  if [ -n "$STDIN_WRITER_PID" ]; then
    echo "    FAIL: stdin_writer_stop left a pid behind"
    result=$((result + 1))
  fi
  if [ -n "$writer_pid" ] && kill -0 "$writer_pid" 2>/dev/null; then
    echo "    FAIL: stdin_writer_stop did not reap the writer"
    kill -KILL "$writer_pid" 2>/dev/null || true
    result=$((result + 1))
  fi
  # A writer mode it does not know is refused, not guessed.
  if stdin_writer_start "$probe_fifo" "" sometimes >/dev/null 2>&1; then
    echo "    FAIL: stdin_writer_start accepted an unknown mode"
    result=$((result + 1))
  fi
  control_report "h8 writer-reaped" "$ctl_before"


  # (h9) wait_for_marker fails on its deadline; it never reports a pass for a
  # file that never gets the marker.
  ctl_before="$result"
  : >"$WORK/probe-marker.log" || result=$((result + 1))
  if wait_for_marker "$WORK/probe-marker.log" 'never-appears' 1 >/dev/null 2>&1; then
    echo "    FAIL: wait_for_marker passed without the marker"
    result=$((result + 1))
  fi
  printf 'the-marker\n' >"$WORK/probe-marker.log" || result=$((result + 1))
  if ! wait_for_marker "$WORK/probe-marker.log" '^the-marker$' 1 >/dev/null 2>&1; then
    echo "    FAIL: wait_for_marker missed a present marker"
    result=$((result + 1))
  fi
  if wait_for_marker "$WORK/probe-marker-absent.log" 'x' 1 >/dev/null 2>&1; then
    echo "    FAIL: wait_for_marker accepted a missing file"
    result=$((result + 1))
  fi
  rm -f "$WORK/probe-marker.log" || result=$((result + 1))
  control_report "h9 marker-deadline" "$ctl_before"


  # (h10) max_rss_kib fails closed (#399 F3): an empty or newline-only file, a
  # non-numeric line, an **unterminated** non-numeric final line (the old
  # `while read` skipped it and returned success), and a file whose only line
  # has internal whitespace (`tr -d '[:space:]'` used to turn `12 34` into
  # `1234`). Real samples, including an unterminated decimal one, still parse.
  ctl_before="$result"
  : >"$WORK/probe-rss-empty" || result=$((result + 1))
  if max_rss_kib "$WORK/probe-rss-empty" >/dev/null 2>&1; then
    echo "    FAIL: max_rss_kib accepted an empty sample file"
    result=$((result + 1))
  fi
  printf '\n\n' >"$WORK/probe-rss-blank" || result=$((result + 1))
  if max_rss_kib "$WORK/probe-rss-blank" >/dev/null 2>&1; then
    echo "    FAIL: max_rss_kib accepted a blank sample file (no validated sample)"
    result=$((result + 1))
  fi
  printf '1200\nnot-a-number\n' >"$WORK/probe-rss-garbage" || result=$((result + 1))
  if max_rss_kib "$WORK/probe-rss-garbage" >/dev/null 2>&1; then
    echo "    FAIL: max_rss_kib accepted a non-numeric sample"
    result=$((result + 1))
  fi
  printf '{"install": {"prefix": "/x"}}' >"$WORK/probe-rss-json" || result=$((result + 1))
  if max_rss_kib "$WORK/probe-rss-json" >/dev/null 2>&1; then
    echo "    FAIL: max_rss_kib accepted an unterminated non-numeric line as a sample"
    result=$((result + 1))
  fi
  printf '  12 34' >"$WORK/probe-rss-internal" || result=$((result + 1))
  if max_rss_kib "$WORK/probe-rss-internal" >/dev/null 2>&1; then
    echo "    FAIL: max_rss_kib accepted internal whitespace as a sample (12 34 -> 1234)"
    result=$((result + 1))
  fi
  printf '  12 34\n' >"$WORK/probe-rss-internal-nl" || result=$((result + 1))
  if max_rss_kib "$WORK/probe-rss-internal-nl" >/dev/null 2>&1; then
    echo "    FAIL: max_rss_kib accepted a terminated line with internal whitespace"
    result=$((result + 1))
  fi
  printf '1024\n3072\n2048\n' >"$WORK/probe-rss" || result=$((result + 1))
  assert_eq "max_rss_kib reports the largest sample" "3072" \
    "$(max_rss_kib "$WORK/probe-rss")" || result=$((result + 1))
  printf '  1024 \n\t3072\n 2048' >"$WORK/probe-rss-padded" || result=$((result + 1))
  assert_eq "max_rss_kib trims only surrounding padding and reads an unterminated final line" \
    "3072" "$(max_rss_kib "$WORK/probe-rss-padded")" || result=$((result + 1))
  rm -f "$WORK/probe-rss-empty" "$WORK/probe-rss-blank" "$WORK/probe-rss-garbage" \
    "$WORK/probe-rss-json" "$WORK/probe-rss-internal" "$WORK/probe-rss-internal-nl" \
    "$WORK/probe-rss" "$WORK/probe-rss-padded" || result=$((result + 1))
  control_report "h10 rss-fail-closed" "$ctl_before"


  # (h11) The live-handshake oracle: a launcher stand-in that prints every
  # marker only at exit must fail the first deadline. This is the
  # collect-until-exit defect (#399 B5) at the harness level.
  ctl_before="$result"
  (
    trap - EXIT
    sleep 2
    printf 'out-ready\nout-got:ping\nout-eof\n'
  ) >"$WORK/probe-collect.stdout" 2>/dev/null &
  local collect_pid=$!
  if wait_for_marker "$WORK/probe-collect.stdout" '^out-ready$' 1 >/dev/null 2>&1; then
    echo "    FAIL: the live-handshake oracle passed a collect-until-exit stream"
    result=$((result + 1))
  fi
  wait "$collect_pid" 2>/dev/null || true
  rm -f "$WORK/probe-collect.stdout" || result=$((result + 1))
  control_report "h11 collect-until-exit" "$ctl_before"


  # (h12) The concurrent-streams oracle (#399 R2-B1). A mock launcher emits the
  # prescribed guest bytes plus the real `==> Running …` notice: that must pass.
  # Two negative controls must fail: guest stderr bytes misrouted to stdout, and
  # a dropped guest chunk. The oracle counts 0xF1 (0xF1 is the stderr byte) on
  # stderr and compares stdout byte for byte, so ASCII notices cannot be counted
  # as guest output.
  ctl_before="$result"
  local oracle_bytes=64 mock_out="$WORK/probe-concurrent.stdout" mock_err="$WORK/probe-concurrent.err"
  LC_ALL=C tr '\0' '\351' < <(head -c "$oracle_bytes" /dev/zero) \
    >"$WORK/probe-concurrent.expected" || result=$((result + 1))
  # The mock stands in for the launcher: guest bytes on their own channel, the
  # mandatory `==> Running …` notice on stderr.
  (
    head -c "$oracle_bytes" /dev/zero | LC_ALL=C tr '\0' '\351'
  ) >"$mock_out" 2>/dev/null || result=$((result + 1))
  (
    printf '==> Running cat in sandbox (no TTY; streaming output)\n' >&2
    head -c "$oracle_bytes" /dev/zero | LC_ALL=C tr '\0' '\361' >&2
  ) 2>"$mock_err" >/dev/null || result=$((result + 1))
  if ! assert_concurrent_stdout "probe-concurrent mock" \
    "$WORK/probe-concurrent.expected" "$mock_out" >/dev/null 2>&1; then
    echo "    FAIL: the concurrent oracle rejected the prescribed guest stdout"
    result=$((result + 1))
  fi
  if ! assert_concurrent_stderr "probe-concurrent mock" "$mock_err" "$oracle_bytes" \
    >/dev/null 2>&1; then
    echo "    FAIL: the concurrent oracle rejected the prescribed guest stderr"
    result=$((result + 1))
  fi
  control_report "h12 concurrent-oracle" "$ctl_before"

  # (i) guest stderr bytes misrouted to stdout.
  ctl_before="$result"
  cp "$WORK/probe-concurrent.expected" "$WORK/probe-misrouted.expected" || result=$((result + 1))
  head -c "$oracle_bytes" /dev/zero | LC_ALL=C tr '\0' '\361' \
    >>"$WORK/probe-misrouted.expected" || result=$((result + 1))
  if assert_concurrent_stdout "probe-misrouted" "$WORK/probe-concurrent.expected" \
    "$WORK/probe-misrouted.expected" >/dev/null 2>&1; then
    echo "    FAIL: the concurrent oracle accepted stderr bytes on stdout"
    result=$((result + 1))
  fi
  control_report "h12-i misrouted-stderr" "$ctl_before"

  # (ii) a dropped guest chunk: stderr one byte short.
  ctl_before="$result"
  head -c $((oracle_bytes - 1)) /dev/zero | LC_ALL=C tr '\0' '\361' \
    >"$WORK/probe-dropped.err" || result=$((result + 1))
  if assert_concurrent_stderr "probe-dropped" "$WORK/probe-dropped.err" "$oracle_bytes" \
    >/dev/null 2>&1; then
    echo "    FAIL: the concurrent oracle accepted a dropped guest chunk"
    result=$((result + 1))
  fi
  control_report "h12-ii dropped-chunk" "$ctl_before"

  # (iii) #399 N1: one expected 0xF1 guest byte moved **into** a `==>` notice,
  # keeping the total 0xF1 count identical. The byte checks all pass (the count
  # is right, no 0xE9, no other non-ASCII after removing 0xF1), so only the
  # expected-notice oracle can reject it. The old control inserted 0xE9, which
  # the earlier no-stdout-byte check rejected first: deleting the notice check
  # left it green.
  ctl_before="$result"
  {
    printf '==> Running cat in sandbox (no TTY; streaming output)\361\n' >&2
    head -c $((oracle_bytes - 1)) /dev/zero | LC_ALL=C tr '\0' '\361' >&2
  } 2>"$WORK/probe-notice.err" >/dev/null || result=$((result + 1))
  if assert_concurrent_stderr "probe-notice" "$WORK/probe-notice.err" "$oracle_bytes" \
    >/dev/null 2>&1; then
    echo "    FAIL: the concurrent oracle accepted an expected guest byte inside a notice"
    result=$((result + 1))
  fi
  control_report "h12-iii guest-byte-in-notice" "$ctl_before"

  # (iv) An unexpected printable-ASCII notice: every byte check passes, so this
  # is the control that proves the notice **set** is enforced rather than "any
  # printable `==>` text".
  ctl_before="$result"
  {
    printf '==> Unexpected diagnostic\n' >&2
    head -c "$oracle_bytes" /dev/zero | LC_ALL=C tr '\0' '\361' >&2
  } 2>"$WORK/probe-unexpected.err" >/dev/null || result=$((result + 1))
  if assert_concurrent_stderr "probe-unexpected" "$WORK/probe-unexpected.err" "$oracle_bytes" \
    >/dev/null 2>&1; then
    echo "    FAIL: the concurrent oracle accepted an unexpected launcher notice"
    result=$((result + 1))
  fi
  rm -f "$WORK/probe-concurrent.stdout" "$WORK/probe-concurrent.err" \
    "$WORK/probe-concurrent.expected" "$WORK/probe-misrouted.expected" \
    "$WORK/probe-dropped.err" "$WORK/probe-notice.err" "$WORK/probe-unexpected.err" \
    "$WORK/probe-notice-field.err" "$WORK/probe-notice-final.err" || result=$((result + 1))
  control_report "h12-iv unexpected-notice" "$ctl_before"

  # (v) #399 R2-2: the guest byte hides in a **wildcard field** of a notice the
  # vocabulary accepts. The byte counts all stay right, so only a rule that is
  # independent of the vocabulary can reject it. The control proves both halves:
  # the vocabulary accepts this exact line, and the byte rule (therefore the
  # full oracle) rejects it.
  ctl_before="$result"
  local notice_field_line
  notice_field_line="==> GitHub repo scope: owner/$(printf '\361')repo"
  if ! notice_vocabulary_matches "$notice_field_line"; then
    echo "    FAIL: the notice vocabulary no longer accepts the wildcard field this control needs"
    result=$((result + 1))
  fi
  if notice_bytes_clean "$notice_field_line"; then
    echo "    FAIL: the notice byte rule accepted a guest byte in a wildcard field"
    result=$((result + 1))
  fi
  {
    printf '%s\n' "$notice_field_line" >&2
    head -c $((oracle_bytes - 1)) /dev/zero | LC_ALL=C tr '\0' '\361' >&2
  } 2>"$WORK/probe-notice-field.err" >/dev/null || result=$((result + 1))
  if assert_concurrent_stderr "probe-notice-field" "$WORK/probe-notice-field.err" "$oracle_bytes" \
    >/dev/null 2>&1; then
    echo "    FAIL: the concurrent oracle accepted a guest byte in a notice wildcard field"
    result=$((result + 1))
  fi
  control_report "h12-v guest-byte-in-notice-field" "$ctl_before"

  # (vi) #399 R2-2: the same injection in an **unterminated final line**. The
  # old `while read` loop dropped it, so the byte was never examined at all.
  ctl_before="$result"
  {
    head -c $((oracle_bytes - 1)) /dev/zero | LC_ALL=C tr '\0' '\361' >&2
    printf '\n' >&2
    printf '==> Running c\361at in sandbox (no TTY; streaming output)' >&2
  } 2>"$WORK/probe-notice-final.err" >/dev/null || result=$((result + 1))
  if assert_concurrent_stderr "probe-notice-final" "$WORK/probe-notice-final.err" "$oracle_bytes" \
    >/dev/null 2>&1; then
    echo "    FAIL: the concurrent oracle accepted a guest byte in an unterminated final notice line"
    result=$((result + 1))
  fi
  control_report "h12-vi guest-byte-in-unterminated-notice" "$ctl_before"

  # (vii) A valid notice line with the allowed punctuation still passes the byte
  # rule: the new check rejects guest bytes without rejecting the launcher's own
  # vocabulary. The **whole** oracle is exercised too — the inner byte rule alone
  # proved nothing about the stream-wide "no other non-ASCII byte" check, which
  # used to reject these very sequences before reaching the notice rule (#399
  # review 3, observation 3).
  ctl_before="$result"
  if ! notice_bytes_clean "==>   $(printf '\342\200\246') and 3 more not shown"; then
    echo "    FAIL: the notice byte rule rejected the launcher's own ellipsis notice"
    result=$((result + 1))
  fi
  if ! notice_bytes_clean "==> TLS interception: ports 443 $(printf '\342\200\224') global"; then
    echo "    FAIL: the notice byte rule rejected the launcher's own em-dash notice"
    result=$((result + 1))
  fi
  # A full stderr stream: exactly `oracle_bytes` guest bytes plus the two
  # punctuation notices the launcher really emits. It must pass end to end.
  {
    printf '==>   %s and 3 more not shown\n' "$(printf '\342\200\246')" >&2
    printf '==> TLS interception: ports 443 %s global\n' "$(printf '\342\200\224')" >&2
    head -c "$oracle_bytes" /dev/zero | LC_ALL=C tr '\0' '\361' >&2
  } 2>"$WORK/probe-punct.err" >/dev/null || result=$((result + 1))
  if ! assert_concurrent_stderr "probe-punct" "$WORK/probe-punct.err" "$oracle_bytes" \
    >/dev/null 2>&1; then
    echo "    FAIL: the full concurrent oracle rejected a valid punctuation notice"
    assert_concurrent_stderr "probe-punct" "$WORK/probe-punct.err" "$oracle_bytes" || true
    result=$((result + 1))
  fi
  # ...and the allowance is notice-scoped: the same em dash on a line that is
  # not an accepted notice is still a stray byte.
  {
    printf 'guest %s output\n' "$(printf '\342\200\224')" >&2
    head -c "$oracle_bytes" /dev/zero | LC_ALL=C tr '\0' '\361' >&2
  } 2>"$WORK/probe-punct-stray.err" >/dev/null || result=$((result + 1))
  if assert_concurrent_stderr "probe-punct-stray" "$WORK/probe-punct-stray.err" \
    "$oracle_bytes" >/dev/null 2>&1; then
    echo "    FAIL: the concurrent oracle accepted notice punctuation on an unvetted line"
    result=$((result + 1))
  fi
  rm -f "$WORK/probe-punct.err" "$WORK/probe-punct-stray.err" || result=$((result + 1))
  control_report "h12-vii notice-punctuation-allowed" "$ctl_before"


  # (h13) #399 F1: an async capture records the observation outcome and the
  # launcher status independently. A mock that emits the exact expected bytes
  # and exits 7 must be recorded as 7 and must fail a status-0 assertion. The
  # old wrapper wrote the observation's `$?` (0) into `.status`, so this shape
  # passed as status 0.
  ctl_before="$result"
  local f1_status=0 f1_capture="probe-async-status"
  (
    trap - EXIT
    stdin_capture() {
      printf 'hello' >"$WORK/$1.stdout"
      CAPTURE_STATUS=7
      return 0
    }
    stdin_capture_async "$f1_capture" "$probe_dir" /dev/null run cat || exit 20
    wait_capture_bounded "$f1_capture" || exit 21
    [ "$(cat "$WORK/$f1_capture.observed" 2>/dev/null)" = 0 ] || exit 22
    [ "$(cat "$WORK/$f1_capture.status" 2>/dev/null)" = 7 ] || exit 23
    if assert_async_launcher_status "probe" "$f1_capture" 0 >/dev/null 2>&1; then exit 24; fi
    assert_async_launcher_status "probe" "$f1_capture" 7 >/dev/null 2>&1 || exit 25
    # An observation failure fails even when the launcher status is 0.
    stdin_capture() {
      printf 'hello' >"$WORK/$1.stdout"
      CAPTURE_STATUS=0
      return 1
    }
    stdin_capture_async "${f1_capture}-obs" "$probe_dir" /dev/null run cat || exit 26
    wait_capture_bounded "${f1_capture}-obs" || exit 27
    if assert_async_launcher_status "probe" "${f1_capture}-obs" 0 >/dev/null 2>&1; then exit 28; fi
    exit 0
  )
  f1_status=$?
  if [ "$f1_status" -ne 0 ]; then
    echo "    FAIL: async status control ($f1_status): observation and launcher status are not independent"
    result=$((result + 1))
  fi
  rm -f "$WORK/$f1_capture.observed" "$WORK/$f1_capture.status" \
    "$WORK/$f1_capture.stdout" "$WORK/$f1_capture.observed.observed" \
    "$WORK/$f1_capture.observed.status" "$WORK/$f1_capture.observed.stdout" || result=$((result + 1))
  control_report "h13 async-status-independence" "$ctl_before"


  # (h14) #399 F2: a missed readiness deadline aborts the handshake -- closes
  # the writer, reaps the capture -- and returns within a bound, instead of
  # opening the FIFO for another synchronous write that can block forever.
  ctl_before="$result"
  local f2_status=0 f2_elapsed=0
  (
    trap - EXIT
    local fifo="$WORK/probe-abort.fifo" started writer
    rm -f "$fifo"
    mkfifo "$fifo" || exit 40
    stdin_writer_start "$fifo" "" hold || exit 41
    writer="$STDIN_WRITER_PID"
    stdin_capture() { sleep 0.2; return 0; }
    stdin_capture_async "probe-abort" "$probe_dir" "$fifo" run cat || exit 42
    if wait_for_marker "$WORK/probe-abort.stdout" '^never$' 1 >/dev/null 2>&1; then exit 43; fi
    started="$(date +%s)"
    abort_live_capture "probe-abort" || exit 44
    f2_elapsed=$(( $(date +%s) - started ))
    printf '%s' "$f2_elapsed" >"$WORK/probe-abort.elapsed" || exit 49
    [ "$f2_elapsed" -le 10 ] || exit 45
    kill -0 "$writer" 2>/dev/null && exit 46
    [ -z "$STDIN_WRITER_PID" ] || exit 47
    [ -z "$STDIN_CAPTURE_PID" ] || exit 48
    exit 0
  )
  f2_status=$?
  f2_elapsed="$(cat "$WORK/probe-abort.elapsed" 2>/dev/null || echo unknown)"
  if [ "$f2_status" -ne 0 ]; then
    echo "    FAIL: readiness-abort control ($f2_status): a missed marker did not abort bounded"
    result=$((result + 1))
  fi
  case "$f2_elapsed" in
  '' | *[!0-9]*)
    echo "    FAIL: readiness-abort control recorded no elapsed time"
    result=$((result + 1))
    ;;
  *)
    if [ "$f2_elapsed" -gt 10 ]; then
      echo "    FAIL: readiness-abort control took ${f2_elapsed}s (limit 10)"
      result=$((result + 1))
    else
      echo "    control h14: readiness-abort elapsed=${f2_elapsed}s (limit 10)"
    fi
    ;;
  esac
  control_report "h14 readiness-abort-bounded" "$ctl_before"


  # (h15) #399 F2: a producer with no reader at all is bounded too, so a row
  # cannot hang in the FIFO open after the launcher died.
  ctl_before="$result"
  local f3_status=0 f3_elapsed=0
  (
    trap - EXIT
    local fifo="$WORK/probe-producer.fifo" started
    rm -f "$fifo"
    mkfifo "$fifo" || exit 50
    STDIN_WRITER_TIMEOUT=1
    started="$(date +%s)"
    if stdin_writer_write_bounded "$fifo" string x >/dev/null 2>&1; then exit 51; fi
    f3_elapsed=$(( $(date +%s) - started ))
    printf '%s' "$f3_elapsed" >"$WORK/probe-producer.elapsed" || exit 53
    [ "$f3_elapsed" -le 5 ] || exit 52
    exit 0
  )
  f3_status=$?
  f3_elapsed="$(cat "$WORK/probe-producer.elapsed" 2>/dev/null || echo unknown)"
  if [ "$f3_status" -ne 0 ]; then
    echo "    FAIL: bounded-producer control ($f3_status): a reader-less FIFO write was not bounded"
    result=$((result + 1))
  fi
  echo "    control h15: reader-less producer returned in ${f3_elapsed}s (limit 5)"
  control_report "h15 producer-bounded" "$ctl_before"


  # (h16) #399 F2: the EXIT-trap cleanup helper reaps a writer a failed row left
  # behind. cleanup_work calls this helper on the run's own shell path.
  ctl_before="$result"
  local f4_status=0
  (
    trap - EXIT
    local fifo="$WORK/probe-cleanup.fifo" writer
    rm -f "$fifo"
    mkfifo "$fifo" || exit 60
    stdin_writer_start "$fifo" "" hold || exit 61
    writer="$STDIN_WRITER_PID"
    cleanup_row_helpers
    kill -0 "$writer" 2>/dev/null && exit 62
    [ -z "$STDIN_WRITER_PID" ] || exit 63
    exit 0
  )
  f4_status=$?
  if [ "$f4_status" -ne 0 ]; then
    echo "    FAIL: cleanup-helper control ($f4_status): a leftover writer was not reaped"
    result=$((result + 1))
  fi
  rm -f "$WORK/probe-abort.fifo" "$WORK/probe-abort.observed" "$WORK/probe-abort.status" \
    "$WORK/probe-abort.out" "$WORK/probe-abort.stdout" "$WORK/probe-abort.elapsed" \
    "$WORK/probe-producer.fifo" "$WORK/probe-producer.elapsed" \
    "$WORK/probe-cleanup.fifo" || result=$((result + 1))
  control_report "h16 exit-cleanup-reaps-writer" "$ctl_before"


  # (h16-trap) #399 R2-3: the *real* EXIT trap, not only the helper. A child
  # shell installs the production `cleanup_work`, leaves a held FIFO writer and a
  # running RSS sampler behind, and exits 7. The trap must reap both helpers and
  # keep the failure status. (The earlier control called cleanup_row_helpers
  # directly, so deleting the call from the trap left it green.)
  ctl_before="$result"
  local f5_status=0 trap_work="$WORK/probe-trap-work" trap_defs helper helper_pid sleeper_pid
  local sleeper_waited=0
  rm -rf "$trap_work" || result=$((result + 1))
  mkdir -p "$trap_work" || result=$((result + 1))
  trap_defs="$(declare -f cleanup_work cleanup_row_helpers stdin_writer_stop \
    stdin_producer_stop stdin_capture_stop rss_sampler_stop stdin_writer_start \
    rss_sample_until_exit)"
  {
    printf '%s\n' "$trap_defs"
    cat <<'CHILD'
set -u
# The production globals the reapers read; the harness initialises them at the
# top level, so the child must too (set -u otherwise aborts the trap itself).
STDIN_CAPTURE_PID=""
STDIN_PRODUCER_PID=""
STDIN_RSS_PID=""
trap cleanup_work EXIT
fifo="$WORK/w.fifo"
mkfifo "$fifo" || exit 90
stdin_writer_start "$fifo" "" hold || exit 91
printf "%s" "$STDIN_WRITER_PID" >"$WORK/writer.pid"
( exec /bin/sleep 30 ) &
sleeper=$!
printf "%s" "$sleeper" >"$WORK/sleeper.pid"
rss_sample_until_exit "$sleeper" "$WORK/long.rss" "$WORK/long.rss.meta"
printf "%s" "$STDIN_RSS_PID" >"$WORK/sampler.pid"
exit 7
CHILD
  } >"$trap_work/child.sh" || result=$((result + 1))
  if (
    WORK="$trap_work" OWNED_BUILDER="" STDIN_WRITER_TIMEOUT=30 RSS_SAMPLE_INTERVAL=0.05 \
      bash "$trap_work/child.sh" >"$WORK/probe-trap.out" 2>&1
  ); then
    f5_status=0
  else
    f5_status=$?
  fi
  if [ "$f5_status" -ne 7 ]; then
    echo "    FAIL: EXIT-trap control: the child exited $f5_status, not 7 (trap changed the status)"
    sed -n '1,20p' "$WORK/probe-trap.out" || true
    result=$((result + 1))
  fi
  # A positive receipt that the real trap code ran: cleanup_work reports the
  # preserved work dir on a non-zero exit.
  if ! grep -q 'preserving .*probe-trap-work' "$WORK/probe-trap.out" 2>/dev/null; then
    echo "    FAIL: EXIT-trap control: cleanup_work did not report its own run"
    sed -n '1,20p' "$WORK/probe-trap.out" || true
    result=$((result + 1))
  fi
  for helper in writer sampler; do
    helper_pid="$(cat "$trap_work/$helper.pid" 2>/dev/null || true)"
    case "$helper_pid" in
    '' | *[!0-9]*)
      echo "    FAIL: EXIT-trap control: the child recorded no $helper pid"
      result=$((result + 1))
      ;;
    *)
      if kill -0 "$helper_pid" 2>/dev/null; then
        echo "    FAIL: EXIT-trap control: cleanup_work left the $helper ($helper_pid) running"
        kill -KILL "$helper_pid" 2>/dev/null || true
        result=$((result + 1))
      fi
      ;;
    esac
  done
  # The passive sleeper is the sampler's *target*: `cleanup_work` must not reap
  # it (it is not one of the row's helpers), so the control that started it must
  # stop it -- on success and on every failure above (#399 review 3,
  # observation 2). It must still be alive here, which is the receipt that this
  # control really had a target to leak.
  sleeper_pid="$(cat "$trap_work/sleeper.pid" 2>/dev/null || true)"
  case "$sleeper_pid" in
  '' | *[!0-9]*)
    echo "    FAIL: EXIT-trap control: the child recorded no sleeper pid"
    result=$((result + 1))
    ;;
  *)
    if kill -0 "$sleeper_pid" 2>/dev/null; then
      echo "    control h16-trap: stopping the passive sampler target $sleeper_pid"
    else
      echo "    FAIL: EXIT-trap control: the passive sampler target $sleeper_pid was already gone"
      result=$((result + 1))
    fi
    kill -KILL "$sleeper_pid" 2>/dev/null || true
    # It is reparented to init by now, so there is nothing to `wait` for; the
    # absence check is bounded instead of instantaneous.
    while [ "$sleeper_waited" -lt 50 ]; do
      kill -0 "$sleeper_pid" 2>/dev/null || break
      sleep 0.1
      sleeper_waited=$((sleeper_waited + 1))
    done
    if kill -0 "$sleeper_pid" 2>/dev/null; then
      echo "    FAIL: EXIT-trap control: the passive sampler target $sleeper_pid survived the control's own stop"
      result=$((result + 1))
    fi
    ;;
  esac
  rm -rf "$trap_work" || result=$((result + 1))
  control_report "h16-trap real-exit-trap-reaps-helpers" "$ctl_before"


  # (h17) #399 R2-1: the sampler measures the process the launch receipt names,
  # not the `/usr/bin/time` wrapper the job was started under. A `sleep` stands
  # in for the launcher; the receipt comes from the same wrapper the row uses.
  # The sampled comm must be `/bin/sleep` while the job's comm is
  # `/usr/bin/time` and the sampled PID differs from the job PID.
  ctl_before="$result"
  local rss_id="$WORK/probe-rss-identity" rss_job rss_sampled rss_comm rss_job_comm
  ensure_launch_wrapper || result=$((result + 1))
  # Stale files go before the child, never inside the sampler (#399 R3-1).
  reset_launcher_rss_files "$rss_id.rss" || result=$((result + 1))
  ( cd "$WORK" || exit 1
    exec /usr/bin/time -l -o "$rss_id.time" \
      "$LAUNCH_WRAPPER" "$rss_id.rss.receipt" /bin/sleep 1 ) &
  rss_job=$!
  if ! sample_launcher_rss "$rss_job" "$rss_id.rss" /bin/sleep; then
    echo "    FAIL: the launcher-RSS sampler could not bind to the receipt's PID"
    result=$((result + 1))
  fi
  wait "$rss_job" 2>/dev/null || true
  rss_sampler_stop
  if ! assert_launcher_rss_identity "$rss_id.rss" "probe-rss-identity"; then
    result=$((result + 1))
  fi
  rss_sampled="$(sed -n 's/^sampled_pid=//p' "$rss_id.rss.meta" 2>/dev/null)"
  rss_job_comm="$(sed -n 's/^launch_job_comm=//p' "$rss_id.rss.meta" 2>/dev/null)"
  if [ "$rss_job_comm" != /usr/bin/time ]; then
    echo "    FAIL: the identity control did not run under a /usr/bin/time wrapper (job comm '$rss_job_comm')"
    result=$((result + 1))
  fi
  if [ -z "$rss_sampled" ] || [ "$rss_sampled" = "$rss_job" ]; then
    echo "    FAIL: the identity control sampled the job PID '$rss_job' instead of the launcher"
    result=$((result + 1))
  fi
  echo "    control h17: sampled_pid=$rss_sampled sampled_comm=$(sed -n 's/^sampled_comm=//p' "$rss_id.rss.meta" 2>/dev/null) job_pid=$rss_job job_comm=$rss_job_comm"
  # The receipt must carry the comm the sampler *observed*, equal to the
  # expected launcher's (#399 review 3, observation 1).
  rss_comm="$(sed -n 's/^sampled_comm=//p' "$rss_id.rss.meta" 2>/dev/null)"
  if [ -z "$rss_comm" ]; then
    echo "    FAIL: the identity control's receipt records no observed sampled_comm"
    result=$((result + 1))
  elif [ "$rss_comm" != /bin/sleep ]; then
    echo "    FAIL: the identity control observed comm '$rss_comm', not /bin/sleep"
    result=$((result + 1))
  fi
  rm -f "$rss_id.rss" "$rss_id.rss.meta" "$rss_id.rss.receipt" "$rss_id.time" || result=$((result + 1))
  control_report "h17 launcher-rss-identity" "$ctl_before"


  # (h18) #399 R2-1: the oracle is proven **sensitive** against a known
  # whole-stream-buffering stand-in that keeps ~256 MiB live, using the same
  # sampler, parser and criterion as the `large` row. A streaming stand-in with
  # the same input must pass, so the control also proves the criterion is not
  # simply failing everything.
  ctl_before="$result"
  local buf_base="$WORK/probe-buffer-base.rss" buf_meas="$WORK/probe-buffer-meas.rss"
  local stream_base="$WORK/probe-stream-base.rss" stream_meas="$WORK/probe-stream-meas.rss"
  local buf_base_kib buf_meas_kib stream_base_kib stream_meas_kib buf_growth stream_growth
  cat >"$WORK/probe-rss-standin.py" <<'STANDIN' || result=$((result + 1))
import sys, time

mode, limit = sys.argv[1], int(sys.argv[2])
time.sleep(0.3)  # let the interpreter reach steady state before anything is read
if mode == "buffer":
    data = sys.stdin.buffer.read(limit)
    time.sleep(3)  # keep the whole input live so the sampler must see it
    sys.stderr.write("buffered=%d\n" % len(data))
else:
    total = 0
    while True:
        chunk = sys.stdin.buffer.read(1048576)
        if not chunk:
            break
        total += len(chunk)
        time.sleep(0.01)  # a real transfer takes real time
    sys.stderr.write("streamed=%d\n" % total)
STANDIN
  # The stand-in must be measured as the interpreter, never as the subshell that
  # is about to `exec` it. The old shape sampled `$!` at once, so a `ps` landing
  # before the `exec` recorded a bash footprint, the sampler stopped with
  # `sampling_mismatch=sampled comm changed …`, and the criterion summed the one
  # tiny sample and never consulted the mismatch — which is how a whole-stream
  # buffer could be "accepted" on a bash-sized number (#399 verification 4,
  # h18). Wait (bounded) for the interpreter's comm to *hold still*, hand that
  # comm to the sampler so every sample is checked against it, and assert the
  # receipt before any number is used.
  probe_rss_standin() { # mode bytes out
    local mode="$1" bytes="$2" out="$3" standin host_comm expected current
    local steps waited=0 streak=0 observed mismatch samples
    host_comm="$(ps -p $$ -o comm= 2>/dev/null)"
    head -c "$bytes" /dev/zero |
      ( exec python3 "$WORK/probe-rss-standin.py" "$mode" "$bytes" ) >/dev/null 2>&1 &
    standin=$!
    steps=$((RSS_RECEIPT_WAIT_SECONDS * 50))
    expected=""
    while [ "$waited" -lt "$steps" ]; do
      current="$(ps -p "$standin" -o comm= 2>/dev/null)"
      if [ "$current" = "$expected" ] && [ -n "$expected" ]; then
        streak=$((streak + 1))
      else
        # A first match is not yet an identity: the interpreter can re-exec
        # itself once at start-up (Homebrew's `python3` becomes the
        # Python.app binary), so require five unchanged readings.
        expected=""
        streak=0
        if [ -n "$current" ] && [ "$current" != "$host_comm" ]; then
          case "$current" in
          *[Pp]ython*) expected="$current" ;;
          esac
        fi
      fi
      [ "$streak" -ge 5 ] && break
      sleep 0.02
      waited=$((waited + 1))
    done
    if [ "$streak" -lt 5 ]; then
      if kill -0 "$standin" 2>/dev/null; then
        echo "    FAIL: control h18 ($mode ${bytes}B): the RSS stand-in PID $standin never settled on the python interpreter (last comm '$current', host shell comm '$host_comm')"
      else
        echo "    FAIL: control h18 ($mode ${bytes}B): the RSS stand-in PID $standin exited before it could be sampled"
      fi
      kill -KILL "$standin" 2>/dev/null || true
      wait "$standin" 2>/dev/null || true
      return 1
    fi
    rss_sample_until_exit "$standin" "$out" "$out.meta" "$expected"
    wait "$standin" 2>/dev/null || true
    rss_sampler_stop
    observed="$(sed -n 's/^sampled_comm=//p' "$out.meta" 2>/dev/null)"
    mismatch="$(sed -n 's/^sampling_mismatch=//p' "$out.meta" 2>/dev/null)"
    samples="$(sed -n 's/^samples=//p' "$out.meta" 2>/dev/null)"
    if [ "$observed" != "$expected" ]; then
      echo "    FAIL: control h18 ($mode ${bytes}B): the sampler observed comm '$observed', not the stand-in '$expected'"
      return 1
    fi
    if [ -n "$mismatch" ]; then
      echo "    FAIL: control h18 ($mode ${bytes}B): the sampler rejected its own samples: $mismatch"
      return 1
    fi
    # A numeric count only: the 1 MiB streaming stand-in lives for ~0.3 s, so a
    # minimum here would be its own load-sensitive failure. The samples are
    # validated by `max_rss_kib`, which fails on none.
    case "$samples" in
    '' | *[!0-9]*)
      echo "    FAIL: control h18 ($mode ${bytes}B): the sampler recorded no sample count ('$samples')"
      return 1
      ;;
    esac
  }
  probe_rss_standin buffer 1048576 "$buf_base" || result=$((result + 1))
  probe_rss_standin buffer 268435456 "$buf_meas" || result=$((result + 1))
  if ! buf_base_kib="$(max_rss_kib "$buf_base")"; then
    result=$((result + 1))
    buf_base_kib=invalid
  fi
  if ! buf_meas_kib="$(max_rss_kib "$buf_meas")"; then
    result=$((result + 1))
    buf_meas_kib=invalid
  fi
  if [ "$buf_base_kib" != invalid ] && [ "$buf_meas_kib" != invalid ]; then
    if buf_growth="$(rss_growth_verdict "$buf_base_kib" "$buf_meas_kib")"; then
      echo "    FAIL: the memory criterion accepted a whole-stream buffer (baseline=${buf_base_kib}KiB measured=${buf_meas_kib}KiB growth=${buf_growth}KiB, limit=$RSS_GROWTH_LIMIT_KIB)"
      result=$((result + 1))
    else
      echo "    control h18: whole-stream buffer baseline=${buf_base_kib}KiB measured=${buf_meas_kib}KiB growth=${buf_growth}KiB >= limit $RSS_GROWTH_LIMIT_KIB (rejected as required)"
    fi
  fi
  probe_rss_standin stream 1048576 "$stream_base" || result=$((result + 1))
  probe_rss_standin stream 268435456 "$stream_meas" || result=$((result + 1))
  if ! stream_base_kib="$(max_rss_kib "$stream_base")"; then
    result=$((result + 1))
    stream_base_kib=invalid
  fi
  if ! stream_meas_kib="$(max_rss_kib "$stream_meas")"; then
    result=$((result + 1))
    stream_meas_kib=invalid
  fi
  if [ "$stream_base_kib" != invalid ] && [ "$stream_meas_kib" != invalid ]; then
    if stream_growth="$(rss_growth_verdict "$stream_base_kib" "$stream_meas_kib")"; then
      echo "    control h18: streaming stand-in baseline=${stream_base_kib}KiB measured=${stream_meas_kib}KiB growth=${stream_growth}KiB < limit $RSS_GROWTH_LIMIT_KIB (accepted)"
    else
      echo "    FAIL: the memory criterion rejected a streaming stand-in (baseline=${stream_base_kib}KiB measured=${stream_meas_kib}KiB growth=${stream_growth}KiB)"
      result=$((result + 1))
    fi
  fi
  rm -f "$buf_base" "$buf_base.meta" "$buf_meas" "$buf_meas.meta" \
    "$stream_base" "$stream_base.meta" "$stream_meas" "$stream_meas.meta" \
    "$WORK/probe-rss-standin.py" || result=$((result + 1))
  control_report "h18 launcher-rss-sensitivity" "$ctl_before"


  # (h19) #399 R2-4: a TERM-ignoring descendant is reparented the moment its
  # capture parent dies, so the KILL pass must use the inventory taken **before**
  # the TERM. The control's descendant records its own PID and ignores TERM; if
  # the escalation rediscovered descendants after the TERM it would miss it and
  # report success while the process survived.
  ctl_before="$result"
  local f6_status=0 child_pid i
  (
    trap - EXIT
    (
      trap - EXIT
      bash -c 'trap "" TERM; printf "%s" "$$" >"$1"; while :; do sleep 1; done' \
        _ "$WORK/probe-escalate.pid"
      wait
    ) &
    STDIN_CAPTURE_PID=$!
    for i in $(seq 1 100); do
      [ -s "$WORK/probe-escalate.pid" ] && break
      sleep 0.1
    done
    if [ ! -s "$WORK/probe-escalate.pid" ]; then
      echo "    FAIL: escalation control: the descendant never recorded its PID"
      kill -KILL "$STDIN_CAPTURE_PID" 2>/dev/null || true
      exit 72
    fi
    child_pid="$(cat "$WORK/probe-escalate.pid")"
    STDIN_CAPTURE_WAIT_SECONDS=0
    if wait_capture_bounded "probe-escalate" >"$WORK/probe-escalate.out" 2>&1; then
      kill -KILL "$child_pid" 2>/dev/null || true
      exit 70
    fi
    # A SIGKILLed process is not necessarily absent on the next instruction
    # (mid-teardown, or an unreaped zombie that `kill -0` calls alive), so give
    # the disappearance a bounded grace instead of one instantaneous reading
    # (#399 verification 4, h19). A child the KILL pass never reached ignores
    # TERM and loops forever, so the deadline still fails this control.
    if ! wait_pid_absent "$child_pid"; then
      kill -KILL "$child_pid" 2>/dev/null || true
      exit 71
    fi
    exit 0
  )
  f6_status=$?
  case "$f6_status" in
  0) echo "    control h19: capture escalation killed the reparented TERM-ignoring descendant" ;;
  *)
    echo "    FAIL: escalation control ($f6_status): a recorded descendant survived the KILL pass"
    sed -n '1,10p' "$WORK/probe-escalate.out" 2>/dev/null || true
    result=$((result + 1))
    ;;
  esac
  rm -f "$WORK/probe-escalate.pid" "$WORK/probe-escalate.out" || result=$((result + 1))
  control_report "h19 capture-escalation-inventory" "$ctl_before"


  # (h19b) #399 R3-2: the same pre-TERM inventory must keep a descendant whose
  # executable **path contains a space**. `descendants_of` used to take the third
  # whitespace-separated `ps` field, so the recorded comm was truncated at the
  # space while `signal_inventory` compares the whole comm: the child matched in
  # neither pass and survived both TERM and KILL. The symlink makes the shape
  # real without executing anything but `/bin/sleep`.
  ctl_before="$result"
  local f8_status=0 space_dir="$WORK/probe-space" space_link space_out space_pid
  space_link="$space_dir/sleep with space"
  space_out="$WORK/probe-space.out"
  rm -rf "$space_dir" || result=$((result + 1))
  mkdir -p "$space_dir" || result=$((result + 1))
  ln -sf /bin/sleep "$space_link" || result=$((result + 1))
  # The PID of a live process whose *whole* comm is this path. `awk` matches its
  # own command line, so the comparison is on comm, never on the full argv.
  probe_space_child_pid() {
    ps -axo pid=,comm= | awk -v link="$space_link" '
      { line=$0; sub(/^[ \t]*/, "", line); split(line, f, /[ \t]+/); pid=f[1]
        comm=line; sub(/^[^ \t]+[ \t]+/, "", comm)
        if (comm == link) { print pid; exit } }'
  }
  (
    trap - EXIT
    (
      trap - EXIT
      "$space_link" 30 &
      wait
    ) &
    STDIN_CAPTURE_PID=$!
    for i in $(seq 1 100); do
      space_pid="$(probe_space_child_pid)"
      [ -n "$space_pid" ] && break
      sleep 0.1
    done
    if [ -z "$space_pid" ]; then
      echo "    FAIL: space-path control: the descendant never appeared"
      kill -KILL "$STDIN_CAPTURE_PID" 2>/dev/null || true
      exit 72
    fi
    STDIN_CAPTURE_WAIT_SECONDS=0
    if wait_capture_bounded "probe-space" >"$space_out" 2>&1; then
      kill -KILL "$space_pid" 2>/dev/null || true
      exit 70
    fi
    if kill -0 "$space_pid" 2>/dev/null; then
      kill -KILL "$space_pid" 2>/dev/null || true
      exit 71
    fi
    exit 0
  )
  f8_status=$?
  case "$f8_status" in
  0) echo "    control h19b: capture escalation killed the descendant whose comm contains a space" ;;
  *)
    echo "    FAIL: space-path-control ($f8_status): a space-named descendant survived the KILL pass"
    sed -n '1,10p' "$space_out" 2>/dev/null || true
    result=$((result + 1))
    ;;
  esac
  # The same comm oracle again, from outside: no process may still carry it.
  space_pid="$(probe_space_child_pid)"
  if [ -n "$space_pid" ]; then
    echo "    FAIL: space-path-control: the descendant $space_pid survived the control"
    kill -KILL "$space_pid" 2>/dev/null || true
    result=$((result + 1))
  fi
  rm -rf "$space_dir"
  rm -f "$space_out" || result=$((result + 1))
  control_report "h19b space-path-descendant" "$ctl_before"


  # (h20) #399 R2-3: a **file** producer blocked on a full pipe (a reader that
  # stops reading but keeps the FIFO open) must fail bounded and must not orphan
  # the `cat` it started. The old shape timed out the wrapper subshell only, so
  # `cat` survived holding the write end. The oracle is process-based: no
  # process may still be writing this control's own data file. Scope: the
  # **timeout/full-pipe** branch of the producer helper — not every signal a row
  # could receive while a producer is writing.
  ctl_before="$result"
  local f7_status=0
  (
    trap - EXIT
    local fifo="$WORK/probe-full.fifo" data="$WORK/probe-full.data" reader i
    head -c 4194304 /dev/urandom >"$data" || exit 80
    rm -f "$fifo" || exit 81
    mkfifo "$fifo" || exit 81
    (
      exec python3 -c '
import sys, time
f = open(sys.argv[1], "rb", buffering=0)
f.read(4096)
time.sleep(8)
' "$fifo"
    ) &
    reader=$!
    for i in $(seq 1 50); do
      [ -p "$fifo" ] && break
      sleep 0.1
    done
    sleep 0.5
    STDIN_WRITER_TIMEOUT=1
    if stdin_writer_write_bounded "$fifo" file "$data" >/dev/null 2>&1; then
      kill -KILL "$reader" 2>/dev/null || true
      exit 82
    fi
    sleep 0.3
    if ps -axo pid=,command= | awk -v d="$data" '$2 != "grep" && $2 != "awk" && index($0, d) { f = 1 } END { exit !f }'; then
      echo "    orphaned producer still writing $data:"
      ps -axo pid=,command= | awk -v d="$data" '$2 != "grep" && $2 != "awk" && index($0, d)'
      kill -KILL "$reader" 2>/dev/null || true
      exit 83
    fi
    kill -KILL "$reader" 2>/dev/null || true
    wait "$reader" 2>/dev/null || true
    exit 0
  )
  f7_status=$?
  if [ "$f7_status" -ne 0 ]; then
    echo "    FAIL: file-producer control ($f7_status): a full-pipe file producer was not bounded cleanly"
    result=$((result + 1))
  else
    echo "    control h20: full-pipe file producer bounded with no orphaned cat"
  fi
  rm -f "$WORK/probe-full.fifo" "$WORK/probe-full.data" || result=$((result + 1))
  control_report "h20 file-producer-no-orphan" "$ctl_before"


  # (h21) #399 R3-1: a legal **child-first** schedule publishes the launch
  # receipt before the sampler is started. The sampler used to `rm -f` the
  # receipt on entry, which discarded a live identity record and then waited for
  # a rewrite that never comes. This control waits for the receipt, then starts
  # the sampler, and requires it to bind and to leave the receipt alone.
  ctl_before="$result"
  local rss_early="$WORK/probe-rss-early" early_job early_pid early_sampled
  ensure_launch_wrapper || result=$((result + 1))
  reset_launcher_rss_files "$rss_early.rss" || {
    echo "    FAIL: child-first control: could not clear the sampler files"
    result=$((result + 1))
  }
  ( cd "$WORK" || exit 1
    exec /usr/bin/time -l -o "$rss_early.time" \
      "$LAUNCH_WRAPPER" "$rss_early.rss.receipt" /bin/sleep 3 ) &
  early_job=$!
  for i in $(seq 1 250); do
    [ -s "$rss_early.rss.receipt" ] && break
    sleep 0.02
  done
  if [ ! -s "$rss_early.rss.receipt" ]; then
    echo "    FAIL: child-first control: the launch published no receipt to start the sampler on"
    kill -KILL "$early_job" 2>/dev/null || true
    result=$((result + 1))
  else
    early_pid="$(launch_receipt_pid "$rss_early.rss.receipt")"
    echo "    control h21: receipt published before sampler startup names pid=${early_pid:-none}"
    if ! sample_launcher_rss "$early_job" "$rss_early.rss" /bin/sleep; then
      echo "    FAIL: child-first control: the sampler rejected a receipt published before it started"
      result=$((result + 1))
    fi
    wait "$early_job" 2>/dev/null || true
    rss_sampler_stop
    # The receipt the launch wrote must still be there, and it must be the one
    # the sampler bound to.
    if [ ! -s "$rss_early.rss.receipt" ]; then
      echo "    FAIL: child-first control: the sampler deleted the live launch receipt"
      result=$((result + 1))
    fi
    if ! assert_launcher_rss_identity "$rss_early.rss" "probe-rss-early"; then
      result=$((result + 1))
    fi
    early_sampled="$(sed -n 's/^sampled_pid=//p' "$rss_early.rss.meta" 2>/dev/null)"
    if [ -z "$early_pid" ] || [ "$early_sampled" != "$early_pid" ]; then
      echo "    FAIL: child-first control: sampled PID '$early_sampled' is not the receipt PID '$early_pid'"
      result=$((result + 1))
    fi
  fi
  rm -f "$rss_early.rss" "$rss_early.rss.meta" "$rss_early.rss.receipt" \
    "$rss_early.time" || result=$((result + 1))
  control_report "h21 receipt-survives-child-first-schedule" "$ctl_before"


  # (h22) #399 R3-1: when the sampler cannot start, the observation fails — and
  # the **launcher it already started** must not be left running. The old
  # failure path stopped the `/usr/bin/time` job only, so the real launcher (a
  # child of that job) and its children survived with no record left to reap
  # them. The stand-in launcher records its own PID (the receipt's) and its
  # child's, so both are checked absent afterwards.
  ctl_before="$result"
  local rss_fail="$WORK/probe-rss-fail" fail_rc=0 fail_pid fail_child probe
  reset_launcher_rss_files "$rss_fail.rss" || result=$((result + 1))
  cat >"$WORK/probe-rss-fail.sh" <<'LAUNCH' || result=$((result + 1))
#!/bin/bash
printf '%s' "$$" >"$1"
/bin/sleep 30 &
printf '%s' "$!" >"$2"
wait
LAUNCH
  chmod +x "$WORK/probe-rss-fail.sh" || result=$((result + 1))
  # The sampler is told to expect an executable this launcher is not, so it
  # burns its (1 s) receipt budget and fails after the tree is fully up.
  # The observation's own FAIL diagnostics are the expected outcome here, so they
  # are captured in a work file rather than pasted into the control log.
  if (
    OBSERVE_RSS_FILE="$rss_fail.rss" OBSERVE_TIME_FILE="$rss_fail.time" \
      OBSERVE_LAUNCHER_EXE=/bin/echo RSS_RECEIPT_WAIT_SECONDS=1 \
      observe_launch "probe-rss-fail" "$probe_dir" "$WORK/probe-rss-fail.out" -- \
      /bin/bash "$WORK/probe-rss-fail.sh" "$WORK/probe-rss-fail.pid" \
      "$WORK/probe-rss-fail.child" >"$WORK/probe-rss-fail.log" 2>&1
  ); then
    fail_rc=0
  else
    fail_rc=$?
  fi
  if [ "$fail_rc" -eq 0 ]; then
    echo "    FAIL: sampler-failure control: observe_launch reported success although its sampler could not bind"
    result=$((result + 1))
  fi
  fail_pid="$(cat "$WORK/probe-rss-fail.pid" 2>/dev/null || true)"
  fail_child="$(cat "$WORK/probe-rss-fail.child" 2>/dev/null || true)"
  for probe in fail_pid fail_child; do
    case "${!probe}" in
    '' | *[!0-9]*)
      echo "    FAIL: sampler-failure control: the launch recorded no $probe"
      result=$((result + 1))
      ;;
    *)
      if kill -0 "${!probe}" 2>/dev/null; then
        echo "    FAIL: sampler-failure control: $probe ${!probe} survived the sampler-start failure path"
        kill -KILL "${!probe}" 2>/dev/null || true
        result=$((result + 1))
      fi
      ;;
    esac
  done
  echo "    control h22: launcher pid=${fail_pid:-none} child=${fail_child:-none} both absent after the failure path (diagnostics: $(basename "$WORK/probe-rss-fail.log"))"
  rm -f "$rss_fail.rss" "$rss_fail.rss.meta" "$rss_fail.rss.receipt" \
    "$rss_fail.time" "$WORK/probe-rss-fail.sh" "$WORK/probe-rss-fail.pid" \
    "$WORK/probe-rss-fail.child" "$WORK/probe-rss-fail.log" || result=$((result + 1))
  control_report "h22 sampler-start-failure-stops-launch-tree" "$ctl_before"


  # (h23) #399 post-3: the sampler stops cleanly when its own target is caught
  # *finishing* — macOS then reports `<defunct>`/`(<name>)` for the comm and
  # 0 KiB of RSS. A native `large` launch failed on exactly that reading, so the
  # rule needs its own receipt: benign only for our own name and only at 0 KiB.
  # Anything else (another name, or a placeholder with a live RSS) stays a
  # mismatch, so the allowance cannot hide a real comm change.
  ctl_before="$result"
  if ! rss_exit_transition "<defunct>" 0 agent-vm; then
    echo "    FAIL: exit-transition rule rejected a zombie of the sampled target"
    result=$((result + 1))
  fi
  if ! rss_exit_transition "(agent-vm)" 0 agent-vm; then
    echo "    FAIL: exit-transition rule rejected the target's own placeholder comm"
    result=$((result + 1))
  fi
  if rss_exit_transition "(other)" 0 agent-vm; then
    echo "    FAIL: exit-transition rule accepted another process's placeholder comm"
    result=$((result + 1))
  fi
  if rss_exit_transition "(agent-vm)" 4096 agent-vm; then
    echo "    FAIL: exit-transition rule accepted a placeholder comm with a live RSS"
    result=$((result + 1))
  fi
  if rss_exit_transition "/bin/sh" 0 agent-vm; then
    echo "    FAIL: exit-transition rule accepted an unrelated comm"
    result=$((result + 1))
  fi
  control_report "h23 rss-exit-transition-rule" "$ctl_before"


  # (h24) #399 review: the runtime identity receipt now probes the pinned runtime
  # HEAD and the firmware source stamp with checked statuses, validates them as
  # object ids and requires the stamp to equal the pinned nested
  # `vendor/libkrunfw` gitlink. The real `stdin_identity_init` runs in a
  # subshell with only `git` stubbed and the receipt path real, so this control
  # exercises the shipped probes rather than a copy; every launch outside it
  # keeps the real git. A rejected probe must leave READY unset and publish no
  # runtime receipt, because a later successful assignment would otherwise hide
  # the failure under the conditional call the rows use.
  ctl_before="$result"
  local identity_dir="$probe_dir/stdin-identity"
  local identity_stamp="$identity_dir/libkrunfw.5.dylib.source-sha"
  local stub_head=3333333333333333333333333333333333333333
  local stub_runtime=1111111111111111111111111111111111111111
  local stub_stamp=2222222222222222222222222222222222222222
  local stub_gitlink="160000 commit $stub_stamp"$'\t'"vendor/libkrunfw"
  mkdir -p "$identity_dir" || result=$((result + 1))

  # Args: want (ok|fail), runtime HEAD (`fail`/`empty`/id), ls-tree line
  # (`fail`/`empty`/line), firmware stamp (id or `missing`/`unreadable`/`empty`).
  stdin_identity_probe() {
    local want="$1" stub_rt="$2" stub_tree="$3" stamp_mode="$4" accepted
    rm -rf "$identity_stamp"
    case "$stamp_mode" in
    missing) ;;
    unreadable) mkdir "$identity_stamp" || return 1 ;;
    empty) : >"$identity_stamp" || return 1 ;;
    *) printf '%s\n' "$stamp_mode" >"$identity_stamp" || return 1 ;;
    esac
    (
      STDIN_EVIDENCE_CANDIDATE=""
      STDIN_EVIDENCE_RUNTIME=""
      STDIN_EVIDENCE_READY=""
      AGENT_VM=/usr/bin/true
      CUSTOM_RUNTIME_DIR="$identity_dir"
      CUSTOM_MSB=/usr/bin/true
      CUSTOM_AGENTD=/usr/bin/true
      CUSTOM_LIBKRUNFW=/usr/bin/true
      # shellcheck disable=SC2317,SC2329  # invoked indirectly by stdin_identity_init;
      # 0.9 (the Ubuntu CI version) reports the body as unreachable instead.
      git() {
        case "$*" in
        *"ls-tree HEAD vendor/libkrunfw"*)
          [ "$stub_tree" != fail ] || return 1
          [ "$stub_tree" != empty ] || return 0
          printf '%s\n' "$stub_tree"
          ;;
        *"rev-parse --verify HEAD"*)
          [ "$stub_rt" != fail ] || return 1
          [ "$stub_rt" != empty ] || return 0
          printf '%s\n' "$stub_rt"
          ;;
        *"rev-parse HEAD"*) printf '%s\n' "$stub_head" ;;
        esac
      }
      if stdin_identity_init; then accepted=ok; else accepted=fail; fi
      [ "$accepted" = "$want" ] || return 1
      if [ "$want" = ok ]; then
        [ "$STDIN_EVIDENCE_READY" = 1 ] || return 1
        case "$STDIN_EVIDENCE_RUNTIME" in
        *"microsandbox=$stub_runtime"*"firmware-source=$stub_stamp"*) return 0 ;;
        esac
        return 1
      fi
      [ -z "$STDIN_EVIDENCE_READY" ] && [ -z "$STDIN_EVIDENCE_RUNTIME" ]
    )
  }

  # A rejected identity is the expected outcome here; the FAIL is acceptance.
  stdin_identity_must_reject() {
    local desc="$1"
    shift
    stdin_identity_probe fail "$@" && return 0
    echo "    FAIL: stdin_identity_init accepted $desc"
    result=$((result + 1))
  }

  if ! stdin_identity_probe ok "$stub_runtime" "$stub_gitlink" "$stub_stamp"; then
    echo "    FAIL: stdin_identity_init rejected the valid pinned identity"
    result=$((result + 1))
  fi
  stdin_identity_must_reject "a missing firmware receipt" \
    "$stub_runtime" "$stub_gitlink" missing
  stdin_identity_must_reject "an unreadable firmware receipt" \
    "$stub_runtime" "$stub_gitlink" unreadable
  stdin_identity_must_reject "an empty firmware receipt" \
    "$stub_runtime" "$stub_gitlink" empty
  stdin_identity_must_reject "an unresolvable firmware receipt" \
    "$stub_runtime" "$stub_gitlink" unknown
  stdin_identity_must_reject "a firmware receipt that is not the pinned gitlink" \
    "$stub_runtime" "$stub_gitlink" 4444444444444444444444444444444444444444
  stdin_identity_must_reject "a failed pinned-runtime HEAD probe" \
    fail "$stub_gitlink" "$stub_stamp"
  stdin_identity_must_reject "an empty pinned-runtime HEAD probe" \
    empty "$stub_gitlink" "$stub_stamp"
  stdin_identity_must_reject "an unresolvable pinned-runtime HEAD probe" \
    unknown "$stub_gitlink" "$stub_stamp"
  stdin_identity_must_reject "a failed firmware gitlink probe" \
    "$stub_runtime" fail "$stub_stamp"
  stdin_identity_must_reject "an empty firmware gitlink probe" \
    "$stub_runtime" empty "$stub_stamp"
  stdin_identity_must_reject "a firmware gitlink that is not an object id" \
    "$stub_runtime" "160000 commit nope"$'\t'"vendor/libkrunfw" "$stub_stamp"
  stdin_identity_must_reject "a firmware gitlink for another path" \
    "$stub_runtime" "160000 commit $stub_stamp"$'\t'"vendor/other" "$stub_stamp"
  control_report "h24 stdin-identity-receipts" "$ctl_before"


  local observed_pass="$PASSED" observed_fail="$FAILED"
  if [ "$observed_pass" -ne 0 ] || [ "$observed_fail" -ne 2 ]; then
    echo "    FAIL: harness negative expected 0 pass / 2 fail, got $observed_pass/$observed_fail"
    # The deliberately expected FAIL output is captured, not shown as the
    # summary's own failures.
    cat "$log"
    result=$((result + 1))
  fi
  assert_no_host_calls || result=$((result + 1))

  PASSED="$saved_passed"
  FAILED="$saved_failed"
  return "$result"
}

# ==================================================== custom-image checks ====

# A per-check project under $WORK with the checked two-tool config.
custom_project() {
  local name="$1"
  local proj="$WORK/$name"
  write_custom_tools_config "$proj" || return 1
  printf '%s' "$proj"
}

# The launcher propagates the guest exit status, so a positive boot is only a
# pass when that status is exactly 0.
require_launch_ok() {
  local desc="$1"
  assert_eq "$desc: guest exit status" "0" "$CAPTURE_STATUS"
}

# jq assertions over the launcher-owned state file, read from the host state
# dir. A jq error or a missing file is a failure, never an "absent" tolerance.
assert_state_json_at() {
  local desc="$1" filter="$2" state="$3"
  if [ ! -f "$state/claude.json" ]; then
    echo "    FAIL: $desc (claude.json absent at $state)"
    return 1
  fi
  if ! jq -e "$filter" "$state/claude.json" >/dev/null; then
    echo "    FAIL: $desc (jq filter: $filter)"
    jq -c . "$state/claude.json" || true
    return 1
  fi
}

assert_state_json() {
  local desc="$1" filter="$2" state
  state="$(host_state_dir "$INTEG_PROJ")" || return 1
  assert_state_json_at "$desc" "$filter" "$state"
}

# 1. marker-free hello runs as host identity (nonroot) and 0:0 (root), and the
# guest confirms the stamp is absent.
custom_image_runs_program() {
  local name="custom-runs" proj out host_uid host_gid
  proj="$(custom_project "$name")" || return 1
  capture_custom_launch "$name" "$proj" --no-git --image "$CUSTOM_MARKER" hello-258 || return 1
  require_launch_ok "$name" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output "$name")"
  host_uid="$(id -u)"
  host_gid="$(id -g)"
  assert_eq "nonroot uid" "uid=$host_uid" "$(grep '^uid=' <<<"$out")" || return 1
  assert_eq "nonroot gid" "gid=$host_gid" "$(grep '^gid=' <<<"$out")" || return 1
  assert_eq "nonroot HOME is the launcher HOME" "home=$CUSTOM_HOME" "$(grep '^home=' <<<"$out")" || return 1
  assert_eq "the marker-free guest confirms no stamp" "stamp=absent" "$(grep '^stamp=' <<<"$out")" || return 1
  assert_eq "nonroot completion sentinel" "hello-258=ok" "$(grep '^hello-258=ok$' <<<"$out")" || return 1

  local root="custom-runs-root" root_proj
  root_proj="$(custom_project "$root")" || return 1
  capture_custom_launch "$root" "$root_proj" --no-git --root --image "$CUSTOM_MARKER" hello-258 || return 1
  require_launch_ok "$root" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output "$root")"
  assert_eq "root uid" "uid=0" "$(grep '^uid=' <<<"$out")" || return 1
  assert_eq "root gid" "gid=0" "$(grep '^gid=' <<<"$out")" || return 1
  assert_eq "root HOME" "home=/root" "$(grep '^home=' <<<"$out")" || return 1
  assert_eq "root completion sentinel" "hello-258=ok" "$(grep '^hello-258=ok$' <<<"$out")" || return 1
}

# 2. state persists across independent boots, nonroot + root. Declared persist
# target, project bind, direct state and (nonroot only) plain HOME sentinels are
# all read back, with link targets and bind owner bits in both sessions.
custom_image_state_persists() {
  local mode="$1" name="custom-state-$1" proj out read
  local -a root_flag=()
  [ "$mode" = root ] && root_flag=(--root)
  proj="$(custom_project "$name")" || return 1
  local host_uid host_gid expected_owner
  host_uid="$(id -u)"
  host_gid="$(id -g)"
  if [ "$mode" = root ]; then expected_owner=0:0; else expected_owner="$host_uid:$host_gid"; fi

  capture_custom_launch "$name" "$proj" --no-git ${root_flag[@]+"${root_flag[@]}"} \
    --image "$CUSTOM_MARKER" hello-258 write "sentinel-258-$mode" || return 1
  require_launch_ok "$name" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output "$name")"
  assert_eq "$mode write: declared link target" \
    "declared_link=/agent-vm-state/persist/.hello-258.state" "$(grep '^declared_link=' <<<"$out")" || return 1
  assert_eq "$mode write: gitconfig link target" \
    "gitconfig_link=/agent-vm-state/gitconfig" "$(grep '^gitconfig_link=' <<<"$out")" || return 1
  assert_eq "$mode write: declared target owner" "declared_owner=$expected_owner" \
    "$(grep '^declared_owner=' <<<"$out")" || return 1
  assert_eq "$mode write: project bind owner" "project_owner_after_write=$expected_owner" \
    "$(grep '^project_owner_after_write=' <<<"$out")" || return 1
  assert_eq "$mode write: direct state owner" "direct_owner_after_write=$expected_owner" \
    "$(grep '^direct_owner_after_write=' <<<"$out")" || return 1

  read="custom-state-$mode-read"
  capture_custom_launch "$read" "$proj" --no-git ${root_flag[@]+"${root_flag[@]}"} \
    --image "$CUSTOM_MARKER" hello-258 read "$mode" || return 1
  require_launch_ok "$read" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output "$read")"
  assert_eq "$mode read: declared sentinel" "declared=sentinel-258-$mode" "$(grep '^declared=' <<<"$out")" || return 1
  assert_eq "$mode read: project sentinel" "project=sentinel-258-$mode" "$(grep '^project=' <<<"$out")" || return 1
  assert_eq "$mode read: direct state sentinel" "direct=sentinel-258-$mode" "$(grep '^direct=' <<<"$out")" || return 1
  if [ "$mode" = nonroot ]; then
    assert_eq "nonroot read: plain HOME sentinel" "plain=sentinel-258-$mode" "$(grep '^plain=' <<<"$out")" || return 1
  fi
  assert_eq "$mode read: declared link target" \
    "declared_link=/agent-vm-state/persist/.hello-258.state" "$(grep '^declared_link=' <<<"$out")" || return 1
  assert_eq "$mode read: gitconfig link target" \
    "gitconfig_link=/agent-vm-state/gitconfig" "$(grep '^gitconfig_link=' <<<"$out")" || return 1
  assert_eq "$mode read: project bind owner" "project_owner=$expected_owner" \
    "$(grep '^project_owner=' <<<"$out")" || return 1
  assert_eq "$mode read: state bind owner" "state_owner=$expected_owner" \
    "$(grep '^state_owner=' <<<"$out")" || return 1
  assert_eq "$mode read: persist bind owner" "persist_owner=$expected_owner" \
    "$(grep '^persist_owner=' <<<"$out")" || return 1
}

# 3. an OCI USER + ENV HOME image: the launcher identity/HOME override wins in
# both modes, writes and owner bits hold, and the provisioned git config is
# readable on an independent boot.
custom_image_user_home_set() {
  local mode="$1" name="custom-user-home-$1" proj out read
  local -a root_flag=()
  [ "$mode" = root ] && root_flag=(--root)
  proj="$(custom_project "$name")" || return 1
  local host_uid host_gid expected_home expected_owner
  host_uid="$(id -u)"
  host_gid="$(id -g)"
  if [ "$mode" = root ]; then
    expected_home=/root
    expected_owner=0:0
  else
    expected_home="$CUSTOM_HOME"
    expected_owner="$host_uid:$host_gid"
  fi

  capture_custom_launch "$name" "$proj" --no-git ${root_flag[@]+"${root_flag[@]}"} \
    --image "$CUSTOM_USER_HOME" hello-258 write "uh-$mode" || return 1
  require_launch_ok "$name" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output "$name")"
  if [ "$mode" = root ]; then
    assert_eq "root overrides USER app" "uid=0" "$(grep '^uid=' <<<"$out")" || return 1
  else
    assert_eq "nonroot overrides OCI USER" "uid=$host_uid" "$(grep '^uid=' <<<"$out")" || return 1
  fi
  assert_eq "$mode overrides ENV HOME=/home/app" "home=$expected_home" "$(grep '^home=' <<<"$out")" || return 1
  assert_eq "$mode bind identity" "state_owner=$expected_owner" "$(grep '^state_owner=' <<<"$out")" || return 1
  assert_eq "$mode write: project bind owner" "project_owner_after_write=$expected_owner" \
    "$(grep '^project_owner_after_write=' <<<"$out")" || return 1
  assert_eq "$mode write: provisioned git config readable" "gitconfig_safe=yes" \
    "$(grep '^gitconfig_safe=' <<<"$out")" || return 1

  read="custom-user-home-$mode-read"
  capture_custom_launch "$read" "$proj" --no-git ${root_flag[@]+"${root_flag[@]}"} \
    --image "$CUSTOM_USER_HOME" hello-258 read "$mode" || return 1
  require_launch_ok "$read" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output "$read")"
  assert_eq "$mode read: declared sentinel survived" "declared=uh-$mode" "$(grep '^declared=' <<<"$out")" || return 1
  assert_eq "$mode read: declared link target" \
    "declared_link=/agent-vm-state/persist/.hello-258.state" "$(grep '^declared_link=' <<<"$out")" || return 1
  assert_eq "$mode read: gitconfig link target" \
    "gitconfig_link=/agent-vm-state/gitconfig" "$(grep '^gitconfig_link=' <<<"$out")" || return 1
  assert_eq "$mode read: state bind owner" "state_owner=$expected_owner" \
    "$(grep '^state_owner=' <<<"$out")" || return 1
}

# 4. a missing selected program: the configured command is requested through the
# real CLI tool-selection path, so the contract guard (not bash's own message)
# must fire with the image's command name and exit 127. A shell function or
# alias with the same name is not an executable and must not satisfy it.
custom_image_missing_program() {
  local name="custom-missing" proj out
  proj="$(custom_project "$name")" || return 1
  capture_custom_launch "$name" "$proj" --no-git --image "$CUSTOM_MARKER" missing-258 || return 1
  assert_eq "missing program exit status" "127" "$CAPTURE_STATUS" || return 1
  out="$(launch_output "$name")"
  assert_match "names the configured command" "not-installed-258" "$out" || return 1
  assert_match "names the boot image" "$CUSTOM_MARKER" "$out" || return 1
  assert_match "explains agent-vm does not install" "does not install software" "$out" || return 1
  assert_match "points at the image contract" "boot-image-contract" "$out" || return 1
  assert_no_match "no Docker/build/pull fallback" "docker|buildx|pulling|Installing" "$out" || return 1
  assert_single_boot_ref "missing program boots only the selected image" "$CUSTOM_MARKER" "$out" || return 1
  assert_no_host_calls || return 1

  local hookname="custom-missing-hook" hookproj
  hookproj="$(custom_project "$hookname")" || return 1
  cat >"$hookproj/.agent-vm.runtime.sh" <<'HOOK' || return 1
not-installed-258() { printf 'function-body\n'; }
alias not-installed-258='printf alias-body\n'
HOOK
  capture_custom_launch "$hookname" "$hookproj" --no-git --image "$CUSTOM_MARKER" missing-258 || return 1
  assert_eq "function/alias exit status" "127" "$CAPTURE_STATUS" || return 1
  out="$(launch_output "$hookname")"
  assert_match "function/alias still gets the contract diagnostic" "not-installed-258" "$out" || return 1
  assert_match "function/alias still explains no install" "does not install software" "$out" || return 1
  assert_no_match "function/alias body never ran" "function-body|alias-body" "$out" || return 1
  assert_single_boot_ref "missing program hook boots only the selected image" "$CUSTOM_MARKER" "$out" || return 1
  assert_no_host_calls || return 1
}

# 5. an image without Bash: kind-specific contract diagnostic, bounded
# completion, no surviving VM/catalog entry and no fallback image.
custom_image_without_bash() {
  local name="custom-no-bash" proj out result=0
  proj="$(custom_project "$name")" || return 1
  if ! capture_custom_launch "$name" "$proj" --no-git --image "$CUSTOM_NO_BASH" hello-258; then
    emergency_sandbox_cleanup "$CUSTOM_NO_BASH" || true
    return 1
  fi
  out="$(launch_output "$name")"
  if [ "$CAPTURE_STATUS" -eq 0 ]; then
    echo "    FAIL: no-Bash launch must fail"
    result=1
  fi
  assert_match "names the missing bash" 'has no runnable `bash`' "$out" || result=1
  assert_single_logs_ref "no-Bash streaming names the log dir once" "$out" || result=1
  assert_no_match "no ExecFailed Debug dump" 'ExecFailed \{' "$out" || result=1
  assert_no_match "no deadline/cleanup error" "timed out|cleanup failed" "$out" || result=1
  assert_single_boot_ref "no-Bash streaming boots only the selected image" "$CUSTOM_NO_BASH" "$out" || result=1
  assert_no_host_calls || result=1
  assert_no_catalog_entry "$CUSTOM_NO_BASH" || result=1
  if [ "$result" -ne 0 ]; then
    emergency_sandbox_cleanup "$CUSTOM_NO_BASH" || true
  fi
  return "$result"
}

# 6. optional integrations: the marker and the supplied wrapper are ordinary
# image capabilities. One project walks absent -> advertised -> opted out ->
# wrapper-provided -> absent, and an unrelated user MCP entry plus an unrelated
# top-level key must survive every sync.
INTEG_PROJ=""
UNRELATED_STATE='.mcpServers["user-owned"] == {"command":"user-cmd"} and .unrelatedTopKey == {"keep":true}'
OWNED_STATE='(.mcpServers["chrome-devtools"].command == "/usr/local/bin/agent-vm-chrome-mcp") and (.mcpServers["chrome-devtools"].args == ["npx","-y","chrome-devtools-mcp@1.0.1","--headless=true","--isolated=true"]) and (.mcpServers["chrome-devtools"].env == {"CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS":"1"})'
NO_OWNED_STATE='(.mcpServers["chrome-devtools"] // null) == null'

custom_image_integrations() {
  INTEG_PROJ="$(custom_project "custom-integrations")" || return 1
  cat >>"$INTEG_PROJ/.agent-vm/config.toml" <<'EOF' || return 1

[[tools]]
name = "verify-mcp-258"
command = "verify-mcp-258"
EOF
  local state seed_json out optout_rc
  state="$(host_state_dir "$INTEG_PROJ")" || return 1

  seed_json='{"mcpServers":{"user-owned":{"command":"user-cmd"}},"unrelatedTopKey":{"keep":true}}'
  # `... shell bash -c 'SCRIPT'` is the supported/documented argv form: the
  # interactive shell joins the separately escaped arguments into one `bash -c`
  # command line, so a bare single script string would be looked up as a command.
  capture_custom_launch "integrations-seed" "$INTEG_PROJ" --no-git --image "$CUSTOM_MARKER" shell \
    bash -c "printf '%s' '$seed_json' > /agent-vm-state/claude.json" || return 1
  require_launch_ok "integrations-seed" || return 1
  assert_no_host_calls || return 1
  assert_state_json "seeded unrelated entries" "$UNRELATED_STATE" || return 1

  # absent: no owned entry, no seed hook, no integration execution.
  capture_custom_launch "integrations-absent" "$INTEG_PROJ" --no-git --image "$CUSTOM_MARKER" hello-258 || return 1
  require_launch_ok "integrations-absent" || return 1
  assert_no_host_calls || return 1
  assert_state_json "absent: no owned entry" "$NO_OWNED_STATE" || return 1
  assert_state_json "absent: unrelated entries intact" "$UNRELATED_STATE" || return 1
  [ ! -e "$state/seed-258.payload" ] || { echo "    FAIL: absent: seed payload exists"; return 1; }
  [ ! -e "$state/mcp-executed-258" ] || { echo "    FAIL: absent: execution file exists"; return 1; }

  # advertised + supplied wrapper: the configured entry is read from state and
  # actually executed; the supplied seed.d hook runs.
  capture_custom_launch "integrations-advertised" "$INTEG_PROJ" --no-git --image "$CUSTOM_INTEGRATIONS" verify-mcp-258 || return 1
  require_launch_ok "integrations-advertised" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output integrations-advertised)"
  assert_match "advertised: configured entry executed" '^verify-mcp-258: OK$' "$out" || return 1
  assert_state_json "advertised: owned entry configured" "$OWNED_STATE" || return 1
  assert_state_json "advertised: unrelated entries intact" "$UNRELATED_STATE" || return 1
  [ -e "$state/seed-258.payload" ] || { echo "    FAIL: advertised: seed.d did not run"; return 1; }
  [ -e "$state/mcp-executed-258" ] || { echo "    FAIL: advertised: no execution file"; return 1; }

  # advertised + opt-out: the owned entry is removed, seed hooks are independent
  # of Chrome opt-out and still run, and nothing executes the integration.
  rm -f "$state/mcp-executed-258" || return 1
  export AGENT_VM_NO_CHROME_MCP=1
  capture_custom_launch "integrations-optout" "$INTEG_PROJ" --no-git --image "$CUSTOM_INTEGRATIONS" shell \
    bash -c 'if [ -e /tmp/seed-258-ran ]; then echo seedflag=present; else echo seedflag=absent; fi'
  optout_rc=$?
  unset AGENT_VM_NO_CHROME_MCP
  [ "$optout_rc" -eq 0 ] || return 1
  require_launch_ok "integrations-optout" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output integrations-optout)"
  assert_eq "opt-out: seed hooks are independent of Chrome opt-out" "seedflag=present" \
    "$(grep '^seedflag=' <<<"$out")" || return 1
  assert_state_json "opt-out: owned entry removed" "$NO_OWNED_STATE" || return 1
  assert_state_json "opt-out: unrelated entries intact" "$UNRELATED_STATE" || return 1
  [ ! -e "$state/mcp-executed-258" ] || { echo "    FAIL: opt-out: integration still executed"; return 1; }

  # wrapper-provided, no capability marker: capability is the supplied artifact,
  # not image identity; there is no seed.d in this target.
  capture_custom_launch "integrations-wrapper" "$INTEG_PROJ" --no-git --image "$CUSTOM_WRAPPER" verify-mcp-258 || return 1
  require_launch_ok "integrations-wrapper" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output integrations-wrapper)"
  assert_match "wrapper-provided: configured entry executed" '^verify-mcp-258: OK$' "$out" || return 1
  assert_state_json "wrapper-provided: owned entry configured" "$OWNED_STATE" || return 1
  assert_state_json "wrapper-provided: unrelated entries intact" "$UNRELATED_STATE" || return 1
  [ -e "$state/mcp-executed-258" ] || { echo "    FAIL: wrapper-provided: no execution file"; return 1; }
  capture_custom_launch "integrations-wrapper-seed" "$INTEG_PROJ" --no-git --image "$CUSTOM_WRAPPER" shell \
    bash -c 'if [ -e /tmp/seed-258-ran ]; then echo seedflag=present; else echo seedflag=absent; fi' || return 1
  require_launch_ok "integrations-wrapper-seed" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output integrations-wrapper-seed)"
  assert_eq "wrapper-provided: no seed.d hook ran" "seedflag=absent" "$(grep '^seedflag=' <<<"$out")" || return 1
  assert_eq "wrapper-provided: prior seed payload unchanged" "seed=initial-258" \
    "$(cat "$state/seed-258.payload")" || return 1

  # absent again: the stale owned entry is removed and nothing re-executes.
  rm -f "$state/mcp-executed-258" || return 1
  capture_custom_launch "integrations-after" "$INTEG_PROJ" --no-git --image "$CUSTOM_MARKER" hello-258 || return 1
  require_launch_ok "integrations-after" || return 1
  assert_no_host_calls || return 1
  assert_state_json "after: owned entry removed" "$NO_OWNED_STATE" || return 1
  assert_state_json "after: unrelated entries intact" "$UNRELATED_STATE" || return 1
  [ ! -e "$state/mcp-executed-258" ] || { echo "    FAIL: after: execution file reappeared"; return 1; }
}

# 7. both supplied seed entry points are always-run and idempotent: the first
# boot seeds, a guest edit survives later boots, the per-boot flag reappears,
# and removing the payload re-seeds it.
custom_image_supplied_seeds() {
  local variant name img proj state out
  for variant in script seedd; do
    case "$variant" in
    script)
      name="custom-seeds-script"
      img="$CUSTOM_SCRIPT"
      ;;
    *)
      name="custom-seeds-seedd"
      img="$CUSTOM_INTEGRATIONS"
      ;;
    esac
    proj="$(custom_project "$name")" || return 1
    state="$(host_state_dir "$proj")" || return 1

    capture_custom_launch "$name-first" "$proj" --no-git --image "$img" hello-258 || return 1
    require_launch_ok "$name-first" || return 1
    assert_eq "$variant: first boot seeds initial bytes" "seed=initial-258" \
      "$(cat "$state/seed-258.payload")" || return 1

    capture_custom_launch "$name-edit" "$proj" --no-git --image "$img" shell \
      bash -c 'printf %s edited-258 > /agent-vm-state/seed-258.payload; if [ -e /tmp/seed-258-ran ]; then echo seedflag=present; else echo seedflag=absent; fi' || return 1
    require_launch_ok "$name-edit" || return 1
    out="$(launch_output "$name-edit")"
    assert_eq "$variant: per-boot flag on the edit boot" "seedflag=present" \
      "$(grep '^seedflag=' <<<"$out")" || return 1

    capture_custom_launch "$name-read" "$proj" --no-git --image "$img" shell \
      bash -c 'cat /agent-vm-state/seed-258.payload; echo; if [ -e /tmp/seed-258-ran ]; then echo seedflag=present; else echo seedflag=absent; fi' || return 1
    require_launch_ok "$name-read" || return 1
    out="$(launch_output "$name-read")"
    assert_eq "$variant: guest edit survived an independent boot" "edited-258" \
      "$(grep '^edited-258$' <<<"$out")" || return 1
    assert_eq "$variant: per-boot flag on the read boot" "seedflag=present" \
      "$(grep '^seedflag=' <<<"$out")" || return 1

    rm -f "$state/seed-258.payload" || return 1
    capture_custom_launch "$name-reseed" "$proj" --no-git --image "$img" hello-258 || return 1
    require_launch_ok "$name-reseed" || return 1
    assert_eq "$variant: re-seeded initial bytes" "seed=initial-258" \
      "$(cat "$state/seed-258.payload")" || return 1
    assert_no_host_calls || return 1
  done
}

# 8. the project runtime hook may export a PATH for a hook-only tool, and only
# the hook can make it resolvable; a configured pathname with spaces survives
# quoting.
custom_image_hook_path() {
  local name="custom-hook" proj out
  proj="$(custom_project "$name")" || return 1
  mkdir -p "$proj/bin" || return 1
  cat >"$proj/bin/hook-only-258" <<'PROG' || return 1
#!/bin/sh
printf 'hook-tool-ok uid=%s gid=%s argv=%s env=%s\n' "$(id -u)" "$(id -g)" "$*" "${HOOK_ENV_258:-unset}"
PROG
  chmod +x "$proj/bin/hook-only-258" || return 1
  cat >"$proj/.agent-vm/config.toml" <<'EOF' || return 1
[[tools]]
name = "hello-258"
command = "hello-258"

[[tools]]
name = "hook-only-258"
command = "hook-only-258"
EOF
  cat >"$proj/.agent-vm.runtime.sh" <<'HOOK' || return 1
export PATH="$PWD/bin:$PATH"
export HOOK_ENV_258=hook-exported-258
HOOK

  capture_custom_launch "$name" "$proj" --no-git --image "$CUSTOM_MARKER" hook-only-258 alpha "beta gamma" || return 1
  require_launch_ok "$name" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output "$name")"
  assert_match "the hook-exported tool executed as the guest user" \
    "hook-tool-ok uid=$(id -u) gid=$(id -g) " "$out" || return 1
  assert_match "forwarded argv including a spaced argument" "argv=alpha beta gamma " "$out" || return 1
  assert_match "hook-exported env reached the program" "env=hook-exported-258" "$out" || return 1

  # Without the PATH export the same declaration is a missing external program:
  # 127 and the contract diagnostic, never a shell resolution.
  local nopath="custom-hook-nopath" noproj
  noproj="$(custom_project "$nopath")" || return 1
  cat >"$noproj/.agent-vm/config.toml" <<'EOF' || return 1
[[tools]]
name = "hook-only-258"
command = "hook-only-258"
EOF
  cat >"$noproj/.agent-vm.runtime.sh" <<'HOOK' || return 1
export HOOK_ENV_258=hook-exported-258
HOOK
  capture_custom_launch "$nopath" "$noproj" --no-git --image "$CUSTOM_MARKER" hook-only-258 || return 1
  assert_eq "without PATH export the tool is missing" "127" "$CAPTURE_STATUS" || return 1
  out="$(launch_output "$nopath")"
  assert_match "no-PATH: names the configured command" "hook-only-258" "$out" || return 1
  assert_match "no-PATH: contract diagnostic" "does not install software" "$out" || return 1
  assert_no_host_calls || return 1

  # A configured pathname containing spaces and quoted argv survives the guard
  # and the final exec.
  local pathname="custom-hook-pathname" pproj
  pproj="$(custom_project "$pathname")" || return 1
  mkdir -p "$pproj/hook dir" || return 1
  cat >"$pproj/hook dir/tool name" <<'PROG' || return 1
#!/bin/sh
printf 'pathname-tool-ok argv1=[%s] argv2=[%s]\n' "$1" "$2"
PROG
  chmod +x "$pproj/hook dir/tool name" || return 1
  cat >"$pproj/.agent-vm/config.toml" <<'EOF' || return 1
[[tools]]
name = "pathname-258"
command = "./hook dir/tool name"
EOF
  capture_custom_launch "$pathname" "$pproj" --no-git --image "$CUSTOM_MARKER" pathname-258 "one two" three || return 1
  require_launch_ok "$pathname" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output "$pathname")"
  assert_match "pathname tool executed" "pathname-tool-ok" "$out" || return 1
  assert_match "pathname argv preserved" "argv1=\[one two\] argv2=\[three\]" "$out" || return 1
}

# 11. the file-backed built-in Anthropic provider (credentials=["anthropic"]):
# a synthetic host credential under the private launcher HOME becomes a
# host-only token plus the documented guest placeholder, never leaking the
# secret; removing the seed makes the same request fail closed.
custom_image_credential_injection() {
  local name="custom-cred" proj out state guest_cred host_tok result=0
  local guest_home creds_link creds_mode ph_access ph_refresh creds_sentinel
  local guest_cred_mode host_tok_value host_tok_mode
  local nname="custom-cred-missing" nproj nout
  proj="$WORK/$name"; nproj="$WORK/$nname"
  write_custom_credential_probe "$proj" || return 1
  write_custom_credential_probe "$nproj" || return 1
  write_custom_credential_seed || { remove_custom_credential_material; return 1; }

  if capture_custom_launch "$name" "$proj" --no-git --image "$CUSTOM_MARKER" credsprobe; then
    require_launch_ok "$name" || result=1
    assert_no_host_calls || result=1
    out="$(read_launch_evidence "$name")" || result=1
    assert_match "the launcher reports the captured Anthropic credential" \
      '==> Agent credentials: claude' "$out" || result=1
    guest_home="$(evidence_line "credential guest HOME" '^home=' "$out")" || result=1
    assert_eq "credential guest HOME is the launcher HOME" "home=$CUSTOM_HOME" \
      "$guest_home" || result=1
    creds_link="$(evidence_line "credential link evidence" '^creds_link=' "$out")" || result=1
    assert_eq "the guest \$HOME/.claude is a state-backed link" \
      "creds_link=/agent-vm-state/claude" "$creds_link" || result=1
    creds_mode="$(evidence_line "credential mode evidence" '^creds_mode=' "$out")" || result=1
    assert_eq "the guest placeholder is mode 600" "creds_mode=600" \
      "$creds_mode" || result=1
    ph_access="$(evidence_line "access placeholder evidence" '^guest_placeholder_access=' "$out")" || result=1
    assert_eq "the guest holds the Anthropic access placeholder" \
      "guest_placeholder_access=present" "$ph_access" || result=1
    ph_refresh="$(evidence_line "refresh placeholder evidence" '^guest_placeholder_refresh=' "$out")" || result=1
    assert_eq "the guest holds the Anthropic refresh placeholder" \
      "guest_placeholder_refresh=present" "$ph_refresh" || result=1
    creds_sentinel="$(evidence_line "credential probe sentinel" '^credsprobe=ok$' "$out")" || result=1
    assert_eq "the credential probe completed" "credsprobe=ok" \
      "$creds_sentinel" || result=1
    assert_no_credential_leak "captured guest output" "$out" || result=1

    if ! state="$(host_state_dir "$proj")"; then
      echo "    FAIL: could not derive the host state dir for $proj"
      result=1
    else
      guest_cred="$state/claude/.credentials.json"
      host_tok="$state.secrets/anthropic"
      if [ ! -f "$guest_cred" ]; then
        echo "    FAIL: the guest placeholder $guest_cred is absent"; result=1
      elif ! jq -e '.claudeAiOauth.accessToken == "msb-anthropic-placeholder-a-v2"
          and .claudeAiOauth.refreshToken == "msb-anthropic-placeholder-r-v2"' \
          "$guest_cred" >/dev/null; then
        echo "    FAIL: the guest placeholder fields are wrong"
        jq -c . "$guest_cred" || true; result=1
      elif ! guest_cred_mode="$(stat -f '%Lp' "$guest_cred")"; then
        echo "    FAIL: could not stat the guest placeholder $guest_cred"; result=1
      elif [ "$guest_cred_mode" != 600 ]; then
        echo "    FAIL: the guest placeholder is not mode 600"; result=1
      fi
      if [ ! -f "$host_tok" ]; then
        echo "    FAIL: the host-only token file $host_tok is absent"; result=1
      elif ! host_tok_value="$(cat "$host_tok")"; then
        echo "    FAIL: could not read the host-only token file $host_tok"; result=1
      elif [ "$host_tok_value" != "$CUSTOM_CREDENTIAL_ACCESS" ]; then
        echo "    FAIL: the host-only token file does not hold the synthetic source"; result=1
      elif ! host_tok_mode="$(stat -f '%Lp' "$host_tok")"; then
        echo "    FAIL: could not stat the host-only token file $host_tok"; result=1
      elif [ "$host_tok_mode" != 600 ]; then
        echo "    FAIL: the host-only token file is not mode 600"; result=1
      fi
    fi
  else
    emergency_sandbox_cleanup "$CUSTOM_MARKER" || true
    result=1
  fi

  rm -f "$CUSTOM_CREDENTIAL_SEED" || result=1
  if capture_custom_launch "$nname" "$nproj" --no-git --image "$CUSTOM_MARKER" credsprobe; then
    nout="$(read_launch_evidence "$nname")" || result=1
    if [ "$CAPTURE_STATUS" -eq 0 ]; then
      echo "    FAIL: missing host credential must not succeed (exit=$CAPTURE_STATUS)"
      result=1
    fi
    assert_match "missing credential fails with the file-backed provider diagnostic" \
      'no usable Claude credential found on the host' "$nout" || result=1
    assert_no_match "missing credential prints no completion sentinel" \
      '^credsprobe=ok$' "$nout" || result=1
    assert_no_host_calls || result=1
  else
    emergency_sandbox_cleanup "$CUSTOM_MARKER" || true
    result=1
  fi

  remove_custom_credential_material || result=1
  return "$result"
}

# 12. present but NON-numeric /etc/agent-vm-image-version: the launcher must
# ignore it and still boot+run the program. Contrast custom_image_runs_program,
# which asserts the marker-free image's stamp is ABSENT (do not weaken it).
custom_image_stamp_present() {
  local name="custom-stamp" proj out vname="custom-stamp-value"
  proj="$(custom_project "$name")" || return 1
  capture_custom_launch "$name" "$proj" --no-git --image "$CUSTOM_STAMP" hello-258 || return 1
  require_launch_ok "$name" || return 1
  assert_no_host_calls || return 1
  out="$(read_launch_evidence "$name")" || return 1
  # #258: each evidence read is guarded in its own assignment, so a reader that
  # prints the expected line and then fails cannot be accepted as a pass.
  local hello_line stamp_line
  hello_line="$(evidence_line "stamped hello sentinel" '^hello-258=ok$' "$out")" || return 1
  assert_eq "the stamped image boots the marker-free base program" "hello-258=ok" \
    "$hello_line" || return 1
  stamp_line="$(evidence_line "stamp observation" '^stamp=' "$out")" || return 1
  assert_eq "a present image-version stamp is observed" "stamp=present" \
    "$stamp_line" || return 1

  capture_custom_launch "$vname" "$proj" --no-git --image "$CUSTOM_STAMP" shell \
    bash -c 'stamp=$(cat /etc/agent-vm-image-version) || { printf "stamp_read=failed\n"; exit 1; }; printf "image_stamp=%s\n" "$stamp"' || return 1
  require_launch_ok "$vname" || return 1
  assert_no_host_calls || return 1
  out="$(read_launch_evidence "$vname")" || return 1
  local stamp_literal
  stamp_literal="$(evidence_line "stamp literal" '^image_stamp=' "$out")" || return 1
  assert_eq "the present non-numeric stamp is left untouched" \
    "image_stamp=$CUSTOM_STAMP_LITERAL" \
    "$stamp_literal" || return 1
}

# 9. an imported nonstandard OCI PATH image executes Bash and the program only
# from that prefix, in both identity modes, with no fallback-prefix copy.
custom_image_nonstandard_imported() {
  local mode name proj out
  local host_uid host_gid envjson
  host_uid="$(id -u)"
  host_gid="$(id -g)"

  # Independently source the OCI PATH literal from the built image config (the
  # input acquired by import and push), not from the runtime under test: exactly
  # one PATH= entry, equal to the literal the oracle composes.
  if ! envjson="$(docker image inspect --format '{{json .Config.Env}}' "$CUSTOM_NONSTANDARD")"; then
    echo "    FAIL: could not inspect the $CUSTOM_NONSTANDARD image config"
    return 1
  fi
  if ! jq -e --arg p "PATH=$NONSTANDARD_OCI_PATH" \
      'type == "array" and ([.[] | select(type == "string" and startswith("PATH="))] | length == 1) and (index($p) != null)' \
      <<<"$envjson" >/dev/null; then
    echo "    FAIL: $CUSTOM_NONSTANDARD does not declare exactly PATH=$NONSTANDARD_OCI_PATH"
    printf '%s\n' "$envjson"
    return 1
  fi

  for mode in nonroot root; do
    name="custom-nonstandard-$mode"
    local -a root_flag=()
    [ "$mode" = root ] && root_flag=(--root)
    proj="$(custom_project "$name")" || return 1
    capture_custom_launch "$name" "$proj" --no-git ${root_flag[@]+"${root_flag[@]}"} \
      --image "$CUSTOM_NONSTANDARD" hello-258 || return 1
    require_launch_ok "$name" || return 1
    assert_no_host_calls || return 1
    out="$(launch_output "$name")"
    expect_effective_path "$mode imported" "$out" || return 1
    if [ "$mode" = root ]; then
      assert_eq "$mode: uid" "uid=0" "$(grep '^uid=' <<<"$out")" || return 1
      assert_eq "$mode: gid" "gid=0" "$(grep '^gid=' <<<"$out")" || return 1
      assert_eq "$mode: HOME" "home=/root" "$(grep '^home=' <<<"$out")" || return 1
      assert_eq "$mode: project bind owner" "project_owner=0:0" "$(grep '^project_owner=' <<<"$out")" || return 1
    else
      assert_eq "$mode: uid" "uid=$host_uid" "$(grep '^uid=' <<<"$out")" || return 1
      assert_eq "$mode: gid" "gid=$host_gid" "$(grep '^gid=' <<<"$out")" || return 1
      assert_eq "$mode: HOME" "home=$CUSTOM_HOME" "$(grep '^home=' <<<"$out")" || return 1
      assert_eq "$mode: project bind owner" "project_owner=$host_uid:$host_gid" "$(grep '^project_owner=' <<<"$out")" || return 1
    fi
  done
}

# 10. genuinely uncached refs published to a local registry: cold first
# acquisition through the real CLI, then an offline warm boot of the same refs.
custom_image_nonstandard_cold_warm() {
  local container port ref_nonroot ref_root suffix_n suffix_r result=0
  local proj_n proj_r name out
  # Create the projects before starting the registry container: a failure here
  # must not leave a running container behind on the early-return path (#258).
  proj_n="$(custom_project "custom-cold-nonroot")" || return 1
  proj_r="$(custom_project "custom-cold-root")" || return 1
  local reg="registry:3@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8"
  container="$(docker run -d --rm -p 127.0.0.1::5000 "$reg")" ||
    { echo "    BLOCKER: could not start the local registry container"; return 1; }
  [ -n "$container" ] || { echo "    BLOCKER: no registry container id"; return 1; }
  port="$(docker port "$container" 5000/tcp | head -1 | sed 's/.*://')"
  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    echo "    BLOCKER: no single numeric mapped registry port"
    docker rm -f "$container" >/dev/null 2>&1 || true
    return 1
  fi
  ref_nonroot="localhost:$port/e2e-258-$RUN_ID:cold-nonroot"
  ref_root="localhost:$port/e2e-258-$RUN_ID:cold-root"
  suffix_n="e2e-258-$RUN_ID:cold-nonroot"
  suffix_r="e2e-258-$RUN_ID:cold-root"

  local deadline=$(( $(date +%s) + 30 )) ready=0
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [ "$ready" -ne 1 ]; then
    echo "    BLOCKER: registry not ready on 127.0.0.1:$port"
    docker rm -f "$container" >/dev/null 2>&1 || true
    return 1
  fi

  docker tag "$CUSTOM_NONSTANDARD" "$ref_nonroot" || result=1
  docker tag "$CUSTOM_NONSTANDARD" "$ref_root" || result=1
  docker push "$ref_nonroot" >/dev/null || result=1
  docker push "$ref_root" >/dev/null || result=1
  if [ "$result" -ne 0 ]; then
    echo "    BLOCKER: could not push the cold refs to the local registry"
    docker rm -f "$container" >/dev/null 2>&1 || true
    return 1
  fi

  # Neither ref may exist in the msb image catalog before the first launch: this
  # is a genuinely cold first acquisition.
  image_catalog_has "$ref_nonroot" "$suffix_n" absent || result=1
  image_catalog_has "$ref_root" "$suffix_r" absent || result=1
  if [ "$result" -ne 0 ]; then
    docker rm -f "$container" >/dev/null 2>&1 || true
    return 1
  fi

  capture_custom_launch "custom-cold-nonroot" "$proj_n" --no-git --image "$ref_nonroot" hello-258 write cold-258 || result=1
  require_launch_ok "custom-cold-nonroot" || result=1
  capture_custom_launch "custom-cold-root" "$proj_r" --no-git --root --image "$ref_root" hello-258 write cold-258 || result=1
  require_launch_ok "custom-cold-root" || result=1
  assert_no_host_calls || result=1
  for name in custom-cold-nonroot custom-cold-root; do
    out="$(launch_output "$name")"
    expect_effective_path "$name cold" "$out" || result=1
    assert_eq "$name: cold completion sentinel" "hello-258=ok" \
      "$(grep '^hello-258=ok$' <<<"$out")" || result=1
    assert_eq "$name: cold declared link target" \
      "declared_link=/agent-vm-state/persist/.hello-258.state" "$(grep '^declared_link=' <<<"$out")" || result=1
  done
  assert_eq "cold nonroot uid" "uid=$(id -u)" "$(grep '^uid=' <<<"$(launch_output custom-cold-nonroot)")" || result=1
  assert_eq "cold nonroot gid" "gid=$(id -g)" "$(grep '^gid=' <<<"$(launch_output custom-cold-nonroot)")" || result=1
  assert_eq "cold nonroot HOME" "home=$CUSTOM_HOME" "$(grep '^home=' <<<"$(launch_output custom-cold-nonroot)")" || result=1
  assert_eq "cold nonroot direct state owner" "direct_owner_after_write=$(id -u):$(id -g)" \
    "$(grep '^direct_owner_after_write=' <<<"$(launch_output custom-cold-nonroot)")" || result=1
  assert_eq "cold root uid" "uid=0" "$(grep '^uid=' <<<"$(launch_output custom-cold-root)")" || result=1
  assert_eq "cold root gid" "gid=0" "$(grep '^gid=' <<<"$(launch_output custom-cold-root)")" || result=1
  assert_eq "cold root HOME" "home=/root" "$(grep '^home=' <<<"$(launch_output custom-cold-root)")" || result=1
  assert_eq "cold root direct state owner" "direct_owner_after_write=0:0" \
    "$(grep '^direct_owner_after_write=' <<<"$(launch_output custom-cold-root)")" || result=1

  # Acquisition must have recorded the approved child in the image catalog. A
  # pinned launch consumes `repo@digest`; the mutable tag is not a cache key, so
  # the catalog entry is content-addressed rather than tag-named (#390).
  local digest_n digest_r
  digest_n="$(jq -r --arg ref "$ref_nonroot" \
    '.pins[] | select(.reference == $ref) | .manifest_digest' \
    "$CUSTOM_HOME/.config/agent-vm/image-pins.json")" || result=1
  digest_r="$(jq -r --arg ref "$ref_root" \
    '.pins[] | select(.reference == $ref) | .manifest_digest' \
    "$CUSTOM_HOME/.config/agent-vm/image-pins.json")" || result=1
  if [ -z "$digest_n" ] || [ -z "$digest_r" ]; then
    echo "    FAIL: no pin recorded for the cold refs"
    result=1
  fi
  image_catalog_has "$ref_nonroot" "e2e-258-$RUN_ID@$digest_n" present || result=1
  image_catalog_has "$ref_root" "e2e-258-$RUN_ID@$digest_r" present || result=1
  assert_custom_cache_isolated "after cold launches" yes || result=1

  docker rm -f "$container" >/dev/null 2>&1 ||
    { echo "    FAIL: registry container removal failed"; result=1; }

  # Warm/offline: the same refs boot again with the registry gone, keep the OCI
  # PATH, execute the program and read back the cold boot's persisted sentinel.
  capture_custom_launch "custom-warm-nonroot" "$proj_n" --no-git --image "$ref_nonroot" hello-258 read nonroot || result=1
  require_launch_ok "custom-warm-nonroot" || result=1
  capture_custom_launch "custom-warm-root" "$proj_r" --no-git --root --image "$ref_root" hello-258 read root || result=1
  require_launch_ok "custom-warm-root" || result=1
  assert_no_host_calls || result=1
  for name in custom-warm-nonroot custom-warm-root; do
    out="$(launch_output "$name")"
    expect_effective_path "$name warm" "$out" || result=1
    assert_eq "$name: warm cold sentinel read back" "declared=cold-258" \
      "$(grep '^declared=' <<<"$out")" || result=1
    assert_eq "$name: warm completion sentinel" "hello-258=ok" \
      "$(grep '^hello-258=ok$' <<<"$out")" || result=1
    assert_no_match "$name: no offline pull/fallback" "pulling|Pulling|Downloading|downloading" "$out" || result=1
  done
  assert_eq "warm nonroot uid" "uid=$(id -u)" "$(grep '^uid=' <<<"$(launch_output custom-warm-nonroot)")" || result=1
  assert_eq "warm root HOME" "home=/root" "$(grep '^home=' <<<"$(launch_output custom-warm-root)")" || result=1
  assert_custom_cache_isolated "after warm launches" yes || result=1
  return "$result"
}

# ---- #259 config-selected custom images ----

# A project `image` selects the boot image with no flag; tool edits and former
# `.agent-vm/layers/` + `.agent-vm/layer/` poison directories keep it fixed.
custom_image_selected_by_project_config() {
  local name="custom-selected-project" proj out
  proj="$WORK/$name"
  mkdir -p "$proj/.agent-vm" || return 1
  cat >"$proj/.agent-vm/config.toml" <<EOF || return 1
image = "$CUSTOM_MARKER"
[[tools]]
name = "hello-258"
command = "hello-258"
persist = [".hello-258.state"]
EOF
  capture_custom_launch "$name" "$proj" --no-git hello-258 || return 1
  require_launch_ok "$name" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output "$name")"
  assert_single_boot_ref "project config selects the image" "$CUSTOM_MARKER" "$out" || return 1
  assert_eq "project-config completion sentinel" "hello-258=ok" "$(grep '^hello-258=ok$' <<<"$out")" || return 1
  assert_eq "project-config uid" "uid=$(id -u)" "$(grep '^uid=' <<<"$out")" || return 1
  assert_eq "project-config HOME" "home=$CUSTOM_HOME" "$(grep '^home=' <<<"$out")" || return 1

  # Changed tool args/catalog and former layer poison directories: selection is
  # still the project image, and no builder ran.
  mkdir -p "$proj/.agent-vm/layers/10-poison" "$proj/.agent-vm/layer" || return 1
  printf '!! not a dockerfile\n' >"$proj/.agent-vm/layers/10-poison/Dockerfile"
  printf '?? legacy\n' >"$proj/.agent-vm/layer/Dockerfile"
  cat >"$proj/.agent-vm/config.toml" <<EOF || return 1
image = "$CUSTOM_MARKER"
[[tools]]
name = "hello-258"
command = "hello-258"
args = ["extra"]
persist = [".hello-258.state"]

[[tools]]
name = "second-258"
command = "hello-258"
EOF
  capture_custom_launch "custom-selected-poisoned" "$proj" --no-git hello-258 || return 1
  require_launch_ok "custom-selected-poisoned" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output custom-selected-poisoned)"
  assert_single_boot_ref "poisoned config still selects the image" "$CUSTOM_MARKER" "$out" || return 1
}

# An image-only user config keeps the shipped runtime tools and selects the
# image for both a shipped shell and a project-declared tool. The user config is
# removed afterward, including on failure.
custom_image_user_image_only_config() {
  local rc=0
  _custom_image_user_image_only_body || rc=1
  rm -f "$CUSTOM_HOME/.config/agent-vm/config.toml" || rc=1
  return "$rc"
}

_custom_image_user_image_only_body() {
  mkdir -p "$CUSTOM_HOME/.config/agent-vm" || return 1
  cat >"$CUSTOM_HOME/.config/agent-vm/config.toml" <<EOF || return 1
image = "$CUSTOM_MARKER"
EOF
  local empty_proj="$WORK/custom-user-image-empty"
  mkdir -p "$empty_proj" || return 1

  # Help and doctor expose the seven shipped runtime tools (an image-only file
  # declares zero tools, so the shipped defaults apply).
  local out tool
  out="$(cd "$empty_proj" && "${CUSTOM_ENV[@]}" HOME="$CUSTOM_HOME" "$AGENT_VM" --help 2>&1)" || return 1
  for tool in dsh pi codex opencode claude copilot shell; do
    grep -qE "^  $tool " <<<"$out" || {
      echo "    FAIL: help does not list $tool under an image-only user config"
      return 1
    }
  done
  out="$(cd "$empty_proj" && "${CUSTOM_ENV[@]}" HOME="$CUSTOM_HOME" "$AGENT_VM" doctor 2>&1)" || return 1
  grep -qE '^  7\. shell -> ' <<<"$out" || {
    echo "    FAIL: doctor does not list the seven shipped tools under an image-only user config"
    return 1
  }
  grep -qF "selected (without --image): $CUSTOM_MARKER" <<<"$out" || {
    echo "    FAIL: doctor does not show the image-only selection"
    return 1
  }

  # The shipped `shell` boots the selected image; the image is allowed to lack
  # the other shipped agents.
  capture_custom_launch "custom-user-image-shell" "$empty_proj" --no-git shell \
    bash -c 'command -v hello-258 && printf "image-only=ok\n"' || return 1
  require_launch_ok "custom-user-image-shell" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output custom-user-image-shell)"
  assert_single_boot_ref "image-only user config selects the image" "$CUSTOM_MARKER" "$out" || return 1
  assert_match "image-only shell completed" '^image-only=ok$' "$out" || return 1

  # The same user image selection with a project that declares its own tool.
  local proj
  proj="$(custom_project custom-user-image-tools)" || return 1
  capture_custom_launch "custom-user-image-tools" "$proj" --no-git hello-258 || return 1
  require_launch_ok "custom-user-image-tools" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output custom-user-image-tools)"
  assert_single_boot_ref "user image with project tools" "$CUSTOM_MARKER" "$out" || return 1
  assert_eq "user-image project tool sentinel" "hello-258=ok" "$(grep '^hello-258=ok$' <<<"$out")" || return 1
}

# Parse every `[debug] sandbox config JSON:` and `[debug] native image
# acquisition JSON:` dump from a captured stream as a complete JSON object
# (python3's decoder), printing one `name<TAB>Oci ref` per dump. A native
# acquisition has no sandbox name, so its fixed `kind` is the row name. Malformed
# JSON after a marker is an error, never a dropped dump.
parse_acquisition_dumps() {
  local file="$1"
  python3 - "$file" <<'PY'
import json
import sys

text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
markers = {
    "[debug] sandbox config JSON: ": "sandbox",
    "[debug] native image acquisition JSON: ": "native",
}
decoder = json.JSONDecoder()
found = []
for marker, kind in markers.items():
    index = 0
    while True:
        start = text.find(marker, index)
        if start < 0:
            break
        found.append((start, start + len(marker), kind))
        index = start + len(marker)
rows = []
for _, start, kind in sorted(found):
    while start < len(text) and text[start] in " \t\r\n":
        start += 1
    try:
        obj, end = decoder.raw_decode(text, start)
    except json.JSONDecodeError as error:
        print(f"malformed debug JSON: {error}", file=sys.stderr)
        sys.exit(1)
    if kind == "native":
        if obj.get("kind") != "native-image-acquire":
            print("unexpected native acquisition kind", file=sys.stderr)
            sys.exit(1)
        rows.append(f"native-image-acquire\t{obj.get('reference', '<none>')}")
    else:
        name = obj.get("name", "<none>")
        try:
            ref = obj["image"]["Oci"]["reference"]
        except (KeyError, TypeError):
            ref = "<none>"
        rows.append(f"{name}\t{ref}")
for row in rows:
    print(row)
PY
}

# Require the capture to hold exactly one native acquisition record and one
# setup-verification sandbox config, each carrying the expected reference. Fields
# are compared **whole**, never as a substring: a wrong-reference suffix, a
# duplicated name, a missing name, an extra name, a stale `agent-vm-pull` sandbox
# record, or any other reference all fail. `$3` is the reference the native
# acquisition must carry; `$4`, when given, is the reference the verification
# config must carry *instead*. They differ exactly when the acquisition validated
# an immutable child: setup boots the verification sandbox from that validated
# `repo@child` so its `IfMissing` create consumes the entry the acquisition
# measured instead of re-resolving the selected spelling. `$2` names the row this
# call is primarily asserting, for the message.
assert_dump() {
  local dumps="$1" expected_name="$2" ref="$3" verify_ref="${4:-$3}"
  local -a rows=()
  local line
  while IFS= read -r line; do
    rows+=("$line")
  done <<<"$dumps"

  if [ "${#rows[@]}" -ne 2 ]; then
    echo "    FAIL: want exactly two acquisition dumps, found ${#rows[@]}"
    printf '%s\n' "$dumps"
    return 1
  fi

  local name dumped matched=0
  local -a names=()
  for line in "${rows[@]}"; do
    name="${line%%	*}"
    dumped="${line#*	}"
    case "$name" in
      native-image-acquire | agent-vm-setup-verify) ;;
      *)
        echo "    FAIL: unexpected acquisition dump name: [$name]"
        printf '%s\n' "$dumps"
        return 1
        ;;
    esac
    local want="$ref"
    if [ "$name" = agent-vm-setup-verify ]; then want="$verify_ref"; fi
    if [ "$dumped" != "$want" ]; then
      echo "    FAIL: the $name dump carries [$dumped], want exactly [$want]"
      printf '%s\n' "$dumps"
      return 1
    fi
    if [ "$name" = "$expected_name" ]; then
      matched=$((matched + 1))
    fi
    names+=("$name")
  done
  if [ "$matched" -ne 1 ]; then
    local want_ref="$ref"
    if [ "$expected_name" = agent-vm-setup-verify ]; then want_ref="$verify_ref"; fi
    echo "    FAIL: want exactly one $expected_name dump with reference [$want_ref], found $matched"
    printf '%s\n' "$dumps"
    return 1
  fi
  if [ "${names[0]}" = "${names[1]}" ]; then
    echo "    FAIL: duplicate acquisition dump name: ${names[0]}"
    printf '%s\n' "$dumps"
    return 1
  fi
}

# #259: a reachable selected image reaches setup's verification step. The two
# built acquisition configs (initial pull, then verify) must each carry an exact
# reference -- not the decoy or the default: the initial pull the *selected*
# spelling, and the verification sandbox the immutable `repo@child` the
# acquisition validated (setup consumes those exact bytes, so its `IfMissing`
# create cannot re-resolve the selected spelling). The verify-only mutation
# overrides verify_image's `.image(image)`, which this check then fails on, while
# the initial pull stays correct.
#
# The child digest is read from the registry (`registry_host_manifest_digest`,
# the same envelope→child resolution a pull performs), never from the dump being
# checked. `msb image list` holds that child identity after a cold setup -- the
# verification create persisted it -- and no row for the selected tag, because a
# native acquisition does not write the SDK's reference table. The tag must still
# be launchable, so a warm launch of it afterwards must consume the cached entry
# with zero registry manifest/blob reads.
#
# setup verifies exactly the *declared* tools and fails on any of them, on any
# image. The synthesized `shell` fallback is not a declaration, so this config
# declares only `hello-258` (which answers `--version`); `bash` is deliberately
# not verified. A config that declared nothing would fall back to the seven
# shipped tools and fail, which is the separate point of the `custom-user-image-*`
# checks below (they never call setup). After the positive assertions this check
# also runs `custom_image_setup_verification_negative`, reusing its pushed image.
custom_image_setup_verification_uses_selected_ref() {
  local name="custom-setup-verify" proj="$WORK/custom-setup-verify-proj"
  mkdir -p "$proj/.agent-vm" || return 1
  local reg="registry:3@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8"
  local container port repo selected decoy suffix child acquired result=0
  container="$(docker run -d --rm -p 127.0.0.1::5000 "$reg")" ||
    { echo "    BLOCKER: could not start the local registry container"; return 1; }
  [ -n "$container" ] || { echo "    BLOCKER: no registry container id"; return 1; }
  port="$(docker port "$container" 5000/tcp | head -1 | sed 's/.*://')"
  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    echo "    BLOCKER: no single numeric mapped registry port"
    docker rm -f "$container" >/dev/null 2>&1 || true
    return 1
  fi
  repo="e2e-259-$RUN_ID"
  selected="localhost:$port/$repo:selected"
  decoy="localhost:$port/$repo:decoy"
  suffix="$repo:selected"

  local deadline=$(( $(date +%s) + 30 )) ready=0
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [ "$ready" -ne 1 ]; then
    echo "    BLOCKER: registry not ready on 127.0.0.1:$port"
    docker rm -f "$container" >/dev/null 2>&1 || true
    return 1
  fi

  # Tag/push before any decoy can enter PATH.
  docker tag "$CUSTOM_MARKER" "$selected" || result=1
  docker tag "$CUSTOM_MARKER" "$decoy" || result=1
  docker push "$selected" >/dev/null || result=1
  docker push "$decoy" >/dev/null || result=1
  if [ "$result" -ne 0 ]; then
    echo "    BLOCKER: could not push the selected/decoy refs"
    docker rm -f "$container" >/dev/null 2>&1 || true
    return 1
  fi

  # Only `hello-258` is declared, and every declared tool must answer
  # `--version`; the `shell` fallback is not verified. `persist` is what makes the
  # fixture's no-argument mode reach its completion sentinel: the warm launch below
  # asserts a real guest run, not merely a resolved image.
  cat >"$proj/.agent-vm/config.toml" <<EOF || result=1
image = "$selected"
[[tools]]
name = "hello-258"
command = "hello-258"
persist = [".hello-258.state"]
EOF
  image_catalog_has "$selected" "$suffix" absent || result=1
  # The immutable identity the acquisition will validate, from the registry.
  child="$(registry_host_manifest_digest "$port" "$repo" selected)" || result=1
  if [ -z "$child" ]; then
    echo "    FAIL: could not read the selected tag's host child digest from the registry"
    result=1
  fi
  acquired="localhost:$port/$repo@$child"

  if [ "$result" -eq 0 ]; then
    observe_launch "$name" "$proj" "$WORK/$name.out" -- \
      "${CUSTOM_ENV[@]}" "${OFFLINE_ENV[@]}" \
      XDG_CONFIG_HOME="$WORK/offline-config" PATH="$SHIM_DIR:/usr/bin:/bin" \
      HOME="$CUSTOM_HOME" \
      HOST_SHIM_LOG="$HOST_SHIM_LOG" \
      AGENT_VM_DEBUG_CONFIG=1 \
      "$AGENT_VM" setup || result=1
  fi
  if [ "$result" -eq 0 ]; then
    local dumps out
    require_launch_ok "$name" || result=1
    assert_no_host_calls || result=1
    dumps="$(parse_acquisition_dumps "$WORK/$name.out")" || result=1
    assert_dump "$dumps" "native-image-acquire" "$selected" "$acquired" || result=1
    assert_dump "$dumps" "agent-vm-setup-verify" "$selected" "$acquired" || result=1
    out="$(launch_output "$name")"
    assert_match "setup reports the selected image ready" "^==> $selected ready$" "$out" || result=1
    assert_no_match "setup never selects the decoy" "$decoy" "$out" || result=1
    # The catalog holds the identity the verification create persisted, and the
    # decoy was never acquired at all.
    image_catalog_has "$acquired" "/$repo@$child" present || result=1
    image_catalog_has "$decoy" "/$repo:decoy" absent || result=1
    assert_custom_cache_isolated "after setup verification" yes || result=1

    # The selected tag must stay launchable after the setup acquisition. The
    # native pull stored the resolved child under the *selected* key, so this
    # warm launch consumes it; a registry manifest/blob read here would mean the
    # tag did not survive the acquisition as a usable cache entry.
    local reads_before reads_after
    reads_before="$(registry_read_count_calibrated "$container" \
      "http://127.0.0.1:$port/v2/$repo/manifests/selected")" || result=1
    capture_custom_launch "custom-setup-warm" "$proj" --no-git hello-258 || result=1
    require_launch_ok "custom-setup-warm" || result=1
    assert_no_host_calls || result=1
    out="$(launch_output custom-setup-warm)"
    assert_eq "a warm launch of the selected tag runs the declared tool" "hello-258=ok" \
      "$(grep '^hello-258=ok$' <<<"$out")" || result=1
    reads_after="$(registry_read_count "$container")" || result=1
    assert_eq "a warm launch of the selected tag makes zero registry manifest/blob reads" \
      "$reads_before" "$reads_after" || result=1
  fi

  # F5: the two failure diagnoses, with real guest evidence, against the same
  # pushed image.
  if [ "$result" -eq 0 ]; then
    custom_image_setup_verification_negative "$selected" || result=1
  fi

  docker rm -f "$container" >/dev/null 2>&1 ||
    { echo "    FAIL: registry container removal failed"; result=1; }
  return "$result"
}

# F5: the setup verification diagnostic's failure cases, each against a real
# guest. `$1` is a registry-hosted image already pushed by the caller.
#
# (a) A declared bare command name the image does not carry on `PATH` must fail
# as "not found on the guest `PATH`". (b) A declared command that is present on
# `PATH` but not executable (the `marker-free` fixture installs `noexec-258` mode
# 0644) must fail as "not executable". Each must exit non-zero and must not claim
# the other case.
custom_image_setup_verification_negative() {
  local selected="$1" result=0 name proj out

  name="custom-setup-absent"
  proj="$WORK/$name-proj"
  mkdir -p "$proj/.agent-vm" || return 1
  cat >"$proj/.agent-vm/config.toml" <<EOF || return 1
image = "$selected"
[[tools]]
name = "absent-258"
command = "not-in-this-image-258"
EOF
  observe_launch "$name" "$proj" "$WORK/$name.out" -- \
    "${CUSTOM_ENV[@]}" "${OFFLINE_ENV[@]}" \
    XDG_CONFIG_HOME="$WORK/offline-config" PATH="$SHIM_DIR:/usr/bin:/bin" \
    HOME="$CUSTOM_HOME" \
    HOST_SHIM_LOG="$HOST_SHIM_LOG" \
    "$AGENT_VM" setup || result=1
  if [ "$CAPTURE_STATUS" -eq 0 ]; then
    echo "    FAIL: setup must fail when a declared command is not found on the guest PATH"
    result=1
  fi
  assert_no_host_calls || result=1
  out="$(launch_output "$name")"
  assert_match "absent declared command names the command" "not-in-this-image-258" "$out" || result=1
  assert_match "absent declared command reports the missing case" "not found on the guest" "$out" || result=1
  assert_no_match "absent declared command is not called non-executable" "not executable" "$out" || result=1
  assert_no_match "absent declared command is not called broken" "broken in this image" "$out" || result=1

  name="custom-setup-noexec"
  proj="$WORK/$name-proj"
  mkdir -p "$proj/.agent-vm" || return 1
  cat >"$proj/.agent-vm/config.toml" <<EOF || return 1
image = "$selected"
[[tools]]
name = "noexec-258"
command = "noexec-258"
EOF
  observe_launch "$name" "$proj" "$WORK/$name.out" -- \
    "${CUSTOM_ENV[@]}" "${OFFLINE_ENV[@]}" \
    XDG_CONFIG_HOME="$WORK/offline-config" PATH="$SHIM_DIR:/usr/bin:/bin" \
    HOME="$CUSTOM_HOME" \
    HOST_SHIM_LOG="$HOST_SHIM_LOG" \
    "$AGENT_VM" setup || result=1
  if [ "$CAPTURE_STATUS" -eq 0 ]; then
    echo "    FAIL: setup must fail when a declared command is present but not executable"
    result=1
  fi
  assert_no_host_calls || result=1
  out="$(launch_output "$name")"
  assert_match "non-executable declared command names the command" "noexec-258" "$out" || result=1
  assert_match "non-executable declared command reports the case" "not executable" "$out" || result=1
  assert_no_match "non-executable declared command is not called missing" "not found on the guest" "$out" || result=1
  assert_no_match "non-executable declared command is not called broken" "broken in this image" "$out" || result=1

  return "$result"
}

# ---- PTY attach checks (macOS BSD `script`) ----

check_custom_no_bash_attach() {
  local name="custom-attach-no-bash" proj out result=0
  proj="$(custom_project "$name")" || return 1
  if ! capture_custom_attach "$name" "$proj" --no-git --image "$CUSTOM_NO_BASH" hello-258; then
    emergency_sandbox_cleanup "$CUSTOM_NO_BASH" || true
    return 1
  fi
  out="$(attach_output "$name")"
  assert_match "attach used the attach branch" "Attaching to" "$out" || result=1
  assert_match "attach no-Bash contract diagnostic" 'has no runnable `bash`' "$out" || result=1
  assert_single_logs_ref "attach no-Bash names the log dir once" "$out" || result=1
  assert_no_match "attach no ExecFailed Debug dump" 'ExecFailed \{' "$out" || result=1
  assert_no_match "attach no deadline/cleanup error" "timed out|cleanup failed" "$out" || result=1
  assert_no_match "attach no hello success sentinel" "^hello-258=ok$" "$out" || result=1
  assert_no_match "attach no hello identity output" "^uid=" "$out" || result=1
  assert_single_boot_ref "attach no-Bash boots only the selected image" "$CUSTOM_NO_BASH" "$out" || result=1
  assert_no_host_calls || result=1
  assert_no_catalog_entry "$CUSTOM_NO_BASH" || result=1
  if [ "$result" -ne 0 ]; then emergency_sandbox_cleanup "$CUSTOM_NO_BASH" || true; fi
  return "$result"
}

# Conflicting OCI USER app + ENV HOME=/home/app under a real PTY: the launcher
# identity/HOME override wins, writes and owner bits hold, and an independent
# PTY session reads the persisted sentinels back.
check_custom_user_home_attach() {
  local mode="$1" name="custom-attach-user-$1" proj out result=0
  local -a root_flag=()
  [ "$mode" = root ] && root_flag=(--root)
  proj="$(custom_project "$name")" || return 1
  local expected_home expected_owner
  if [ "$mode" = root ]; then
    expected_home=/root
    expected_owner=0:0
  else
    expected_home="$CUSTOM_HOME"
    expected_owner="$(id -u):$(id -g)"
  fi

  if ! capture_custom_attach "$name" "$proj" --no-git ${root_flag[@]+"${root_flag[@]}"} \
    --image "$CUSTOM_USER_HOME" hello-258 write "attach-258-$mode"; then
    return 1
  fi
  out="$(attach_output "$name")"
  assert_match "attach write: took the attach branch" "Attaching to" "$out" || result=1
  # `script`'s exit status does not have to equal the guest's, so a positive
  # attach session is proven by the program's own completion sentinel plus the
  # identity it printed, never by the driver's status alone.
  assert_match "attach write: guest completed" "^hello-258=ok$" "$out" || result=1
  if [ "$mode" = root ]; then
    assert_eq "attach write: uid 0" "uid=0" "$(grep '^uid=' <<<"$out")" || result=1
  else
    assert_eq "attach write: host uid" "uid=$(id -u)" "$(grep '^uid=' <<<"$out")" || result=1
  fi
  assert_eq "attach write: HOME" "home=$expected_home" "$(grep '^home=' <<<"$out")" || result=1
  assert_eq "attach write: project bind owner" "project_owner_after_write=$expected_owner" \
    "$(grep '^project_owner_after_write=' <<<"$out")" || result=1
  assert_eq "attach write: declared link target" \
    "declared_link=/agent-vm-state/persist/.hello-258.state" "$(grep '^declared_link=' <<<"$out")" || result=1
  assert_no_host_calls || result=1

  local read="$name-read"
  if ! capture_custom_attach "$read" "$proj" --no-git ${root_flag[@]+"${root_flag[@]}"} \
    --image "$CUSTOM_USER_HOME" hello-258 read "$mode"; then
    return 1
  fi
  out="$(attach_output "$read")"
  assert_match "attach read: guest completed" "^hello-258=ok$" "$out" || result=1
  assert_eq "attach read: declared sentinel" "declared=attach-258-$mode" "$(grep '^declared=' <<<"$out")" || result=1
  assert_eq "attach read: project sentinel" "project=attach-258-$mode" "$(grep '^project=' <<<"$out")" || result=1
  assert_eq "attach read: direct sentinel" "direct=attach-258-$mode" "$(grep '^direct=' <<<"$out")" || result=1
  assert_eq "attach read: state bind owner" "state_owner=$expected_owner" "$(grep '^state_owner=' <<<"$out")" || result=1
  assert_no_host_calls || result=1
  return "$result"
}

# One imported nonstandard-PATH attach run proves the per-exec `.env(PATH)`
# override is applied on the attach path too.
check_custom_nonstandard_attach() {
  local name="custom-attach-nonstandard" proj out result=0
  proj="$(custom_project "$name")" || return 1
  if ! capture_custom_attach "$name" "$proj" --no-git --image "$CUSTOM_NONSTANDARD" hello-258; then
    return 1
  fi
  out="$(attach_output "$name")"
  assert_match "attach: took the attach branch" "Attaching to" "$out" || result=1
  assert_match "attach: guest completed" "^hello-258=ok$" "$out" || result=1
  expect_effective_path "attach imported" "$out" || result=1
  assert_no_host_calls || result=1
  return "$result"
}

# ------------------------------------------- retained default (#261) -------

# The registry's own `docker-content-digest` for a pushed tag: the digest-pinned
# reference a record must carry comes from the registry, never from a guess.
registry_manifest_digest() {
  local port="$1" repo="$2" tag="$3" headers digest
  headers="$(curl -fsS -o /dev/null -D - \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
    "http://127.0.0.1:$port/v2/$repo/manifests/$tag")" || return 1
  digest="$(awk 'tolower($1)=="docker-content-digest:"{ gsub(/\r/,""); print $2 }' <<<"$headers")"
  [ -n "$digest" ] || return 1
  printf '%s' "$digest"
}

# Manifest/blob read requests the registry served, from its own access log. Only
# the anchored Apache combined record counts: registry v3 also emits trace spans
# whose names contain the request path, and counting those doubled every figure.
# A `docker logs` failure is a failure, never a vacuous zero. The optional second
# argument narrows the count to one exact manifest path (tag, index or digest).
registry_read_count() {
  local container="$1" path="${2:-}" pattern logs count status=0
  if [ -n "$path" ]; then
    pattern="^[^ ]+ - - \[.*\] \"(GET|HEAD) /v2/$path "
  else
    pattern='^[^ ]+ - - \[.*\] "(GET|HEAD) /v2/[^ ]*/(manifests|blobs)/'
  fi
  logs="$(docker logs "$container" 2>&1)" || return 1
  count="$(grep -cE "$pattern" <<<"$logs")" || status=$?
  case "$status" in
    0) printf '%s' "$count" ;;
    1) printf '0' ;;
    *) return "$status" ;;
  esac
}

# Registry access logs flush asynchronously, so an earlier acquisition's records
# can land after that launch exits. A zero-delta claim is only meaningful behind
# an ordered barrier: make one calibration request and wait until its own access
# record is visible. Any earlier record must already be visible at that point.
registry_read_count_calibrated() {
  local container="$1" url="$2" path="${3:-}" before target count deadline
  before="$(registry_read_count "$container" "$path")" || return 1
  target=$((before + 1))
  curl -fsS -o /dev/null \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
    "$url" || return 1
  deadline=$(( $(date +%s) + 15 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    count="$(registry_read_count "$container" "$path")" || return 1
    if [ "$count" -ge "$target" ]; then
      printf '%s' "$count"
      return 0
    fi
    sleep 1
  done
  echo "    FAIL: the calibration read was never recorded" >&2
  return 1
}

# The retained-default check's own private HOME/state (never the shared custom
# root): its record must be invisible to every other check. `retained_env`
# rebuilds LAUNCH_ENV with or without the debug-only initial-recommendation
# seam; `AGENT_VM_DEBUG_CONFIG=1` reveals the acquisition config (the default
# tier's reference is redacted there, so the guest stamp below is the oracle).
RETAINED_HOME=""
RETAINED_STATE=""
AGENT_VM_RETAINED_BIN=""
LAUNCH_ENV=()

retained_env() {
  local seam="${1:-}" shared=(
    env
    -u AGENT_VM_IMAGE_TAG
    -u AGENT_VM_ROOT
    -u AGENT_VM_SHARE_MSB_CACHE
    -u AGENT_VM_MSB_CACHE_DIR
    -u MSB_CONFIG_PATH
    -u AGENT_VM_TEST_DEFAULT_IMAGE
    AGENT_VM_STATE_DIR="$RETAINED_STATE"
    HOME="$RETAINED_HOME"
    AGENT_VM_DEBUG_CONFIG=1
  )
  if [ -n "$seam" ]; then
    LAUNCH_ENV=("${shared[@]}" AGENT_VM_TEST_DEFAULT_IMAGE="$seam")
  else
    LAUNCH_ENV=("${shared[@]}")
  fi
}

retained_launch() {
  local name="$1" proj="$2"
  shift 2
  observe_launch "$name" "$proj" "$WORK/$name.out" -- \
    "${LAUNCH_ENV[@]}" "${OFFLINE_ENV[@]}" \
    XDG_CONFIG_HOME="$WORK/offline-config" PATH="$SHIM_DIR:/usr/bin:/bin" \
    HOST_SHIM_LOG="$HOST_SHIM_LOG" \
    "$AGENT_VM_RETAINED_BIN" "$@"
}

retained_record() {
  printf '%s' "$RETAINED_HOME/.config/agent-vm/default-image.json"
}

# `agent-vm msb ...` against the retained check's private state/HOME.
avm_retained_state() {
  env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_ROOT -u AGENT_VM_SHARE_MSB_CACHE \
    -u AGENT_VM_MSB_CACHE_DIR -u MSB_CONFIG_PATH -u AGENT_VM_TEST_DEFAULT_IMAGE \
    AGENT_VM_STATE_DIR="$RETAINED_STATE" HOME="$RETAINED_HOME" \
    "$AGENT_VM_DEV_BIN" "$@"
}

# Run `doctor` against a private, empty HOME/state with an optional initial
# recommendation seam; return its exit status (2 for a probe-setup failure). An
# *absent* record is required so the seam, not a retained record, decides.
retained_probe_doctor() {
  local bin="$1" seam="$2" probe_home="$3" probe_state="$4"
  mkdir -p "$probe_home" "$probe_state/msb-home" || return 2
  local base=(env
    -u AGENT_VM_IMAGE_TAG -u AGENT_VM_ROOT -u AGENT_VM_SHARE_MSB_CACHE
    -u AGENT_VM_MSB_CACHE_DIR -u MSB_CONFIG_PATH -u AGENT_VM_TEST_DEFAULT_IMAGE
    HOME="$probe_home" AGENT_VM_STATE_DIR="$probe_state")
  if [ -n "$seam" ]; then
    "${base[@]}" AGENT_VM_TEST_DEFAULT_IMAGE="$seam" "$bin" doctor >/dev/null 2>&1
  else
    "${base[@]}" "$bin" doctor >/dev/null 2>&1
  fi
}

# 0 = a debug build (a tag-only seam is rejected, so `doctor` exits nonzero);
# 1 = a release build (the seam is compiled out, so `doctor` exits 0); 2 = the
# healthy no-seam baseline itself failed, so the probe proves nothing.
retained_bin_honors_seam() {
  local bin="$1"
  retained_probe_doctor "$bin" "" "$WORK/seam-base-h" "$WORK/seam-base-s" || return 2
  retained_probe_doctor "$bin" "localhost:1/seam-probe:latest" \
    "$WORK/seam-debug-h" "$WORK/seam-debug-s" && return 1
  return 0
}

# The complement: 0 = a release build ignores the seam; 1 = a debug build (or an
# inconclusive probe). Both slots are classified so a debug binary in the release
# slot is refused, not merely tolerated.
retained_bin_ignores_seam() {
  local bin="$1"
  retained_probe_doctor "$bin" "" "$WORK/seam-base-rh" "$WORK/seam-base-rs" || return 2
  retained_probe_doctor "$bin" "localhost:1/seam-probe:latest" \
    "$WORK/seam-release-h" "$WORK/seam-release-s" && return 0
  return 1
}

# 11. #261: the default is a digest bookmark, adopted only after a successful
# default-tier acquisition; it survives a changed launcher recommendation, is
# not probed from the registry on a warm launch, and is never substituted by
# the recommendation or lost when a cache is cold.
custom_image_retained_default() {
  local result=0 container="" port repo ref_a ref_b digest_a digest_b
  local proj out host_uid host_gid dev_bin rel_bin
  local cold_state="$WORK/rst" empty_state="$WORK/rest"
  local reg="registry:3@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8"

  proj="$(custom_project "retained-default")" || return 1
  # Two explicit, validated candidates: a missing one is a failure, never a
  # silent skip (CONTRIBUTING: native prerequisites are required).
  dev_bin="$AGENT_VM_DEV_BIN"
  rel_bin="$AGENT_VM_RELEASE_BIN"
  if [ ! -x "$dev_bin" ]; then
    echo "    BLOCKER: the debug launcher $dev_bin is absent (set AGENT_VM_DEV_BIN)"
    return 1
  fi
  if [ ! -x "$rel_bin" ]; then
    echo "    BLOCKER: the release launcher $rel_bin is absent (set AGENT_VM_RELEASE_BIN);"
    echo "             the retained-default check requires a debug *and* a release launcher"
    return 1
  fi
  if ! retained_bin_honors_seam "$dev_bin"; then
    echo "    BLOCKER: the debug candidate $dev_bin does not honour"
    echo "             AGENT_VM_TEST_DEFAULT_IMAGE (release build, or an inconclusive probe);"
    echo "             set AGENT_VM_DEV_BIN to a debug launcher"
    return 1
  fi
  if ! retained_bin_ignores_seam "$rel_bin"; then
    echo "    BLOCKER: the release candidate $rel_bin honours the debug seam"
    echo "             (a debug build is in the release slot, or the probe was inconclusive);"
    echo "             set AGENT_VM_RELEASE_BIN to a release launcher"
    return 1
  fi

  RETAINED_HOME="$WORK/rh"
  RETAINED_STATE="$cold_state"
  AGENT_VM_RETAINED_BIN="$dev_bin"
  mkdir -p "$RETAINED_HOME" "$RETAINED_STATE/msb-home" || return 1
  retained_env
  "${LAUNCH_ENV[@]}" "$dev_bin" msb --version >/dev/null 2>&1 ||
    { echo "    BLOCKER: could not initialize the private state root at $RETAINED_STATE"; return 1; }

  container="$(docker run -d --rm -p 127.0.0.1::5000 "$reg")" ||
    { echo "    BLOCKER: could not start the local registry container"; return 1; }
  port="$(docker port "$container" 5000/tcp | head -1 | sed 's/.*://')"
  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    echo "    BLOCKER: no single numeric mapped registry port"
    docker rm -f "$container" >/dev/null 2>&1 || true
    return 1
  fi

  local deadline=$(( $(date +%s) + 30 )) ready=0
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [ "$ready" -ne 1 ]; then
    echo "    BLOCKER: registry not ready on 127.0.0.1:$port"
    docker rm -f "$container" >/dev/null 2>&1 || true
    return 1
  fi

  repo="e2e-261-$RUN_ID"
  # A and B differ in the guest-visible image stamp, so the *guest* proves which
  # image booted (A prints stamp=absent, B stamp=present); both still supply the
  # same hello-258 program.
  docker tag "$CUSTOM_MARKER" "localhost:$port/$repo:default-a" || result=1
  docker tag "$CUSTOM_STAMP" "localhost:$port/$repo:default-b" || result=1
  docker push "localhost:$port/$repo:default-a" >/dev/null || result=1
  docker push "localhost:$port/$repo:default-b" >/dev/null || result=1
  digest_a="$(registry_manifest_digest "$port" "$repo" default-a)" || result=1
  digest_b="$(registry_manifest_digest "$port" "$repo" default-b)" || result=1
  if [ "$result" -ne 0 ] || [ -z "$digest_a" ] || [ -z "$digest_b" ]; then
    echo "    BLOCKER: could not publish the recommendation refs to the registry"
    docker rm -f "$container" >/dev/null 2>&1 || true
    return 1
  fi
  ref_a="localhost:$port/$repo@$digest_a"
  ref_b="localhost:$port/$repo@$digest_b"
  [ "$ref_a" != "$ref_b" ] || { echo "    FAIL: the two recommendations are the same digest"; result=1; }

  # (1) A genuinely cold first launch through the debug recommendation seam
  # acquires A and *adopts* it: the record names exactly A.
  retained_env "$ref_a"
  retained_launch "retained-cold" "$proj" --no-git hello-258 write cold-acquire
  require_launch_ok "retained-cold" || result=1
  assert_no_host_calls || result=1
  out="$(launch_output retained-cold)"
  host_uid="$(id -u)"
  host_gid="$(id -g)"
  assert_eq "retained cold: uid" "uid=$host_uid" "$(grep '^uid=' <<<"$out")" || result=1
  assert_eq "retained cold: gid" "gid=$host_gid" "$(grep '^gid=' <<<"$out")" || result=1
  assert_eq "retained cold: HOME" "home=$RETAINED_HOME" "$(grep '^home=' <<<"$out")" || result=1
  assert_eq "retained cold: completion sentinel" "hello-258=ok" "$(grep '^hello-258=ok$' <<<"$out")" || result=1
  assert_eq "retained cold: the recommendation booted (stamp absent)" "stamp=absent" \
    "$(grep '^stamp=' <<<"$out")" || result=1
  if [ ! -f "$(retained_record)" ]; then
    echo "    FAIL: a successful default-tier acquisition did not adopt a record"
    result=1
  fi
  local record_before
  record_before="$(cat "$(retained_record)" 2>/dev/null || true)"
  if ! grep -qF "$ref_a" <<<"$record_before"; then
    echo "    FAIL: the retained record does not name the acquired digest: $record_before"
    result=1
  fi

  # (2) A launcher whose recommendation changed (B) still boots the retained A,
  # and a warm ordinary launch makes NO registry manifest/blob request: the
  # default is not tag-polled or re-probed.
  local reads_before reads_after
  reads_before="$(registry_read_count_calibrated "$container" \
    "http://127.0.0.1:$port/v2/$repo/manifests/default-a")" || result=1
  retained_env "$ref_b"
  retained_launch "retained-warm-b" "$proj" --no-git hello-258
  require_launch_ok "retained-warm-b" || result=1
  assert_no_host_calls || result=1
  out="$(launch_output retained-warm-b)"
  assert_eq "retained warm: still boots A, not recommendation B (stamp absent)" "stamp=absent" \
    "$(grep '^stamp=' <<<"$out")" || result=1
  assert_eq "retained warm: completion sentinel" "hello-258=ok" "$(grep '^hello-258=ok$' <<<"$out")" || result=1
  assert_eq "retained warm: record unchanged" "$record_before" "$(cat "$(retained_record)")" || result=1
  reads_after="$(registry_read_count "$container")" || result=1
  assert_eq "retained warm launch makes zero registry manifest/blob reads" "$reads_before" "$reads_after" || result=1

  # (3) A *fresh* private cache under the same HOME cannot substitute the
  # recommendation: A is re-acquired from the registry and B never executes.
  RETAINED_STATE="$empty_state"
  mkdir -p "$RETAINED_STATE/msb-home" || result=1
  retained_env "$ref_b"
  retained_launch "retained-cold-cache-b" "$proj" --no-git hello-258
  require_launch_ok "retained-cold-cache-b" || result=1
  assert_no_host_calls || result=1
  out="$(launch_output retained-cold-cache-b)"
  assert_eq "cold cache: A is re-acquired, not recommendation B (stamp absent)" "stamp=absent" \
    "$(grep '^stamp=' <<<"$out")" || result=1
  assert_eq "cold cache: completion sentinel" "hello-258=ok" "$(grep '^hello-258=ok$' <<<"$out")" || result=1
  assert_eq "cold cache: record unchanged" "$record_before" "$(cat "$(retained_record)")" || result=1

  # (4) Post-acquisition adoption failure: the image *is* acquired (registry
  # up), but the record cannot be written (a directory stands in for the lock).
  # The guest command must not run and the sandbox must be torn down.
  local fail_home="$WORK/rh-fail" fail_state="$WORK/rst-fail" sandboxes
  RETAINED_HOME="$fail_home"
  RETAINED_STATE="$fail_state"
  mkdir -p "$fail_home/.config/agent-vm/default-image.lock" "$fail_state/msb-home" || result=1
  retained_env "$ref_a"
  retained_launch "retained-adopt-fail" "$proj" --no-git hello-258
  if [ "$CAPTURE_STATUS" -eq 0 ]; then
    echo "    FAIL: an adoption failure after a successful acquisition must fail the launch"
    result=1
  fi
  out="$(launch_output retained-adopt-fail)"
  assert_no_match "adopt-fail: the guest command must not run" "hello-258=ok" "$out" || result=1
  # The failure must be the *retention/storage* stage, not an acquisition
  # failure: #390's journaled transaction reports one closed pin-authority
  # storage error when the fallback lock cannot be opened.
  assert_match "adopt-fail: names the pin authority stage" \
    'image pin authority at \$HOME/\.config/agent-vm/image-pins\.json could not be accessed or saved' \
    "$out" || result=1
  assert_match "adopt-fail: the acquisition itself succeeded" \
    '"kind": "native-image-acquire"' "$out" || result=1
  if [ -f "$fail_home/.config/agent-vm/default-image.json" ]; then
    echo "    FAIL: a failed adoption must leave the record absent"
    result=1
  fi
  sandboxes="$(avm_retained_state msb list --format json 2>/dev/null)" ||
    { echo "    FAIL: could not list the sandbox catalog after the failed adoption"; result=1; sandboxes='[]'; }
  if ! printf '%s' "$sandboxes" | jq -e 'type == "array" and length == 0' >/dev/null; then
    echo "    FAIL: a sandbox lingered after a failed adoption: $sandboxes"
    result=1
  fi

  # (5) Offline from the warm cache: the retained image and its persisted state
  # survive with the registry gone.
  docker rm -f "$container" >/dev/null 2>&1 ||
    { echo "    FAIL: registry container removal failed"; result=1; }
  container=""
  RETAINED_HOME="$WORK/rh"
  RETAINED_STATE="$cold_state"
  retained_env "$ref_b"
  retained_launch "retained-offline" "$proj" --no-git hello-258 read nonroot
  require_launch_ok "retained-offline" || result=1
  assert_no_host_calls || result=1
  out="$(launch_output retained-offline)"
  assert_eq "offline: persisted sentinel read back" "declared=cold-acquire" \
    "$(grep '^declared=' <<<"$out")" || result=1
  assert_eq "offline: completion sentinel" "hello-258=ok" "$(grep '^hello-258=ok$' <<<"$out")" || result=1
  assert_eq "offline: record unchanged" "$record_before" "$(cat "$(retained_record)")" || result=1

  # (6) The release binary must use the retained record too (the debug-only seam
  # is compiled out), still booting A offline. Release coverage is required, not
  # skipped; both candidates were validated up front.
  AGENT_VM_RETAINED_BIN="$rel_bin"
  retained_env "$ref_b"
  retained_launch "retained-release" "$proj" --no-git hello-258
  require_launch_ok "retained-release" || result=1
  assert_no_host_calls || result=1
  out="$(launch_output retained-release)"
  assert_eq "release: the debug seam is not an override; A is booted (stamp absent)" "stamp=absent" \
    "$(grep '^stamp=' <<<"$out")" || result=1
  assert_eq "release: completion sentinel" "hello-258=ok" "$(grep '^hello-258=ok$' <<<"$out")" || result=1
  AGENT_VM_RETAINED_BIN="$dev_bin"

  # (7) Registry gone and a cold private cache: the retained A cannot be
  # acquired, the launch fails, record A survives, and nothing substitutes it.
  rm -rf "$empty_state" || result=1
  RETAINED_STATE="$empty_state"
  mkdir -p "$RETAINED_STATE/msb-home" || result=1
  retained_env "$ref_b"
  retained_launch "retained-unreachable" "$proj" --no-git hello-258
  if [ "$CAPTURE_STATUS" -eq 0 ]; then
    echo "    FAIL: an unreachable retained digest must fail the launch"
    result=1
  fi
  out="$(launch_output retained-unreachable)"
  assert_no_match "unreachable: no substitute program ran" "hello-258=ok" "$out" || result=1
  assert_eq "unreachable: record still A" "$record_before" "$(cat "$(retained_record)")" || result=1

  [ -n "$container" ] || return "$result"
  docker rm -f "$container" >/dev/null 2>&1 || { echo "    FAIL: registry container removal failed"; result=1; }
  return "$result"
}

# Docker's image store may push an OCI index even for a host-only fixture.
# Upgrade retains the child manifest, not that envelope digest.
registry_host_manifest_digest() {
  local port="$1" repo="$2" tag="$3" doc child
  doc="$(curl -fsS -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json'     "http://127.0.0.1:$port/v2/$repo/manifests/$tag")" || return 1
  child="$(jq -r '[.manifests[]? | select(.platform.os == "linux" and .platform.architecture == "arm64") | .digest][0] // empty' <<<"$doc")" || return 1
  if [ -n "$child" ]; then printf '%s' "$child"; else registry_manifest_digest "$port" "$repo" "$tag"; fi
}

# Publication shares the operator's local daemon, not registry credentials or
# credential helpers. Only its Unix endpoint is carried into test-owned config.
UPGRADE_DOCKER_HOST=""
upgrade_docker() {
  env -u DOCKER_CONTEXT -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH -u DOCKER_API_VERSION     DOCKER_HOST="$UPGRADE_DOCKER_HOST" DOCKER_CONFIG="$RETAINED_HOME/docker"     "$REAL_DOCKER" "$@"
}

# Native metadata is an inventory input, not an unchanged-content oracle. Hash
# full artifact bytes and VMDK extents independently before a failed upgrade.
upgrade_cache_snapshot() {
  python3 - "$RETAINED_STATE/msb-home/cache" "$1" "$2" "$WORK/upgrade-b-manifest.json" <<'PY'
import hashlib, json, pathlib, re, sys
cache, ref, output = pathlib.Path(sys.argv[1]), sys.argv[2], pathlib.Path(sys.argv[3])
digest = ref.split('@', 1)[1]
paths = set()
for path in (cache / 'manifests').glob('*.json'):
    doc = json.loads(path.read_bytes())
    if doc['manifest_digest'] != digest:
        continue
    # Native metadata reserializes the parsed manifest. Verify its semantics
    # against independently fetched registry bytes, not that serialization hash.
    fixture = pathlib.Path(sys.argv[4])
    assert 'sha256:' + hashlib.sha256(fixture.read_bytes()).hexdigest() == digest
    assert json.loads(doc['raw_manifest_json']) == json.loads(fixture.read_bytes())
    assert 'sha256:' + hashlib.sha256(doc['raw_config_json'].encode()).hexdigest() == doc['config_digest']
    config = json.loads(doc['raw_config_json'])
    assert config['rootfs']['diff_ids'] == [layer['diff_id'] for layer in doc['layers']]
    paths.add(path)
    safe = digest.replace(':', '_')
    paths.add(cache / 'fsmeta' / (safe + '.erofs'))
    descriptor = cache / 'vmdk' / (safe + '.vmdk')
    paths.add(descriptor)
    for line in descriptor.read_text().splitlines():
        if line.startswith(('RW ', 'RDONLY ')):
            extent = pathlib.Path(re.search(r'"([^"]+)"', line)[1])
            paths.add(extent if extent.is_absolute() else descriptor.parent / extent)
    for layer in doc['layers']:
        paths.add(cache / 'layers' / (layer['diff_id'].replace(':', '_') + '.erofs'))
        blob = cache / 'layers' / (layer['digest'].replace(':', '_') + '.tar.gz')
        if blob.exists(): paths.add(blob)
assert paths, 'no cached metadata for retained digest'
inventory = {}
for path in paths:
    data = path.read_bytes()
    inventory[str(path)] = [len(data), hashlib.sha256(data).hexdigest()]
output.write_text(json.dumps(inventory, sort_keys=True))
PY
}

# Count manifest/blob access records in one registry log text. Registry v3
# asynchronously emits duplicate trace spans whose names contain GET paths
# after the request has already completed, so only the anchored Apache combined
# access record counts. grep status 1 is a legitimate no-match (zero); any other
# failure is an observation error and must never become a zero.
upgrade_access_record_count() {
  local count status=0
  count="$(grep -cE '^[^ ]+ - - \[.*\] "(GET|HEAD) /v2/[^ ]*/(manifests|blobs)/' <<<"$1")" || status=$?
  case "$status" in
    0) printf '%s' "$count" ;;
    1) printf '0' ;;
    *) return "$status" ;;
  esac
}

upgrade_registry_read_count() {
  local logs
  logs="$(upgrade_docker logs "$1" 2>&1)" || return 1
  upgrade_access_record_count "$logs"
}

# A fresh tick proves guest execution continued, not merely that the launcher
# process and a stale status file survived.
upgrade_live_advanced() {
  local dir="$1" pid="$2" old_tick="$3" deadline=$(( $(date +%s) + 15 ))
  while [ "$(date +%s)" -lt "$deadline" ] && kill -0 "$pid" 2>/dev/null; do
    if [ -f "$dir/tick" ] && [ "$(cat "$dir/tick")" != "$old_tick" ]; then return 0; fi
    sleep 1
  done
  echo '    FAIL: live A guest did not advance its handshake'
  return 1
}

custom_image_default_upgrade() {
  local result=0 container port repo ref_a ref_b proj live out reads_before reads_after
  local live_pid=0 identity tick catalog_before pids_before deadline ready=0
  local reg="registry:3@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8"
  [ -x "$AGENT_VM_DEV_BIN" ] && [ -x "$AGENT_VM_RELEASE_BIN" ] || return 1
  retained_bin_honors_seam "$AGENT_VM_DEV_BIN" || return 1
  retained_bin_ignores_seam "$AGENT_VM_RELEASE_BIN" || return 1
  RETAINED_HOME="$WORK/uh"
  RETAINED_STATE="$WORK/ust"
  AGENT_VM_RETAINED_BIN="$AGENT_VM_DEV_BIN"
  mkdir -p "$RETAINED_HOME/docker" "$RETAINED_STATE/msb-home" || return 1
  printf '{"auths":{}}\n' > "$RETAINED_HOME/docker/config.json"
  UPGRADE_DOCKER_HOST="${DOCKER_HOST:-$(docker context inspect --format '{{.Endpoints.docker.Host}}')}" || return 1
  case "$UPGRADE_DOCKER_HOST" in
    unix://*) ;;
    *) echo '    BLOCKER: #262 fixtures require a local Unix Docker endpoint for credential-isolated publication'; return 1 ;;
  esac
  proj="$(custom_project upgrade-probe)" || return 1
  live="$(custom_project upgrade-live)" || return 1
  container="$(upgrade_docker run -d --rm -p 127.0.0.1::5000 "$reg")" || return 1
  port="$(upgrade_docker port "$container" 5000/tcp | head -1 | sed 's/.*://')"
  deadline=$(( $(date +%s) + 30 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  if [ "$ready" -ne 1 ]; then upgrade_docker rm -f "$container" >/dev/null; return 1; fi
  repo="e2e-262-$RUN_ID"
  upgrade_docker tag "$CUSTOM_MARKER" "localhost:$port/$repo:a" || result=1
  upgrade_docker tag "$CUSTOM_STAMP" "localhost:$port/$repo:b" || result=1
  upgrade_docker push "localhost:$port/$repo:a" >/dev/null || result=1
  upgrade_docker push "localhost:$port/$repo:b" >/dev/null || result=1
  ref_a="localhost:$port/$repo@$(registry_manifest_digest "$port" "$repo" a)" || result=1
  ref_b="localhost:$port/$repo@$(registry_host_manifest_digest "$port" "$repo" b)" || result=1
  curl -fsS -H 'Accept: application/vnd.oci.image.manifest.v1+json'     "http://127.0.0.1:$port/v2/$repo/manifests/${ref_b##*@}" > "$WORK/upgrade-b-manifest.json" || result=1
  retained_env "$ref_a"
  retained_launch upgrade-cold "$proj" --no-git hello-258 || result=1
  require_launch_ok upgrade-cold || result=1
  out="$(launch_output upgrade-cold)"
  assert_eq 'upgrade cold guest A' stamp=absent "$(grep '^stamp=' <<<"$out")" || result=1
  grep -qF "$ref_a" "$(retained_record)" || result=1
  if [ "$result" -eq 0 ]; then
    # Same guest Bash process writes its identity and stamp on each observation.
    # A separate project prevents B's launch from replacing A by sandbox name.
    (cd "$live" || exit 1; exec "${LAUNCH_ENV[@]}" "${OFFLINE_ENV[@]}" \
      DOCKER_CONFIG="$RETAINED_HOME/docker" XDG_CONFIG_HOME="$WORK/offline-config" \
      PATH="$SHIM_DIR:/usr/bin:/bin" HOST_SHIM_LOG="$HOST_SHIM_LOG" \
      "$AGENT_VM_DEV_BIN" --no-git --mount "$live:/probe" shell bash -c \
      'for ((i=0;i<180;i++)); do printf "%s\n" "$$" > /probe/identity; hello-258 > /probe/status.tmp; mv /probe/status.tmp /probe/status; printf "%s\n" "$i" > /probe/tick; [ ! -e /probe/stop ] || exit 0; sleep 1; done; exit 94') \
      > "$WORK/upgrade-live.out" 2>&1 </dev/null &
    live_pid=$!
    deadline=$(( $(date +%s) + 60 ))
    while { [ ! -f "$live/status" ] || [ ! -f "$live/tick" ]; } && [ "$(date +%s)" -lt "$deadline" ] && kill -0 "$live_pid" 2>/dev/null; do sleep 1; done
    if [ ! -f "$live/status" ] || [ ! -f "$live/tick" ]; then result=1; else
      identity="$(cat "$live/identity")"
      tick="$(cat "$live/tick")"
      grep -q '^stamp=absent$' "$live/status" || result=1
      catalog_before="$(avm_retained_state msb list --format json)" || result=1
      pids_before="$(runtime_pids)" || result=1
      retained_env
      AGENT_VM_RETAINED_BIN="$AGENT_VM_RELEASE_BIN"
      retained_launch upgrade-command "$proj" image set-default --image "$ref_b" || result=1
      require_launch_ok upgrade-command || result=1
      assert_eq 'upgrade creates no sandbox entries' "$catalog_before" "$(avm_retained_state msb list --format json)" || result=1
      assert_eq 'upgrade creates no VM processes' "$pids_before" "$(runtime_pids)" || result=1
      jq -e --arg ref "$ref_b" '.version == 1 and .image == $ref' "$(retained_record)" >/dev/null || result=1
      kill -0 "$live_pid" 2>/dev/null || result=1
      upgrade_live_advanced "$live" "$live_pid" "$tick" || result=1
      assert_eq 'live A process identity unchanged' "$identity" "$(cat "$live/identity")" || result=1
      grep -q '^stamp=absent$' "$live/status" || result=1
      assert_no_host_calls || result=1
      retained_launch upgrade-new-b "$proj" --no-git hello-258 || result=1
      require_launch_ok upgrade-new-b || result=1
      grep -q '^stamp=present$' "$WORK/upgrade-new-b.out" || result=1
      cp "$(retained_record)" "$WORK/upgrade-record-before"
      upgrade_cache_snapshot "$ref_b" "$WORK/upgrade-cache-before" || result=1
      tick="$(cat "$live/tick")"
      retained_launch upgrade-failure "$proj" image set-default --image "localhost:$port/$repo:unavailable" || result=1
      [ "$CAPTURE_STATUS" -eq 1 ] || result=1
      cmp "$(retained_record)" "$WORK/upgrade-record-before" || result=1
      upgrade_cache_snapshot "$ref_b" "$WORK/upgrade-cache-after" || result=1
      cmp "$WORK/upgrade-cache-before" "$WORK/upgrade-cache-after" || result=1
      kill -0 "$live_pid" 2>/dev/null || result=1
      upgrade_live_advanced "$live" "$live_pid" "$tick" || result=1
      assert_eq 'failed upgrade leaves live A identity' "$identity" "$(cat "$live/identity")" || result=1
      grep -q '^stamp=absent$' "$live/status" || result=1
    fi
    touch "$live/stop"
    deadline=$(( $(date +%s) + 30 ))
    while kill -0 "$live_pid" 2>/dev/null && [ "$(date +%s)" -lt "$deadline" ]; do sleep 1; done
    if kill -0 "$live_pid" 2>/dev/null; then
      kill -TERM "$live_pid" 2>/dev/null || true
      sleep 5
      kill -KILL "$live_pid" 2>/dev/null || true
      result=1
    fi
    wait "$live_pid" || result=1
  fi
  upgrade_docker logs "$container" > "$WORK/upgrade-registry-before.log" 2>&1 || result=1
  reads_before="$(upgrade_registry_read_count "$container")" || result=1
  # Non-vacuous negative oracle: the cold acquisition, the explicit upgrade and
  # the failed acquisition must already be visible as access records before a
  # zero-warm claim means anything. Then one deliberate live manifest read must
  # increment the same counter; the registry access log flushes asynchronously,
  # so wait for the increment within a bounded deadline.
  if [ "${reads_before:-0}" -le 0 ]; then
    echo "    FAIL: cold/upgrade produced no observable registry access records"
    result=1
  fi
  local cal_target=$(( ${reads_before:-0} + 1 )) cal_deadline
  curl -fsS -o /dev/null \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
    "http://127.0.0.1:$port/v2/$repo/manifests/a" || result=1
  cal_deadline=$(( $(date +%s) + 15 ))
  while [ "$(date +%s)" -lt "$cal_deadline" ]; do
    reads_before="$(upgrade_registry_read_count "$container")" || { result=1; break; }
    if [ "$reads_before" -ge "$cal_target" ]; then break; fi
    sleep 1
  done
  assert_eq 'one live manifest read increments the access oracle' "$cal_target" "$reads_before" || result=1
  retained_env "$ref_a"
  AGENT_VM_RETAINED_BIN="$AGENT_VM_DEV_BIN"
  retained_launch upgrade-warm "$proj" --no-git hello-258 || result=1
  require_launch_ok upgrade-warm || result=1
  out="$(launch_output upgrade-warm)"
  assert_eq 'changed recommendation still boots B' stamp=present "$(grep '^stamp=' <<<"$out")" || result=1
  AGENT_VM_RETAINED_BIN="$AGENT_VM_RELEASE_BIN"
  retained_env
  retained_launch upgrade-release-warm "$proj" --no-git hello-258 || result=1
  require_launch_ok upgrade-release-warm || result=1
  reads_after="$(upgrade_registry_read_count "$container")" || result=1
  upgrade_docker logs "$container" > "$WORK/upgrade-registry-after.log" 2>&1 || result=1
  assert_eq 'warm default makes zero registry reads' "$reads_before" "$reads_after" || result=1
  # Adjacent override boundaries use guest stamps, not notices. User A must
  # outrank project B, env B must outrank user A, and CLI B must outrank env A.
  # The project-only case then repoints the project fixture to A, so project A
  # must outrank the retained default B: a launcher that ignored project
  # overrides would fall through to retained B (stamp=present) and fail there.
  printf 'image = "%s"\n' "$ref_a" > "$RETAINED_HOME/.config/agent-vm/config.toml"
  cp "$proj/.agent-vm/config.toml" "$WORK/upgrade-project-before"
  { printf 'image = "%s"\n' "$ref_b"; cat "$WORK/upgrade-project-before"; } > "$proj/.agent-vm/config.toml"
  cp "$proj/.agent-vm/config.toml" "$WORK/upgrade-project-with-image"
  cp "$RETAINED_HOME/.config/agent-vm/config.toml" "$WORK/upgrade-user-before"
  local tier expected
  for tier in cli env user; do
    retained_env
    expected=stamp=absent
    case "$tier" in
      cli) LAUNCH_ENV+=(AGENT_VM_IMAGE_TAG="$ref_a"); retained_launch "upgrade-$tier" "$proj" --no-git --image "$ref_b" hello-258; expected=stamp=present ;;
      env) LAUNCH_ENV+=(AGENT_VM_IMAGE_TAG="$ref_b"); retained_launch "upgrade-$tier" "$proj" --no-git hello-258; expected=stamp=present ;;
      user) retained_launch "upgrade-$tier" "$proj" --no-git hello-258 ;;
    esac
    require_launch_ok "upgrade-$tier" || result=1
    out="$(launch_output "upgrade-$tier")"
    assert_eq "upgrade override $tier guest" "$expected" "$(grep '^stamp=' <<<"$out")" || result=1
    cmp "$proj/.agent-vm/config.toml" "$WORK/upgrade-project-with-image" || result=1
    cmp "$(retained_record)" "$WORK/upgrade-record-before" || result=1
    cmp "$RETAINED_HOME/.config/agent-vm/config.toml" "$WORK/upgrade-user-before" || result=1
  done
  # Project-only: remove the user tier and repoint the project fixture to A,
  # refreshing its expected-byte snapshot before the guest observation.
  rm "$RETAINED_HOME/.config/agent-vm/config.toml"
  { printf 'image = "%s"\n' "$ref_a"; cat "$WORK/upgrade-project-before"; } > "$proj/.agent-vm/config.toml"
  cp "$proj/.agent-vm/config.toml" "$WORK/upgrade-project-with-image"
  retained_env
  retained_launch upgrade-project "$proj" --no-git hello-258 || result=1
  require_launch_ok upgrade-project || result=1
  out="$(launch_output upgrade-project)"
  assert_eq 'upgrade override project guest' stamp=absent "$(grep '^stamp=' <<<"$out")" || result=1
  cmp "$proj/.agent-vm/config.toml" "$WORK/upgrade-project-with-image" || result=1
  cmp "$(retained_record)" "$WORK/upgrade-record-before" || result=1
  cp "$WORK/upgrade-project-before" "$proj/.agent-vm/config.toml"
  upgrade_docker rm -f "$container" >/dev/null || result=1
  retained_env
  retained_launch upgrade-offline-b "$proj" --no-git hello-258 || result=1
  require_launch_ok upgrade-offline-b || result=1
  out="$(launch_output upgrade-offline-b)"
  assert_eq 'offline default B boots' stamp=present "$(grep '^stamp=' <<<"$out")" || result=1
  retained_launch upgrade-offline-a "$proj" --no-git --image "$ref_a" hello-258 || result=1
  require_launch_ok upgrade-offline-a || result=1
  out="$(launch_output upgrade-offline-a)"
  assert_eq 'old cached A remains bootable' stamp=absent "$(grep '^stamp=' <<<"$out")" || result=1
  assert_no_host_calls || result=1
  return "$result"
}

# ------------------------------------------- host-wide image pins (#390) ---

PINS_HOME=""
PINS_STATE=""
PINS_BIN=""
PINS_ENV=()
PINS_OBSERVER_PID=""

# Every command here runs under one private HOME/state pair, with the inherited
# image/cache overrides cleared and the host decoys first on PATH.
pins_env() {
  local home="$1" state="$2"
  PINS_HOME="$home"
  PINS_STATE="$state"
  PINS_ENV=(env
    -u AGENT_VM_IMAGE_TAG -u AGENT_VM_ROOT -u AGENT_VM_SHARE_MSB_CACHE
    -u AGENT_VM_MSB_CACHE_DIR -u MSB_CONFIG_PATH -u AGENT_VM_TEST_DEFAULT_IMAGE
    HOME="$home" AGENT_VM_STATE_DIR="$state")
}

pins_launch() {
  local name="$1" proj="$2"
  shift 2
  observe_launch "$name" "$proj" "$WORK/$name.out" -- \
    "${PINS_ENV[@]}" "${OFFLINE_ENV[@]}" \
    XDG_CONFIG_HOME="$WORK/offline-config" PATH="$SHIM_DIR:/usr/bin:/bin" \
    HOST_SHIM_LOG="$HOST_SHIM_LOG" "$PINS_BIN" "$@"
}

pins_avm() {
  "${PINS_ENV[@]}" "$PINS_BIN" "$@"
}

pins_store() {
  printf '%s' "$PINS_HOME/.config/agent-vm/image-pins.json"
}

pins_record() {
  printf '%s' "$PINS_HOME/.config/agent-vm/default-image.json"
}

# One exact registry access-record count for a manifest path (tag, index or
# digest): the shared counter narrowed to that path.
pins_registry_count() {
  registry_read_count "$1" "$2"
}

# One debug-gate observer for both sockets (#390 test seams). It reports every
# stage, replies `continue`, and holds one named pin stage until the release
# file exists. The log is the ordering oracle.
pins_observer_body() {
  python3 - "$@" <<'PY'
import os, selectors, socket, sys, time

pin_path, acquire_path, log_path, hold, release = sys.argv[1:6]

def listener(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(64)
    server.setblocking(False)
    return server

log = open(log_path, "a", buffering=1)
selector = selectors.DefaultSelector()
for name, path in (("pin", pin_path), ("acquire", acquire_path)):
    selector.register(listener(path), selectors.EVENT_READ, name)

while True:
    for key, _ in selector.select(timeout=1.0):
        connection, _ = key.fileobj.accept()
        connection.settimeout(60)
        data = b""
        while not data.endswith(b"\n") and len(data) < 4096:
            chunk = connection.recv(256)
            if not chunk:
                break
            data += chunk
        stage = data.decode("utf-8", "replace").strip()
        log.write(f"{key.data} {stage}\n")
        log.flush()
        if key.data == "pin" and stage == hold:
            deadline = time.time() + 90
            while not os.path.exists(release) and time.time() < deadline:
                time.sleep(0.05)
        connection.sendall(b"continue\n")
        connection.close()
PY
}

start_pin_observer() {
  local log="$1" hold="$2" release="$3" pin="$WORK/pin-gate.sock" acq="$WORK/acq-gate.sock" deadline
  stop_pin_observer
  rm -f "$pin" "$acq" "$release" "$log"
  pins_observer_body "$pin" "$acq" "$log" "$hold" "$release" >"$WORK/pins-observer.out" 2>&1 &
  PINS_OBSERVER_PID=$!
  deadline=$(( $(date +%s) + 15 ))
  while { [ ! -S "$pin" ] || [ ! -S "$acq" ]; } && [ "$(date +%s)" -lt "$deadline" ]; do sleep 0.1; done
  [ -S "$pin" ] && [ -S "$acq" ]
}

stop_pin_observer() {
  [ -n "${PINS_OBSERVER_PID:-}" ] || return 0
  kill "$PINS_OBSERVER_PID" 2>/dev/null || true
  wait "$PINS_OBSERVER_PID" 2>/dev/null || true
  PINS_OBSERVER_PID=""
}

# A candidate whose blobs are present but whose layer is not a valid archive:
# the tag resolves and the config parses, then native validation fails before
# approval. Deterministic, Docker/buildx-free and unlike a manifest with missing
# blobs (which the registry itself rejects on PUT).
pins_push_unbootable_candidate() {
  local port="$1" repo="$2" tag="$3"
  python3 - "$port" "$repo" "$tag" <<'PY'
import hashlib, json, sys, urllib.request

port, repo, tag = sys.argv[1:4]
base = f"http://127.0.0.1:{port}"


def upload(data):
    request = urllib.request.Request(
        f"{base}/v2/{repo}/blobs/uploads/", data=b"", method="POST"
    )
    location = urllib.request.urlopen(request).headers["Location"]
    if location.startswith("/"):
        location = base + location
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    separator = "&" if "?" in location else "?"
    request = urllib.request.Request(
        f"{location}{separator}digest={digest}",
        data=data,
        method="PUT",
        headers={"Content-Type": "application/octet-stream"},
    )
    urllib.request.urlopen(request).read()
    return digest, len(data)


layer = b"not-a-tarball"
layer_digest, layer_size = upload(layer)
config = json.dumps(
    {
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
        "config": {},
    }
).encode()
config_digest, config_size = upload(config)
manifest = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": config_digest,
        "size": config_size,
    },
    "layers": [
        {
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": layer_digest,
            "size": layer_size,
        }
    ],
}
request = urllib.request.Request(
    f"{base}/v2/{repo}/manifests/{tag}",
    data=json.dumps(manifest).encode(),
    method="PUT",
    headers={"Content-Type": "application/vnd.oci.image.manifest.v1+json"},
)
urllib.request.urlopen(request).read()
PY
}

# Snapshot the approval store while a debug launch is held at a pin stage. The
# SDK-consumption stage is then provably absent at pin commit.
pins_snapshot_at_hold() {
  local log="$1" hold="$2" release="$3" snapdir="$4" deadline
  deadline=$(( $(date +%s) + 90 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -qxF "pin $hold" "$log" 2>/dev/null; then
      mkdir -p "$snapdir" || return 1
      cp "$(pins_store)" "$snapdir/store.json" 2>/dev/null || return 1
      cp "$log" "$snapdir/gate.log" || return 1
      : >"$release" || return 1
      return 0
    fi
    sleep 0.1
  done
  echo "    FAIL: never observed pin stage $hold" >&2
  : >"$release"
  return 1
}

# Deliberate create failure after the pin commit: while the launch is held at
# `pin-committed`, replace its state root with a regular file. Acquisition and
# approval already happened; the SDK's create cannot use the state root.
pins_break_state_at_hold() {
  local log="$1" release="$2" state="$3" marker="$4" deadline
  deadline=$(( $(date +%s) + 90 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -qxF "pin pin-committed" "$log" 2>/dev/null; then
      mv "$state" "$state.held" || return 1
      : >"$state" || return 1
      : >"$marker" || return 1
      : >"$release" || return 1
      return 0
    fi
    sleep 0.1
  done
  echo "    FAIL: never observed the pin commit for the create-failure case" >&2
  : >"$release"
  return 1
}

pins_restore_state() {
  local state="$1" marker="$2"
  [ -f "$marker" ] || return 0
  rm -f "$state"
  if [ -d "$state.held" ] && ! mv "$state.held" "$state"; then
    return 1
  fi
  return 0
}

pins_hold_marker() {
  local snapdir="$1" stage="$2" lines
  [ -f "$snapdir/gate.log" ] || return 1
  grep -qxF "pin $stage" "$snapdir/gate.log" || return 1
  if grep -qF "acquire before-sdk-consume" "$snapdir/gate.log"; then
    echo "    FAIL: the SDK consumed the image before the pin was committed"
    return 1
  fi
  lines="$(wc -l <"$snapdir/gate.log" | tr -d ' ')"
  [ "${lines:-0}" -gt 0 ] || return 1
}

pins_stamp() {
  grep '^stamp=' "$WORK/$1.out" || true
}

# One PTY replacement attempt: stdin is piped into `script`, which gives the
# child a real terminal on both ends. The answer text is the input.
pins_pty_update() {
  local name="$1" input="$2"
  shift 2
  rm -f "$WORK/$name.pty"
  local status=0
  printf '%s' "$input" | /usr/bin/script -q "$WORK/$name.pty" \
    "${PINS_ENV[@]}" "${OFFLINE_ENV[@]}" "$PINS_BIN" "$@" \
    >"$WORK/$name.out" 2>&1 || status=$?
  PIN_PTY_STATUS=$status
  tr -d '\r' <"$WORK/$name.pty" >"$WORK/$name.pty.txt" 2>/dev/null || true
}

pins_pty_text() {
  cat "$WORK/$1.pty.txt" 2>/dev/null || true
}

pins_live_advanced() {
  local dir="$1" pid="$2" old_tick="$3" deadline=$(( $(date +%s) + 15 ))
  while [ "$(date +%s)" -lt "$deadline" ] && kill -0 "$pid" 2>/dev/null; do
    if [ -f "$dir/tick" ] && [ "$(cat "$dir/tick")" != "$old_tick" ]; then return 0; fi
    sleep 1
  done
  echo '    FAIL: live A guest did not advance its tick'
  return 1
}

# 12. #390: every OCI selection is approved host-wide. One registry tag moves
# A→B; the guest stamp (`marker-free` = A prints stamp=absent, `stamp-present` =
# B prints stamp=present) proves which content booted, and exact registry
# access-request counts prove what was (not) consulted. A live A guest runs
# throughout so both update verbs are shown not to touch it.
custom_image_host_pins() {
  local result=0 container="" port repo tag ref_a ref_b digest_a digest_b
  local reg="registry:3@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8"
  local proj live out reads_before reads_after deadline target ready=0
  local live_pid=0 identity="" tick="" rootid="" tag_before digest_before b_before
  local cold_state cold_proj default_home default_state rootfs pin_snapshot default_snapshot docker_host
  # The group's own precondition is Apple Silicon, so the measured host platform
  # these pins are keyed by is exactly linux/arm64.
  local host_arch="arm64"

  if [ ! -x "$AGENT_VM_DEV_BIN" ] || [ ! -x "$AGENT_VM_RELEASE_BIN" ]; then
    echo "    BLOCKER: custom-image-host-pins needs AGENT_VM_DEV_BIN and AGENT_VM_RELEASE_BIN"
    return 1
  fi
  retained_bin_honors_seam "$AGENT_VM_DEV_BIN" || {
    echo "    BLOCKER: AGENT_VM_DEV_BIN does not honour the debug recommendation seam"
    return 1
  }
  retained_bin_ignores_seam "$AGENT_VM_RELEASE_BIN" || {
    echo "    BLOCKER: AGENT_VM_RELEASE_BIN honours the debug recommendation seam"
    return 1
  }
  PINS_BIN="$AGENT_VM_DEV_BIN"
  proj="$(custom_project pins-main)" || return 1
  live="$(custom_project pins-live)" || return 1
  pins_env "$WORK/pins-home" "$WORK/pins-state"
  mkdir -p "$PINS_HOME" "$PINS_STATE/msb-home" || return 1
  "${PINS_ENV[@]}" "$PINS_BIN" msb --version >/dev/null 2>&1 ||
    { echo "    BLOCKER: could not initialize the private state root"; return 1; }
  docker_host="${DOCKER_HOST:-$(docker context inspect --format '{{.Endpoints.docker.Host}}')}" || return 1

  container="$(docker run -d --rm -e REGISTRY_STORAGE_DELETE_ENABLED=true \
    -p 127.0.0.1::5000 "$reg")" ||
    { echo "    BLOCKER: could not start the local registry container"; return 1; }
  port="$(docker port "$container" 5000/tcp | head -1 | sed 's/.*://')"
  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    echo "    BLOCKER: no single numeric mapped registry port"
    docker rm -f "$container" >/dev/null 2>&1 || true
    return 1
  fi
  deadline=$(( $(date +%s) + 30 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  if [ "$ready" -ne 1 ]; then
    echo "    BLOCKER: registry not ready on 127.0.0.1:$port"
    docker rm -f "$container" >/dev/null 2>&1 || true
    return 1
  fi

  repo="e2e-390-$RUN_ID"
  tag="localhost:$port/$repo:pin"
  docker tag "$CUSTOM_MARKER" "$tag" || result=1
  docker push "$tag" >/dev/null || result=1
  digest_a="$(registry_host_manifest_digest "$port" "$repo" pin)" || result=1
  docker tag "$CUSTOM_STAMP" "localhost:$port/$repo:b" || result=1
  docker push "localhost:$port/$repo:b" >/dev/null || result=1
  digest_b="$(registry_host_manifest_digest "$port" "$repo" b)" || result=1
  if [ "$result" -ne 0 ] || [ -z "$digest_a" ] || [ -z "$digest_b" ] || [ "$digest_a" = "$digest_b" ]; then
    echo "    BLOCKER: could not publish or resolve distinct A/B fixture digests"
    docker rm -f "$container" >/dev/null 2>&1 || true
    return 1
  fi
  ref_a="localhost:$port/$repo@$digest_a"
  ref_b="localhost:$port/$repo@$digest_b"
  # Name the identities this row's assertions are about, so the log itself
  # records the A/B content and the platform every pin below is keyed by.
  echo "    A=$ref_a"
  echo "    B=$ref_b platform=linux/$host_arch"

  # ---- the first launch acquires, pins, and only then reaches the SDK ----
  start_pin_observer "$WORK/pins-gate.log" pin-committed "$WORK/pins-release" ||
    { echo "    FAIL: could not start the debug pin observer"; result=1; }
  pins_snapshot_at_hold "$WORK/pins-gate.log" pin-committed "$WORK/pins-release" \
    "$WORK/pins-hold" &
  local watcher=$!
  AGENT_VM_TEST_PIN_GATE="$WORK/pin-gate.sock" \
  AGENT_VM_TEST_ACQUIRE_GATE="$WORK/acq-gate.sock" \
    pins_launch pins-first "$proj" --image "$tag" hello-258 write pins-sentinel || result=1
  wait "$watcher" || result=1
  stop_pin_observer
  require_launch_ok pins-first || result=1
  assert_no_host_calls || result=1
  out="$(launch_output pins-first)"
  assert_eq "first launch boots fixture A" "stamp=absent" "$(grep '^stamp=' <<<"$out")" || result=1
  assert_eq "first launch runs the program" "hello-258=ok" "$(grep '^hello-258=ok$' <<<"$out")" || result=1
  pins_hold_marker "$WORK/pins-hold" pin-committed || result=1
  # The approval key is the reference *and* the measured host Linux platform: the
  # group runs only on Apple Silicon (`linux/arm64`), so naming that architecture
  # is a real assertion rather than a restatement of "an entry exists". A variant
  # is optional in the schema and must be a printable spelling when it is present.
  if ! jq -e --arg ref "$tag" --arg digest "$digest_a" --arg arch "$host_arch" \
    '.version == 1 and (.pins | length) == 1
     and .pins[0].reference == $ref and .pins[0].manifest_digest == $digest
     and .pins[0].platform.os == "linux"
     and .pins[0].platform.architecture == $arch
     and (.pins[0].platform | has("variant"))
     and ((.pins[0].platform.variant == null)
          or (.pins[0].platform.variant | test("^[!-~]{1,64}$")))
     and .pins[0].revision >= 1' \
    "$WORK/pins-hold/store.json" >/dev/null 2>&1; then
    echo "    FAIL: the first pin was not committed for the selected reference and host platform before create"
    cat "$WORK/pins-hold/store.json" 2>/dev/null || true
    result=1
  fi
  if [ -e "$(pins_record)" ]; then
    echo "    FAIL: an explicit CLI selection must not adopt the retained default"
    result=1
  fi

  # A warm pinned launch reads no registry and no mutable tag, even with the
  # removed advisory environment inherited as truthy.
  target="$(registry_read_count_calibrated "$container" \
    "http://127.0.0.1:$port/v2/$repo/manifests/pin" "$repo/manifests/pin")" || result=1
  assert_eq "one live tag read increments the access oracle" "$target" \
    "$(pins_registry_count "$container" "$repo/manifests/pin")" || result=1
  reads_before="$(registry_read_count_calibrated "$container" \
    "http://127.0.0.1:$port/v2/$repo/manifests/$digest_a")" || result=1
  AGENT_VM_UPDATE_CHECK=1 pins_launch pins-warm "$proj" --image "$tag" hello-258 || result=1
  require_launch_ok pins-warm || result=1
  assert_no_host_calls || result=1
  assert_eq "warm pinned launch boots A" "stamp=absent" "$(pins_stamp pins-warm)" || result=1
  reads_after="$(registry_read_count "$container")" || result=1
  assert_eq "warm pinned launch makes zero registry reads" "$reads_before" "$reads_after" || result=1

  # ---- acquisition and approval survive a failed create ----
  pins_env "$WORK/pkh" "$WORK/pkx"
  mkdir -p "$PINS_HOME" "$PINS_STATE/msb-home" || result=1
  "${PINS_ENV[@]}" "$PINS_BIN" msb --version >/dev/null 2>&1 || result=1
  start_pin_observer "$WORK/pins-create-gate.log" pin-committed "$WORK/pins-create-release" ||
    { echo "    FAIL: could not start the create-failure observer"; result=1; }
  pins_break_state_at_hold "$WORK/pins-create-gate.log" "$WORK/pins-create-release" \
    "$PINS_STATE" "$WORK/pins-create-held" &
  watcher=$!
  AGENT_VM_TEST_PIN_GATE="$WORK/pin-gate.sock" \
  AGENT_VM_TEST_ACQUIRE_GATE="$WORK/acq-gate.sock" \
    pins_launch pins-create-fail "$proj" --image "$tag" hello-258 || result=1
  wait "$watcher" || result=1
  stop_pin_observer
  pins_restore_state "$PINS_STATE" "$WORK/pins-create-held" || result=1
  [ -f "$WORK/pins-create-held" ] || { echo "    FAIL: the create-failure stage was not reached"; result=1; }
  if [ "$CAPTURE_STATUS" -eq 0 ]; then
    echo "    FAIL: a deliberately broken state root must fail the create"
    result=1
  fi
  assert_no_match "failed create: the guest must not run" "hello-258=ok" \
    "$(launch_output pins-create-fail)" || result=1
  if ! jq -e --arg ref "$tag" --arg digest "$digest_a" \
    '.pins | length == 1 and .[0].reference == $ref and .[0].manifest_digest == $digest' \
    "$(pins_store)" >/dev/null 2>&1; then
    echo "    FAIL: a post-acquisition create failure must leave the first pin"
    cat "$(pins_store)" 2>/dev/null || true
    result=1
  fi

  # ---- an import alias over the pinned tag does not switch the guest ----
  pins_env "$WORK/pins-home" "$WORK/pins-state"
  pin_snapshot="$(cat "$(pins_store)")"
  DOCKER_HOST="$docker_host" DOCKER_CONFIG="$PINS_HOME/docker" \
    pins_avm image import --docker "$CUSTOM_STAMP" --tag "$tag" \
    >"$WORK/pins-import.out" 2>&1 || {
    echo "    FAIL: importing fixture B over the pinned tag failed"
    cat "$WORK/pins-import.out"
    result=1
  }
  assert_eq "import leaves the approval bytes unchanged" "$pin_snapshot" "$(cat "$(pins_store)")" || result=1
  pins_launch pins-after-import "$proj" --image "$tag" hello-258 || result=1
  require_launch_ok pins-after-import || result=1
  assert_eq "an import alias cannot swap the pinned guest" "stamp=absent" \
    "$(pins_stamp pins-after-import)" || result=1

  # ---- a live A guest keeps running while the tag moves and nothing probes it ----
  (cd "$live" || exit 1; exec "${PINS_ENV[@]}" "${OFFLINE_ENV[@]}" \
    XDG_CONFIG_HOME="$WORK/offline-config" PATH="$SHIM_DIR:/usr/bin:/bin" \
    HOST_SHIM_LOG="$HOST_SHIM_LOG" \
    "$PINS_BIN" --no-git --image "$tag" --mount "$live:/probe" shell bash -c \
    'printf "%s\n" live-sentinel > "$HOME/.hello-258.plain" || exit 3
     for ((i=0;i<240;i++)); do
       printf "%s\n" "$$" > /probe/identity
       hello-258 > /probe/status.tmp 2>/dev/null || true
       mv /probe/status.tmp /probe/status
       printf "%s\n" "$i" > /probe/tick
       [ ! -e /probe/stop ] || exit 0
       sleep 1
     done; exit 94') \
    >"$WORK/pins-live.out" 2>&1 </dev/null &
  live_pid=$!
  deadline=$(( $(date +%s) + 90 ))
  while { [ ! -f "$live/status" ] || [ ! -f "$live/tick" ]; } &&
    [ "$(date +%s)" -lt "$deadline" ] && kill -0 "$live_pid" 2>/dev/null; do sleep 1; done
  if [ ! -f "$live/status" ] || [ ! -f "$live/tick" ]; then
    echo "    FAIL: the live A guest did not start"
    result=1
  else
    identity="$(cat "$live/identity")"
    tick="$(cat "$live/tick")"
    assert_eq "live guest is A" "stamp=absent" "$(grep '^stamp=' "$live/status")" || result=1
    # The guest's own resolved identity: the uid/gid it runs as and the HOME and
    # PATH its rootfs supplies. These are read by the booted guest, so they are
    # the rootfs/identity stamp this row compares after both update verbs.
    rootid="$(grep -E '^(uid|gid|home|path)=' "$live/status")" || result=1
  fi
  docker tag "$CUSTOM_STAMP" "$tag" || result=1
  docker push "$tag" >/dev/null || result=1
  reads_before="$(registry_read_count_calibrated "$container" \
    "http://127.0.0.1:$port/v2/$repo/manifests/$digest_b")" || result=1
  # The removed advisory is inherited by the launch that follows the move too,
  # so "a moved tag is not probed" is measured with the variable set throughout.
  AGENT_VM_UPDATE_CHECK=1 pins_launch pins-moved-warm "$proj" --image "$tag" hello-258 || result=1
  require_launch_ok pins-moved-warm || result=1
  assert_eq "a moved tag does not change the approved guest" "stamp=absent" \
    "$(pins_stamp pins-moved-warm)" || result=1
  reads_after="$(registry_read_count "$container")" || result=1
  assert_eq "a moved tag is not probed" "$reads_before" "$reads_after" || result=1

  # ---- A cold, independent state/cache reacquires A and changes no record --
  pin_snapshot="$(cat "$(pins_store)")"
  if [ -e "$(pins_record)" ]; then default_snapshot="$(cat "$(pins_record)")"; else default_snapshot="<absent>"; fi
  cold_state="$WORK/pcs"
  cold_proj="$(custom_project pins-cold)" || result=1
  mkdir -p "$cold_state/msb-home" || result=1
  tag_before="$(pins_registry_count "$container" "$repo/manifests/pin")" || result=1
  digest_before="$(pins_registry_count "$container" "$repo/manifests/$digest_a")" || result=1
  pins_env "$WORK/pins-home" "$cold_state"
  pins_launch pins-cold "$cold_proj" --image "$tag" hello-258 || result=1
  require_launch_ok pins-cold || result=1
  assert_eq "a cold independent cache reacquires A" "stamp=absent" "$(pins_stamp pins-cold)" || result=1
  assert_eq "a cold cache never queries the moved tag" "$tag_before" \
    "$(pins_registry_count "$container" "$repo/manifests/pin")" || result=1
  if [ "$(pins_registry_count "$container" "$repo/manifests/$digest_a")" -le "$digest_before" ]; then
    echo "    FAIL: the cold cache did not request the approved digest A"
    result=1
  fi
  # Take A out of the registry. Warm A stays usable; a new cold state must fail
  # without requesting the tag or B.
  curl -fsS -X DELETE "http://127.0.0.1:$port/v2/$repo/manifests/$digest_a" >/dev/null || result=1
  pins_env "$WORK/pins-home" "$WORK/pins-state"
  pins_launch pins-warm-unavailable "$proj" --image "$tag" hello-258 || result=1
  require_launch_ok pins-warm-unavailable || result=1
  assert_eq "warm A remains usable after its registry content is gone" "stamp=absent" \
    "$(pins_stamp pins-warm-unavailable)" || result=1
  cold_state="$WORK/pcm"
  cold_proj="$(custom_project pins-cold-missing)" || result=1
  mkdir -p "$cold_state/msb-home" || result=1
  digest_before="$(pins_registry_count "$container" "$repo/manifests/$digest_a")" || result=1
  tag_before="$(pins_registry_count "$container" "$repo/manifests/pin")" || result=1
  b_before="$(pins_registry_count "$container" "$repo/manifests/$digest_b")" || result=1
  pins_env "$WORK/pins-home" "$cold_state"
  pins_launch pins-cold-missing "$cold_proj" --image "$tag" hello-258 || result=1
  if [ "$CAPTURE_STATUS" -eq 0 ]; then
    echo "    FAIL: an unavailable approved digest must fail the cold launch"
    result=1
  fi
  assert_no_match "cold unavailable: the guest must not run" "hello-258=ok" \
    "$(launch_output pins-cold-missing)" || result=1
  if [ "$(pins_registry_count "$container" "$repo/manifests/$digest_a")" -le "$digest_before" ]; then
    echo "    FAIL: the failing cold launch did not request approved digest A"
    result=1
  fi
  assert_eq "cold unavailable: the moved tag is not requested" "$tag_before" \
    "$(pins_registry_count "$container" "$repo/manifests/pin")" || result=1
  assert_eq "cold unavailable: B is not requested" "$b_before" \
    "$(pins_registry_count "$container" "$repo/manifests/$digest_b")" || result=1
  # None of the three cold/independent runs may rewrite either record.
  assert_eq "cold/warm steps leave the approval bytes identical" "$pin_snapshot" \
    "$(cat "$(pins_store)")" || result=1
  if [ "$default_snapshot" = "<absent>" ]; then
    if [ -e "$(pins_record)" ]; then
      echo "    FAIL: a CLI-selection launch initialized the retained default"
      result=1
    fi
  else
    assert_eq "cold/warm steps leave the retained default bytes identical" \
      "$default_snapshot" "$(cat "$(pins_record)")" || result=1
  fi

  # ---- decline, fail, approve; the live A guest is untouched ----
  pins_env "$WORK/pins-home" "$WORK/pins-state"
  pin_snapshot="$(cat "$(pins_store)")"
  pins_pty_update pins-decline $'n\n' image refresh --image "$tag"
  assert_eq "a declined replacement exits nonzero" "1" "$PIN_PTY_STATUS" || result=1
  assert_match "decline prompt names the escaped source and its platform" \
    "Replace the approved image for localhost:$port/$repo:pin \\(linux/$host_arch\\)" \
    "$(pins_pty_text pins-decline)" || result=1
  assert_match "decline prompt shows the full old digest" "old: $digest_a" \
    "$(pins_pty_text pins-decline)" || result=1
  assert_match "decline prompt shows the full new digest" "new: $digest_b" \
    "$(pins_pty_text pins-decline)" || result=1
  assert_eq "declining leaves the approval unchanged" "$pin_snapshot" "$(cat "$(pins_store)")" || result=1
  pins_pty_update pins-decline-empty $'\n' image refresh --image "$tag"
  assert_eq "an empty answer exits nonzero" "1" "$PIN_PTY_STATUS" || result=1
  assert_match "empty answer still renders the full old digest" "old: $digest_a" \
    "$(pins_pty_text pins-decline-empty)" || result=1
  assert_match "empty answer still renders the full new digest" "new: $digest_b" \
    "$(pins_pty_text pins-decline-empty)" || result=1
  assert_eq "empty input declines and leaves the approval unchanged" "$pin_snapshot" \
    "$(cat "$(pins_store)")" || result=1
  if [ "$live_pid" -gt 0 ]; then
    kill -0 "$live_pid" 2>/dev/null || { echo "    FAIL: the live A guest died"; result=1; }
    pins_live_advanced "$live" "$live_pid" "$tick" || result=1
  fi
  # A candidate that cannot be validated keeps A, even with --yes.
  pins_push_unbootable_candidate "$port" "$repo" pin || {
    echo "    FAIL: could not publish an unbootable candidate"
    result=1
  }
  pins_env "$WORK/pins-home" "$WORK/pins-state"
  pins_avm image refresh --image "$tag" --yes >"$WORK/pins-broken.out" 2>&1 && {
    echo "    FAIL: a broken candidate must fail the approved refresh"
    result=1
  }
  assert_eq "a failed candidate leaves the approval unchanged" "$pin_snapshot" \
    "$(cat "$(pins_store)")" || result=1
  pins_launch pins-after-failure "$proj" --image "$tag" hello-258 || result=1
  require_launch_ok pins-after-failure || result=1
  assert_eq "A still boots after declined/failed candidates" "stamp=absent" \
    "$(pins_stamp pins-after-failure)" || result=1
  # Approve B explicitly.
  docker tag "$CUSTOM_STAMP" "$tag" || result=1
  docker push "$tag" >/dev/null || result=1
  pins_avm image refresh --image "$tag" --yes >"$WORK/pins-approve.out" 2>&1 || {
    echo "    FAIL: approving the resolved candidate failed"
    cat "$WORK/pins-approve.out"
    result=1
  }
  if ! jq -e --arg ref "$tag" --arg digest "$digest_b" \
    '.pins[0].reference == $ref and .pins[0].manifest_digest == $digest
     and .pins[0].revision >= 2' "$(pins_store)" >/dev/null 2>&1; then
    echo "    FAIL: the approved pin does not name the frozen candidate B"
    cat "$(pins_store)" 2>/dev/null || true
    result=1
  fi
  reads_before="$(registry_read_count_calibrated "$container" \
    "http://127.0.0.1:$port/v2/$repo/manifests/$digest_b")" || result=1
  pins_launch pins-approved "$proj" --image "$tag" hello-258 || result=1
  require_launch_ok pins-approved || result=1
  assert_eq "future launches boot approved B" "stamp=present" "$(pins_stamp pins-approved)" || result=1
  reads_after="$(registry_read_count "$container")" || result=1
  assert_eq "warm approved B makes zero registry reads" "$reads_before" "$reads_after" || result=1
  # set-default: the explicit target ignores ambient selection, stores the
  # approved host child, and future precedence is unchanged.
  pins_avm image set-default --image "$tag" --yes >"$WORK/pins-set-default.out" 2>&1 || {
    echo "    FAIL: set-default of the approved target failed"
    cat "$WORK/pins-set-default.out"
    result=1
  }
  if ! jq -e --arg ref "$ref_b" '.version == 1 and .image == $ref' "$(pins_record)" >/dev/null 2>&1; then
    echo "    FAIL: set-default did not retain the approved host child B"
    cat "$(pins_record)" 2>/dev/null || true
    result=1
  fi
  pins_launch pins-default-b "$proj" hello-258 || result=1
  require_launch_ok pins-default-b || result=1
  assert_eq "the retained fallback boots B" "stamp=present" "$(pins_stamp pins-default-b)" || result=1
  pins_launch pins-override-a "$proj" --image "$ref_a" hello-258 || result=1
  require_launch_ok pins-override-a || result=1
  assert_eq "an explicit override still outranks the fallback" "stamp=absent" \
    "$(pins_stamp pins-override-a)" || result=1
  # A live guest keeps running across the tag move, both decline paths and B's
  # approval: its PID, the identity its own rootfs resolves, and the booted image
  # stamp must all be unchanged, which is what "changed pins affect future
  # launches only" means.
  if [ "$live_pid" -gt 0 ]; then
    kill -0 "$live_pid" 2>/dev/null || { echo "    FAIL: the live A guest died"; result=1; }
    pins_live_advanced "$live" "$live_pid" "$tick" || result=1
    assert_eq "live A process identity is unchanged" "$identity" "$(cat "$live/identity")" || result=1
    assert_eq "live A rootfs identity is unchanged" "$rootid" \
      "$(grep -E '^(uid|gid|home|path)=' "$live/status")" || result=1
    assert_eq "live A booted image stamp is unchanged" "stamp=absent" "$(grep '^stamp=' "$live/status")" || result=1
  fi
  # B is a *new* guest in the first launch's project: it must read back the
  # program-visible state that launch wrote through the launcher's own
  # project/state/HOME plumbing. A host bind of the project directory would prove
  # only that the host filesystem is shared, which is not the claim.
  pins_launch pins-b-reads "$proj" hello-258 read nonroot || result=1
  require_launch_ok pins-b-reads || result=1
  out="$(launch_output pins-b-reads)"
  assert_eq "the sentinel-reading guest is B" "stamp=present" \
    "$(pins_stamp pins-b-reads)" || result=1
  assert_eq "B reads the first launch's project state file" "project=pins-sentinel" \
    "$(grep '^project=' <<<"$out")" || result=1
  assert_eq "B reads the first launch's declared state file" "declared=pins-sentinel" \
    "$(grep '^declared=' <<<"$out")" || result=1
  assert_eq "B reads the first launch's HOME file" "plain=pins-sentinel" \
    "$(grep '^plain=' <<<"$out")" || result=1

  # ---- local paths bypass approval (one invariant) ----
  # The invariant this row proves is the local/OCI boundary itself: a local
  # rootfs selection performs no approval lookup and neither reads nor repairs a
  # damaged approval store. Whether the launch then boots is not claimed here —
  # this host's SDK rejects a managed `root_disk` for a non-OCI image, a
  # pre-existing limitation recorded as not-run in the acceptance evidence.
  rootfs="$WORK/plr"
  mkdir -p "$rootfs" || result=1
  default_home="$WORK/plh"
  pins_env "$default_home" "$WORK/pins-state"
  mkdir -p "$PINS_HOME/.config/agent-vm" || result=1
  printf 'not-json\n' >"$(pins_store)" || result=1
  pin_snapshot="$(cat "$(pins_store)")"
  pins_launch pins-local "$proj" --image "$rootfs" hello-258 || result=1
  assert_no_match "a local launch performs no approval lookup" "image pin authority" \
    "$(launch_output pins-local)" || result=1
  assert_eq "a local launch neither reads nor repairs a damaged store" "$pin_snapshot" \
    "$(cat "$(pins_store)")" || result=1
  if [ "$CAPTURE_STATUS" -eq 0 ]; then
    echo "    observed: the local-path launch booted (stamp: $(pins_stamp pins-local))"
  else
    echo "    observed: the local-path launch stopped at the SDK's non-OCI root_disk boundary"
  fi

  # ---- a default-tier acquisition adopts the retained digest once ----
  default_home="$WORK/pdh"
  default_state="$WORK/pds"
  mkdir -p "$default_home" "$default_state/msb-home" || result=1
  pins_env "$default_home" "$default_state"
  observe_launch pins-default-first "$proj" "$WORK/pins-default-first.out" -- \
    "${PINS_ENV[@]}" "${OFFLINE_ENV[@]}" AGENT_VM_TEST_DEFAULT_IMAGE="$ref_b" \
    XDG_CONFIG_HOME="$WORK/offline-config" PATH="$SHIM_DIR:/usr/bin:/bin" \
    HOST_SHIM_LOG="$HOST_SHIM_LOG" "$PINS_BIN" hello-258 || result=1
  require_launch_ok pins-default-first || result=1
  assert_eq "a first default-tier launch boots the acquired content" "stamp=present" \
    "$(pins_stamp pins-default-first)" || result=1
  if ! grep -qF "$ref_b" "$(pins_record)"; then
    echo "    FAIL: the default-tier acquisition did not adopt its record"
    result=1
  fi
  if ! jq -e --arg digest "$digest_b" \
    '.pins | length == 1 and .[0].manifest_digest == $digest' "$(pins_store)" >/dev/null 2>&1; then
    echo "    FAIL: the default-tier selection did not establish its pin"
    cat "$(pins_store)" 2>/dev/null || true
    result=1
  fi
  # The release candidate honours the retained digest (the seam is debug-only).
  PINS_BIN="$AGENT_VM_RELEASE_BIN"
  reads_before="$(registry_read_count_calibrated "$container" \
    "http://127.0.0.1:$port/v2/$repo/manifests/$digest_b")" || result=1
  pins_launch pins-default-release "$proj" hello-258 || result=1
  require_launch_ok pins-default-release || result=1
  assert_eq "the release launcher boots the retained digest" "stamp=present" \
    "$(pins_stamp pins-default-release)" || result=1
  reads_after="$(registry_read_count "$container")" || result=1
  assert_eq "the release retained-default launch makes zero registry reads" \
    "$reads_before" "$reads_after" || result=1
  PINS_BIN="$AGENT_VM_DEV_BIN"

  # Stop the live guest before the registry/fixtures go away.
  if [ "$live_pid" -gt 0 ]; then
    touch "$live/stop"
    deadline=$(( $(date +%s) + 30 ))
    while kill -0 "$live_pid" 2>/dev/null && [ "$(date +%s)" -lt "$deadline" ]; do sleep 1; done
    if kill -0 "$live_pid" 2>/dev/null; then
      kill -TERM "$live_pid" 2>/dev/null || true
      sleep 5
      kill -KILL "$live_pid" 2>/dev/null || true
      result=1
    fi
    wait "$live_pid" || result=1
  fi
  docker rm -f "$container" >/dev/null 2>&1 || { echo "    FAIL: registry removal failed"; result=1; }
  return "$result"
}

# --------------------------------------------------------------- run all ----

echo "e2e: group=$GROUP"
printf 'e2e: argv=%q ' "$0" "$@"
printf '\n'
echo "e2e: repo=$REPO_ROOT commit=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
echo "e2e: only-rows=${E2E_ONLY_ROWS:-<all>}"
echo "e2e: launcher=$AGENT_VM"
make_host_shims
run_check "harness-negative" check_harness_negative

# #260 uses a separate short HOME/state, never the #258 fixture store.
setup_explicit_builder() {
  BUILDER="${AGENT_VM_E2E_BUILDER:-agent-vm-e2e-260-$RUN_ID}"
  mkdir -p "$WORK/build-bin" "$WORK/offline-config" || return 1
  cp "$REPO_ROOT/script/test/fixtures/build-archive-tee.sh" "$WORK/build-bin/docker" || return 1
  chmod 755 "$WORK/build-bin/docker" || return 1
  printf '#!/bin/bash\nprintf calibration-260\nexit 23\n' > "$WORK/calibration-docker"
  chmod 755 "$WORK/calibration-docker"
  local status=0
  REAL_DOCKER="$WORK/calibration-docker" BUILD_CAPTURE="$WORK/calibration.tar" \
    "$WORK/build-bin/docker" buildx build > "$WORK/calibration.out" || status=$?
  [ "$status" = 23 ] && [ "$(cat "$WORK/calibration.out")" = calibration-260 ] || return 1
  cmp "$WORK/calibration.out" "$WORK/calibration.tar" || return 1
  [ ! -e "$WORK/calibration.tar.error" ] || return 1
  if [ -z "${AGENT_VM_E2E_BUILDER:-}" ]; then
    docker buildx create --name "$BUILDER" --driver docker-container || return 1
    OWNED_BUILDER="$BUILDER"
  fi
  "${BUILD_ENV[@]}" HOME="$WORK/bh" "$REAL_DOCKER" buildx version || return 1
  local inspection
  inspection="$("${BUILD_ENV[@]}" HOME="$WORK/bh" "$REAL_DOCKER" buildx inspect "$BUILDER" --bootstrap)" || return 1
  grep -q 'Driver:.*docker-container' <<< "$inspection" || return 1
}

explicit_build() {
  local target="$2" capture="$WORK/$1.oci.tar"
  (cd "$BUILD_PROJECT" && "${BUILD_ENV[@]}" \
    env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_ROOT -u MSB_CONFIG_PATH \
    HOME="$BUILD_HOME" AGENT_VM_STATE_DIR="$BUILD_STATE" \
    AGENT_VM_SHARE_MSB_CACHE="$BUILD_SHARE" AGENT_VM_MSB_CACHE_DIR="$BUILD_CACHE" \
    REAL_DOCKER="$REAL_DOCKER" BUILD_CAPTURE="$capture" PATH="$WORK/build-bin:$PATH" \
    "$AGENT_VM" image build --tag "$BUILD_REF" --builder "$BUILDER" \
    --file "$FIXTURE_DIR/Dockerfile" --target "$target" "$FIXTURE_DIR") || return 1
  [ ! -e "$capture.error" ] || return 1
  python3 "$REPO_ROOT/script/test/fixtures/build-archive-oracle.py" "$capture" > "$capture.report.json" || return 1
  [ ! -e "$BUILD_HOME/.config/agent-vm/default-image.json" ] || return 1
  if docker image inspect "$BUILD_REF" >/dev/null 2>&1; then return 1; fi
}

explicit_offline() {
  "${OFFLINE_ENV[@]}" env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_ROOT -u MSB_CONFIG_PATH \
    HOME="$BUILD_HOME" AGENT_VM_STATE_DIR="$BUILD_STATE" \
    AGENT_VM_SHARE_MSB_CACHE="$BUILD_SHARE" AGENT_VM_MSB_CACHE_DIR="$BUILD_CACHE" \
    XDG_CONFIG_HOME="$WORK/offline-config" PATH="$SHIM_DIR:/usr/bin:/bin" \
    HOST_SHIM_LOG="$HOST_SHIM_LOG" "$AGENT_VM" "$@"
}

explicit_boot() {
  local name="$1" stamp="$2"
  shift 2
  observe_launch "$name" "$BUILD_PROJECT" "$WORK/$name.out" -- \
    "${OFFLINE_ENV[@]}" env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_ROOT -u MSB_CONFIG_PATH \
    HOME="$BUILD_HOME" AGENT_VM_STATE_DIR="$BUILD_STATE" \
    AGENT_VM_SHARE_MSB_CACHE="$BUILD_SHARE" AGENT_VM_MSB_CACHE_DIR="$BUILD_CACHE" \
    XDG_CONFIG_HOME="$WORK/offline-config" PATH="$SHIM_DIR:/usr/bin:/bin" \
    HOST_SHIM_LOG="$HOST_SHIM_LOG" "$AGENT_VM" "$@" || return 1
  require_launch_ok "$name" || return 1
  local out
  out="$(launch_output "$name")" || return 1
  assert_eq "$name program" hello-258=ok "$(grep '^hello-258=ok$' <<< "$out")" || return 1
  assert_eq "$name stamp" "stamp=$stamp" "$(grep '^stamp=' <<< "$out")" || return 1
  assert_no_host_calls || return 1
}

# Acquisition failure through the bounded observer, in private state, Docker-free.
explicit_miss() {
  local name="$1"
  shift
  observe_launch "$name" "$BUILD_PROJECT" "$WORK/$name.out" -- \
    "${OFFLINE_ENV[@]}" env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_ROOT -u MSB_CONFIG_PATH \
    HOME="$BUILD_HOME" AGENT_VM_STATE_DIR="$BUILD_STATE" \
    AGENT_VM_SHARE_MSB_CACHE="$BUILD_SHARE" AGENT_VM_MSB_CACHE_DIR="$BUILD_CACHE" \
    XDG_CONFIG_HOME="$WORK/offline-config" PATH="$SHIM_DIR:/usr/bin:/bin" \
    HOST_SHIM_LOG="$HOST_SHIM_LOG" "$AGENT_VM" "$@" || return 1
  [ ! -e "$WORK/$name.timeout" ] || return 1
  [ "$CAPTURE_STATUS" -ne 0 ] || { echo "    FAIL: $name: the launch succeeded"; return 1; }
  assert_no_host_calls || return 1
}

custom_docker_import_workflow() {
  BUILD_HOME="$WORK/ih" BUILD_STATE="$WORK/is" BUILD_PROJECT="$WORK/ip"
  BUILD_SHARE=0 BUILD_CACHE="$WORK/unused-cache"
  local ref="agent-vm-e2e-359-$RUN_ID:dev" container port missing result=0
  local reg="registry:3@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8"
  explicit_project || return 1
  (cd "$BUILD_PROJECT" && "${BUILD_ENV[@]}" env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_ROOT -u MSB_CONFIG_PATH \
    HOME="$BUILD_HOME" AGENT_VM_STATE_DIR="$BUILD_STATE" \
    AGENT_VM_SHARE_MSB_CACHE="$BUILD_SHARE" AGENT_VM_MSB_CACHE_DIR="$BUILD_CACHE" \
    XDG_CONFIG_HOME="$WORK/offline-config" PATH="${REAL_DOCKER%/*}:/usr/bin:/bin" \
    "$AGENT_VM" image import --docker "$CUSTOM_MARKER" --tag "$ref") \
    > "$WORK/import359.out" 2> "$WORK/import359.err" || return 1
  grep -qF -- "launch it with \`--image $ref\`" "$WORK/import359.out" || return 1
  explicit_boot import359 absent --no-git --image "$ref" shell hello-258 || return 1
  container="$(docker run -d --rm -p 127.0.0.1::5000 "$reg")" ||
    { echo "    BLOCKER: could not start the local registry container"; return 1; }
  [ -n "$container" ] || { echo "    BLOCKER: no registry container id"; return 1; }
  port="$(docker port "$container" 5000/tcp | head -1 | sed 's/.*://')"
  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    echo "    BLOCKER: no single numeric mapped registry port"
    docker rm -f "$container" >/dev/null 2>&1 || { echo "    FAIL: registry removal failed"; }
    return 1
  fi
  local deadline=$(( $(date +%s) + 30 )) ready=0
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  if [ "$ready" -ne 1 ]; then
    echo "    BLOCKER: registry not ready on 127.0.0.1:$port"
    docker rm -f "$container" >/dev/null 2>&1 || { echo "    FAIL: registry removal failed"; }
    return 1
  fi
  missing="localhost:$port/e2e-359-$RUN_ID:absent"
  explicit_miss miss359 --no-git --image "$missing" shell hello-258 || result=1
  grep -qF "agent-vm image import --docker $missing --tag $missing" "$WORK/miss359.out" || result=1
  grep -qF "registry error" "$WORK/miss359.out" || result=1
  docker rm -f "$container" >/dev/null 2>&1 || { echo "    FAIL: registry container removal failed"; result=1; }
  return "$result"
}

explicit_project() {
  mkdir -p "$BUILD_PROJECT/.agent-vm" "$BUILD_HOME" || return 1
  cat > "$BUILD_PROJECT/.agent-vm/config.toml" <<'CONFIG'
[[tools]]
name = "shell"
command = "bash"
tools = []
credentials = []
interactive_shell = true
persist = [".hello-258.state"]
CONFIG
}

custom_explicit_build_workflow() {
  setup_explicit_builder || return 1
  BUILD_HOME="$WORK/bh" BUILD_STATE="$WORK/bs" BUILD_PROJECT="$WORK/bp"
  BUILD_SHARE=0 BUILD_CACHE="$WORK/unused-cache"
  BUILD_REF="agent-vm-e2e-260-$RUN_ID:dev"
  explicit_project || return 1
  local source_before
  source_before="$(shasum -a 256 "$FIXTURE_DIR"/*)" || return 1
  explicit_build build260 marker-free || return 1
  [ "$source_before" = "$(shasum -a 256 "$FIXTURE_DIR"/*)" ] || return 1
  python3 "$REPO_ROOT/script/test/fixtures/build-archive-oracle.py" --controls "$WORK/build260.oci.tar" || return 1
  explicit_boot build260-first absent --no-git --image "$BUILD_REF" shell hello-258 || return 1
  local out
  out="$(launch_output build260-first)" || return 1
  assert_eq uid "uid=$(id -u)" "$(grep '^uid=' <<< "$out")" || return 1
  assert_eq gid "gid=$(id -g)" "$(grep '^gid=' <<< "$out")" || return 1
  assert_eq home "home=$BUILD_HOME" "$(grep '^home=' <<< "$out")" || return 1
  explicit_boot build260-root absent --no-git --root --image "$BUILD_REF" shell hello-258 || return 1
  out="$(launch_output build260-root)" || return 1
  assert_eq root uid=0 "$(grep '^uid=' <<< "$out")" || return 1
  explicit_boot build260-write absent --no-git --image "$BUILD_REF" shell hello-258 write sentinel260 || return 1
  explicit_boot build260-read absent --no-git --image "$BUILD_REF" shell hello-258 read || return 1
  out="$(launch_output build260-read)" || return 1
  for field in declared plain project direct; do
    assert_eq "persist $field" "$field=sentinel260" "$(grep "^$field=" <<< "$out")" || return 1
  done
  local format
  for format in docker oci; do
    explicit_offline msb image save "$BUILD_REF" --format "$format" --output "$WORK/saved260.$format.tar" || return 1
  done
  local original_home="$BUILD_HOME" original_state="$BUILD_STATE" original_project="$BUILD_PROJECT"
  for format in docker oci; do
    BUILD_HOME="$WORK/bh-$format" BUILD_STATE="$WORK/bs-$format" BUILD_PROJECT="$WORK/bp-$format"
    explicit_project || return 1
    explicit_offline msb image load --input "$WORK/saved260.$format.tar" --tag "$BUILD_REF" || return 1
    explicit_boot "build260-import-$format" absent --no-git --image "$BUILD_REF" shell hello-258 || return 1
  done
  BUILD_HOME="$WORK/bh-sh" BUILD_STATE="$WORK/bs-sh" BUILD_PROJECT="$WORK/bp-sh"
  BUILD_SHARE=1 BUILD_CACHE="$WORK/shared260"
  explicit_project || return 1
  explicit_build build260-shared marker-free || return 1
  [ -d "$BUILD_CACHE/layers" ] || return 1
  [ ! -d "$BUILD_STATE/msb-home/cache/layers" ] || return 1
  explicit_boot build260-shared absent --no-git --image "$BUILD_REF" shell hello-258 || return 1
  BUILD_SHARE=0
  explicit_boot build260-shared-persisted absent --no-git --image "$BUILD_REF" shell hello-258 || return 1
  BUILD_HOME="$original_home" BUILD_STATE="$original_state" BUILD_PROJECT="$original_project"
  BUILD_CACHE="$WORK/unused-cache"
  # Native archive save can reconstruct transport: derive the pin AFTER reimport.
  explicit_offline msb image load --input "$WORK/saved260.oci.tar" --tag "$BUILD_REF" || return 1
  local digest pin record
  digest="$(explicit_offline msb image inspect --format json "$BUILD_REF" | jq -er '.digest')" || return 1
  pin="${BUILD_REF%:*}@$digest"
  explicit_offline msb image load --input "$WORK/saved260.oci.tar" --tag "$pin" || return 1
  record="$BUILD_HOME/.config/agent-vm/default-image.json"
  mkdir -p "${record%/*}" || return 1
  jq -n --arg image "$pin" '{version:1,image:$image}' > "$record" || return 1
  explicit_boot build260-default absent --no-git shell hello-258 || return 1
  cp "$record" "$WORK/record260.before" || return 1
  cp "$BUILD_PROJECT/.agent-vm/config.toml" "$WORK/config260.before" || return 1
  [ ! -e "$BUILD_STATE/msb-home/config.json" ] || return 1
  if (cd "$BUILD_PROJECT" && "${BUILD_ENV[@]}" env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_ROOT -u MSB_CONFIG_PATH \
      HOME="$BUILD_HOME" AGENT_VM_STATE_DIR="$BUILD_STATE" \
      AGENT_VM_SHARE_MSB_CACHE="$BUILD_SHARE" AGENT_VM_MSB_CACHE_DIR="$BUILD_CACHE" \
      "$AGENT_VM" image build --tag "$BUILD_REF" --builder "$BUILDER" --target nonexistent260 "$FIXTURE_DIR"); then return 1; fi
  printf broken > "$WORK/broken260.tar"
  if explicit_offline msb image load --input "$WORK/broken260.tar" --tag "$BUILD_REF"; then return 1; fi
  explicit_boot build260-failure-result absent --no-git --image "$BUILD_REF" shell hello-258 || return 1
  explicit_boot build260-failure-default absent --no-git shell hello-258 || return 1
  cmp "$record" "$WORK/record260.before" || return 1
  cmp "$BUILD_PROJECT/.agent-vm/config.toml" "$WORK/config260.before" || return 1
  [ ! -e "$BUILD_STATE/msb-home/config.json" ] || return 1
  # Success must replace the mutable result without adopting the replacement.
  (cd "$BUILD_PROJECT" && "${BUILD_ENV[@]}" env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_ROOT -u MSB_CONFIG_PATH \
      HOME="$BUILD_HOME" AGENT_VM_STATE_DIR="$BUILD_STATE" \
      AGENT_VM_SHARE_MSB_CACHE="$BUILD_SHARE" AGENT_VM_MSB_CACHE_DIR="$BUILD_CACHE" \
    REAL_DOCKER="$REAL_DOCKER" BUILD_CAPTURE="$WORK/rebuild260.oci.tar" PATH="$WORK/build-bin:$PATH" \
    "$AGENT_VM" image build --tag "$BUILD_REF" --builder "$BUILDER" --target stamp-present "$FIXTURE_DIR") || return 1
  [ ! -e "$WORK/rebuild260.oci.tar.error" ] || return 1
  python3 "$REPO_ROOT/script/test/fixtures/build-archive-oracle.py" "$WORK/rebuild260.oci.tar" > "$WORK/rebuild260.report.json" || return 1
  # #391 staging: the successful build published a new alias, but an established
  # pin is not replaced by a cache publication. The launch stays on the approved
  # marker-free child; a fresh HOME with no approval sees the rebuilt content.
  explicit_boot build260-replaced absent --no-git --image "$BUILD_REF" shell hello-258 || return 1
  local rebuilt_home="$WORK/bh-rebuilt"
  BUILD_HOME="$rebuilt_home" BUILD_STATE="$original_state" BUILD_PROJECT="$original_project"
  explicit_boot build260-rebuilt-fresh present --no-git --image "$BUILD_REF" shell hello-258 || return 1
  BUILD_HOME="$original_home" BUILD_STATE="$original_state" BUILD_PROJECT="$original_project"
  explicit_boot build260-retained absent --no-git shell hello-258 || return 1
  cmp "$record" "$WORK/record260.before" || return 1
  cmp "$BUILD_PROJECT/.agent-vm/config.toml" "$WORK/config260.before" || return 1
  [ ! -e "$BUILD_STATE/msb-home/config.json" ] || return 1
}

# ---------------------------------------------------------------------------
# #398 — direct launches (`run` and top-level `--`)
# ---------------------------------------------------------------------------

# 1. Both spellings launch the same program with the same identity, cwd, HOME
# and PATH, nonroot and root. The oracles are literal, not a comparison of two
# possibly-wrong runs.
custom_image_direct_both_forms() {
  local mode form name proj out result=0
  for mode in nonroot root; do
    local -a root_flag=()
    [ "$mode" = root ] && root_flag=(--root)
    for form in run separator; do
      name="custom-direct-ident-$mode-$form"
      proj="$(custom_project "$name")" ||
        { direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" 1; return 1; }
      local route=run
      [ "$form" = separator ] && route=--
      if ! capture_custom_direct "$name" "$proj" --no-git \
        ${root_flag[@]+"${root_flag[@]}"} --image "$CUSTOM_MARKER" \
        "$route" direct-probe-398 identity; then
        result=1
      else
        out="$(direct_stdout "$name")" || result=1
        local host_uid host_gid want_uid want_gid want_home
        host_uid="$(id -u)"
        host_gid="$(id -g)"
        if [ "$mode" = root ]; then want_uid=0; want_gid=0; want_home=/root
        else want_uid="$host_uid"; want_gid="$host_gid"; want_home="$CUSTOM_HOME"; fi
        assert_eq "$name: guest exit status" "0" "$CAPTURE_STATUS" || result=1
        assert_eq "$name: uid" "uid=$want_uid" "$(grep '^uid=' <<<"$out")" || result=1
        assert_eq "$name: gid" "gid=$want_gid" "$(grep '^gid=' <<<"$out")" || result=1
        assert_eq "$name: guest HOME" "home=$want_home" "$(grep '^home=' <<<"$out")" || result=1
        assert_eq "$name: cwd is the mounted project" \
          "cwd=$(cd "$proj" && pwd -P)" "$(grep '^cwd=' <<<"$out")" || result=1
        assert_eq "$name: program resolves under the image PATH" \
          "probe=/usr/local/bin/direct-probe-398" "$(grep '^probe=' <<<"$out")" || result=1
        assert_eq "$name: completion sentinel" \
          "direct-probe-398=ok" "$(grep '^direct-probe-398=ok$' <<<"$out")" || result=1
        # Zero catalog provisioning: no catalog persist link, no provider or
        # custom tool/shell environment reached the guest.
        assert_eq "$name: no catalog persist link" \
          "hello_persist=absent" "$(grep '^hello_persist=' <<<"$out")" || result=1
        assert_no_match "$name: no inherited provider/tool env" \
          "^inherited_env=" "$out" || result=1
        assert_single_boot_ref "$name boots only the selected image" \
          "$CUSTOM_MARKER" "$(launch_output "$name")" || result=1
        assert_no_host_calls || result=1
      fi
      direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || result=1
    done
  done
  return "$result"
}

# 2. Literal argv in both spellings: byte-exact count and arguments, including
# an empty argument, spaces, quotes, Unicode, shell metacharacters, a literal
# `$HOME`, `--help`, a later `--` and duplicates.
direct_argv_expectation() {
  python3 - "$1" <<'ARGVCHECK'
import sys

expected_args = [
    "",
    "a b",
    "q'\"uote",
    "日本語",
    "$HOME",
    "*",
    ";",
    "|",
    "--help",
    "--",
    "x",
    "x",
    "line\nbreak",
]
expected = b"argv-count=%d\n" % len(expected_args)
for argument in expected_args:
    expected += argument.encode() + b"\0"
expected += b"direct-probe-398=ok\n"
actual = open(sys.argv[1], "rb").read()
if actual != expected:
    print("    FAIL: direct argv bytes differ from the exact expected vector")
    print("    expected:", expected)
    print("    actual:  ", actual)
    raise SystemExit(1)
ARGVCHECK
}

custom_image_direct_argv() {
  local form name proj result=0
  for form in run separator; do
    name="custom-direct-argv-$form"
    proj="$(custom_project "$name")" ||
      { direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" 1; return 1; }
    local route=run
    [ "$form" = separator ] && route=--
    if ! capture_custom_direct "$name" "$proj" --no-git --image "$CUSTOM_MARKER" \
      "$route" direct-probe-398 argv '' 'a b' "q'\"uote" '日本語' '$HOME' '*' ';' '|' \
      '--help' '--' 'x' 'x' 'line
break'; then
      result=1
    else
      assert_eq "$name: guest exit status" "0" "$CAPTURE_STATUS" || result=1
      direct_argv_expectation "$WORK/$name.stdout" || result=1
      assert_no_host_calls || result=1
    fi
    direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || result=1
  done

  # An external program receives `$HOME` literally; shell syntax needs an
  # explicit shell.
  for form in run separator; do
    name="custom-direct-printf-$form"
    proj="$(custom_project "$name")" ||
      { direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" 1; return 1; }
    local route=run
    [ "$form" = separator ] && route=--
    if ! capture_custom_direct "$name" "$proj" --no-git --image "$CUSTOM_MARKER" \
      "$route" printf '%s\n' '$HOME'; then
      result=1
    else
      assert_eq "$name: literal printf status" "0" "$CAPTURE_STATUS" || result=1
      # Exactly `$HOME` plus one newline, compared as bytes.
      assert_direct_stdout_bytes "$name: literal \$HOME bytes" "$name" $'$HOME\n' || result=1
    fi
    direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || result=1
  done
  return "$result"
}

# 3. The status table: 127 for an absent executable (bare name and path), 126
# for a present non-executable file and for a directory named by path, 127 for
# a bare name that resolves to a PATH directory, and pass-through of the
# program's own status.
custom_image_direct_statuses() {
  local form name proj result=0
  for form in run separator; do
    local route=run
    [ "$form" = separator ] && route=--
    local spec program expected slug
    for spec in \
      'missing-398:127' \
      '/nonexistent/direct-398:127' \
      'noexec-258:126' \
      '/usr/local/bin/noexec-258:126' \
      '/usr:126' \
      'sh|exit 7:7' \
      'false:1'; do
      program="${spec%:*}"
      expected="${spec##*:}"
      slug="$(printf '%s' "$program" | tr -c 'a-zA-Z0-9' '-')"
      name="custom-direct-status-$form-$slug"
      proj="$(custom_project "$name")" ||
        { direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" 1; result=1; continue; }
      local -a argv=()
      case "$program" in
      'sh|exit 7') argv=(sh -c 'exit 7') ;;
      *) argv=("$program") ;;
      esac
      if ! capture_custom_direct "$name" "$proj" --no-git --image "$CUSTOM_MARKER" \
        "$route" "${argv[@]}"; then
        result=1
      else
        assert_eq "$name: status for $program" "$expected" "$CAPTURE_STATUS" || result=1
        case "$expected" in
        127 | 126)
          assert_match "$name: direct stderr diagnostic" \
            "agent-vm: (executable not found|not executable)" \
            "$(launch_output "$name")" || result=1
          # Launcher diagnostics never reach guest stdout.
          assert_direct_stdout_empty "$name: stdout stays empty" "$name" || result=1
          ;;
        esac
        assert_no_host_calls || result=1
      fi
      direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || result=1
    done
  done
  return "$result"
}

# 4. The project runtime hook is retained for direct launches: its exports
# affect the effective PATH and executable lookup, and its status passes
# through with the command never executed.
custom_image_direct_hook() {
  local form name proj out result=0
  for form in run separator; do
    local route=run
    [ "$form" = separator ] && route=--
    name="custom-direct-hook-$form"
    proj="$(custom_project "$name")" ||
      { direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" 1; return 1; }
    mkdir -p "$proj/bin" ||
      { direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" 1; return 1; }
    cat >"$proj/bin/hooked-398" <<'HOOKED' ||
      { direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" 1; return 1; }
#!/bin/sh
printf 'hooked-path=%s\n' "$1"
printf 'hooked-env=%s\n' "${DIRECT_HOOK_ENV:-unset}"
printf 'hooked=ok\n'
HOOKED
    chmod 0755 "$proj/bin/hooked-398" ||
      { direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" 1; return 1; }
    cat >"$proj/.agent-vm.runtime.sh" <<'HOOK' ||
      { direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" 1; return 1; }
DIRECT_HOOK_ENV=hooked
export DIRECT_HOOK_ENV
PATH="$PWD/bin:$PATH"
export PATH
HOOK
    if ! capture_custom_direct "$name" "$proj" --no-git --image "$CUSTOM_MARKER" \
      "$route" hooked-398 hook-arg; then
      result=1
    else
      out="$(direct_stdout "$name")" || result=1
      assert_eq "$name: hook-exported program status" "0" "$CAPTURE_STATUS" || result=1
      assert_eq "$name: hook argv" "hooked-path=hook-arg" "$(grep '^hooked-path=' <<<"$out")" || result=1
      assert_eq "$name: hook-exported env" "hooked-env=hooked" "$(grep '^hooked-env=' <<<"$out")" || result=1
      assert_eq "$name: hook completion sentinel" "hooked=ok" "$(grep '^hooked=ok$' <<<"$out")" || result=1
      # No launcher notice leaks into guest stdout.
      assert_no_match "$name: no launcher notices on stdout" "^==>" "$out" || result=1
    fi
    rm -f "$proj/.agent-vm.runtime.sh" || result=1
    direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || result=1
  done

  # A failing hook passes its status through and the command never runs.
  local body slug
  for body in 'return 9' 'exit 9'; do
    slug="$(printf '%s' "$body" | tr -c 'a-zA-Z0-9' '-')"
    name="custom-direct-hook-fail-$slug"
    proj="$(custom_project "$name")" ||
      { direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" 1; return 1; }
    printf '%s\n' "$body" >"$proj/.agent-vm.runtime.sh" ||
      { direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" 1; return 1; }
    if ! capture_custom_direct "$name" "$proj" --no-git --image "$CUSTOM_MARKER" \
      run direct-probe-398 identity; then
      result=1
    else
      assert_eq "$name: hook status passes through" "9" "$CAPTURE_STATUS" || result=1
      assert_no_match "$name: the command never ran" "direct-probe-398=ok" \
        "$(direct_stdout "$name")" || result=1
      if [ "$body" = 'return 9' ]; then
        assert_match "$name: failed-hook diagnostic" "failed \(exit 9\)" \
          "$(launch_output "$name")" || result=1
      fi
    fi
    rm -f "$proj/.agent-vm.runtime.sh" || result=1
    direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || result=1
  done
  return "$result"
}

# 5. A host executable that shares the program's name is never executed: the
# direct route reaches the guest lookup. The decoy is calibrated first on the
# exact child PATH, then reset, so "unchanged" is not vacuous.
custom_image_direct_host_decoy() {
  local form name proj result=0
  local decoy="$SHIM_DIR/direct-decoy-398"
  cat >"$decoy" <<'DECOY' || return 1
#!/bin/sh
printf 'host-decoy\n' >>"$HOST_SHIM_LOG"
exit 96
DECOY
  chmod 0755 "$decoy" || return 1
  # Wiring control on the exact PATH (and env) the launch's children get. The
  # decoy exits 96 by contract, so that status (not zero) is the reachable proof.
  : >"$HOST_SHIM_LOG" || return 1
  local control_status=0
  (PATH="$SHIM_DIR:/usr/bin:/bin" HOST_SHIM_LOG="$HOST_SHIM_LOG" "$decoy") >/dev/null 2>&1 ||
    control_status=$?
  if [ "$control_status" -ne 96 ]; then
    echo "    FAIL: the host decoy did not exit 96 on the child PATH (got $control_status)"
    return 1
  fi
  if ! grep -q '^host-decoy$' "$HOST_SHIM_LOG"; then
    echo "    FAIL: the host decoy did not log on the child PATH"
    return 1
  fi
  : >"$HOST_SHIM_LOG" || return 1
  for form in run separator; do
    local route=run
    [ "$form" = separator ] && route=--
    name="custom-direct-decoy-$form"
    proj="$(custom_project "$name")" ||
      { direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" 1; return 1; }
    if ! capture_custom_direct "$name" "$proj" --no-git --image "$CUSTOM_MARKER" \
      "$route" direct-decoy-398; then
      result=1
    else
      assert_eq "$name: host decoy is not a guest program" "127" "$CAPTURE_STATUS" || result=1
      assert_direct_stdout_empty "$name: guest stdout stays empty" "$name" || result=1
      # A read error is a failed observation, never proof that the decoy log is
      # empty (assert_no_host_calls owns that distinction).
      assert_no_host_calls || result=1
    fi
    direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || result=1
  done
  rm -f "$decoy" || result=1
  return "$result"
}

# 6. The nonstandard-PATH fixture, launched directly in both spellings: the
# probe and Bash resolve only under /opt/e2e-258/bin, with no fallback copy.
custom_image_direct_nonstandard() {
  local form name proj out result=0
  name="custom-direct-nonstandard"
  proj="$(custom_project "$name")" ||
    { direct_cleanup "$name" "$proj" "$CUSTOM_NONSTANDARD" 1; return 1; }
  for form in run separator; do
    local route=run
    [ "$form" = separator ] && route=--
    if ! capture_custom_direct "$name-$form" "$proj" --no-git --image "$CUSTOM_NONSTANDARD" \
      "$route" direct-probe-398 identity; then
      result=1
    else
      # The recorded child status is part of the row: output that looks right
      # after a launcher cleanup failure is not a pass.
      assert_eq "$name-$form: guest exit status" "0" "$CAPTURE_STATUS" || result=1
      out="$(direct_stdout "$name-$form")" || result=1
      assert_eq "$name-$form: nonstandard program resolves" \
        "probe=/opt/e2e-258/bin/direct-probe-398" "$(grep '^probe=' <<<"$out")" || result=1
      assert_eq "$name-$form: nonstandard bash resolves" \
        "bash=/opt/e2e-258/bin/bash" "$(grep '^bash=' <<<"$out")" || result=1
      assert_eq "$name-$form: completion sentinel" \
        "direct-probe-398=ok" "$(grep '^direct-probe-398=ok$' <<<"$out")" || result=1
      assert_no_host_calls || result=1
    fi
  done
  direct_cleanup "$name" "$proj" "$CUSTOM_NONSTANDARD" "$result" || result=1
  return "$result"
}

# 7. Native zero provider provisioning. The project's catalog declares a hostile
# definition that *shares the direct program's name* (its own command, default
# args, env, provider credential, transitive tool, network request and persist
# declaration) plus a hostile configured `shell`, and a *usable* synthetic
# provider credential is seeded in the private launcher HOME. A direct launch
# must still provision nothing. Four independent directions are asserted: the
# guest's own environment/identity output, the launcher's credential notice, the
# config it handed the SDK, and the host state it left behind. The control tool
# proves the credential really was usable, so "no capture" is not "inert seed".
write_direct_hostile_config() {
  local dir="$1"
  mkdir -p "$dir/.agent-vm" || return 1
  cat >"$dir/.agent-vm/config.toml" <<'EOF' || return 1
[[tools]]
name = "direct-probe-398"
command = "probe-from-catalog"
args = ["--from-catalog"]
env = { PROBE_CATALOG_ENV = "yes" }
credentials = ["anthropic"]
tools = ["direct-helper-398"]
persist = ["direct-398.state"]
network_requests = ["api.example.test"]

[[tools]]
name = "direct-helper-398"
command = "direct-helper-398"

[[tools]]
name = "prov-control"
command = "direct-probe-398"
credentials = ["anthropic"]
# A catalog-declared persist link for the probe's own `hello_persist` line, so
# the control launch proves that line can observe a link at all (see the
# control's `hello_persist=present` assertion).
persist = [".hello-258.state"]

[[tools]]
name = "shell"
command = "hostile-shell"
args = ["--hostile"]
interactive_shell = true
env = { SHELL_CATALOG_ENV = "yes" }
credentials = ["anthropic"]
network_requests = ["api.example.test"]
persist = ["shell-state"]
EOF
}

custom_image_direct_zero_provisioning() {
  local form route name proj out state host_uid host_gid result=0
  local control control_proj control_state
  host_uid="$(id -u)"
  host_gid="$(id -g)"
  write_custom_credential_seed ||
    { echo "    FAIL: could not seed the synthetic host credential"; return 1; }
  for form in run separator; do
    route=run
    [ "$form" = separator ] && route=--
    name="custom-direct-prov-$form"
    proj="$WORK/$name"
    write_direct_hostile_config "$proj" ||
      { direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" 1; result=1; continue; }
    state="$(direct_state_child "$proj")" ||
      { echo "    FAIL: could not resolve the state dir for $name"; result=1; continue; }
    # The launcher's own sandbox config is part of this row's evidence, so this
    # capture (and only this one) opts into the debug dump.
    local capture=0
    DIRECT_CAPTURE_ENV=(AGENT_VM_DEBUG_CONFIG=1)
    capture_custom_direct "$name" "$proj" --no-git --image "$CUSTOM_MARKER" \
      "$route" direct-probe-398 identity || capture=1
    DIRECT_CAPTURE_ENV=()
    if [ "$capture" -ne 0 ]; then
      result=1
    else
      assert_eq "$name: guest exit status" "0" "$CAPTURE_STATUS" || result=1
      out="$(direct_stdout "$name")" || result=1
      # The literal program ran with the launch identity, and the probe's
      # variable-NAME report proves no catalog tool/shell environment reached it.
      assert_eq "$name: uid" "uid=$host_uid" "$(grep '^uid=' <<<"$out")" || result=1
      assert_eq "$name: gid" "gid=$host_gid" "$(grep '^gid=' <<<"$out")" || result=1
      assert_eq "$name: guest HOME" "home=$CUSTOM_HOME" "$(grep '^home=' <<<"$out")" || result=1
      assert_eq "$name: completion sentinel" "direct-probe-398=ok" \
        "$(grep '^direct-probe-398=ok$' <<<"$out")" || result=1
      assert_no_match "$name: no inherited provider/tool env" "^inherited_env=" "$out" || result=1
      assert_eq "$name: no catalog persist link in the guest" "direct_persist=absent" \
        "$(grep '^direct_persist=' <<<"$out")" || result=1
      # No credential capture, although the catalog declares one and a usable
      # seed exists.
      assert_match "$name: no agent credentials captured" "^==> Agent credentials: <none>" \
        "$(launch_output "$name")" || result=1
      # The exact empty default-deny grant in the config the launch handed the
      # SDK (no request rule, secret, intercept route or TLS intercept).
      assert_direct_default_deny "$name: default-deny empty grant" "$name" || result=1
      # The host state a direct launch leaves behind: exactly the generic
      # furniture, no declared persist path, no provider token/placeholder/
      # bypass file, no launcher-owned Chrome entry on an incapable image.
      assert_direct_state_furniture "$name: generic HOME furniture" "$state" || result=1
      assert_state_entries_absent "$name: no provisioned state" "$state" \
        home/direct-398.state home/shell-state \
        persist/direct-398.state persist/shell-state \
        claude/.credentials.json claude/settings.json \
        codex/auth.json codex/config.toml copilot/config.json \
        opencode-config/opencode.json || result=1
      assert_state_entries_absent "$name: no captured provider token" "$CUSTOM_STATE" \
        "$(basename "$state").secrets/anthropic" \
        "$(basename "$state").secrets/openai" \
        "$(basename "$state").secrets/copilot" || result=1
      if [ -f "$state/claude.json" ] &&
        ! jq -e '(.mcpServers["chrome-devtools"] // null) == null' \
          "$state/claude.json" >/dev/null; then
        echo "    FAIL: $name: the launcher-owned Chrome MCP entry must not be provisioned"
        jq -c '.mcpServers // {}' "$state/claude.json" || true
        result=1
      fi
      if [ -f "$state/opencode/auth.json" ] &&
        ! jq -e '(type == "object") and (length == 0)' "$state/opencode/auth.json" >/dev/null; then
        echo "    FAIL: $name: no OpenCode provider entry may be provisioned"
        jq -c . "$state/opencode/auth.json" || true
        result=1
      fi
      assert_no_host_calls || result=1
    fi
    direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || result=1
  done

  # Positive control: the same catalog definition *is* provisioned when it is
  # launched as a catalog tool, so the direct row's "no capture" cannot pass
  # because the seeded credential was unusable.
  control="custom-direct-prov-control"
  control_proj="$WORK/$control"
  write_direct_hostile_config "$control_proj" || result=1
  control_state="$(direct_state_child "$control_proj")" || result=1
  if capture_custom_direct "$control" "$control_proj" --no-git --image "$CUSTOM_MARKER" \
    prov-control; then
    assert_eq "$control: guest exit status" "0" "$CAPTURE_STATUS" || result=1
    assert_match "$control: the seeded credential is usable" "^==> Agent credentials: claude" \
      "$(launch_output "$control")" || result=1
    if [ ! -f "$control_state.secrets/anthropic" ]; then
      echo "    FAIL: $control: the catalog tool captured no host token from the seed"
      result=1
    fi
    if [ ! -f "$control_state/claude/.credentials.json" ]; then
      echo "    FAIL: $control: the catalog tool wrote no guest placeholder"
      result=1
    fi
    # The guest-side persist oracle is not vacuous: the same probe reports
    # `present` for this catalog tool, whose persist link is a *dangling*
    # symlink on a fresh project's first launch. Without `-L` in the probe the
    # direct rows' `absent` lines could not distinguish "no link" from
    # "dangling link".
    assert_eq "$control: the persist oracle sees a catalog persist link" \
      "hello_persist=present" \
      "$(grep '^hello_persist=' <<<"$(direct_stdout "$control")")" || result=1
    assert_eq "$control: the same oracle sees no direct persist link" \
      "direct_persist=absent" \
      "$(grep '^direct_persist=' <<<"$(direct_stdout "$control")")" || result=1
  else
    result=1
  fi
  rm -f "$CUSTOM_CREDENTIAL_SEED" || result=1
  # The control's own state and captured token are this test's: remove both.
  direct_cleanup "$control" "$control_proj" "$CUSTOM_MARKER" "$result" || result=1
  return "$result"
}

# 8. The image-owned Chrome MCP `claude.json` entry through direct launches:
# capable -> incapable -> capable, with an unrelated user MCP entry and an
# unrelated top-level key surviving every sync. The capable phases run the
# image's own `verify-mcp-258`, which reads the configured entry back from guest
# state and executes it, so the entry is proven guest-visible, not just present
# on the host. No provider grant, no captured credential, no catalog entry.
assert_direct_chrome_state() {
  local desc="$1" state="$2" expected="$3"
  if [ "$expected" = owned ]; then
    assert_state_json_at "$desc: owned entry configured" "$OWNED_STATE" "$state" || return 1
  else
    assert_state_json_at "$desc: owned entry removed" "$NO_OWNED_STATE" "$state" || return 1
  fi
  assert_state_json_at "$desc: unrelated entries intact" "$UNRELATED_STATE" "$state"
}

custom_image_direct_chrome_furniture() {
  local name="custom-direct-chrome" proj state result=0 phase
  local seed='{"mcpServers":{"user-owned":{"command":"user-cmd"}},"unrelatedTopKey":{"keep":true}}'
  proj="$WORK/$name"
  write_custom_tools_config "$proj" || return 1
  state="$(direct_state_child "$proj")" ||
    { echo "    FAIL: could not resolve the state dir for $name"; return 1; }

  # Seed the user's own MCP state with a direct launch on the incapable image.
  if capture_custom_direct "$name-seed" "$proj" --no-git --image "$CUSTOM_MARKER" \
    run bash -c "printf '%s' '$seed' > /agent-vm-state/claude.json"; then
    assert_eq "$name-seed: guest exit status" "0" "$CAPTURE_STATUS" || result=1
    assert_state_json_at "$name-seed: seeded user entries" "$UNRELATED_STATE" "$state" || result=1
  else
    result=1
  fi

  # Capable: the owned entry appears and the configured command really runs.
  if capture_custom_direct "$name-capable" "$proj" --no-git --image "$CUSTOM_INTEGRATIONS" \
    run verify-mcp-258; then
    assert_eq "$name-capable: guest exit status" "0" "$CAPTURE_STATUS" || result=1
    assert_match "$name-capable: the configured entry executed" "^verify-mcp-258: OK$" \
      "$(direct_stdout "$name-capable")" || result=1
    assert_direct_chrome_state "$name-capable" "$state" owned || result=1
    assert_match "$name-capable: no agent credentials" "^==> Agent credentials: <none>" \
      "$(launch_output "$name-capable")" || result=1
  else
    result=1
  fi

  # Incapable: only the owned entry is removed; the user's state survives.
  if capture_custom_direct "$name-incapable" "$proj" --no-git --image "$CUSTOM_MARKER" \
    -- direct-probe-398 identity; then
    assert_eq "$name-incapable: guest exit status" "0" "$CAPTURE_STATUS" || result=1
    assert_eq "$name-incapable: the direct program ran" "direct-probe-398=ok" \
      "$(grep '^direct-probe-398=ok$' <<<"$(direct_stdout "$name-incapable")")" || result=1
    assert_direct_chrome_state "$name-incapable" "$state" absent || result=1
  else
    result=1
  fi

  # Capable again: the entry comes back exactly as before.
  if capture_custom_direct "$name-capable-again" "$proj" --no-git \
    --image "$CUSTOM_INTEGRATIONS" run verify-mcp-258; then
    assert_eq "$name-capable-again: guest exit status" "0" "$CAPTURE_STATUS" || result=1
    assert_match "$name-capable-again: the configured entry executed again" \
      "^verify-mcp-258: OK$" "$(direct_stdout "$name-capable-again")" || result=1
    assert_direct_chrome_state "$name-capable-again" "$state" owned || result=1
    assert_match "$name-capable-again: no agent credentials" \
      "^==> Agent credentials: <none>" "$(launch_output "$name-capable-again")" || result=1
  else
    result=1
  fi

  # No provider grant in either phase: no captured token beside the state.
  assert_state_entries_absent "$name: no captured provider token" "$CUSTOM_STATE" \
    "$(basename "$state").secrets/anthropic" \
    "$(basename "$state").secrets/openai" \
    "$(basename "$state").secrets/copilot" || result=1
  # No owned runtime survives for either image before the state is removed.
  assert_no_catalog_entry "$CUSTOM_INTEGRATIONS" || result=1
  assert_no_catalog_entry "$CUSTOM_MARKER" || result=1
  assert_no_host_calls || result=1
  if direct_cleanup "$name" "$proj" "$CUSTOM_INTEGRATIONS" "$result"; then
    # This row's evidence is one capture per phase, none of them named after the
    # row, so `direct_cleanup` removes only the state here.
    for phase in seed capable incapable capable-again; do
      rm -f "$WORK/$name-$phase.stdout" "$WORK/$name-$phase.expected" || result=1
    done
  else
    result=1
  fi
  return "$result"
}

# ── #399: native streamed-stdin rows (both direct syntax forms) ────────────
#
# Every row runs `agent-vm run PROGRAM` and `agent-vm -- PROGRAM` over an input
# the row owns, asserts on the split captures, and closes its writer on every
# exit path. Guest stdout is compared byte for byte; the launcher's notices stay
# on stderr.

# `small`: a FIFO written with `hello` and closed by the row.
custom_image_direct_stdin_small() {
  local name=direct-stdin-small form capture proj result=0 status
  proj="$(stdin_row_project "$name" "$CUSTOM_MARKER")" || return 1
  for form in run dash; do
    capture="$name-$form"
    stdin_fifo_closed "$capture" hello || { result=1; continue; }
    if stdin_capture "$capture" "$proj" "$STDIN_FIFO" "$form" cat; then
      stdin_writer_stop
      status="$CAPTURE_STATUS"
      assert_eq "$capture: guest exit status" "0" "$status" || result=1
      assert_direct_stdout_bytes "$capture: guest stdout is exactly the input" \
        "$capture" hello || result=1
      assert_no_match "$capture: no launcher notice on guest stdout" '^==>' \
        "$(direct_stdout "$capture")" || result=1
      stdin_form_evidence "$form" "$status" "stdout==hello; no-notice-on-stdout" || result=1
    else
      stdin_writer_stop
      result=1
    fi
    assert_no_host_calls || result=1
  done
  direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || result=1
  return "$result"
}

# `empty`: /dev/null, and an empty FIFO the writer opens and closes.
custom_image_direct_stdin_empty() {
  local name=direct-stdin-empty form kind capture proj fifo result=0 status
  proj="$(stdin_row_project "$name" "$CUSTOM_MARKER")" || return 1
  for form in run dash; do
    for kind in dev-null empty-fifo; do
      # One FIFO per launch: a FIFO is consumed by the reader that opens it, so
      # a second launch over the same one would block waiting for a writer.
      for program in cat wc-count; do
        capture="$name-$form-$kind-$program"
        fifo=/dev/null
        if [ "$kind" = empty-fifo ]; then
          stdin_fifo_closed "$capture" "" || { result=1; continue; }
          fifo="$STDIN_FIFO"
        fi
        if [ "$program" = cat ]; then
          if ! stdin_capture "$capture" "$proj" "$fifo" "$form" cat; then
            stdin_writer_stop
            result=1
            continue
          fi
        else
          if ! stdin_capture "$capture" "$proj" "$fifo" "$form" wc -c; then
            stdin_writer_stop
            result=1
            continue
          fi
        fi
        stdin_writer_stop
        status="$CAPTURE_STATUS"
        assert_eq "$capture: guest exit status" "0" "$status" || result=1
        if [ "$program" = cat ]; then
          assert_direct_stdout_empty "$capture: cat sees an empty stream" \
            "$capture" || result=1
          stdin_form_evidence "$form" "$status" "$kind: stdout-empty" || result=1
        else
          assert_eq "$capture: the guest sees EOF, not a pending stdin" "0" \
            "$(direct_stdout "$capture")" || result=1
          stdin_form_evidence "$form" "$status" "$kind: stdout==0" || result=1
        fi
      done
    done
  done
  direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || result=1
  return "$result"
}

# The row's binary input: a block of all 256 byte values (0x00..0xFF) repeated
# 1024 times, then a separate 1024-byte NUL run, so the stream is neither ASCII
# nor valid UTF-8 and every byte value occurs inside a block (#399 N4).
stdin_binary_input() {
  local out="$1" chunky i=0
  chunky="$(for byte in $(seq 0 255); do printf '\\%03o' "$byte"; done)" || return 1
  {
    while [ "$i" -lt 1024 ]; do
      printf '%b' "$chunky" || return 1
      i=$((i + 1))
    done
    head -c 1024 /dev/zero || return 1
  } >"$out" || return 1
}

# `binary`: the same file through `cat` (byte equality) and `sha256sum`.
custom_image_direct_stdin_binary() {
  local name=direct-stdin-binary form capture proj input result=0 want got status
  proj="$(stdin_row_project "$name" "$CUSTOM_MARKER")" || return 1
  input="$WORK/$name.input"
  stdin_binary_input "$input" || return 1
  want="$(shasum -a 256 "$input" | cut -d' ' -f1)"
  for form in run dash; do
    capture="$name-cat-$form"
    if stdin_capture "$capture" "$proj" "$input" "$form" cat; then
      status="$CAPTURE_STATUS"
      assert_eq "$capture: guest exit status" "0" "$status" || result=1
      if ! cmp -s "$input" "$WORK/$capture.stdout"; then
        echo "    FAIL: $capture: the guest did not receive the exact bytes"
        cmp -l "$input" "$WORK/$capture.stdout" | head -5 || true
        result=1
      fi
      stdin_form_evidence "$form" "$status" "cat: cmp==input" || result=1
    else
      result=1
    fi
    capture="$name-sha-$form"
    if stdin_capture "$capture" "$proj" "$input" "$form" sha256sum; then
      status="$CAPTURE_STATUS"
      assert_eq "$capture: guest exit status" "0" "$status" || result=1
      got="$(direct_stdout "$capture" | cut -d' ' -f1)"
      assert_eq "$capture: guest checksum matches the host's" "$want" "$got" || result=1
      stdin_form_evidence "$form" "$status" "sha256sum==host-sha256" || result=1
    else
      result=1
    fi
  done
  direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || result=1
  return "$result"
}

# `hook-read`: a real image seed hook and a project hook that each read before
# the program runs; both must see EOF, and the hook's export must survive.
custom_image_direct_stdin_hook_read() {
  local name=direct-stdin-hook-read form capture proj result=0 input fifo out status
  proj="$(stdin_row_project "$name" "$CUSTOM_STDIN_SEED")" || return 1
  cat >"$proj/.agent-vm.runtime.sh" <<'HOOK' || return 1
if IFS= read -r _line; then echo "hook-read=GOT" >&2; else echo "hook-read=EOF" >&2; fi
V=hook-value
export V
HOOK
  for form in run dash; do
    capture="$name-$form"
    stdin_fifo_closed "$capture" "hello-stdin" || { result=1; continue; }
    fifo="$STDIN_FIFO"
    if stdin_capture "$capture" "$proj" "$fifo" "$form" bash -c \
      'cat; printf "v=%s\n" "$V" >&2'; then
      stdin_writer_stop
      status="$CAPTURE_STATUS"
      assert_eq "$capture: guest exit status" "0" "$status" || result=1
      assert_direct_stdout_bytes "$capture: guest stdout is exactly the input" \
        "$capture" "hello-stdin" || result=1
      out="$(launch_output "$capture")" || result=1
      assert_match "$capture: the image seed hook saw EOF" '^seed-read=EOF$' "$out" || result=1
      assert_no_match "$capture: the seed hook did not consume the input" \
        '^seed-read=GOT$' "$out" || result=1
      assert_match "$capture: the project hook saw EOF" '^hook-read=EOF$' "$out" || result=1
      assert_match "$capture: the hook's export reached the program" '^v=hook-value$' "$out" || result=1
      stdin_form_evidence "$form" "$status" "stdout==input; seed-read=EOF; hook-read=EOF; export-hook-value" || result=1
    else
      stdin_writer_stop
      result=1
    fi
  done
  rm -f "$proj/.agent-vm.runtime.sh" || result=1
  direct_cleanup "$name" "$proj" "$CUSTOM_STDIN_SEED" "$result" || result=1
  return "$result"
}

# The `/usr/bin/time -l -o` corroboration: macOS reports "maximum resident set
# size" in bytes. It is evidence only (it can include waited-for descendants),
# so the oracle stays the launcher-only RSS sampler.
time_max_rss_bytes() {
  local file="$1" value
  [ -s "$file" ] || {
    echo "    FAIL: /usr/bin/time wrote no report to $file" >&2
    return 1
  }
  value="$(awk '/maximum resident set size/ { print $1; found = 1 }
    END { exit !found }' "$file")" || {
    echo "    FAIL: no maximum-resident-set-size line in $file" >&2
    return 1
  }
  printf '%s' "$value"
}

# `large`: 256 MiB hashed and 64 MiB round-tripped through `cat`, plus the
# calibrated launcher-RSS comparison **per syntax form** (one warm-up, three
# baseline samples over 1 MiB, three measured samples over 256 MiB). Every
# sample's status and checksum is verified before its RSS is used, and every
# sample records both the launcher-PID sampler and `/usr/bin/time -l -o`
# (#399 B1).
custom_image_direct_stdin_large() {
  local name=direct-stdin-large proj input want base_want got form sample result=0 status
  local cap base_median measured_median growth growth_ok rss time_bytes assertions form_status
  local rss_receipt
  local -a baseline=() measured=()
  proj="$(stdin_row_project "$name" "$CUSTOM_MARKER")" || return 1
  input="$WORK/$name.input"
  head -c 268435456 /dev/urandom >"$input" || return 1
  want="$(shasum -a 256 "$input" | cut -d' ' -f1)" || return 1
  head -c 67108864 "$input" >"$WORK/$name.cat.input" || return 1
  head -c 1048576 "$input" >"$WORK/$name.baseline.input" || return 1
  base_want="$(shasum -a 256 "$WORK/$name.baseline.input" | cut -d' ' -f1)" || return 1
  stdin_identity_init || return 1

  for form in run dash; do
    baseline=()
    measured=()
    form_status=unknown
    # Warm-up: one checked launch so the image is hot. Its checksum is
    # verified too; a failed warm-up must not silently precede the samples.
    cap="$name-warm-$form"
    if stdin_capture "$cap" "$proj" "$WORK/$name.baseline.input" "$form" sha256sum; then
      status="$CAPTURE_STATUS"
      form_status="$status"
      assert_eq "$cap: warm-up exit status" "0" "$status" || result=1
      got="$(direct_stdout "$cap" | cut -d' ' -f1)"
      assert_eq "$cap: warm-up checksum" "$base_want" "$got" || result=1
      printf '    sample: form=%s kind=warm-up status=%s checksum=%s rss_kib=not-sampled time_maxrss_bytes=not-sampled\n' \
        "$form" "$status" "$base_want"
    else
      form_status=observation_failed
      result=1
    fi

    for sample in 1 2 3; do
      cap="$name-baseline-$form-$sample"
      OBSERVE_RSS_FILE="$WORK/$cap.rss"
      OBSERVE_TIME_FILE="$WORK/$cap.time"
      if stdin_capture "$cap" "$proj" "$WORK/$name.baseline.input" "$form" sha256sum; then
        status="$CAPTURE_STATUS"
        form_status="$status"
        rss_sampler_stop
        if assert_eq "$cap: baseline exit status" "0" "$status" &&
          assert_eq "$cap: baseline checksum" "$base_want"             "$(direct_stdout "$cap" | cut -d' ' -f1)" &&
          assert_launcher_rss_identity "$WORK/$cap.rss" "$cap"; then
          rss="$(max_rss_kib "$WORK/$cap.rss")" || { rss=invalid; result=1; }
          time_bytes="$(time_max_rss_bytes "$WORK/$cap.time")" || { time_bytes=invalid; result=1; }
          baseline+=("$rss")
          printf '    sample: form=%s kind=baseline-%s status=%s checksum=%s rss_kib=%s time_maxrss_bytes=%s\n' \
            "$form" "$sample" "$status" "$base_want" "$rss" "$time_bytes"
          # The receipt line is printed from a checked read: printing it
          # through `$(...)` discarded the check's status (#399 review 3).
          rss_receipt="$(launcher_rss_receipt "$WORK/$cap.rss")" || result=1
          printf '    rss_receipt: form=%s kind=baseline-%s %s\n' "$form" "$sample" \
            "$rss_receipt"
        else
          result=1
        fi
      else
        form_status=observation_failed
        rss_sampler_stop
        result=1
      fi
      unset OBSERVE_RSS_FILE OBSERVE_TIME_FILE

      cap="$name-sha-$form-$sample"
      OBSERVE_RSS_FILE="$WORK/$cap.rss"
      OBSERVE_TIME_FILE="$WORK/$cap.time"
      if stdin_capture "$cap" "$proj" "$input" "$form" sha256sum; then
        status="$CAPTURE_STATUS"
        form_status="$status"
        rss_sampler_stop
        if assert_eq "$cap: measured exit status" "0" "$status" &&
          assert_eq "$cap: 256 MiB checksum matches the host's" "$want" \
            "$(direct_stdout "$cap" | cut -d' ' -f1)" &&
          assert_launcher_rss_identity "$WORK/$cap.rss" "$cap"; then
          rss="$(max_rss_kib "$WORK/$cap.rss")" || { rss=invalid; result=1; }
          time_bytes="$(time_max_rss_bytes "$WORK/$cap.time")" || { time_bytes=invalid; result=1; }
          measured+=("$rss")
          printf '    sample: form=%s kind=measured-%s status=%s checksum=%s rss_kib=%s time_maxrss_bytes=%s\n' \
            "$form" "$sample" "$status" "$want" "$rss" "$time_bytes"
          rss_receipt="$(launcher_rss_receipt "$WORK/$cap.rss")" || result=1
          printf '    rss_receipt: form=%s kind=measured-%s %s\n' "$form" "$sample" \
            "$rss_receipt"
        else
          result=1
        fi
      else
        form_status=observation_failed
        rss_sampler_stop
        result=1
      fi
      unset OBSERVE_RSS_FILE OBSERVE_TIME_FILE
    done

    if [ "${#baseline[@]}" -eq 3 ] && [ "${#measured[@]}" -eq 3 ]; then
      base_median="$(median3 "${baseline[0]}" "${baseline[1]}" "${baseline[2]}")" || result=1
      measured_median="$(median3 "${measured[0]}" "${measured[1]}" "${measured[2]}")" || result=1
      if growth="$(rss_growth_verdict "$base_median" "$measured_median")"; then
        growth_ok=yes
      else
        growth_ok=no
        result=1
      fi
      printf '    rss_kib form=%s baseline=%s,%s,%s median=%s measured=%s,%s,%s median=%s growth=%s limit=%s growth_within_limit=%s\n' \
        "$form" "${baseline[0]}" "${baseline[1]}" "${baseline[2]}" "$base_median" \
        "${measured[0]}" "${measured[1]}" "${measured[2]}" "$measured_median" "$growth" \
        "$RSS_GROWTH_LIMIT_KIB" "$growth_ok"
      if [ "$growth_ok" = no ]; then
        echo "    FAIL: $name ($form): launcher RSS grew ${growth} KiB (limit $RSS_GROWTH_LIMIT_KIB)"
      fi
      assertions="warmup+baseline status/checksum+sampler-identity; 256MiB checksum+sampler-identity; growth<$RSS_GROWTH_LIMIT_KIB KiB"
    else
      echo "    FAIL: $name ($form): did not collect three validated baseline and measured samples"
      result=1
      assertions="sample collection failed"
    fi
    # The per-form receipt carries the status the launcher was observed to
    # exit with, never a success-shaped constant on a failed form (#399 R2).
    stdin_form_evidence "$form" "$form_status" "$assertions" || result=1
  done

  # The byte-exact round trip, both forms, over the 64 MiB slice.
  for form in run dash; do
    if stdin_capture "$name-cat-$form" "$proj" "$WORK/$name.cat.input" "$form" cat; then
      status="$CAPTURE_STATUS"
      assert_eq "$name-cat-$form: guest exit status" "0" "$status" || result=1
      if ! cmp -s "$WORK/$name.cat.input" "$WORK/$name-cat-$form.stdout"; then
        echo "    FAIL: $name-cat-$form: the 64 MiB round trip is not byte-identical"
        cmp -l "$WORK/$name.cat.input" "$WORK/$name-cat-$form.stdout" | head -5 || true
        result=1
      fi
      stdin_form_evidence "$form" "$status" "cat 64MiB: cmp==input" || result=1
    else
      result=1
    fi
  done

  direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || return 1
  return "$result"
}

# The median of three integers.
median3() {
  local a="$1" b="$2" c="$3" low middle
  if [ "$a" -gt "$b" ]; then low="$b"; middle="$a"; else low="$a"; middle="$b"; fi
  if [ "$c" -le "$low" ]; then printf '%s' "$low"
  elif [ "$c" -le "$middle" ]; then printf '%s' "$c"
  else printf '%s' "$middle"; fi
}

# `early-close`: 64 MiB of input, a guest that reads 16 bytes and exits. The
# guest's own status stands and nothing is reported as a broken pipe.
custom_image_direct_stdin_early_close() {
  local name=direct-stdin-early-close proj input result=0 form capture started elapsed status
  proj="$(stdin_row_project "$name" "$CUSTOM_MARKER")" || return 1
  input="$WORK/$name.input"
  head -c 67108864 /dev/urandom >"$input" || return 1
  head -c 16 "$input" >"$WORK/$name.expected" || return 1
  for form in run dash; do
    capture="$name-$form"
    started="$(date +%s)"
    if stdin_capture "$capture" "$proj" "$input" "$form" head -c 16; then
      elapsed=$(( $(date +%s) - started ))
      status="$CAPTURE_STATUS"
      assert_eq "$capture: guest exit status" "0" "$status" || result=1
      assert_direct_stdout_file "$capture: the guest received the first 16 bytes" \
        "$capture" "$WORK/$name.expected" || result=1
      assert_no_match "$capture: an early close is not a forwarding failure" \
        'forwarding stdin' "$(launch_output "$capture")" || result=1
      assert_no_match "$capture: an early close is not a broken pipe" \
        'broken pipe' "$(launch_output "$capture")" || result=1
      if [ "$elapsed" -ge 60 ]; then
        echo "    FAIL: $capture: an early-closing guest took ${elapsed}s (limit 60)"
        result=1
      fi
      stdin_form_evidence "$form" "$status" "stdout==first-16-bytes; no-forwarding-failure; <60s" ||
        result=1
    else
      result=1
    fi
  done
  direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || return 1
  return "$result"
}

# `live-handshake`: both streams are observed, and a line is echoed, *before*
# input ends. A collect-until-exit implementation fails the first deadline.
#
# Readiness is a handshake gate, not a report: a missed marker aborts the form
# (close the writer, reap the capture) instead of opening the FIFO for another
# synchronous write, which could block forever when no reader remains (#399 F2).
custom_image_direct_stdin_live_handshake() {
  local name=direct-stdin-live-handshake proj fifo result=0 form capture guest status
  proj="$(stdin_row_project "$name" "$CUSTOM_MARKER")" || return 1
  guest='printf "out-ready\n"; printf "err-ready\n" >&2;
    if IFS= read -r l; then printf "out-got:%s\n" "$l"; printf "err-got:%s\n" "$l" >&2; fi;
    cat >/dev/null; printf "out-eof\n"; printf "err-eof\n" >&2'
  for form in run dash; do
    capture="$name-$form"
    fifo="$WORK/$capture.fifo"
    rm -f "$fifo" || { result=1; continue; }
    mkfifo "$fifo" || { result=1; continue; }
    stdin_writer_start "$fifo" "" hold || { result=1; continue; }
    if ! stdin_capture_async "$capture" "$proj" "$fifo" "$form" bash -c "$guest"; then
      echo "    FAIL: $capture: could not start the background capture"
      abort_live_capture "$capture"
      result=1
      continue
    fi
    # Nothing has been written yet: the guest must still be producing output.
    if ! wait_for_marker "$WORK/$capture.stdout" '^out-ready$' 120; then
      abort_live_capture "$capture"
      result=1
      continue
    fi
    if ! wait_for_marker "$WORK/$capture.out" '^err-ready$' 10; then
      abort_live_capture "$capture"
      result=1
      continue
    fi
    if ! stdin_writer_send "$fifo" "ping
"; then
      abort_live_capture "$capture"
      result=1
      continue
    fi
    if ! wait_for_marker "$WORK/$capture.stdout" '^out-got:ping$' 10; then
      abort_live_capture "$capture"
      result=1
      continue
    fi
    if ! wait_for_marker "$WORK/$capture.out" '^err-got:ping$' 10; then
      abort_live_capture "$capture"
      result=1
      continue
    fi
    # The writer is still open and the launcher still running.
    if ! kill -0 "$STDIN_WRITER_PID" 2>/dev/null; then
      echo "    FAIL: $capture: the row's writer died before the handshake"
      abort_live_capture "$capture"
      result=1
      continue
    fi
    stdin_writer_close
    if ! wait_for_marker "$WORK/$capture.stdout" '^out-eof$' 10; then
      abort_live_capture "$capture"
      result=1
      continue
    fi
    if ! wait_for_marker "$WORK/$capture.out" '^err-eof$' 10; then
      abort_live_capture "$capture"
      result=1
      continue
    fi
    wait_capture_bounded "$capture" || result=1
    stdin_writer_stop
    if ! status="$(stdin_capture_launcher_status "$capture")"; then
      result=1
      continue
    fi
    assert_eq "$capture: guest exit status" "0" "$status" || result=1
    assert_direct_stdout_bytes "$capture: guest stdout is the three ordered lines" \
      "$capture" $'out-ready\nout-got:ping\nout-eof\n' || result=1
    # The stderr lines are ordered, and every line is either a guest line or a
    # launcher notice.
    if ! awk '/^==> /{next} /^(err-ready|err-got:ping|err-eof)$/{n++; next} {print; bad=1}
      END {exit !(n == 3 && !bad)}' "$WORK/$capture.out" >/dev/null; then
      echo "    FAIL: $capture: guest stderr lines are missing, out of order or mixed"
      grep -aE 'err-|==>' "$WORK/$capture.out" | head -20 || true
      result=1
    fi
    printf 'err-ready\nerr-got:ping\nerr-eof\n' >"$WORK/$capture.stderr.expected" || result=1
    if ! LC_ALL=C grep -a -E '^err-(ready|got:ping|eof)$' "$WORK/$capture.out" |
      cmp -s - "$WORK/$capture.stderr.expected"; then
      echo "    FAIL: $capture: guest stderr lines are missing or out of order"
      result=1
    fi
    stdin_form_evidence "$form" "$status" \
      "out-ready before input; ping round-trip with writer open; EOF; ordered stderr" || result=1
  done
  direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || return 1
  return "$result"
}

# `concurrent-streams`: 4 MiB of 0xE9 on stdout and 4 MiB of 0xF1 on stderr at
# once, while 1 MiB of input is consumed. The bytes are channel-distinct and
# non-ASCII so no launcher diagnostic can be counted as guest output.
custom_image_direct_stdin_concurrent_streams() {
  local name=direct-stdin-concurrent proj fifo result=0 form capture guest status
  proj="$(stdin_row_project "$name" "$CUSTOM_MARKER")" || return 1
  LC_ALL=C tr '\0' '\351' < <(head -c 4194304 /dev/zero) \
    >"$WORK/$name.stdout.expected" || return 1
  # LC_ALL=C in the guest too: `tr` in a UTF-8 locale would emit the UTF-8
  # encoding of U+00E9/U+00F1 instead of one byte.
  guest='(head -c 4194304 /dev/zero | LC_ALL=C tr "\0" "\351") &
    (head -c 4194304 /dev/zero | LC_ALL=C tr "\0" "\361" >&2) &
    cat >/dev/null; wait'
  for form in run dash; do
    capture="$name-$form"
    fifo="$WORK/$capture.fifo"
    rm -f "$fifo" || { result=1; continue; }
    mkfifo "$fifo" || { result=1; continue; }
    stdin_writer_start "$fifo" "" hold || { result=1; continue; }
    if ! stdin_capture_async "$capture" "$proj" "$fifo" "$form" bash -c "$guest"; then
      echo "    FAIL: $capture: could not start the background capture"
      abort_live_capture "$capture"
      result=1
      continue
    fi
    # The guest must be alive and producing: wait for the first stdout byte,
    # then feed the 1 MiB and let the guest see EOF.
    if ! wait_for_nonempty "$WORK/$capture.stdout" 120; then
      abort_live_capture "$capture"
      result=1
      continue
    fi
    head -c 1048576 /dev/urandom >"$WORK/$capture.input" || {
      abort_live_capture "$capture"
      result=1
      continue
    }
    if ! stdin_writer_write_bounded "$fifo" file "$WORK/$capture.input"; then
      abort_live_capture "$capture"
      result=1
      continue
    fi
    stdin_writer_close
    wait_capture_bounded "$capture" || result=1
    stdin_writer_stop
    if ! status="$(stdin_capture_launcher_status "$capture")"; then
      result=1
      continue
    fi
    assert_eq "$capture: guest exit status" "0" "$status" || result=1
    assert_concurrent_stdout "$capture" "$WORK/$name.stdout.expected" \
      "$WORK/$capture.stdout" || result=1
    assert_concurrent_stderr "$capture" "$WORK/$capture.out" 4194304 || result=1
    stdin_form_evidence "$form" "$status" \
      "stdout==4MiB 0xE9; stderr==4MiB 0xF1; zero cross-channel; expected notices" || result=1
  done
  direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || return 1
  return "$result"
}

# `host-open`: the guest exits while the row's writer is still open. A reader
# that is joined at teardown, or a launcher that waits for stdin EOF, misses the
# 30 s bound.
custom_image_direct_stdin_host_open() {
  local name=direct-stdin-host-open proj fifo result=0 form capture started elapsed expected
  local program want status
  local -a argv=()
  proj="$(stdin_row_project "$name" "$CUSTOM_MARKER")" || return 1
  for form in run dash; do
    for expected in true:0 exit7:7; do
      program="${expected%%:*}"
      want="${expected##*:}"
      case "$program" in
      true) argv=(true) ;;
      exit7) argv=(sh -c 'exit 7') ;;
      esac
      capture="$name-$form-$program"
      fifo="$WORK/$capture.fifo"
      rm -f "$fifo" || { result=1; continue; }
      mkfifo "$fifo" || { result=1; continue; }
      stdin_writer_start "$fifo" "" hold || { result=1; continue; }
      started="$(date +%s)"
      if stdin_capture "$capture" "$proj" "$fifo" "$form" "${argv[@]}"; then
        elapsed=$(( $(date +%s) - started ))
        status="$CAPTURE_STATUS"
        # The launcher returned while the writer was still alive.
        if ! kill -0 "$STDIN_WRITER_PID" 2>/dev/null; then
          echo "    FAIL: $capture: the row's writer was gone before the launcher exited"
          result=1
        fi
        stdin_writer_stop
        assert_eq "$capture: guest exit status while host stdin is open" "$want" \
          "$status" || result=1
        if [ "$elapsed" -ge 30 ]; then
          echo "    FAIL: $capture: the launcher waited ${elapsed}s on open host stdin (limit 30)"
          result=1
        fi
        stdin_form_evidence "$form" "$status" "guest=${argv[*]}; writer-open; <30s" || result=1
      else
        stdin_writer_stop
        result=1
      fi
    done
  done
  direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || return 1
  return "$result"
}

# `eof-wait`: a command that waits for EOF gets it.
custom_image_direct_stdin_eof_wait() {
  local name=direct-stdin-eof-wait proj fifo result=0 form capture status
  proj="$(stdin_row_project "$name" "$CUSTOM_MARKER")" || return 1
  for form in run dash; do
    capture="$name-$form"
    stdin_fifo_closed "$capture" abc || { result=1; continue; }
    fifo="$STDIN_FIFO"
    if stdin_capture "$capture" "$proj" "$fifo" "$form" sh -c 'cat >/dev/null; echo done'; then
      stdin_writer_stop
      status="$CAPTURE_STATUS"
      assert_eq "$capture: guest exit status" "0" "$status" || result=1
      assert_direct_stdout_bytes "$capture: the command ran to EOF" "$capture" \
        $'done\n' || result=1
      stdin_form_evidence "$form" "$status" "stdout==done; EOF observed" || result=1
    else
      stdin_writer_stop
      result=1
    fi
  done
  direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || return 1
  return "$result"
}

# `shell-unchanged`: the legacy contract, natively. A `shell` launch keeps the
# bootstrap's `/dev/null`, so bytes waiting on stdin never reach the program.
custom_image_direct_stdin_shell_unchanged() {
  local name=direct-stdin-shell-unchanged proj capture status result=0
  proj="$(stdin_row_project "$name" "$CUSTOM_MARKER")" || return 1
  capture="$name-run"
  stdin_fifo_closed "$capture" hello || return 1
  # The writer is reaped on both of this row's returns, the failed capture
  # included: the row used to return before stopping it (#399 F2). These two
  # paths are what h15/h16-trap cover; no claim is made about every signal.
  if ! capture_custom_direct_input "$capture" "$proj" "$STDIN_FIFO" -- \
    shell bash -c 'cat; echo end'; then
    stdin_writer_stop
    return 1
  fi
  stdin_writer_stop
  status="$CAPTURE_STATUS"
  assert_eq "$capture: shell exit status" "0" "$status" || result=1
  assert_direct_stdout_bytes "$capture: a shell launch still sees /dev/null" \
    "$capture" $'end\n' || result=1
  stdin_form_evidence "shell" "$status" "stdout==end; input never reaches the program" || result=1
  direct_cleanup "$name" "$proj" "$CUSTOM_MARKER" "$result" || return 1
  return "$result"
}

run_check "explicit-build-archive-workflow" custom_explicit_build_workflow

if rows_need_fixtures; then
  prepare_custom_fixtures || die "could not build/import the custom-image fixtures"
fi
run_check "explicit-docker-import-workflow" custom_docker_import_workflow
run_check "custom-image-fixtures-imported" check_custom_fixtures_imported
run_check "custom-image-env-isolation-audit" check_custom_env_isolation
run_check "custom-image-cache-isolated" check_custom_cache_isolation
run_check "custom-image-selected-by-project-config" custom_image_selected_by_project_config
run_check "custom-image-user-image-only-config" custom_image_user_image_only_config
run_check "custom-image-setup-verification-selected-ref" custom_image_setup_verification_uses_selected_ref

run_check "custom-image-runs-program" custom_image_runs_program
run_check "custom-image-stamp-present-nonnumeric" custom_image_stamp_present
run_check "custom-image-direct-both-forms" custom_image_direct_both_forms
run_check "custom-image-direct-argv" custom_image_direct_argv
run_check "custom-image-direct-statuses" custom_image_direct_statuses
run_check "custom-image-direct-hook" custom_image_direct_hook
run_check "custom-image-direct-stdin-small" custom_image_direct_stdin_small
run_check "custom-image-direct-stdin-empty" custom_image_direct_stdin_empty
run_check "custom-image-direct-stdin-binary" custom_image_direct_stdin_binary
run_check "custom-image-direct-stdin-large" custom_image_direct_stdin_large
run_check "custom-image-direct-stdin-hook-read" custom_image_direct_stdin_hook_read
run_check "custom-image-direct-stdin-early-close" custom_image_direct_stdin_early_close
run_check "custom-image-direct-stdin-live-handshake" custom_image_direct_stdin_live_handshake
run_check "custom-image-direct-stdin-concurrent-streams" custom_image_direct_stdin_concurrent_streams
run_check "custom-image-direct-stdin-host-open" custom_image_direct_stdin_host_open
run_check "custom-image-direct-stdin-eof-wait" custom_image_direct_stdin_eof_wait
run_check "custom-image-direct-stdin-shell-unchanged" custom_image_direct_stdin_shell_unchanged
run_check "custom-image-direct-host-decoy" custom_image_direct_host_decoy
run_check "custom-image-direct-nonstandard" custom_image_direct_nonstandard
run_check "custom-image-direct-zero-provisioning" custom_image_direct_zero_provisioning
run_check "custom-image-direct-chrome-furniture" custom_image_direct_chrome_furniture
run_check "custom-image-state-persists-nonroot" custom_image_state_persists nonroot
run_check "custom-image-state-persists-root" custom_image_state_persists root
run_check "custom-image-user-home-set-nonroot" custom_image_user_home_set nonroot
run_check "custom-image-user-home-set-root" custom_image_user_home_set root
run_check "custom-image-missing-program" custom_image_missing_program
run_check "custom-image-without-bash" custom_image_without_bash
run_check "custom-image-integrations" custom_image_integrations
run_check "custom-image-supplied-seeds" custom_image_supplied_seeds
run_check "custom-image-hook-path" custom_image_hook_path
run_check "custom-image-credential-injection" custom_image_credential_injection
run_check "custom-image-nonstandard-imported" custom_image_nonstandard_imported
run_check "custom-image-nonstandard-cold-warm" custom_image_nonstandard_cold_warm
run_check "custom-image-retained-default" custom_image_retained_default
run_check "custom-image-default-upgrade" custom_image_default_upgrade
run_check "custom-image-host-pins" custom_image_host_pins
run_check "custom-image-no-bash-attach" check_custom_no_bash_attach
run_check "custom-image-user-home-attach-nonroot" check_custom_user_home_attach nonroot
run_check "custom-image-user-home-attach-root" check_custom_user_home_attach root
run_check "custom-image-nonstandard-attach" check_custom_nonstandard_attach
run_check "custom-image-cache-isolated-final" check_custom_cache_isolation

echo
echo "e2e: $PASSED passed, $FAILED failed, $SKIPPED skipped"
[[ "$FAILED" -eq 0 ]]
