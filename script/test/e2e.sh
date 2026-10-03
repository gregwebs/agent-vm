#!/usr/bin/env bash
# shellcheck disable=SC2016  # guest-side commands deliberately single-quote `$(...)`
#
# End-to-end (VM-boot) verification for agent-vm on Apple Silicon.
#
# It boots real microVMs through the agent-vm CLI and asserts the behaviours
# CI cannot observe. Two groups:
#   all          (default) the dev-image checks below plus the custom-image group
#   custom-image only the #258 marker-free custom-image group; needs Docker, the
#                release-bundle `msb`, and a launcher binary — no dev images
#
# See CONTRIBUTING.md#end-to-end-vm-boot-tests-optional for background and
# acceptance criteria.
#
# This is **not** run on CI: GitHub's macOS runners are Intel and cannot boot
# these arm64 microVMs. It is the standard local entry point instead.
#
# Inputs (all optional; `env -u` if your shell exports the image vars):
#   AGENT_VM_BIN                     launcher binary. Default: target/macos-dev/bin/agent-vm,
#                                    else target/macos/bin/agent-vm.
#   AGENT_VM_STATE_DIR               state root. Default: $HOME/.local/state/agent-vm.
#   AGENT_VM_E2E_STATE_DIR           overrides AGENT_VM_STATE_DIR for this run only.
#   AGENT_VM_E2E_TEMPLATE_IMAGE      composed template in docker. Default: agent-vm-template:dev.
#   AGENT_VM_E2E_BASE_IMAGE          tool-free base in docker. Default: agent-vm-base:dev.
#
# Opt-in checks (skipped, with a notice, when the variable is unset):
#   AGENT_VM_E2E_LEGACY_IMAGE=<ref>           an image that supplies
#                                             /opt/agent-vm/seed-claude-plugins.sh (E8)
#   AGENT_VM_E2E_SETUP_BASE_REF=<ref>         a pullable linux/arm64 base ref for `setup` (E10)
#   AGENT_VM_E2E_UPDATE_CHECK=1               probe the registry (E9; needs network)
#   AGENT_VM_E2E_RUST=1                       also run the #[ignore]d Rust Docker e2e
#
# State changes (all additive): the dev images are imported into
# $AGENT_VM_STATE_DIR's msb cache, the dev template is also imported under its
# published default ref (so the fast path resolves offline), and the custom
# fixtures are imported into a fresh isolated under-$WORK state root. Undo with
# `agent-vm doctor --reset-msb-db` plus `docker rmi agent-vm-base:<hex>` if you
# want the state dir byte-identical.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

PUBLISHED_TEMPLATE_REF="ghcr.io/wirenboard/agent-vm-template:latest"
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
  all | custom-image)
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

# ---------------------------------------------------------------- inputs ----

if [[ -n "${AGENT_VM_BIN:-}" ]]; then
  AGENT_VM="$(cd "$(dirname "$AGENT_VM_BIN")" && pwd)/$(basename "$AGENT_VM_BIN")"
elif [[ -x "$REPO_ROOT/target/macos-dev/bin/agent-vm" ]]; then
  AGENT_VM="$REPO_ROOT/target/macos-dev/bin/agent-vm"
else
  AGENT_VM="$REPO_ROOT/target/macos/bin/agent-vm"
fi

TEMPLATE_IMAGE="${AGENT_VM_E2E_TEMPLATE_IMAGE:-agent-vm-template:dev}"
BASE_IMAGE="${AGENT_VM_E2E_BASE_IMAGE:-agent-vm-base:dev}"
STATE_DIR="${AGENT_VM_E2E_STATE_DIR:-${AGENT_VM_STATE_DIR:-$HOME/.local/state/agent-vm}}"

# ----------------------------------------------------------- preconditions --

[[ -x "$AGENT_VM" ]] || die "launcher not found at $AGENT_VM; build it with
  ./script/build/macos.sh --dev
or point AGENT_VM_BIN at one."

command -v docker >/dev/null 2>&1 || die "docker is required but not on PATH"
docker info >/dev/null 2>&1 || die "the docker daemon is unreachable; start colima or Docker Desktop"

# `script/build/import-image.sh` hardcodes the release bundle's msb. The --dev
# bundle alone cannot import images, so say so up front rather than half-way in.
[[ -x "$REPO_ROOT/target/macos/bin/msb" ]] || die "script/build/import-image.sh
needs the release bundle's msb at target/macos/bin/msb. Run ./script/build/macos.sh
(the --dev bundle does not provide it)."

if [[ "$GROUP" == all ]]; then
  for image in "$BASE_IMAGE" "$TEMPLATE_IMAGE"; do
    docker image inspect "$image" >/dev/null 2>&1 ||
      die "docker image '$image' is missing; build the dev images first — see
  macos-build.md (and AGENT_VM_E2E_BASE_IMAGE / AGENT_VM_E2E_TEMPLATE_IMAGE to
  point at different tags)."
  done
fi

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
  if [ "$status" -ne 0 ]; then
    echo "e2e: preserving $WORK for failure evidence (exit $status)" >&2
    return 0
  fi
  rm -rf "$WORK"
}
trap cleanup_work EXIT
# Derived images are tagged agent-vm-layer:<project-basename>-<content-hash>, so a
# fresh basename per run forces the compose checks to build (and print their
# plan) instead of silently reusing a cached step from an earlier run. Docker
# repository names and the local-registry refs must be lowercase, and mktemp's
# suffix is mixed-case, so normalize it once here.
RUN_ID="$(printf '%s' "${WORK##*.}" | tr '[:upper:]' '[:lower:]')"

# The developer's real state dir is only the dev-image groups' store. The
# custom-image group uses its own fresh under-$WORK root ($CUSTOM_STATE), and
# touching the dev dir there could write a one-way cache redirect into it.
if [[ "$GROUP" == all ]]; then
  mkdir -p "$STATE_DIR/msb-home"

  # The cache-config trap (agent-vm #84 verification, CONTRIBUTING.md): with
  # AGENT_VM_SHARE_MSB_CACHE enabled, agent-vm's boot rewrites msb-home/config.json
  # to redirect paths.cache at the shared ~/.microsandbox/cache, but
  # import-image.sh runs `msb image load` directly and never applies that redirect.
  # Initialising through a non-Launch builtin first writes the same config.json the
  # boot will use, so import and boot agree.
  if [[ ! -f "$STATE_DIR/msb-home/config.json" ]]; then
    echo "==> Initializing $STATE_DIR/msb-home (so import and boot share one cache)"
    AGENT_VM_STATE_DIR="$STATE_DIR" "$AGENT_VM" msb --version >/dev/null 2>&1 || true
  fi
fi

# A fresh, short, isolated state root for every custom-image boot. Never the
# shared dev state dir above: these checks must not see dev-image derived tags.
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
# The one environment every command that touches the custom root runs under.
# The host may export AGENT_VM_SHARE_MSB_CACHE, and the pinned SDK reads
# MSB_CONFIG_PATH instead of MSB_HOME/config.json when it is set (a loaded
# paths.cache overrides the private default). Leaving either in place lets an
# isolated import write one cache while a launch reads another and falls
# through to a registry pull, so neutralise both here: the private
# $CUSTOM_STATE/msb-home/cache is the only store this group exercises.
CUSTOM_ENV=(env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_BASE_IMAGE -u AGENT_VM_ROOT -u AGENT_VM_SHARE_MSB_CACHE -u AGENT_VM_MSB_CACHE_DIR -u MSB_CONFIG_PATH AGENT_VM_STATE_DIR="$CUSTOM_STATE")
if [ -n "${AGENT_VM_SHARE_MSB_CACHE:-}" ]; then
  echo "e2e: neutralized inherited AGENT_VM_SHARE_MSB_CACHE=$AGENT_VM_SHARE_MSB_CACHE for the isolated custom root"
fi
if [ -n "${MSB_CONFIG_PATH:-}" ]; then
  echo "e2e: unset inherited MSB_CONFIG_PATH=$MSB_CONFIG_PATH for the isolated custom root"
fi

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
"${CUSTOM_ENV[@]}" "$AGENT_VM" msb --version >/dev/null 2>&1 ||
  die "could not initialize the custom-image state root at $CUSTOM_STATE"
assert_custom_cache_isolated "after init" ||
  die "the custom msb-home is not isolated (see above)"

# ------------------------------------------------------------- host helpers --

# agent-vm with the image env vars dropped, so a default-config check really
# resolves the default rather than an inherited AGENT_VM_IMAGE_TAG / _BASE_IMAGE.
avm() {
  env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_BASE_IMAGE \
    AGENT_VM_STATE_DIR="$STATE_DIR" "$AGENT_VM" "$@"
}

# agent-vm against the isolated custom state root (only ever used off the shim).
avm_custom_state() {
  "${CUSTOM_ENV[@]}" "$AGENT_VM" "$@"
}

import_image() {
  local source="$1" dest="${2:-$1}" state="${3:-$STATE_DIR}"
  echo "==> Importing $source as $dest"
  if [ "$state" = "$CUSTOM_STATE" ]; then
    "${CUSTOM_ENV[@]}" "$REPO_ROOT/script/build/import-image.sh" "$source" "$dest" >/dev/null
  else
    AGENT_VM_STATE_DIR="$state" "$REPO_ROOT/script/build/import-image.sh" "$source" "$dest" >/dev/null
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
  if [[ -s "$HOST_SHIM_LOG" ]]; then
    echo "    FAIL: a host decoy was invoked:"
    cat "$HOST_SHIM_LOG"
    return 1
  fi
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
    "$CUSTOM_NONSTANDARD" "$CUSTOM_STAMP"; do
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

# Transitive descendants of $1 (bounded depth), one `pid:comm` per line.
descendants_of() {
  local root="$1"
  ps -axo pid=,ppid=,comm= | awk -v root="$root" '
    { p[$1]=$2; c[$1]=$3 }
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

# Bounded teardown of an in-flight observed launch: the watchdog is stopped
# first so it cannot later signal a recycled PID, then the recorded launcher is
# TERMed, given 5s, and KILLed. Both children are reaped so a failed observation
# cannot return while a VM process is still starting.
stop_observed_launch() {
  local pid="$1" watchdog="$2" i=0
  kill -TERM "$watchdog" 2>/dev/null || true
  kill -TERM "$pid" 2>/dev/null || true
  while [ "$i" -lt 5 ]; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
    i=$((i + 1))
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
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

  (cd "$proj" || exit 1; exec "$@") >"$out" 2>&1 </dev/null &
  local pid=$!
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
  # running, so every early exit below goes through the same bounded teardown.
  local start elapsed snap
  start=$(date +%s)
  while kill -0 "$pid" 2>/dev/null; do
    if ! ps -axo pid=,ppid=,comm= >/dev/null; then
      echo "    FAIL: ps snapshot failed"
      stop_observed_launch "$pid" "$watchdog"
      return 1
    fi
    if ! snap="$(descendants_of "$pid")"; then
      echo "    FAIL: descendant observation failed"
      stop_observed_launch "$pid" "$watchdog"
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
    "${CUSTOM_ENV[@]}" \
    PATH="$SHIM_DIR:/usr/bin:/bin" \
    HOME="$CUSTOM_HOME" \
    HOST_SHIM_LOG="$HOST_SHIM_LOG" \
    "$AGENT_VM" "$@"
}

# Attach-branch launch under a real PTY (macOS BSD `script`). `script`'s exit
# status is not assumed to equal the guest's; callers inspect the recorded PTY
# output. The watchdog and observer are identical to the streaming path.
capture_custom_attach() {
  local name="$1" proj="$2" pty="$WORK/$1.pty" log="$WORK/$1.pty.log"
  shift 2
  rm -f "$pty" "$log" || return 1
  observe_launch "$name" "$proj" "$log" -- \
    "${CUSTOM_ENV[@]}" \
    PATH="$SHIM_DIR:/usr/bin:/bin" \
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

  # shellcheck disable=SC2329  # invoked indirectly through run_check
  failing_capture() {
    local out
    out="$(exit 37)" || return 1
    : "$out"
    assert_no_host_calls
  }
  # shellcheck disable=SC2329  # invoked indirectly through run_check
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
    result=1
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
      result=1
    fi
  done
  if expect_effective_path "oracle-two-lines" "$(path_oracle_row "$accepted")"$'\n'"path=$accepted" >/dev/null 2>&1; then
    echo "    FAIL: PATH oracle accepted two path= lines"
    result=1
  fi

  # #258: the real corrected subjects, probed in isolated subshells with stub
  # subprocesses. No VM is booted and no host filesystem path is removed: the
  # stubs substitute the readers/removers, so only the wiring is exercised.
  local probe_dir="$WORK/harness-negative-probes"
  local removed_state37 removed_rm38 probe_target
  if ! mkdir -p "$probe_dir"; then
    echo "    FAIL: could not create the harness-negative probe dir"
    result=1
  fi

  # (a) An evidence reader that prints complete, expected-looking lines and then
  # exits nonzero must fail the guarded read, never pass on its printed output.
  if (
    launch_output() { printf 'credsprobe=ok\nhome=/x\nuid=1 gid=1\n'; return 37; }
    read_launch_evidence "probe" >/dev/null 2>&1
  ); then
    echo "    FAIL: guarded evidence read accepted a reader that failed after printing"
    result=1
  fi

  # (b) A grep error (status 2) must not be treated as proof that a synthetic
  # token is absent from guest output.
  if (
    # shellcheck disable=SC2329  # invoked indirectly by assert_no_match
    grep() { return 2; }
    assert_no_credential_leak "grep2 probe" "haystack with no tokens" >/dev/null 2>&1
  ); then
    echo "    FAIL: grep status 2 was treated as proven absence"
    result=1
  fi

  # (c) A state-dir resolution failure must fail cleanup while the other
  # project's private token is still attempted.
  removed_state37="$probe_dir/removed-state37.txt"
  : >"$removed_state37" || result=1
  if (
    host_state_dir() {
      if [ "$1" = "$WORK/custom-cred" ]; then return 37; fi
      printf '%s' "$probe_dir/state-missing"
    }
    rm() { printf '%s\n' "$*" >>"$removed_state37"; return 0; }
    remove_custom_credential_material
  ) >/dev/null 2>&1; then
    echo "    FAIL: cleanup succeeded despite a state-dir resolution failure"
    result=1
  fi
  if ! grep -qF -- "$probe_dir/state-missing.secrets/anthropic" "$removed_state37"; then
    echo "    FAIL: cleanup skipped the other project after a resolution failure"
    result=1
  fi

  # (d) An rm failure must fail cleanup while other removals are attempted.
  removed_rm38="$probe_dir/removed-rm38.txt"
  : >"$removed_rm38" || result=1
  if (
    host_state_dir() { printf '%s' "$probe_dir/state-ok"; }
    rm() { printf '%s\n' "$*" >>"$removed_rm38"; return 38; }
    remove_custom_credential_material
  ) >/dev/null 2>&1; then
    echo "    FAIL: cleanup succeeded despite an rm failure"
    result=1
  fi
  for probe_target in "$CUSTOM_CREDENTIAL_SEED" "$probe_dir/state-ok.secrets/anthropic"; do
    if ! grep -qF -- "$probe_target" "$removed_rm38"; then
      echo "    FAIL: rm-failure cleanup did not attempt removing $probe_target"
      result=1
    fi
  done

  # (e) The real stamp subject: an evidence reader that prints the complete
  # expected lines and then exits nonzero must make custom_image_stamp_present
  # FAIL. Each capture is guarded in its own assignment, so a reverted nested
  # capture would accept the printed output, return success, and turn this
  # probe red. No VM boots and no host path is removed: the launcher and reader
  # are stubbed inside the subshell.
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
    result=1
  fi

  local observed_pass="$PASSED" observed_fail="$FAILED"
  if [ "$observed_pass" -ne 0 ] || [ "$observed_fail" -ne 2 ]; then
    echo "    FAIL: harness negative expected 0 pass / 2 fail, got $observed_pass/$observed_fail"
    # The deliberately expected FAIL output is captured, not shown as the
    # summary's own failures.
    cat "$log"
    result=1
  fi
  assert_no_host_calls || result=1

  PASSED="$saved_passed"
  FAILED="$saved_failed"
  return "$result"
}

# ============================================================ dev checks ====

# AC: the locally built base carries no agent CLI and no image-version stamp.
check_base_is_tool_free() {
  local out
  out="$(avm shell --no-git --image "$BASE_IMAGE" -- bash -c '
    for b in dsh pi claude codex opencode copilot; do
      if command -v "$b" >/dev/null 2>&1; then echo "PRESENT:$b"; else echo "absent:$b"; fi
    done
    if [ -e /etc/agent-vm-image-version ]; then echo "stamp=present"; else echo "stamp=absent"; fi
  ' 2>&1)" || {
    echo "$out" | tail -20
    return 1
  }
  assert_no_match "no agent CLI on PATH" "^PRESENT:" "$out" || return 1
  assert_eq "all six absent" "6" "$(grep -c '^absent:' <<<"$out")" || return 1
  assert_eq "the locally built base carries no stamp" "stamp=absent" \
    "$(grep '^stamp=' <<<"$out")" || return 1
}

# E1: all six --version checks pass in the composed template guest.
check_template_has_all_tools() {
  local out
  out="$(avm shell --no-git --image "$TEMPLATE_IMAGE" -- bash -c '
    for t in dsh pi codex opencode claude copilot; do
      if [ "$t" = dsh ]; then
        [ -n "$(dsh --version 2>/dev/null)" ] || { echo "MISSING:$t"; exit 1; }
      else
        "$t" --version >/dev/null 2>&1 || { echo "MISSING:$t"; exit 1; }
      fi
    done
  ' 2>&1)" || {
    echo "$out" | tail -20
    return 1
  }
  assert_no_match "no missing tool" "MISSING:" "$out"
}

# E2 / AC 7: a default config with no project layers boots the published
# template with docker absent from PATH (and its invocation shim silent).
check_fast_path_zero_docker() {
  local proj="$WORK/fastpath" shim="$WORK/shim-dev" log="$WORK/docker-calls.log"
  mkdir -p "$proj" "$shim"
  cat >"$shim/docker" <<'SHIM'
#!/usr/bin/env bash
echo "docker $*" >>"$DOCKER_SHIM_LOG"
exit 1
SHIM
  chmod +x "$shim/docker"
  : >"$log"

  local out
  out="$(cd "$proj" && env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_BASE_IMAGE \
    PATH="$shim:/usr/bin:/bin" DOCKER_SHIM_LOG="$log" AGENT_VM_STATE_DIR="$STATE_DIR" \
    "$AGENT_VM" shell --no-git -- bash -c 'true' 2>&1)" || {
    echo "$out" | tail -20
    return 1
  }
  assert_match "boots the published default template" \
    "^==> Booting sandbox from $PUBLISHED_TEMPLATE_REF " "$out" || return 1
  if [[ -s "$log" ]]; then
    echo "    FAIL: docker was invoked on the fast path:"
    cat "$log"
    return 1
  fi
}

# E3 / AC 8: tools = ["claude"] composes the claude layer onto the base, and
# codex is genuinely absent from the guest PATH.
check_tools_claude_composes() {
  local proj="$WORK/claude-$RUN_ID"
  mkdir -p "$proj/.agent-vm"
  cat >"$proj/.agent-vm/config.toml" <<'EOF'
[[tools]]
name = "claude"
command = "claude"
args = ["--dangerously-skip-permissions"]
layer = { builtin = "claude" }
EOF

  local out
  out="$(cd "$proj" && avm shell --yes --base-image "$BASE_IMAGE" -- bash -c '
    printf "codex "; command -v codex || echo "rc=$?"
    printf "claude "; command -v claude || echo "rc=$?"
  ' 2>&1)" || {
    echo "$out" | tail -20
    return 1
  }
  assert_match 'one builtin "claude" tool step' 'tool "claude" \(builtin layer claude\)' "$out" || return 1
  assert_eq "codex absent from guest PATH" "codex rc=1" "$(grep -E '^codex ' <<<"$out")" || return 1
  assert_match "claude present in guest" "^claude /opt/agent" "$out"
}

# E1b / #95: tools = ["pi"] composes the pi layer onto the base, and the
# end-user pi experience works in the guest.
check_tools_pi_composes() {
  local proj="$WORK/pi-$RUN_ID"
  mkdir -p "$proj/.agent-vm"
  cat >"$proj/.agent-vm/config.toml" <<'EOF'
[[tools]]
name = "pi"
command = "pi"
layer = { builtin = "pi" }
EOF

  local pin
  pin="$(jq -r '.dependencies["@earendil-works/pi-coding-agent"]' \
    "$REPO_ROOT/images/tools/pi/package.json")"

  local out
  out="$(cd "$proj" && avm shell --yes --base-image "$BASE_IMAGE" -- bash -c '
    printf "which=%s\n" "$(command -v pi)"
    printf "version=%s\n" "$(timeout 60 pi --version)"
    printf "warn=%s\n" "$(printf "" | timeout 60 pi --mode rpc --no-session --no-approve 2>/dev/null | grep -c "agent-vm: signing in here")"
    printf "warn_ne=%s\n" "$(printf "" | timeout 60 pi -ne --mode rpc --no-session --no-approve 2>/dev/null | grep -c "agent-vm: signing in here")"
    pi_print="$(printf "" | timeout 60 pi -p --no-session 2>/dev/null)"; pi_print_rc=$?
    printf "print_bytes=%s\n" "$(printf %s "$pi_print" | wc -c | tr -d " ")"
    printf "print_rc=%s\n" "$pi_print_rc"
    printf "list=%s\n" "$(timeout 60 pi list)"
  ' 2>&1)" || {
    echo "$out" | tail -20
    return 1
  }
  assert_match "one builtin pi tool step" 'tool "pi" \(builtin layer pi\)' "$out" || return 1
  assert_match "the stable wrapper is on PATH" "^which=/usr/local/bin/pi$" "$out" || return 1
  assert_match "the pinned version is installed" "^version=$pin$" "$out" || return 1
  assert_match "the mandatory warning fires" "^warn=1$" "$out" || return 1
  assert_match "--no-extensions cannot silence it" "^warn_ne=1$" "$out" || return 1
  assert_match "print mode stdout is empty" "^print_bytes=0$" "$out" || return 1
  assert_match "print mode exits cleanly" "^print_rc=0$" "$out" || return 1
  assert_match "pi list is a subcommand, not a prompt" "^list=No packages installed\.$" "$out"
}

# E1c / #96: ~/.pi resolves to state and persists across an independent boot.
pi_home_persists() {
  local mode="$1"
  local -a root_flag=()
  [[ "$mode" == root ]] && root_flag=(--root)
  local proj="$WORK/pi-home-$mode-$RUN_ID"
  mkdir -p "$proj/.agent-vm"
  cat >"$proj/.agent-vm/config.toml" <<'EOF'
[[tools]]
name = "pi"
command = "pi"
layer = { builtin = "pi" }
EOF

  local first second
  first="$(cd "$proj" && avm shell --yes ${root_flag[@]+"${root_flag[@]}"} \
    --base-image "$BASE_IMAGE" -- bash -c '
      printf "link=%s\n" "$(readlink "$HOME/.pi")"
      printf "isdir=%s\n" "$([ -d "$HOME/.pi" ] && echo yes)"
      mkdir -p "$HOME/.pi/agent/npm/node_modules" \
        && printf "sentinel-96" > "$HOME/.pi/agent/npm/node_modules/e2e-marker"
      printf "wrote=%s\n" "$?"
    ' 2>&1)" || { echo "$first" | tail -20; return 1; }
  assert_match "$mode: ~/.pi points at the state dir" "^link=/agent-vm-state/pi$" "$first" || return 1
  assert_match "$mode: ~/.pi resolves to a real directory" "^isdir=yes$" "$first" || return 1
  assert_match "$mode: Pi's global-package dir is writable" "^wrote=0$" "$first" || return 1

  second="$(cd "$proj" && avm shell --yes ${root_flag[@]+"${root_flag[@]}"} \
    --base-image "$BASE_IMAGE" -- bash -c '
      printf "survived=%s\n" "$(cat "$HOME/.pi/agent/npm/node_modules/e2e-marker" 2>&1)"
    ' 2>&1)" || { echo "$second" | tail -20; return 1; }
  assert_match "$mode: state survives an independent boot" "^survived=sentinel-96$" "$second"
}

# E4: a project layer chains on the template in one step, not five.
check_project_layer_chains_on_template() {
  local proj="$WORK/layer-$RUN_ID"
  mkdir -p "$proj/.agent-vm/layers/10-e2e"
  cat >"$proj/.agent-vm/layers/10-e2e/Dockerfile" <<'EOF'
ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-template:latest
FROM ${BASE_IMAGE}
RUN echo "e2e marker" > /e2e-marker.txt
EOF

  local out
  out="$(cd "$proj" && avm shell --yes -- bash -c 'cat /e2e-marker.txt' 2>&1)" || {
    echo "$out" | tail -20
    return 1
  }
  assert_match "exactly one layer step" "step 1/1" "$out" || return 1
  assert_no_match "not a five-step tool chain" "step 1/5" "$out" || return 1
  assert_match "layer applied in guest" "e2e marker" "$out"
}

# E8 / optional: an image that supplies /opt/agent-vm/seed-claude-plugins.sh is
# seeded through the ordinary runtime entry point. This tests that supplied
# artifact only; it makes no released-default or lineage claim.
check_legacy_seed() {
  local proj="$WORK/legacy"
  mkdir -p "$proj"
  local out
  out="$(cd "$proj" && avm shell --no-git --image "$AGENT_VM_E2E_LEGACY_IMAGE" -- bash -c '
    echo "seed-d-entries=$(ls /opt/agent-vm/seed.d 2>/dev/null | wc -l | tr -d " ")"
    claude plugin list 2>&1
  ' 2>&1)" || {
    echo "$out" | tail -20
    return 1
  }
  assert_match "the image supplies no seed.d" "^seed-d-entries=0$" "$out" || return 1
  assert_match "plugins seeded via the supplied named script" \
    "lsp@claude-plugins-official" "$out"
}

# E9: --update-check probes the published chain root, never a derived tag.
check_update_check() {
  local proj="$WORK/update"
  mkdir -p "$proj"
  local out
  out="$(cd "$proj" && env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_BASE_IMAGE \
    AGENT_VM_UPDATE_CHECK=1 RUST_LOG=agent_vm=debug AGENT_VM_STATE_DIR="$STATE_DIR" \
    "$AGENT_VM" shell --no-git -- bash -c 'sleep 6' 2>&1)" || {
    echo "$out" | tail -20
    return 1
  }
  assert_match "probes the published template ref" \
    "registry update probe.*$PUBLISHED_TEMPLATE_REF" "$out" || return 1
  assert_no_match "never probes a derived layer tag" \
    "registry update probe.*agent-vm-layer:" "$out"
}

# E10 / D10: setup under tools = ["claude"] pulls the base, reports claude as
# supplied by a not-yet-composed layer, and exits 0.
check_setup_notice() {
  local proj="$WORK/setup"
  mkdir -p "$proj/.agent-vm"
  cat >"$proj/.agent-vm/config.toml" <<'EOF'
[[tools]]
name = "claude"
command = "claude"
layer = { builtin = "claude" }
EOF

  local out
  out="$(cd "$proj" && avm setup --base-image "$AGENT_VM_E2E_SETUP_BASE_REF" 2>&1)" || {
    echo "$out" | tail -20
    if grep -q 'Exec format error' <<<"$out"; then
      echo "    hint: $AGENT_VM_E2E_SETUP_BASE_REF is not linux/arm64 (the published"
      echo '          ghcr template is amd64 by design); serve a locally built base.'
    fi
    return 1
  }
  assert_match "D10 notice names the supplying layer" \
    'claude is supplied by tool layer "claude"' "$out" || return 1
  assert_match "setup reports the image ready" \
    "$AGENT_VM_E2E_SETUP_BASE_REF ready" "$out"
}

check_rust_compose_e2e() {
  AGENT_VM_E2E_BASE_IMAGE="$BASE_IMAGE" cargo test -p agent-vm --bin agent-vm -- \
    e2e_builtin_tool_layer_composes_onto_an_imported_base --ignored --test-threads=1
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
assert_state_json() {
  local desc="$1" filter="$2" state
  state="$(host_state_dir "$INTEG_PROJ")" || return 1
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

# 1. marker-free hello runs as host identity (nonroot) and 0:0 (root), and the
# guest confirms the stamp is absent.
custom_image_runs_program() {
  local name="custom-runs" proj out host_uid host_gid
  proj="$(custom_project "$name")" || return 1
  capture_custom_launch "$name" "$proj" hello-258 --no-git --image "$CUSTOM_MARKER" || return 1
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
  capture_custom_launch "$root" "$root_proj" hello-258 --no-git --root --image "$CUSTOM_MARKER" || return 1
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

  capture_custom_launch "$name" "$proj" hello-258 --no-git ${root_flag[@]+"${root_flag[@]}"} \
    --image "$CUSTOM_MARKER" write "sentinel-258-$mode" || return 1
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
  capture_custom_launch "$read" "$proj" hello-258 --no-git ${root_flag[@]+"${root_flag[@]}"} \
    --image "$CUSTOM_MARKER" read "$mode" || return 1
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

  capture_custom_launch "$name" "$proj" hello-258 --no-git ${root_flag[@]+"${root_flag[@]}"} \
    --image "$CUSTOM_USER_HOME" write "uh-$mode" || return 1
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
  capture_custom_launch "$read" "$proj" hello-258 --no-git ${root_flag[@]+"${root_flag[@]}"} \
    --image "$CUSTOM_USER_HOME" read "$mode" || return 1
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
  capture_custom_launch "$name" "$proj" missing-258 --no-git --image "$CUSTOM_MARKER" || return 1
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
  capture_custom_launch "$hookname" "$hookproj" missing-258 --no-git --image "$CUSTOM_MARKER" || return 1
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
  if ! capture_custom_launch "$name" "$proj" hello-258 --no-git --image "$CUSTOM_NO_BASH"; then
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
  # `shell ... -- bash -c 'SCRIPT'` is the supported/documented argv form: the
  # interactive shell joins the separately escaped arguments into one `bash -c`
  # command line, so a bare single script string would be looked up as a command.
  capture_custom_launch "integrations-seed" "$INTEG_PROJ" shell --no-git --image "$CUSTOM_MARKER" -- \
    bash -c "printf '%s' '$seed_json' > /agent-vm-state/claude.json" || return 1
  require_launch_ok "integrations-seed" || return 1
  assert_no_host_calls || return 1
  assert_state_json "seeded unrelated entries" "$UNRELATED_STATE" || return 1

  # absent: no owned entry, no seed hook, no integration execution.
  capture_custom_launch "integrations-absent" "$INTEG_PROJ" hello-258 --no-git --image "$CUSTOM_MARKER" || return 1
  require_launch_ok "integrations-absent" || return 1
  assert_no_host_calls || return 1
  assert_state_json "absent: no owned entry" "$NO_OWNED_STATE" || return 1
  assert_state_json "absent: unrelated entries intact" "$UNRELATED_STATE" || return 1
  [ ! -e "$state/seed-258.payload" ] || { echo "    FAIL: absent: seed payload exists"; return 1; }
  [ ! -e "$state/mcp-executed-258" ] || { echo "    FAIL: absent: execution file exists"; return 1; }

  # advertised + supplied wrapper: the configured entry is read from state and
  # actually executed; the supplied seed.d hook runs.
  capture_custom_launch "integrations-advertised" "$INTEG_PROJ" verify-mcp-258 --no-git --image "$CUSTOM_INTEGRATIONS" || return 1
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
  capture_custom_launch "integrations-optout" "$INTEG_PROJ" shell --no-git --image "$CUSTOM_INTEGRATIONS" -- \
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
  capture_custom_launch "integrations-wrapper" "$INTEG_PROJ" verify-mcp-258 --no-git --image "$CUSTOM_WRAPPER" || return 1
  require_launch_ok "integrations-wrapper" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output integrations-wrapper)"
  assert_match "wrapper-provided: configured entry executed" '^verify-mcp-258: OK$' "$out" || return 1
  assert_state_json "wrapper-provided: owned entry configured" "$OWNED_STATE" || return 1
  assert_state_json "wrapper-provided: unrelated entries intact" "$UNRELATED_STATE" || return 1
  [ -e "$state/mcp-executed-258" ] || { echo "    FAIL: wrapper-provided: no execution file"; return 1; }
  capture_custom_launch "integrations-wrapper-seed" "$INTEG_PROJ" shell --no-git --image "$CUSTOM_WRAPPER" -- \
    bash -c 'if [ -e /tmp/seed-258-ran ]; then echo seedflag=present; else echo seedflag=absent; fi' || return 1
  require_launch_ok "integrations-wrapper-seed" || return 1
  assert_no_host_calls || return 1
  out="$(launch_output integrations-wrapper-seed)"
  assert_eq "wrapper-provided: no seed.d hook ran" "seedflag=absent" "$(grep '^seedflag=' <<<"$out")" || return 1
  assert_eq "wrapper-provided: prior seed payload unchanged" "seed=initial-258" \
    "$(cat "$state/seed-258.payload")" || return 1

  # absent again: the stale owned entry is removed and nothing re-executes.
  rm -f "$state/mcp-executed-258" || return 1
  capture_custom_launch "integrations-after" "$INTEG_PROJ" hello-258 --no-git --image "$CUSTOM_MARKER" || return 1
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

    capture_custom_launch "$name-first" "$proj" hello-258 --no-git --image "$img" || return 1
    require_launch_ok "$name-first" || return 1
    assert_eq "$variant: first boot seeds initial bytes" "seed=initial-258" \
      "$(cat "$state/seed-258.payload")" || return 1

    capture_custom_launch "$name-edit" "$proj" shell --no-git --image "$img" -- \
      bash -c 'printf %s edited-258 > /agent-vm-state/seed-258.payload; if [ -e /tmp/seed-258-ran ]; then echo seedflag=present; else echo seedflag=absent; fi' || return 1
    require_launch_ok "$name-edit" || return 1
    out="$(launch_output "$name-edit")"
    assert_eq "$variant: per-boot flag on the edit boot" "seedflag=present" \
      "$(grep '^seedflag=' <<<"$out")" || return 1

    capture_custom_launch "$name-read" "$proj" shell --no-git --image "$img" -- \
      bash -c 'cat /agent-vm-state/seed-258.payload; echo; if [ -e /tmp/seed-258-ran ]; then echo seedflag=present; else echo seedflag=absent; fi' || return 1
    require_launch_ok "$name-read" || return 1
    out="$(launch_output "$name-read")"
    assert_eq "$variant: guest edit survived an independent boot" "edited-258" \
      "$(grep '^edited-258$' <<<"$out")" || return 1
    assert_eq "$variant: per-boot flag on the read boot" "seedflag=present" \
      "$(grep '^seedflag=' <<<"$out")" || return 1

    rm -f "$state/seed-258.payload" || return 1
    capture_custom_launch "$name-reseed" "$proj" hello-258 --no-git --image "$img" || return 1
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

  capture_custom_launch "$name" "$proj" hook-only-258 --no-git --image "$CUSTOM_MARKER" alpha "beta gamma" || return 1
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
  capture_custom_launch "$nopath" "$noproj" hook-only-258 --no-git --image "$CUSTOM_MARKER" || return 1
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
  capture_custom_launch "$pathname" "$pproj" pathname-258 --no-git --image "$CUSTOM_MARKER" "one two" three || return 1
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

  if capture_custom_launch "$name" "$proj" credsprobe --no-git --image "$CUSTOM_MARKER"; then
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
  if capture_custom_launch "$nname" "$nproj" credsprobe --no-git --image "$CUSTOM_MARKER"; then
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
  capture_custom_launch "$name" "$proj" hello-258 --no-git --image "$CUSTOM_STAMP" || return 1
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

  capture_custom_launch "$vname" "$proj" shell --no-git --image "$CUSTOM_STAMP" -- \
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
    capture_custom_launch "$name" "$proj" hello-258 --no-git ${root_flag[@]+"${root_flag[@]}"} \
      --image "$CUSTOM_NONSTANDARD" || return 1
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

  capture_custom_launch "custom-cold-nonroot" "$proj_n" hello-258 --no-git --image "$ref_nonroot" write cold-258 || result=1
  require_launch_ok "custom-cold-nonroot" || result=1
  capture_custom_launch "custom-cold-root" "$proj_r" hello-258 --no-git --root --image "$ref_root" write cold-258 || result=1
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

  # Acquisition must have recorded the refs in the image catalog, and the
  # custom cache must still be private (no config redirect).
  image_catalog_has "$ref_nonroot" "$suffix_n" present || result=1
  image_catalog_has "$ref_root" "$suffix_r" present || result=1
  assert_custom_cache_isolated "after cold launches" yes || result=1

  docker rm -f "$container" >/dev/null 2>&1 ||
    { echo "    FAIL: registry container removal failed"; result=1; }

  # Warm/offline: the same refs boot again with the registry gone, keep the OCI
  # PATH, execute the program and read back the cold boot's persisted sentinel.
  capture_custom_launch "custom-warm-nonroot" "$proj_n" hello-258 --no-git --image "$ref_nonroot" read nonroot || result=1
  require_launch_ok "custom-warm-nonroot" || result=1
  capture_custom_launch "custom-warm-root" "$proj_r" hello-258 --no-git --root --image "$ref_root" read root || result=1
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

# ---- PTY attach checks (macOS BSD `script`) ----

check_custom_no_bash_attach() {
  local name="custom-attach-no-bash" proj out result=0
  proj="$(custom_project "$name")" || return 1
  if ! capture_custom_attach "$name" "$proj" hello-258 --no-git --image "$CUSTOM_NO_BASH"; then
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

  if ! capture_custom_attach "$name" "$proj" hello-258 --no-git ${root_flag[@]+"${root_flag[@]}"} \
    --image "$CUSTOM_USER_HOME" write "attach-258-$mode"; then
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
  if ! capture_custom_attach "$read" "$proj" hello-258 --no-git ${root_flag[@]+"${root_flag[@]}"} \
    --image "$CUSTOM_USER_HOME" read "$mode"; then
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
  if ! capture_custom_attach "$name" "$proj" hello-258 --no-git --image "$CUSTOM_NONSTANDARD"; then
    return 1
  fi
  out="$(attach_output "$name")"
  assert_match "attach: took the attach branch" "Attaching to" "$out" || result=1
  assert_match "attach: guest completed" "^hello-258=ok$" "$out" || result=1
  expect_effective_path "attach imported" "$out" || result=1
  assert_no_host_calls || result=1
  return "$result"
}

# --------------------------------------------------------------- run all ----

echo "e2e: group=$GROUP"
echo "e2e: launcher=$AGENT_VM"
if [[ "$GROUP" == all ]]; then
  echo "e2e: state=$STATE_DIR"
  echo "e2e: images=$BASE_IMAGE + $TEMPLATE_IMAGE"
fi

make_host_shims
run_check "harness-negative" check_harness_negative

if [[ "$GROUP" == all ]]; then
  import_image "$BASE_IMAGE"
  import_image "$TEMPLATE_IMAGE"
  import_image "$TEMPLATE_IMAGE" "$PUBLISHED_TEMPLATE_REF"

  run_check "base-is-tool-free" check_base_is_tool_free
  run_check "template-has-all-tools" check_template_has_all_tools
  run_check "fast-path-zero-docker" check_fast_path_zero_docker
  run_check "tools-claude-composes" check_tools_claude_composes
  run_check "tools-pi-composes" check_tools_pi_composes
  run_check "pi-home-persists-nonroot" pi_home_persists non-root
  run_check "pi-home-persists-root" pi_home_persists root
  run_check "project-layer-chains-on-template" check_project_layer_chains_on_template
  run_optional "supplied-named-seed" AGENT_VM_E2E_LEGACY_IMAGE check_legacy_seed
  run_optional "update-check-probes-published" AGENT_VM_E2E_UPDATE_CHECK check_update_check
  run_optional "setup-notice-under-claude" AGENT_VM_E2E_SETUP_BASE_REF check_setup_notice
  run_optional "rust-compose-e2e" AGENT_VM_E2E_RUST check_rust_compose_e2e
fi

prepare_custom_fixtures || die "could not build/import the custom-image fixtures"
run_check "custom-image-fixtures-imported" check_custom_fixtures_imported
run_check "custom-image-env-isolation-audit" check_custom_env_isolation
run_check "custom-image-cache-isolated" check_custom_cache_isolation

run_check "custom-image-runs-program" custom_image_runs_program
run_check "custom-image-stamp-present-nonnumeric" custom_image_stamp_present
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
run_check "custom-image-no-bash-attach" check_custom_no_bash_attach
run_check "custom-image-user-home-attach-nonroot" check_custom_user_home_attach nonroot
run_check "custom-image-user-home-attach-root" check_custom_user_home_attach root
run_check "custom-image-nonstandard-attach" check_custom_nonstandard_attach
run_check "custom-image-cache-isolated-final" check_custom_cache_isolation

echo
echo "e2e: $PASSED passed, $FAILED failed, $SKIPPED skipped"
[[ "$FAILED" -eq 0 ]]
