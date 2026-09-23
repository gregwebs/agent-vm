#!/usr/bin/env bash
# shellcheck disable=SC2016  # guest-side commands deliberately single-quote `$(...)`
#
# End-to-end (VM-boot) verification for agent-vm on Apple Silicon.
#
# It boots real microVMs through the agent-vm CLI and asserts the behaviours
# CI cannot observe: the tool-free base, the fast path (a default launch boots
# the published template with **zero** `docker` invocations), per-tool-layer
# composition, the project-layer chain, the legacy API-1/2 seed fallback, and
# (#96) `~/.pi` resolving to project state and surviving an independent boot in
# both guest modes.
# See CONTRIBUTING.md#end-to-end-vm-boot-tests-optional for the background and the
# per-check acceptance criteria.
#
# This is **not** run on CI: GitHub's macOS runners are Intel and cannot boot
# these arm64 microVMs, and the checks need `docker` + the multi-GB images
# below. It is the standard local entry point instead.
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
#   AGENT_VM_E2E_OLD_LAUNCHER=<path>          a pre-#84 agent-vm binary (E5)
#   AGENT_VM_E2E_LEGACY_IMAGE=<ref>           a cached API-1/2 image (E8)
#   AGENT_VM_E2E_SETUP_BASE_REF=<ref>         a pullable linux/arm64 base ref for `setup` (E10)
#   AGENT_VM_E2E_UPDATE_CHECK=1               probe the registry (E9; needs network)
#   AGENT_VM_E2E_RUST=1                       also run the #[ignore]d Rust Docker e2e
#
# State changes (all additive): the two dev images are imported into
# $AGENT_VM_STATE_DIR's msb cache, the dev template is also imported under its
# published default ref (so the fast path resolves offline), and `docker tag`
# records the manifest base links. Undo with `agent-vm doctor --reset-msb-db`
# plus `docker rmi agent-vm-base:<hex>` if you want the state dir byte-identical.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

PUBLISHED_TEMPLATE_REF="ghcr.io/wirenboard/agent-vm-template:latest"

usage() {
  # Print the header comment (lines after the shebang) as the help text.
  awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "${BASH_SOURCE[0]}"
}

case "${1:-}" in
  -h | --help)
    usage
    exit 0
    ;;
  "")
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

for image in "$BASE_IMAGE" "$TEMPLATE_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 ||
    die "docker image '$image' is missing; build the dev images first — see
  macos-build.md (and AGENT_VM_E2E_BASE_IMAGE / AGENT_VM_E2E_TEMPLATE_IMAGE to
  point at different tags)."
done

# `script/build/import-image.sh` hardcodes the release bundle's msb. The --dev
# bundle alone cannot import images, so say so up front rather than half-way in.
[[ -x "$REPO_ROOT/target/macos/bin/msb" ]] || die "script/build/import-image.sh
needs the release bundle's msb at target/macos/bin/msb. Run ./script/build/macos.sh
(the --dev bundle does not provide it)."

WORK="$(mktemp -d "${TMPDIR:-/tmp}/agent-vm-e2e.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# Derived images are tagged agent-vm-layer:<project-basename>-<content-hash>, so a
# fresh basename per run forces the compose checks to build (and print their
# plan) instead of silently reusing a cached step from an earlier run.
RUN_ID="${WORK##*.}"

mkdir -p "$STATE_DIR/msb-home"

# The cache-config trap (agent-vm #84 verification, CONTRIBUTING.md): with
# AGENT_VM_SHARE_MSB_CACHE enabled, agent-vm's boot rewrites
# msb-home/config.json to redirect paths.cache at the shared
# ~/.microsandbox/cache, but import-image.sh runs `msb image load` directly and
# never applies that redirect. On a *fresh* state dir the imported blobs land
# in the private msb-home/cache and the boot then looks in the shared cache and
# falls through to a registry pull. Initialising through a non-Launch builtin
# that still runs normal msb setup (`msb`, not `doctor` - doctor is deliberately
# observational and writes nothing) first writes the same config.json the boot
# will use, so import and boot agree.
if [[ ! -f "$STATE_DIR/msb-home/config.json" ]]; then
  echo "==> Initializing $STATE_DIR/msb-home (so import and boot share one cache)"
  AGENT_VM_STATE_DIR="$STATE_DIR" "$AGENT_VM" msb --version >/dev/null 2>&1 || true
fi

# ------------------------------------------------------------- host helpers --

# agent-vm with the two image env vars dropped, so a default-config check
# really resolves the default and not a stale AGENT_VM_IMAGE_TAG / _BASE_IMAGE
# inherited from the shell (a second trap this harness exists to remove).
avm() {
  env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_BASE_IMAGE \
    AGENT_VM_STATE_DIR="$STATE_DIR" "$AGENT_VM" "$@"
}

import_image() {
  local source="$1" dest="${2:-$1}"
  echo "==> Importing $source as $dest"
  AGENT_VM_STATE_DIR="$STATE_DIR" "$REPO_ROOT/script/build/import-image.sh" "$source" "$dest" >/dev/null
}

# ------------------------------------------------------------- assertions ---

assert_match() {
  local desc="$1" re="$2" hay="$3"
  grep -qE -- "$re" <<<"$hay" || {
    echo "    FAIL: $desc (no match for /$re/)"
    return 1
  }
}

assert_no_match() {
  local desc="$1" re="$2" hay="$3"
  if grep -qE -- "$re" <<<"$hay"; then
    echo "    FAIL: $desc (unexpected /$re/ in output)"
    return 1
  fi
}

assert_eq() {
  local desc="$1" want="$2" got="$3"
  [[ "$want" == "$got" ]] || {
    echo "    FAIL: $desc (want [$want], got [$got])"
    return 1
  }
}

PASSED=0
FAILED=0
SKIPPED=0

run_check() {
  local name="$1"
  shift
  echo
  echo "==> $name"
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

# ---------------------------------------------------------------- checks ----

# AC: the base carries no agent CLI and advertises image API 3.
check_base_is_tool_free() {
  local out
  out="$(avm shell --no-git --image "$BASE_IMAGE" -- bash -c '
    for b in dsh pi claude codex opencode copilot; do
      if command -v "$b" >/dev/null 2>&1; then echo "PRESENT:$b"; else echo "absent:$b"; fi
    done
    echo "api=$(cat /etc/agent-vm-image-version)"
  ' 2>&1)" || {
    echo "$out" | tail -20
    return 1
  }
  assert_no_match "no agent CLI on PATH" "^PRESENT:" "$out" || return 1
  assert_eq "all six absent" "6" "$(grep -c '^absent:' <<<"$out")" || return 1
  assert_match "image API 3" "^api=3$" "$out" || return 1
}

# E1: all six --version checks pass in the composed template guest.
check_template_has_all_tools() {
  local out
  out="$(avm shell --no-git --image "$TEMPLATE_IMAGE" -- bash -c '
    for t in dsh pi codex opencode claude copilot; do
      if [ "$t" = dsh ]; then
        # dsh exits 0 with no output on a too-old Node, so assert the string.
        [ -n "$(dsh --version 2>/dev/null)" ] || { echo "MISSING:$t"; exit 1; }
      else
        "$t" --version >/dev/null 2>&1 || { echo "MISSING:$t"; exit 1; }
      fi
    done
    echo "api=$(cat /etc/agent-vm-image-version)"
  ' 2>&1)" || {
    echo "$out" | tail -20
    return 1
  }
  assert_no_match "no missing tool" "MISSING:" "$out" || return 1
  assert_match "image API 3" "^api=3$" "$out" || return 1
}

# E2 / AC 7: a default config with no project layers boots the published
# template with docker absent from PATH (and its invocation shim silent).
check_fast_path_zero_docker() {
  local proj="$WORK/fastpath" shim="$WORK/shim" log="$WORK/docker-calls.log"
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
  assert_match "claude present in guest" "^claude /opt/agent" "$out" || return 1
}

# E1b / #95: tools = ["pi"] composes the pi layer onto the base, and the
# end-user pi experience works in the guest -- the pinned version behind the
# stable wrapper, the mandatory credential warning (also under -ne), a clean
# print-mode stdout, and a subcommand that is forwarded rather than turned into
# an agent prompt.
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
  # `timeout 60` on every guest pi invocation mirrors the layer build gate: a
  # future pi that decides to prompt must not hang the run. print_rc bounds
  # print_bytes so an empty stdout from a broken pi cannot satisfy it vacuously.
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

# E1c / #96: ~/.pi resolves to /agent-vm-state/pi, the target is a real
# directory Pi's `mkdir -p ~/.pi/agent` can write into, Pi's own global-package
# path under it is writable, and the bytes survive an INDEPENDENT boot. Run for
# both guest modes: they provision the link through completely different code
# paths (rootfs .patch() vs host-side provision_guest_home). Separate project
# dirs per mode, so root-owned files from the root boot cannot poison the
# non-root one.
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
  # ${arr[@]+"${arr[@]}"} is the empty-array-safe expansion (macOS bash 3.2).
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
  assert_match "layer applied in guest" "e2e marker" "$out" || return 1
}

# E5: a pre-#84 launcher rejects the API-3 base with the "too NEW" diagnostic.
check_old_launcher_rejects() {
  local out
  out="$(env -u AGENT_VM_IMAGE_TAG -u AGENT_VM_BASE_IMAGE AGENT_VM_STATE_DIR="$STATE_DIR" \
    "$AGENT_VM_E2E_OLD_LAUNCHER" shell --image "$BASE_IMAGE" -- true 2>&1)" || true
  assert_match "rejects the API-3 base as too new" \
    "image-API version 3 is too NEW \(this agent-vm supports 1\.\.=2\)" "$out"
}

# E8 / D11: the generic seed prelude still seeds an already-cached API-1/2
# image via its legacy /opt/agent-vm/seed-claude-plugins.sh fallback.
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
  assert_match "legacy image has no seed.d" "^seed-d-entries=0$" "$out" || return 1
  assert_match "plugins seeded via the legacy fallback" \
    "lsp@claude-plugins-official" "$out" || return 1
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
    "registry update probe.*agent-vm-layer:" "$out" || return 1
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
      echo '          ghcr template is amd64 by design); serve a locally built base:'
      echo '            docker run -d -p 127.0.0.1:5099:5000 --name avm-e2e-registry registry:2'
      echo "            docker tag $BASE_IMAGE 127.0.0.1:5099/agent-vm-base:dev"
      echo '            docker push 127.0.0.1:5099/agent-vm-base:dev'
      echo '            AGENT_VM_E2E_SETUP_BASE_REF=127.0.0.1:5099/agent-vm-base:dev ./script/test/e2e.sh'
    fi
    return 1
  }
  assert_match "D10 notice names the supplying layer" \
    'claude is supplied by tool layer "claude"' "$out" || return 1
  assert_match "setup reports the image ready" \
    "$AGENT_VM_E2E_SETUP_BASE_REF ready" "$out"
}

# Optional: the #[ignore]d Docker-level compose e2e (no VM boot) from run.rs.
check_rust_compose_e2e() {
  AGENT_VM_E2E_BASE_IMAGE="$BASE_IMAGE" cargo test -p agent-vm --bin agent-vm -- \
    e2e_builtin_tool_layer_composes_onto_an_imported_base --ignored --test-threads=1
}

# ------------------------------------------------------------------- run ----

echo "e2e: launcher=$AGENT_VM"
echo "e2e: state=$STATE_DIR"
echo "e2e: images=$BASE_IMAGE + $TEMPLATE_IMAGE"

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
run_optional "old-launcher-rejects-api3" AGENT_VM_E2E_OLD_LAUNCHER check_old_launcher_rejects
run_optional "legacy-seed-fallback" AGENT_VM_E2E_LEGACY_IMAGE check_legacy_seed
run_optional "update-check-probes-published" AGENT_VM_E2E_UPDATE_CHECK check_update_check
run_optional "setup-notice-under-claude" AGENT_VM_E2E_SETUP_BASE_REF check_setup_notice
run_optional "rust-compose-e2e" AGENT_VM_E2E_RUST check_rust_compose_e2e

echo
echo "e2e: $PASSED passed, $FAILED failed, $SKIPPED skipped"
[[ "$FAILED" -eq 0 ]]
