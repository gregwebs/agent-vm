#!/usr/bin/env bash
# shellcheck disable=SC2016 # Commands are interpreted in the guest, not here.
# Native hardware evidence for ADR-0038; never run in CI or with concurrent VMs.
set -euo pipefail

: "${AGENT_VM_BIN:?set AGENT_VM_BIN to an absolute native bundle binary}"
: "${AGENT_VM_LIVE_TEST_IMAGE:?set AGENT_VM_LIVE_TEST_IMAGE to a verified native image}"
[[ "$AGENT_VM_BIN" = /* ]] || { echo 'AGENT_VM_BIN must be absolute' >&2; exit 1; }
script_dir="$(cd -- "${BASH_SOURCE[0]%/*}" && pwd)"
fixtures="$script_dir/fixtures/config-dir-guard"
# shellcheck source=script/test/lib/config-dir-guard.sh
source "$script_dir/lib/config-dir-guard.sh"

# Deliberately under /tmp, not TMPDIR: macOS TMPDIR is long enough that the
# default canonical root pushes the runtime's control socket past the 103-byte
# sun_path limit, so N7 could never boot. The budget checks below fail loudly if
# this drifts again.
root="$(mktemp -d /tmp/avm-cgf.XXXXXX)"
root="$(cd "$root" && pwd -P)"
echo "Evidence retained at $root"
export HOME="$root/home" AGENT_VM_STATE_DIR="$root/state"

assert_state_budget() {
  local label="$1" state="$2" len
  if ! len="$(avm_guard_state_dir_fits "$state")"; then
    echo "$label '$state' yields a ${len}-byte control socket, over the $(avm_sun_path_usable_len)-byte limit; shorten the root" >&2
    exit 1
  fi
}

mkdir -p "$HOME/.config/agent-vm" "$AGENT_VM_STATE_DIR" "$root/p1" "$root/p2" "$root/aux"
assert_state_budget 'live private state' "$AGENT_VM_STATE_DIR"
assert_state_budget 'N7 case state' "$root/case-state"
unset AGENT_VM_IMAGE_TAG AGENT_VM_ROOT AGENT_VM_TEST_CREDENTIAL AGENT_VM_TEST_DEFAULT_IMAGE AGENT_VM_DEBUG_CONFIG
cfg="$HOME/.config/agent-vm/config.toml"
cp "$fixtures/seed-config.toml" "$cfg"
cp "$cfg" "$root/original"
# Passed to the guest snippets so they can compare the seeded bytes exactly;
# the printf sentinel keeps the trailing newline that plain $() would strip.
seed_text="$(cat "$fixtures/seed-config.toml"; printf x)"
seed_text="${seed_text%x}"
aux="$root/aux"
cd "$root/p1"

run_guest() {
  "$AGENT_VM_BIN" --no-git --image "$AGENT_VM_LIVE_TEST_IMAGE" "$@"
}
refuse() {
  local row="$1" message="$2"
  shift 2
  if run_guest "$@" >"$root/$row.log" 2>&1; then
    echo "$row unexpectedly launched" >&2; exit 1
  fi
  grep -F "$message" "$root/$row.log"
  if grep -Fq 'GUEST_EXECUTED' "$root/$row.log"; then
    echo "$row guest ran" >&2; exit 1
  fi
  cmp "$cfg" "$root/original"
  [[ -z "$(find "$AGENT_VM_STATE_DIR" -mindepth 1 -print -quit)" ]]
  echo "PASS $row"
}

ln "$cfg" "$aux/cfg.toml"
refuse N1a 'has 2 hard links' --mount "$aux:/aux" shell bash -ceu "$(cat "$fixtures/guest-n1a.sh")" avm-seed "$seed_text"
refuse N1b 'has 2 hard links' --mount "$aux:/aux" shell bash -ceu "$(cat "$fixtures/guest-n1b.sh")" avm-seed "$seed_text"
rm "$aux/cfg.toml"

# These refusals also precede the first cache acquisition.
cd "$HOME"
refuse N5-home 'project directory' shell bash -ceu "$(cat "$fixtures/guest-n5.sh")"
cd "$root/p1"
refuse N5-mount 'would let the guest change' --mount "$HOME/.config" shell bash -ceu "$(cat "$fixtures/guest-n5.sh")"

run_guest --mount "$HOME/.config/agent-vm:/cfg:ro" shell bash -ceu "$(cat "$fixtures/guest-n3.sh")" avm-seed "$seed_text" >"$root/N3.log" 2>&1
grep -F 'N3_GUEST_OK' "$root/N3.log"
cmp "$cfg" "$root/original"
run_guest shell bash -ceu 'echo N3_SECOND_BOOT_OK' >"$root/N3-second.log" 2>&1
grep -F 'N3_SECOND_BOOT_OK' "$root/N3-second.log"
echo 'PASS N3'

run_guest --mount "$HOME/.config/agent-vm:/cfg:fork" shell bash -ceu "$(cat "$fixtures/guest-n4.sh")" avm-seed "$seed_text" >"$root/N4.log" 2>&1
grep -F 'N4_GUEST_OK' "$root/N4.log"
cmp "$cfg" "$root/original"
run_guest shell bash -ceu 'echo N4_SECOND_BOOT_OK' >"$root/N4-second.log" 2>&1
grep -F 'N4_SECOND_BOOT_OK' "$root/N4-second.log"
echo 'PASS N4'

# Separate state so P1 has never been provisioned in this layout.
mkdir -p "$root/probe/abc"
if [[ "$(uname -s)" != Darwin ]] || ! [[ "$root/probe/abc" -ef "$root/probe/ABC" ]]; then
  echo 'SKIPPED N7: requires macOS on a case-insensitive filesystem'
  exit 0
fi
# The upper-case spelling is only a distinct layout when the hash has an ASCII
# letter; a twelve-hex-digit hash can lack one, so pick a deterministic
# candidate project or skip honestly rather than pass without the case arm.
# Selection distinguishes a genuine letterless exhaustion (skip) from an I/O or
# hash failure (fail) so a broken helper cannot masquerade as a skip.
select_rc=0
p1="$(avm_guard_select_case_variant_project "$root" 64)" || select_rc=$?
if ((select_rc == 1)); then
  echo 'SKIPPED N7: no candidate project hash within 64 has an ASCII letter'
  exit 0
elif ((select_rc != 0)); then
  echo 'N7 case-variant selection failed (not a genuine skip)' >&2
  exit 1
fi
hash="$(avm_guard_project_hash "$p1")"
upper="$(printf '%s' "$hash" | tr '[:lower:]' '[:upper:]')"
[[ "$hash" != "$upper" ]] || { echo 'N7 project hash did not change under case folding' >&2; exit 1; }
mv "$HOME/.config" "$HOME/config-before-N7"
export AGENT_VM_STATE_DIR="$root/case-state"
mkdir -p "$AGENT_VM_STATE_DIR"
ln -s "$AGENT_VM_STATE_DIR/$upper/home/.config" "$HOME/.config"
# The config file is now absent, so N7 has a distinct oracle from refuse().
cd "$p1"
if run_guest shell bash -ceu "$(cat "$fixtures/guest-n7.sh")" avm-seed "$seed_text" >"$root/N7.log" 2>&1; then
  echo 'N7 unexpectedly launched' >&2; exit 1
fi
grep -F 'does not exist yet' "$root/N7.log"
if grep -Fq 'GUEST_EXECUTED' "$root/N7.log"; then
  echo 'N7 guest ran' >&2; exit 1
fi
[[ ! -e "$AGENT_VM_STATE_DIR/$hash" ]]
[[ -z "$(find "$AGENT_VM_STATE_DIR" -mindepth 1 -print -quit)" ]]
cd "$root/p2"
run_guest shell bash -ceu 'echo N7_P2_BOOT_OK' >"$root/N7-p2.log" 2>&1
grep -F 'N7_P2_BOOT_OK' "$root/N7-p2.log"
[[ ! -e "$AGENT_VM_STATE_DIR/$hash" ]]
[[ ! -e "$HOME/.config/agent-vm/credentials.yaml" ]]
echo 'PASS N7'
shasum -a 256 "$AGENT_VM_BIN"
printf 'Image: %s\n' "$AGENT_VM_LIVE_TEST_IMAGE"
