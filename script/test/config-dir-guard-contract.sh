#!/usr/bin/env bash
# Boot-free host controls for the ADR-0038 config-dir guard evidence (#323).
#
# These are host-only controls, never native VM evidence: no VM, no agent-vm
# binary, no image. They run the *actual* guest snippets the native harness
# passes (single source of truth under fixtures/config-dir-guard/) against a local
# filesystem, and check socket-path source-shape sentinels plus independent
# fixed-shape budget controls. This is the boot-free companion described in CONTRIBUTING.md.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT_DIR="$REPO_ROOT/script/test"
FIXTURES="$SCRIPT_DIR/fixtures/config-dir-guard"
LIVE="$SCRIPT_DIR/config-dir-guard-live.sh"

# shellcheck source=script/test/lib/config-dir-guard.sh
source "$SCRIPT_DIR/lib/config-dir-guard.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/avm-cgf-control.XXXXXX")"
trap 'rm -rf "$work"' EXIT

seed="$FIXTURES/seed-config.toml"
grep -q 'private live fixture' "$seed" || fail "seed fixture lost its marker"
seed_text="$(cat "$seed"; printf x)"
seed_text="${seed_text%x}"

# Run one checked-in guest snippet exactly as the native harness does: a
# fragment handed to `bash -ceu`, with the seed as $1 and optional env
# assignments for the local stand-in paths.
run_snippet() {
    local snippet="$1"
    shift
    env "$@" bash -ceu "$(cat "$snippet")" avm-seed "$seed_text"
}

# --- R1: the guest snippets do what the native rows assume -------------------

# N3 read-only success control. chmod 0444 does not deny writes to root, so a
# root host cannot exercise this row: print a skip reason rather than fail or
# claim the body ran. The writable and missing-target hostile controls below are
# independent of uid and always run.
if [[ "$(id -u)" -eq 0 ]]; then
    echo 'SKIPPED N3 read-only control: running as root, mode 0444 does not deny writes'
else
    cp "$seed" "$work/seed-ro.toml"
    chmod 0444 "$work/seed-ro.toml"
    out="$(run_snippet "$FIXTURES/guest-n3.sh" CFG_PATH="$work/seed-ro.toml" 2>&1)"
    [[ "$out" == *N3_GUEST_OK* ]] || fail "N3 snippet did not pass on a read-only file: $out"
    cmp -s "$seed" "$work/seed-ro.toml" || fail "N3 control mutated the read-only file"
fi

# N3 hostile control: when the write *succeeds* the snippet must fail loudly. A
# bare `! sh -c ...` would not (bash exempts negation from errexit), which is
# exactly the false positive R1 found.
cp "$seed" "$work/seed-rw.toml"
if out="$(run_snippet "$FIXTURES/guest-n3.sh" CFG_PATH="$work/seed-rw.toml" 2>&1)"; then
    fail "N3 snippet passed with a writable target: $out"
fi
[[ "$out" == *N3_WRITE_SUCCEEDED* ]] || fail "N3 snippet failed for the wrong reason: $out"

# N3 missing-target control: a missing mount must fail the seed precondition,
# not look like a read-only refusal.
if out="$(run_snippet "$FIXTURES/guest-n3.sh" CFG_PATH="$work/absent.toml" 2>&1)"; then
    fail "N3 snippet passed with a missing target: $out"
fi
[[ "$out" == *N3_PRECONDITION_MISSING* ]] || fail "N3 missing-target reason wrong: $out"

# N4 success control: the append lands in the guest's copy and the snippet
# verifies the exact changed bytes itself.
cp "$seed" "$work/fork.toml"
out="$(run_snippet "$FIXTURES/guest-n4.sh" CFG_PATH="$work/fork.toml")"
[[ "$out" == *N4_GUEST_OK* ]] || fail "N4 snippet did not pass: $out"
grep -q '^fork-only$' "$work/fork.toml" || fail "N4 snippet did not write"
if out="$(run_snippet "$FIXTURES/guest-n4.sh" CFG_PATH="$work/absent.toml" 2>&1)"; then
    fail "N4 snippet passed with a missing target: $out"
fi
[[ "$out" == *N4_PRECONDITION_MISSING* ]] || fail "N4 missing-target reason wrong: $out"

# N3/N4 byte-exactness controls: the precondition must compare every byte, so a
# seed altered only by an appended NUL or an extra trailing newline has to fail
# with the precondition marker. A `$(cat)`-based comparison would silently drop
# the embedded NUL and accept the first file (N4 would then pass outright), which
# is exactly why the snippets now pipe through `cmp`. Both snippets run with the
# original clean seed as $1 and the altered file as CFG_PATH.
cp "$seed" "$work/seed-nul.toml"
printf '\0' >>"$work/seed-nul.toml"
cp "$seed" "$work/seed-extra-nl.toml"
printf '\n' >>"$work/seed-extra-nl.toml"
for hostile in "$work/seed-nul.toml" "$work/seed-extra-nl.toml"; do
    if cmp -s "$seed" "$hostile"; then
        fail "hostile byte fixture $hostile is byte-identical to the clean seed"
    fi
    for pair in 'guest-n3.sh:N3_PRECONDITION_MISSING' 'guest-n4.sh:N4_PRECONDITION_MISSING'; do
        snippet="${pair%%:*}"
        marker="${pair##*:}"
        if out="$(run_snippet "$FIXTURES/$snippet" CFG_PATH="$hostile" 2>&1)"; then
            fail "$snippet passed against a byte-altered seed ($hostile): $out"
        fi
        [[ "$out" == *"$marker"* ]] || fail "$snippet failed for the wrong reason against $hostile: $out"
    done
done

# N1a/N1b controls: the real setup is a hard link to the original config file.
# Prove the snippet appends through that link and then unlinks the second name,
# leaving the original inode mutated with no second name — the laundering the
# pre-boot refusal prevents, so the refusal is load-bearing.
for snippet in guest-n1a.sh guest-n1b.sh; do
    orig="$work/n1-orig-$snippet"
    aux="$work/aux-$snippet"
    cp "$seed" "$orig"
    cp "$seed" "$work/n1-before-$snippet"
    mkdir -p "$aux"
    ln "$orig" "$aux/cfg.toml"
    out="$(run_snippet "$FIXTURES/$snippet" AUX_DIR="$aux")"
    [[ "$out" == *GUEST_EXECUTED* ]] || fail "$snippet did not reach GUEST_EXECUTED: $out"
    [[ ! -e "$aux/cfg.toml" ]] || fail "$snippet did not remove the aux link"
    if cmp -s "$orig" "$work/n1-before-$snippet"; then
        fail "$snippet did not mutate the original through the link"
    fi
    grep -q '^# planted$' "$orig" || fail "$snippet did not append the planted line"
    links="$(python3 -c 'import os, sys; print(os.stat(sys.argv[1]).st_nlink)' "$orig")"
    [[ "$links" == 1 ]] || fail "$snippet left the original hard-linked ($links links)"
done

# N5/N7 controls: the markers fire and N7 really plants the credentials file.
out="$(run_snippet "$FIXTURES/guest-n5.sh")"
[[ "$out" == *GUEST_EXECUTED* ]] || fail "N5 marker snippet broken: $out"
home="$work/n7-home"
out="$(run_snippet "$FIXTURES/guest-n7.sh" GUEST_HOME="$home")"
[[ "$out" == *GUEST_EXECUTED* ]] || fail "N7 snippet did not plant: $out"
printf 'credentials: []\n' | cmp -s - "$home/.config/agent-vm/credentials.yaml" ||
    fail "N7 snippet planted wrong bytes"

# The live harness must use those same fixtures, not an inlined copy that could
# drift out of sync with what these controls prove.
grep -qF 'fixtures/config-dir-guard' "$LIVE" || fail "live harness lost the fixture dir"
# shellcheck disable=SC2013 # paths have no whitespace; this is a fixed list.
for name in $(cd "$FIXTURES" && printf '%s\n' *); do
    grep -qF "$name" "$LIVE" || fail "live harness does not use fixture $name"
done

# --- R2: socket-path budget with source-shape drift sentinels ---------------

ipc="$REPO_ROOT/vendor/microsandbox/crates/runtime/lib/client/ipc.rs"
utils="$REPO_ROOT/vendor/microsandbox/crates/utils/lib/lib.rs"
install="$REPO_ROOT/crates/agent-vm/src/msb_install.rs"
if [[ -f "$ipc" && -f "$utils" ]]; then
    grep -q 'CANONICAL_SOCKET_HASH_BYTES: usize = 12' "$ipc" ||
        fail "runtime canonical socket hash width moved"
    grep -q 'join("sandboxes")' "$ipc" || fail "runtime socket dir template moved"
    grep -q 'with_file_name("control.sock")' "$ipc" || fail "runtime control socket leaf moved"
    grep -q 'RUN_SUBDIR: &str = "run"' "$utils" || fail "runtime run subdir moved"
else
    echo 'notice: vendored runtime absent; socket-shape source check skipped (submodule not initialized)' >&2
fi
grep -q 'join("msb-home")' "$install" || fail "agent-vm msb-home template moved"
grep -q 'SUN_PATH_USABLE_LEN: usize = 104 - 1' "$install" || fail "macOS socket budget moved"
grep -q 'SUN_PATH_USABLE_LEN: usize = 108 - 1' "$install" || fail "Linux socket budget moved"

((AVM_GUARD_SOCKET_HASH_BYTES == 12)) || fail "lib hash-width constant drift"
((${#AVM_GUARD_SOCKET_SUFFIX} == 24)) || fail "lib suffix-prefix constant drift"
((${#AVM_GUARD_SOCKET_LEAF} == 13)) || fail "lib suffix-leaf constant drift"
suffix_total=$((${#AVM_GUARD_SOCKET_SUFFIX} + AVM_GUARD_SOCKET_HASH_BYTES * 2 + ${#AVM_GUARD_SOCKET_LEAF}))
((suffix_total == 61)) || fail "socket suffix total drift: $suffix_total"

# The budget is measured in bytes, not characters: a multibyte state path must
# count its UTF-8 byte length. The control input is genuinely multibyte, so it
# would catch a character-counting helper under a UTF-8 locale.
mb_state="/é"
mb_bytes="$(python3 -c 'import sys; print(len(sys.argv[1].encode()))' "$mb_state")"
mb_chars="$(python3 -c 'import sys; print(len(sys.argv[1]))' "$mb_state")"
((mb_bytes != mb_chars)) || fail "multibyte control input is not multibyte"
(( $(avm_guard_control_socket_len "$mb_state") == mb_bytes + suffix_total )) ||
    fail "socket budget counted characters, not bytes"

limit="$(avm_sun_path_usable_len)"

# Boundary controls: exactly the limit fits, one byte more is rejected.
fit_state="$(python3 -c "print('/' + 'x' * ($limit - $suffix_total - 1))")"
over_state="$(python3 -c "print('/' + 'x' * ($limit - $suffix_total))")"
(( $(avm_guard_control_socket_len "$fit_state") == limit )) ||
    fail "fit-boundary arithmetic wrong"
(( $(avm_guard_control_socket_len "$over_state") == limit + 1 )) ||
    fail "over-boundary arithmetic wrong"
avm_guard_state_dir_fits "$fit_state" || fail "state dir at the limit was rejected"
if avm_guard_state_dir_fits "$over_state" >/dev/null; then
    fail "state dir one byte over the limit was accepted"
fi

# The concrete failure R2 found: the old default root under /private/tmp gives a
# 104-byte control socket. The short owned root the live harness now uses fits.
old_root="/private/tmp/avm-cfg-live.XXXXXX/case-state"
(( $(avm_guard_control_socket_len "$old_root") == 104 )) || fail "R2 example length drift"
if [[ "$(uname -s)" == Darwin ]]; then
    if avm_guard_state_dir_fits "$old_root" >/dev/null; then
        fail "the R2 long case-state root unexpectedly fits"
    fi
    avm_guard_state_dir_fits "/private/tmp/avm-cgf.XXXXXX/case-state" ||
        fail "the new short root does not fit"
fi

# --- R3: case-variant selection --------------------------------------------

avm_guard_case_variant_is_distinct 000000000000 &&
    fail "a letterless hash was treated as a distinct case spelling"
avm_guard_case_variant_is_distinct 00000000000a ||
    fail "a hash with a letter was rejected"
chosen="$(avm_guard_select_case_variant_project "$work/n7-candidates" 64)"
[[ -n "$chosen" ]] || fail "no case-variant candidate within 64"
chosen_hash="$(avm_guard_project_hash "$chosen")"
chosen_upper="$(printf '%s' "$chosen_hash" | tr '[:lower:]' '[:upper:]')"
[[ "$chosen_hash" != "$chosen_upper" ]] ||
    fail "selector returned a case-invariant hash: $chosen_hash"

# The selector must not report an I/O/hash failure as a genuine letterless
# skip: exhausted candidates are code 1, every other failure is code 2.
letterless_rc=0
(avm_guard_case_variant_is_distinct() { return 1; }
    avm_guard_select_case_variant_project "$work/letterless" 3) || letterless_rc=$?
((letterless_rc == 1)) || fail "letterless exhaustion reported rc=$letterless_rc, not 1"
forced_rc=0
(avm_guard_project_hash() { return 3; }
    avm_guard_select_case_variant_project "$work/forced" 2) || forced_rc=$?
((forced_rc == 2)) || fail "an I/O/hash failure reported rc=$forced_rc, not 2"

# --- Registration: both guard lists + the CI invocation ----------------------

bash "$SCRIPT_DIR/ci-contracts.sh" --guard-only

python3 - "$REPO_ROOT" <<'PY'
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(sys.argv[1])
source = (root / "script/test/ci-contracts.sh").read_text()
files = ("script/test/lib/config-dir-guard.sh",
         "script/test/config-dir-guard-live.sh",
         "script/test/config-dir-guard-contract.sh",
         "script/test/fixtures/config-dir-guard/guest-n1a.sh",
         "script/test/fixtures/config-dir-guard/guest-n1b.sh",
         "script/test/fixtures/config-dir-guard/guest-n3.sh",
         "script/test/fixtures/config-dir-guard/guest-n4.sh",
         "script/test/fixtures/config-dir-guard/guest-n5.sh",
         "script/test/fixtures/config-dir-guard/guest-n7.sh")
run_list = source.split("# --- Shell guard rail", 1)[0]
assert 'bash "$REPO_ROOT/script/test/config-dir-guard-contract.sh"' in run_list, \
    "ci-contracts.sh does not invoke the host controls"
for array, label in (("syntax_check", "bash -n"), ("shellcheck_files", "shellcheck")):
    for script in files:
        start = source.index(array + "=(")
        end = source.index("\n)", start)
        block = source[start:end]
        entry = "    " + script + "\n"
        assert block.count(entry) == 1, (array, script)
        # Each removal must die for the correct reason: its explicit
        # assert_listed membership check, not an incidental missing-file error.
        assert f"assert_listed '{label}' '{script}'" in source, \
            f"no explicit {label} membership assertion for {script}"
        mutated = source[:start] + block.replace(entry, "", 1) + source[end:]
        with tempfile.TemporaryDirectory(prefix="cfg-guard-mutation-") as tmp:
            path = Path(tmp) / "script/test/ci-contracts.sh"
            path.parent.mkdir(parents=True)
            path.write_text(mutated)
            result = subprocess.run(["bash", str(path), "--guard-only"],
                                    capture_output=True, text=True, timeout=10)
            assert result.returncode == 1, result.stdout + result.stderr
            assert f"({script}) is missing from the {label} guard list" in result.stderr, result.stderr
        print(f"host-only removal mutation PASS: {array}: {script}")
PY

echo 'host-only config-dir guard controls passed (guest snippets + socket budget; no VM run)'
