#!/usr/bin/env bash
# Black-box contract tests for the T5 command audit
# (images/recipe-contract/check-tool-access.py): the all-class permission
# predicate, symlink resolution, and the failure cases that must NOT pass.
#
# No Docker: fixtures are real files under a fresh directory whose own ancestors
# are world-traversable (the macOS per-user $TMPDIR is 0700 and would fail every
# case for the wrong reason). The checker is Python3, so this runs on Linux and
# macOS alike. The uid-12345/12345:45678 ownership variants from the plan need
# real numeric identities and are exercised in the Docker tier
# (script/test/shipped-tool-recipes.sh).
set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
CHECKER="$REPO_ROOT/images/recipe-contract/check-tool-access.py"

PYTHON="$(command -v python3 || true)"
[[ -n "$PYTHON" ]] || { echo "FAIL: python3 is required" >&2; exit 1; }

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# A fixture root under /tmp (/private/tmp on macOS): its ancestors are 0755/1777
# so only the modes a case sets can cause a failure.
ROOT="$(mktemp -d /tmp/tool-access.XXXXXX)"
# mktemp creates the root 0700; the checker must see a world-traversable root so
# only the per-case modes it sets can cause a failure.
chmod 0755 "$ROOT"
trap 'chmod -R u+rwX "$ROOT" 2>/dev/null || true; rm -rf "$ROOT"' EXIT

# run <target...>; sets RUN_STATUS/RUN_OUTPUT (combined streams).
run() {
    set +e
    RUN_OUTPUT="$(python3 "$CHECKER" "$@" 2>&1)"
    RUN_STATUS=$?
    set -e
}

expect_ok() {
    run "$@"
    [[ $RUN_STATUS -eq 0 ]] || fail "expected OK for '$*' but got $RUN_STATUS: $RUN_OUTPUT"
}

expect_fail() {
    local needle="$1"
    shift
    run "$@"
    [[ $RUN_STATUS -ne 0 ]] || fail "expected failure for '$*' but it passed: $RUN_OUTPUT"
    [[ "$RUN_OUTPUT" == *"$needle"* ]] || fail "expected failure to mention '$needle': $RUN_OUTPUT"
}

# --- a valid 0755 command ----------------------------------------------------

case_dir="$ROOT/pass"
mkdir -p "$case_dir/bin"
printf '#!/bin/sh\necho hi\n' >"$case_dir/bin/hello"
chmod 0755 "$case_dir/bin/hello"
expect_ok "$case_dir/bin/hello"

# --- PATH lookup picks the FIRST candidate, never a later usable one ---------

first="$ROOT/first"
second="$ROOT/second"
mkdir -p "$first" "$second"
printf '#!/bin/sh\n' >"$first/tool"
chmod 0644 "$first/tool" # present but not executable
printf '#!/bin/sh\n' >"$second/tool"
chmod 0755 "$second/tool"
set +e
RUN_OUTPUT="$(PATH="$first:$second" "$PYTHON" "$CHECKER" tool 2>&1)"
RUN_STATUS=$?
set -e
[[ $RUN_STATUS -ne 0 ]] || fail "a present-but-unusable first PATH candidate must fail"
[[ "$RUN_OUTPUT" == *"$first/tool"* ]] || fail "failure must name the first candidate: $RUN_OUTPUT"

# --- 0701 group-match directory (owner rwx, group --x, other --x) ------------

case_dir="$ROOT/group-mode"
mkdir -p "$case_dir/private/bin"
printf '#!/bin/sh\n' >"$case_dir/private/bin/cmd"
chmod 0755 "$case_dir/private/bin/cmd"
chmod 0701 "$case_dir/private"
expect_fail "not traversable by all" "$case_dir/private/bin/cmd"

# --- 0001 non-root-owner executable -----------------------------------------

case_dir="$ROOT/owner-mode"
mkdir -p "$case_dir/bin"
printf '#!/bin/sh\n' >"$case_dir/bin/cmd"
chmod 0001 "$case_dir/bin/cmd"
expect_fail "not executable by all" "$case_dir/bin/cmd"

# --- private lexical ancestor (the directory HOLDING a symlink) --------------

case_dir="$ROOT/lexical"
mkdir -p "$case_dir/linkdir" "$case_dir/real/bin"
printf '#!/bin/sh\n' >"$case_dir/real/bin/cmd"
chmod 0755 "$case_dir/real/bin/cmd"
ln -s "$case_dir/real/bin/cmd" "$case_dir/linkdir/cmd"
chmod 0700 "$case_dir/linkdir"
expect_fail "not traversable by all" "$case_dir/linkdir/cmd"

# --- private target ancestor (in the RESOLVED chain) -------------------------

case_dir="$ROOT/target"
mkdir -p "$case_dir/outside/bin"
printf '#!/bin/sh\n' >"$case_dir/outside/bin/cmd"
chmod 0755 "$case_dir/outside/bin/cmd"
chmod 0700 "$case_dir/outside"
expect_fail "not traversable by all" "$case_dir/outside/bin/cmd"

# --- relative multi-hop link resolves and passes when every mode is open -----

case_dir="$ROOT/multihop"
mkdir -p "$case_dir/bin"
printf '#!/bin/sh\n' >"$case_dir/bin/real"
chmod 0755 "$case_dir/bin/real"
ln -s real "$case_dir/bin/one"
ln -s one "$case_dir/bin/two"
expect_ok "$case_dir/bin/two"

# --- absolute multi-hop link -------------------------------------------------

case_dir="$ROOT/abs"
mkdir -p "$case_dir/bin"
printf '#!/bin/sh\n' >"$case_dir/bin/real"
chmod 0755 "$case_dir/bin/real"
ln -s "$case_dir/bin/real" "$case_dir/bin/abs-one"
expect_ok "$case_dir/bin/abs-one"

# --- a `..` in the path audits the directory it leaves -----------------------

case_dir="$ROOT/dotdot"
mkdir -p "$case_dir/leaving/bin"
printf '#!/bin/sh\n' >"$case_dir/leaving/bin/cmd"
chmod 0755 "$case_dir/leaving/bin/cmd"
chmod 0700 "$case_dir/leaving"
expect_fail "not traversable by all" "$case_dir/leaving/bin/../bin/cmd"

# --- dangling symlink --------------------------------------------------------

case_dir="$ROOT/dangling"
mkdir -p "$case_dir/bin"
ln -s nowhere "$case_dir/bin/dangle"
expect_fail "does not exist" "$case_dir/bin/dangle"

# --- symlink cycle -----------------------------------------------------------

case_dir="$ROOT/cycle"
mkdir -p "$case_dir/bin"
ln -s b "$case_dir/bin/a"
ln -s a "$case_dir/bin/b"
expect_fail "symlink chain exceeds" "$case_dir/bin/a"

# --- non-regular final target (a directory) ----------------------------------

case_dir="$ROOT/dirtarget"
mkdir -p "$case_dir/thing"
expect_fail "not a regular file" "$case_dir/thing"

# --- script content must be readable by all (0711 and 0111) ------------------

case_dir="$ROOT/scriptmode"
mkdir -p "$case_dir/bin"
printf '#!/bin/sh\n' >"$case_dir/bin/blocked"
chmod 0711 "$case_dir/bin/blocked"
expect_fail "not readable by all" "$case_dir/bin/blocked"
chmod 0111 "$case_dir/bin/blocked"
expect_fail "$case_dir/bin/blocked" "$case_dir/bin/blocked"

# --- shebang interpreter is audited (a 0700 interpreter fails) ---------------

case_dir="$ROOT/shebang"
mkdir -p "$case_dir/bin" "$case_dir/interp"
printf '#!/bin/sh\necho hi\n' >"$case_dir/interp/sh"
chmod 0755 "$case_dir/interp/sh"
# A script whose shebang names a private interpreter must fail on the
# interpreter, even though the script itself is fine.
printf '#!%s\n' "$case_dir/interp/sh" >"$case_dir/bin/uses-interp"
chmod 0755 "$case_dir/bin/uses-interp"
chmod 0700 "$case_dir/interp"
expect_fail "$case_dir/interp" "$case_dir/bin/uses-interp"

# --- repaired tree passes ----------------------------------------------------

case_dir="$ROOT/repaired"
mkdir -p "$case_dir/one/two"
printf '#!/bin/sh\n' >"$case_dir/one/two/cmd"
chmod 0755 "$case_dir/one" "$case_dir/one/two" "$case_dir/one/two/cmd"
expect_ok "$case_dir/one/two/cmd"

# --- SP1: `#!/usr/bin/env NAME` audits NAME on PATH --------------------------
# A command whose shebang is `#!/usr/bin/env node` must fail when the PATH
# `node` is not usable by all -- the npm CLI shebang. Comparing bytes to "env"
# used to skip the whole branch, so only the (fine) `/usr/bin/env` was audited.

case_dir="$ROOT/env-interp"
mkdir -p "$case_dir/bin"
printf '#!/bin/sh\necho interp\n' >"$case_dir/bin/private-interp"
chmod 0700 "$case_dir/bin/private-interp"
printf '#!/usr/bin/env private-interp\necho hi\n' >"$case_dir/bin/tool"
chmod 0755 "$case_dir/bin/tool"
set +e
RUN_OUTPUT="$(PATH="$case_dir/bin:/usr/bin:/bin" "$PYTHON" "$CHECKER" "$case_dir/bin/tool" 2>&1)"
RUN_STATUS=$?
set -e
[[ $RUN_STATUS -ne 0 ]] || fail "a 0700 PATH interpreter behind `#!/usr/bin/env` must fail: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *private-interp* ]] || fail "failure must name the PATH interpreter: $RUN_OUTPUT"
# Repairing the interpreter makes the same command pass.
chmod 0755 "$case_dir/bin/private-interp"
PATH="$case_dir/bin:/usr/bin:/bin" expect_ok "$case_dir/bin/tool"

# --- SP1: a relative path keeps the directory `..` leaves ---------------------
# `os.path.abspath` collapsed `private/../bin/tool`, so a 0700 `private` was
# never audited (the equivalent absolute path was correctly rejected).

case_dir="$ROOT/dotdot-relative"
mkdir -p "$case_dir/private" "$case_dir/bin"
printf '#!/bin/sh\n' >"$case_dir/bin/tool"
chmod 0755 "$case_dir/bin/tool"
chmod 0700 "$case_dir/private"
set +e
RUN_OUTPUT="$(cd "$case_dir" && "$PYTHON" "$CHECKER" private/../bin/tool 2>&1)"
RUN_STATUS=$?
set -e
[[ $RUN_STATUS -ne 0 ]] || fail "a relative 'private/../bin/tool' must audit 'private': $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *private* ]] || fail "failure must name the lexical directory: $RUN_OUTPUT"
chmod 0755 "$case_dir/private"
(cd "$case_dir" && expect_ok private/../bin/tool)

# --- SP1: `#!/usr/bin/env -S PATH=... NAME` audits the EFFECTIVE PATH ---------
# The kernel passes the whole remainder to env, which splits it and selects NAME
# under the PATH its own assignment sets. The auditor must model that lookup,
# not resolve NAME on its own PATH (which contained a good interpreter and hid
# the 0700 one the real build would select).

case_dir="$ROOT/env-path"
mkdir -p "$case_dir/bad" "$case_dir/good"
printf '#!/bin/sh\necho bad\n' >"$case_dir/bad/chosen"
chmod 0700 "$case_dir/bad/chosen"
printf '#!/bin/sh\necho good\n' >"$case_dir/good/chosen"
chmod 0755 "$case_dir/good/chosen"
printf '#!%s\n' "/usr/bin/env -S PATH=$case_dir/bad chosen" >"$case_dir/tool"
chmod 0755 "$case_dir/tool"
# The invoking PATH points at the good interpreter, exactly the case that used
# to mask the bad one.
set +e
RUN_OUTPUT="$(PATH="$case_dir/good:/usr/bin:/bin" "$PYTHON" "$CHECKER" "$case_dir/tool" 2>&1)"
RUN_STATUS=$?
set -e
[[ $RUN_STATUS -ne 0 ]] || fail "a PATH-changing env -S shebang must audit its effective PATH: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *bad/chosen* ]] || fail "failure must name the effective-PATH interpreter: $RUN_OUTPUT"
# Repairing the effective interpreter makes the same command pass.
chmod 0755 "$case_dir/bad/chosen"
PATH="$case_dir/good:/usr/bin:/bin" expect_ok "$case_dir/tool"

# An env option whose lookup effect we do not model must be rejected closed.
case_dir="$ROOT/env-ignore"
mkdir -p "$case_dir/bin"
printf '#!/bin/sh\n' >"$case_dir/bin/chosen"
chmod 0755 "$case_dir/bin/chosen"
printf '#!/usr/bin/env -i chosen\n' >"$case_dir/bin/tool"
chmod 0755 "$case_dir/bin/tool"
set +e
RUN_OUTPUT="$(PATH="$case_dir/bin:/usr/bin:/bin" "$PYTHON" "$CHECKER" "$case_dir/bin/tool" 2>&1)"
RUN_STATUS=$?
set -e
[[ $RUN_STATUS -ne 0 ]] || fail "env -i changes lookup and must be rejected closed: $RUN_OUTPUT"

case_dir="$ROOT/env-unset-path"
mkdir -p "$case_dir/bin"
printf '#!/bin/sh\n' >"$case_dir/bin/chosen"
chmod 0755 "$case_dir/bin/chosen"
printf '#!/usr/bin/env -u PATH chosen\n' >"$case_dir/bin/tool"
chmod 0755 "$case_dir/bin/tool"
set +e
RUN_OUTPUT="$(PATH="$case_dir/bin:/usr/bin:/bin" "$PYTHON" "$CHECKER" "$case_dir/bin/tool" 2>&1)"
RUN_STATUS=$?
set -e
[[ $RUN_STATUS -ne 0 ]] || fail "env -u PATH changes lookup and must be rejected closed: $RUN_OUTPUT"

# --- SP1: a nested `#!/usr/bin/env NAME` inherits the effective PATH ---------
# `tool` selects `chosen` under the `bad` PATH; `chosen`'s own
# `#!/usr/bin/env inner` shebang sets no PATH, so the kernel passes `bad` down
# and `inner` must be resolved THERE (0700 => fail). Resolving it on the
# auditor's PATH found a good `inner` and certified a tool the real build could
# not execute (audit rc0 but numeric-uid execution rc126).
case_dir="$ROOT/env-nested"
mkdir -p "$case_dir/bad" "$case_dir/good"
printf '#!/usr/bin/env inner\necho bad\n' >"$case_dir/bad/chosen"
chmod 0755 "$case_dir/bad/chosen"
printf '#!/bin/sh\necho bad-inner\n' >"$case_dir/bad/inner"
chmod 0700 "$case_dir/bad/inner"
printf '#!/bin/sh\necho good-inner\n' >"$case_dir/good/inner"
chmod 0755 "$case_dir/good/inner"
printf '#!%s\n' "/usr/bin/env -S PATH=$case_dir/bad chosen" >"$case_dir/tool"
chmod 0755 "$case_dir/tool"
set +e
RUN_OUTPUT="$(PATH="$case_dir/good:/usr/bin:/bin" "$PYTHON" "$CHECKER" "$case_dir/tool" 2>&1)"
RUN_STATUS=$?
set -e
[[ $RUN_STATUS -ne 0 ]] || fail "a nested env interpreter must inherit the effective PATH: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *bad/inner* ]] || fail "failure must name the inherited-PATH interpreter: $RUN_OUTPUT"
# Repairing the inherited-PATH interpreter makes the same command pass, even
# though the auditor's PATH still holds a usable `inner`.
chmod 0755 "$case_dir/bad/inner"
PATH="$case_dir/good:/usr/bin:/bin" expect_ok "$case_dir/tool"

# --- A1: an interpreter cycle is not proof of health ------------------------
# Two readable, executable scripts whose shebangs name each other used to be
# certified: the second visit found the interpreter in `seen` and returned Ok.
# The kernel raises ELOOP, so the audit must reject the cycle.
case_dir="$ROOT/interp-cycle"
mkdir -p "$case_dir/bin"
printf '#!%s\n' "$case_dir/bin/b" >"$case_dir/bin/a"
printf '#!%s\n' "$case_dir/bin/a" >"$case_dir/bin/b"
chmod 0755 "$case_dir/bin/a" "$case_dir/bin/b"
expect_fail "interpreter cycle" "$case_dir/bin/a"

# A single script whose shebang names itself is the same cycle.
case_dir="$ROOT/self-cycle"
mkdir -p "$case_dir/bin"
printf '#!%s\n' "$case_dir/bin/self" >"$case_dir/bin/self"
chmod 0755 "$case_dir/bin/self"
expect_fail "interpreter cycle" "$case_dir/bin/self"

# Excessive nesting is ELOOP in the kernel (five scripts resolve, six do not).
case_dir="$ROOT/depth"
mkdir -p "$case_dir/bin"
for i in 0 1 2 3 4 5; do
    if [[ $i -eq 5 ]]; then
        printf '#!/bin/sh\necho x\n' >"$case_dir/bin/s$i"
    else
        printf '#!%s\n' "$case_dir/bin/s$((i + 1))" >"$case_dir/bin/s$i"
    fi
    chmod 0755 "$case_dir/bin/s$i"
done
expect_fail "interpreter nesting" "$case_dir/bin/s0"
expect_ok "$case_dir/bin/s1"

# --- A2: Linux passes the env shebang remainder as ONE argument -------------
# `#!/usr/bin/env sh -e` makes env run a program literally named `sh -e`; it is
# not `sh` with option `-e`. The old parser split on whitespace and certified it.
case_dir="$ROOT/env-single-arg"
mkdir -p "$case_dir/bin"
printf '#!/usr/bin/env sh -e\necho hi\n' >"$case_dir/bin/tool"
chmod 0755 "$case_dir/bin/tool"
set +e
RUN_OUTPUT="$(PATH="/usr/bin:/bin" "$PYTHON" "$CHECKER" "$case_dir/bin/tool" 2>&1)"
RUN_STATUS=$?
set -e
[[ $RUN_STATUS -ne 0 ]] || fail 'a "#!/usr/bin/env sh -e" shebang must not certify sh'

# The supported `-S` split form still splits into words and resolves the command.
case_dir="$ROOT/env-split-arg"
mkdir -p "$case_dir/bin"
printf '#!/bin/sh\necho hi\n' >"$case_dir/bin/chosen"
chmod 0755 "$case_dir/bin/chosen"
printf '#!%s\n' "/usr/bin/env -S PATH=$case_dir/bin chosen" >"$case_dir/bin/tool"
chmod 0755 "$case_dir/bin/tool"
set +e
RUN_OUTPUT="$(PATH="/usr/bin:/bin" "$PYTHON" "$CHECKER" "$case_dir/bin/tool" 2>&1)"
RUN_STATUS=$?
set -e
[[ $RUN_STATUS -eq 0 ]] || fail "a valid env -S split shebang must pass: $RUN_OUTPUT"

# --- A2: a CRLF shebang names `/bin/sh\r`, which does not exist -------------
case_dir="$ROOT/crlf-shebang"
mkdir -p "$case_dir/bin"
printf '#!/bin/sh\r\necho hi\n' >"$case_dir/bin/tool"
chmod 0755 "$case_dir/bin/tool"
expect_fail "does not exist" "$case_dir/bin/tool"

# --- A2: a malformed shebang with no interpreter fails closed ---------------
case_dir="$ROOT/empty-shebang"
mkdir -p "$case_dir/bin"
printf '#!\necho hi\n' >"$case_dir/bin/tool"
chmod 0755 "$case_dir/bin/tool"
expect_fail "shebang names no interpreter" "$case_dir/bin/tool"

# --- --content: required data is audited for readability, not execution -----
# The bridge source/mandatory extension are read, never run: they must be
# all-class READABLE and reachable, but need no execute bit.
case_dir="$ROOT/content-pass"
mkdir -p "$case_dir/tree"
printf 'data\n' >"$case_dir/tree/index.ts"
chmod 0644 "$case_dir/tree/index.ts"
chmod 0755 "$case_dir" "$case_dir/tree"
expect_ok --content "$case_dir/tree/index.ts"

# A content symlink into a 0700 directory must fail on the target ancestor.
case_dir="$ROOT/content-private-target"
mkdir -p "$case_dir/tree" "$case_dir/private"
printf 'data\n' >"$case_dir/private/index.ts"
chmod 0644 "$case_dir/private/index.ts"
chmod 0700 "$case_dir/private"
ln -s "$case_dir/private/index.ts" "$case_dir/tree/index.ts"
chmod 0755 "$case_dir" "$case_dir/tree"
expect_fail "not traversable by all" --content "$case_dir/tree/index.ts"

# A content file with no all-class read bit fails.
case_dir="$ROOT/content-unreadable"
mkdir -p "$case_dir/tree"
printf 'data\n' >"$case_dir/tree/index.ts"
chmod 0600 "$case_dir/tree/index.ts"
expect_fail "not readable by all" --content "$case_dir/tree/index.ts"

echo "tool-access black-box tests passed"
