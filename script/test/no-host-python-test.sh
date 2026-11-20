#!/usr/bin/env bash
# Controls for no-host-python.sh (ADR-0072). Proves the guard rejects new host
# Python in every form it claims to catch, that the allowlist excuses exactly the
# occurrences it counts and no more, and that a stale entry fails, so the ledger
# cannot outlive the Python it excuses.
set -euo pipefail

ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/av-nohostpy.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

guard="$ROOT/script/test/no-host-python.sh"
tree="$WORK/tree"
ledger="$tree/script/test/host-python-allowlist.txt"

# The guard must not depend on the caller's working directory, and the real
# checkout must pass: that is its actual subject, and a failure here means the
# allowlist has drifted from the tree.
(cd / && bash "$guard") >/dev/null || {
    echo "FAIL: the real checkout is not clean" >&2
    exit 1
}
echo 'the real checkout is clean'

# A miniature checkout. `git add` is enough to make a file tracked, which is all
# the guard scans; nothing here needs a commit or a git identity.
mkdir -p "$tree/script/test" "$tree/crates/x/src" "$tree/tools"
printf '%s\n' '# allowlist for this fixture' >"$ledger"
git -c init.defaultBranch=main init -q "$tree"
track() {
    git -C "$tree" add -A
}

write() { # write <path> <lines...>
    local path="$1"
    shift
    printf '%s\n' "$@" >"$tree/$path"
    track
}

# Replace one path's entry, so each control states the count it is testing
# instead of inheriting one from an earlier rewrite.
set_allow() { # set_allow <path> [count]
    local path="$1" count="${2:-}"
    awk -v p="$path" '$1 != p' "$ledger" >"$WORK/ledger"
    if [[ -n "$count" ]]; then
        printf '%s %s\n' "$path" "$count" >>"$WORK/ledger"
    else
        printf '%s\n' "$path" >>"$WORK/ledger"
    fi
    mv "$WORK/ledger" "$ledger"
    track
}

allow() { # append an entry without disturbing the ones already there
    printf '%s\n' "$@" >>"$ledger"
    track
}

reject() {
    local label="$1" needle
    shift
    if bash "$guard" "$tree" >"$WORK/result" 2>&1; then
        cat "$WORK/result" >&2
        echo "FAIL: guard accepted $label" >&2
        exit 1
    fi
    for needle in "$@"; do
        grep -Fq -- "$needle" "$WORK/result" || {
            cat "$WORK/result" >&2
            echo "FAIL: guard rejected $label without naming $needle" >&2
            exit 1
        }
    done
}

pass() {
    local label="$1"
    bash "$guard" "$tree" >"$WORK/result" 2>&1 || {
        cat "$WORK/result" >&2
        echo "FAIL: guard rejected $label" >&2
        exit 1
    }
}

pass 'an empty checkout'

# A missing allowlist is a broken guard, not a clean tree.
mv "$ledger" "$WORK/allowlist"
reject 'a checkout with no allowlist' 'missing allowlist'
mv "$WORK/allowlist" "$ledger"

write script/probe.py 'print("hi")'
reject 'a new Python file' 'script/probe.py' 'tracked Python file' 'ADR-0072'
allow script/probe.py
pass 'an allowlisted Python file'

# --- Interpreter forms the guard claims to catch ---------------------------
write script/run.sh '#!/usr/bin/env bash' 'python3 script/probe.py'
reject 'a shell script calling python3' 'script/run.sh:2' 'calls Python'
set_allow script/run.sh 1
pass 'a caller whose count matches'

write script/run.sh '#!/usr/bin/env bash' 'python3 script/probe.py' '' 'python3.12 "$@"'
reject 'a second call in an allowlisted file' 'script/run.sh' 'excuses 1'
set_allow script/run.sh 2
pass 'a caller whose count is raised to match'

# shellcheck disable=SC2016 # the forms are fixture text, not this shell's variables.
for form in '/usr/bin/python -V' 'uv run python -V' 'ENV=${PYTHON:-python3}'; do
    write script/run.sh '#!/usr/bin/env bash' "$form"
    reject "the form: $form" 'script/run.sh:2'
done

# A shell `case` arm starts with `*`, which must not read as a Rust comment.
# shellcheck disable=SC2016 # the case arm is fixture text for the guard to read.
write script/run.sh '#!/usr/bin/env bash' 'case "$1" in' '  *) python3 -c "pass";;' 'esac'
reject 'a case arm whose line starts with an asterisk' 'script/run.sh:3'
set_allow script/run.sh 1
pass 'a case arm the allowlist counts'

# A .py program run without naming the interpreter is the same debt.
write tools/archive.py 'print("hi")'
allow tools/archive.py
write script/exec.sh '#!/usr/bin/env bash' 'exec tools/archive.py "$@"'
reject 'a script executing a .py file directly' 'script/exec.sh:2'
set_allow script/exec.sh 1
pass 'an allowlisted direct .py execution'

# --- Rust callers ---------------------------------------------------------
write crates/x/src/lib.rs 'pub fn run() {' '    std::process::Command::new("python3").status();' '}'
reject 'a Rust test shelling out to python3' 'crates/x/src/lib.rs:2'
set_allow crates/x/src/lib.rs 1
pass 'an allowlisted Rust caller'

# --- Prose and near-misses ------------------------------------------------
# These must not trip the guard, or it gets switched off the first time it fires
# on a comment or on a hostname.
write script/notes.sh \
    '#!/usr/bin/env bash' \
    '# The probe used to call python3; see ADR-0072.' \
    'host=files.pythonhosted.org' \
    'export PYTHONPATH=/nowhere' \
    'echo run-python3'
write crates/x/src/notes.rs 'pub fn go() {}' '// python3 used to be here.'
pass 'a comment, a hostname, a python-named command and PYTHONPATH'

# --- The ledger cannot outlive what it excuses ---------------------------
set_allow script/exec.sh 1
allow 'script/gone.sh 1'
reject 'a stale allowlist entry' 'script/gone.sh: stale allowlist entry'
set_allow script/gone.sh

set_allow script/run.sh 9
reject 'a count left too high after a port' 'the allowlist excuses 9'

echo 'no-host-python controls passed'
