#!/usr/bin/env bash
# Host Python guard for ADR-0072: building and testing the repository must not
# need `python3` on the host. Fails on:
#
#   * a tracked `*.py` file;
#   * a `python`/`python3` call in a tracked `*.sh` or `*.rs`;
#   * a reference to a `.py` file from a tracked `*.sh` or `*.rs`, which is how a
#     script runs a Python program without naming the interpreter;
#   * a `*.md` line that says the build or tests require host Python;
#
# unless host-python-allowlist.txt excuses it. The documentation rule has no
# allowlist: a prerequisite claim is false, not debt. A `.sh`/`.rs` entry carries
# the number of occurrences it excuses, so the ledger records debt, not a veto: a new
# call in an already-listed file fails, and so does a count left too high after a
# port. An entry that excuses nothing fails too.
#
# Whole-line comments are skipped. A comment that describes the Python this rule
# forbids is prose, not an invocation, and a guard that flagged prose would be
# switched off the first time it fired (the reasoning in
# no-image-source-dependency.sh). Trailing comments still fail: closed is safer
# than clever, and the fix is to move the note onto its own line.
set -euo pipefail
export LC_ALL=C

[[ $# -le 1 ]] || {
    echo 'usage: no-host-python.sh [checkout]' >&2
    exit 2
}

ROOT="$(cd "${1:-${BASH_SOURCE[0]%/*}/../..}" && pwd)"
ALLOWLIST="$ROOT/script/test/host-python-allowlist.txt"

fail() {
    echo "host python: $*" >&2
    exit 1
}

[[ -f "$ALLOWLIST" ]] || fail "missing allowlist: $ALLOWLIST"
git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 ||
    fail "$ROOT is not a git checkout, so tracked files cannot be scanned"

# This script and its controls name Python on purpose, in the pattern, the
# messages and the fixtures, so they are outside the scan. Nothing else is:
# excluding a real caller here would be the mute button the allowlist is not.
# The class syntax puts `-` first inside the brackets on purpose: BSD grep reads
# a trailing `-` after `.` as a range, which silently stops `:` from matching
# `${PY:-python3}`.
word_start='(:-|^|[^-_.[:alnum:]])'
word_end='([^-_[:alnum:]]|$)'
call_pattern="$word_start"'python[0-9]*(\.[0-9]+)*'"$word_end"
py_file_pattern='[[:alnum:]_.-]+\.py'"$word_end"
# A document must not tell a contributor to put Python on the host. This scan is
# narrow on purpose: a line needs both a Python name and a requirement verb, and
# must not negate them ("needs no `python3`" is the true statement this record
# makes). Historical prose is written in the past tense instead.
doc_claim='(require[sd]?|requiring|needs?|needing|must have|install(s|ed|ing)?|depend(s|ed|ing)? on|dependency on)[^.]*python[0-9]|python[0-9][^.]*(required|needed|mandatory)'
doc_negation='(no|not|never|without)[^.]*python[0-9]'

WORK="$(mktemp -d "${TMPDIR:-/tmp}/av-no-host-python.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

scan() { # scan <glob> <comment-line filter> <out>
    local glob="$1" drop="$2" out="$3" status=0
    git -C "$ROOT" -c color.grep=never grep -n -E \
        -e "$call_pattern" -e "$py_file_pattern" -- "$glob" \
        ':(exclude)script/test/no-host-python.sh' \
        ':(exclude)script/test/no-host-python-test.sh' >"$WORK/raw" 2>"$WORK/err" || status=$?
    # 1 is "no match"; anything else is a broken scan, not a clean tree.
    ((status <= 1)) || {
        cat "$WORK/err" >&2
        fail "git grep over $glob failed with status $status"
    }
    grep -vE "$drop" "$WORK/raw" >"$out" || true
}

# `#` is a comment in shell; `//`, `/*` and `*` open Rust comments. Scanning each
# language with its own rule is what keeps a shell `case` arm (`*) python3 ...`)
# from being mistaken for a Rust block comment.
scan '*.sh' ':[0-9]+:[[:space:]]*#' "$WORK/hits_sh"
scan '*.rs' ':[0-9]+:[[:space:]]*(//|/\*|\*)' "$WORK/hits_rs"
cat "$WORK/hits_sh" "$WORK/hits_rs" >"$WORK/hits"

# One violation line per file: a bare path for a Python file, `path<TAB>count`
# for a caller, so the allowlist can be compared file by file.
git -C "$ROOT" ls-files -- '*.py' | sed 's/$/\t/' | sort -u >"$WORK/violations"
cut -d: -f1 "$WORK/hits" | sort | uniq -c |
    awk '{ print $2 "\t" $1 }' >>"$WORK/violations"

# Compare the ledger against the tree. awk, not bash, because macOS CI runs
# /bin/bash 3.2, which has no associative arrays.
# shellcheck disable=SC2016 # the awk program runs in awk, not in this shell.
awk -v allowlist="$ALLOWLIST" '
BEGIN {
    while ((getline line < allowlist) > 0) {
        sub(/#.*/, "", line)
        gsub(/[ \t]+/, " ", line)
        sub(/^ /, "", line)
        sub(/ $/, "", line)
        if (line == "") continue
        fields = split(line, entry, " ")
        allow[entry[1]] = (fields > 1 ? entry[2] : "")
    }
    close(allowlist)
}
{
    path = $1
    count = $2
    if (!(path in allow)) {
        print "OFFENDING|" path "||" count
        next
    }
    seen[path] = 1
    if (allow[path] != count) print "MISMATCH|" path "|" allow[path] "|" count
}
END {
    for (path in allow) if (!(path in seen)) print "STALE|" path "|" allow[path] "|"
}
' "$WORK/violations" >"$WORK/findings"

status=0
while IFS='|' read -r kind path expected found; do
    case "$kind" in
        OFFENDING)
            if [[ -z "$found" ]]; then
                printf '%s: tracked Python file\n' "$path" >&2
            else
                printf '%s: calls Python (%s)\n' "$path" "$found"
                grep -F "$path:" "$WORK/hits" >&2 || true
            fi
            ;;
        MISMATCH)
            if [[ -z "$expected" ]]; then
                printf '%s: %s Python occurrence(s), but the allowlist has no count; write "%s %s"\n' \
                    "$path" "$found" "$path" "$found" >&2
            elif [[ -z "$found" ]]; then
                printf '%s: no Python left, but the allowlist still excuses %s; delete the line\n' \
                    "$path" "$expected" >&2
            else
                printf '%s: the allowlist excuses %s Python occurrence(s), the file has %s\n' \
                    "$path" "$expected" "$found" >&2
                grep -F "$path:" "$WORK/hits" >&2 || true
            fi
            ;;
        STALE)
            printf '%s: stale allowlist entry (nothing there uses Python; delete the line)\n' \
                "$path" >&2
            ;;
    esac
    status=1
done <"$WORK/findings"

((status == 0)) ||
    fail 'the tree needs Python the allowlist does not record (see ADR-0072 and script/test/host-python-allowlist.txt)'

# Documentation is not allowlisted: a prerequisite claim has no debt to excuse,
# it is simply false once the port is done.
docs_require=0
doc_status=0
git -C "$ROOT" -c color.grep=never grep -n -i -E \
    -e "$doc_claim" -- '*.md' >"$WORK/docs_raw" 2>"$WORK/err" || doc_status=$?
((doc_status <= 1)) || {
    cat "$WORK/err" >&2
    fail "git grep over documentation failed with status $doc_status"
}
grep -viE "$doc_negation" "$WORK/docs_raw" >"$WORK/docs_hits" || true
if [[ -s "$WORK/docs_hits" ]]; then
    cat "$WORK/docs_hits" >&2
    docs_require=1
fi
((docs_require == 0)) ||
    fail 'documentation says the build or tests need host Python (ADR-0072)'

echo 'no host Python outside the allowlist'
