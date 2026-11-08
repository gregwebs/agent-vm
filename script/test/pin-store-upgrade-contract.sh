#!/usr/bin/env bash
# Contract test for the USAGE upgrade/rollback procedure (#532, spec R13).
#
# The blocks in USAGE are the only place the operator-facing procedure exists:
# npm installs ship no scripts, so the text itself is the program. This runs that
# text verbatim — extracted by marker, never retyped — against fixture HOMEs,
# including fault injection for every command whose failure must stop it. A
# broken block therefore fails here instead of on a user's only copy of their
# approvals.
#
# What the blocks do is deliberately narrow (spec supersedance, #532): they copy
# bytes and refuse what they cannot copy exactly. They never reconstruct an
# approval or a default out of JSON, so the rows below assert two different
# things — that a file the old reader would refuse is still archived, and that
# the one state requiring a decision (an interrupted `image set-default`) is
# refused with a way out.
#
# The inner interpreter is chosen explicitly: each block starts
# `bash -euo pipefail <<'EOF'`, so the `bash` the blocks resolve is the one this
# script puts on the fixture PATH, named by PIN_CONTRACT_BASH. CI runs it on
# Linux bash 5; `PIN_CONTRACT_BASH=/bin/bash` on macOS exercises bash 3.2, which
# is what a macOS user has. Merely launching this script with an old bash does
# not select the blocks' interpreter, because the blocks resolve their own.
#
# Usage: bash script/test/pin-store-upgrade-contract.sh [FILE.md]
#
# check/stub bodies are eval'd or written to files, so their expansions are deferred.
# shellcheck disable=SC2016,SC2034
set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
DOC="${1:-$REPO_ROOT/USAGE.md}"
OUTER_SH="${PIN_CONTRACT_SH:-/bin/sh}"
INNER_BASH="${PIN_CONTRACT_BASH:-/bin/bash}"

for tool in sh bash jq cmp pgrep mktemp cp mv rm cat grep; do
    command -v "$tool" >/dev/null || {
        echo "FAIL: $tool is required" >&2
        exit 2
    }
done
[ -x "$OUTER_SH" ] || {
    echo "FAIL: the outer interpreter $OUTER_SH is not executable" >&2
    exit 2
}
[ -x "$INNER_BASH" ] || {
    echo "FAIL: the inner interpreter $INNER_BASH is not executable" >&2
    exit 2
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/av-pin-upgrade-contract.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# extract DOC NAME OUTFILE — the one fenced shell block between exactly one marker
# pair, with the fences stripped. It fails unless that pair and its fence are
# unambiguous: a duplicated, displaced, unpaired or prose-only block would
# otherwise leave every check green while operators execute different text.
#
# Every rejection names its reason on stderr. The negative controls below assert
# the reason, not just the status: a fixture rejected for a missing marker proves
# nothing about the defect it is named for.
extract() {
    local doc="$1" out="$3" open close seen
    open="<!-- $2 -->"
    close="<!-- /$2 -->"
    seen="$(grep -c -x -F -- "$open" "$doc")"
    [ "$seen" -eq 1 ] || {
        echo "extract: $seen occurrences of $open, expected one" >&2
        return 1
    }
    seen="$(grep -c -x -F -- "$close" "$doc")"
    [ "$seen" -eq 1 ] || {
        echo "extract: $seen occurrences of $close, expected one" >&2
        return 1
    }
    # Flags, not `exit`: awk still runs END after an exit, so an early exit code
    # would be overwritten by the unclosed check below.
    if awk -v m="$open" -v e="$close" '
        $0 == m { if (on) repeated = 1; on = 1; next }
        $0 == e { if (!on) reversed = 1; on = 0; closed = 1; next }
        on { print }
        END { if (repeated) exit 1; if (reversed) exit 2; if (!closed) exit 3 }
    ' "$doc" >"$out.raw"; then
        :
    else
        case $? in
            2) echo "extract: $close comes before $open" >&2 ;;
            3) echo "extract: $open is never closed by $close" >&2 ;;
            *) echo "extract: $open appears twice inside its own block" >&2 ;;
        esac
        return 1
    fi
    # Exactly one shell block, opened and closed, and nothing else around it.
    seen="$(grep -c '^```' "$out.raw")"
    [ "$seen" -eq 2 ] || {
        echo "extract: $seen fence lines, expected one open and one close" >&2
        return 1
    }
    [ "$(sed -n 1p "$out.raw")" = '```sh' ] || {
        echo "extract: the first fence is not \`\`\`sh" >&2
        return 1
    }
    [ "$(tail -n 1 "$out.raw")" = '```' ] || {
        echo "extract: the last line is not a closing fence" >&2
        return 1
    }
    sed '1d;$d' "$out.raw" >"$out"
    # The block is the program the operator pastes: `bash -euo pipefail` around a
    # single quoted heredoc, not prose that mentions one.
    [ "$(sed -n 1p "$out")" = "bash -euo pipefail <<'EOF'" ] || {
        echo "extract: the block does not open the documented program" >&2
        return 1
    }
    [ "$(tail -n 1 "$out")" = 'EOF' ] || {
        echo "extract: the block does not close the documented program" >&2
        return 1
    }
    [ -s "$out" ] || {
        echo "extract: the block is empty" >&2
        return 1
    }
}
extract "$DOC" pin-store-upgrade "$WORK/upgrade.sh"
extract "$DOC" pin-store-rollback "$WORK/rollback.sh"

# Negative controls: the operator executes the extracted text, so an extraction
# that would silently pick a different block has to fail here. Each fixture is a
# *validly marked up* document — one marker pair around one fenced block — that is
# then mutated in exactly one property, so it is rejected for the defect it names
# and not for a missing marker. `named_reason` below asserts that reason.
real_block="$(cat "$WORK/upgrade.sh.raw")"
tick='```'
pair() { # pair TEXT — one operator marker pair around TEXT
    printf '<!-- pin-store-upgrade -->\n%s\n<!-- /pin-store-upgrade -->\n' "$1"
}
neg() { # neg NAME TEXT — a document the extractor must reject
    printf '%s\n' "$2" >"$WORK/neg-$1.md"
}
five_lines="bash -euo pipefail <<'EOF'
echo hi
EOF"
neg duplicate "$(pair "$real_block")

$(pair "$real_block")"
neg displaced "$(pair "$real_block")
<!-- /pin-store-upgrade -->"
neg unpaired "<!-- pin-store-upgrade -->
$real_block"
neg reversed "<!-- /pin-store-upgrade -->
${tick}sh
$five_lines
$tick
<!-- pin-store-upgrade -->"
neg wrong-fence "$(pair "$(printf '%s\n' "$real_block" | sed "1s/^${tick}sh\$/${tick}bash/")")"
neg two-fences "$(pair "$(printf '%s\n' "$real_block" | awk -v f="$tick" 'NR == 2 { print f } { print }')")"
neg not-a-program "$(pair "${tick}sh
echo hi
$tick")"
neg nested "<!-- pin-store-upgrade -->
<!-- pin-store-upgrade -->
$real_block
<!-- /pin-store-upgrade -->"

# Every tool the blocks run, resolved once; fixtures get a PATH of symlinks so a
# test can remove or wrap exactly one tool. `bash` resolves to the explicitly
# chosen inner interpreter, never to whatever PATH would have found.
TOOLS=(sh bash jq cmp pgrep mktemp cp mv rm cat grep)
real() {
    if [ "$1" = bash ]; then
        printf '%s' "$INNER_BASH"
    else
        command -v "$1"
    fi
}

# toolbox NAME [OMIT] — a PATH dir of real tools (minus OMIT) with pgrep
# answering "no agent-vm process" (status 1) unless overridden.
toolbox() {
    local dir="$WORK/tools-$1"
    mkdir -p "$dir"
    for t in "${TOOLS[@]}"; do
        [ "$t" = "${2:-}" ] && continue
        ln -sf "$(real "$t")" "$dir/$t"
    done
    if [ "${2:-}" != pgrep ]; then stub "$1" pgrep 'exit 1'; fi
    printf '%s' "$dir"
}
# stub BOX TOOL BODY — replace one tool with a shell body that may exit, else runs $REAL.
stub() {
    local dir="$WORK/tools-$1"
    rm -f "$dir/$2"
    printf '#!%s\nREAL=%q\n%s\nexec "$REAL" "$@"\n' "$(real sh)" "$(real "$2")" "$3" >"$dir/$2"
    chmod +x "$dir/$2"
}

PASS=0
FAIL=0
check() {
    if eval "$2"; then
        echo "ok   $1"
        PASS=$((PASS + 1))
    else
        echo "FAIL $1"
        FAIL=$((FAIL + 1))
    fi
}

# The interpreter pair the blocks actually ran under, recorded so a compatibility
# claim names what was executed rather than what launched this script.
echo "# running the blocks under inner bash: $("$INNER_BASH" --version | head -1)"
echo "# outer interpreter: $OUTER_SH"

echo "# the extractor rejects text that is not exactly one operator block"
for case in duplicate displaced unpaired reversed wrong-fence two-fences not-a-program nested; do
    check "extractor rejects a $case block" '! extract "$WORK/neg-$case.md" pin-store-upgrade "$WORK/neg-$case.out" 2>"$WORK/neg-$case.err"'
done
# Why each document was rejected, so a control cannot pass because the fixture
# lost its markers: the reason names the defect, and only the defect.
want_reason() { # want_reason CASE
    case "$1" in
        duplicate|nested) printf '%s' '2 occurrences of <!-- pin-store-upgrade -->' ;;
        displaced) printf '%s' '2 occurrences of <!-- /pin-store-upgrade -->' ;;
        unpaired) printf '%s' '0 occurrences of <!-- /pin-store-upgrade -->' ;;
        reversed) printf '%s' 'comes before <!-- pin-store-upgrade -->' ;;
        wrong-fence) printf '%s' 'the first fence is not' ;;
        two-fences) printf '%s' '3 fence lines' ;;
        not-a-program) printf '%s' 'does not open the documented program' ;;
    esac
}
named_reason() { grep -qF -- "$(want_reason "$1")" "$WORK/neg-$1.err"; }
for case in duplicate displaced unpaired reversed wrong-fence two-fences not-a-program nested; do
    check "a $case block is rejected for that defect" 'named_reason "$case"'
done

DA='{"version":1,"image":"r.example/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
DB='{"version":1,"image":"r.example/b@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}'
DC='{"version":1,"image":"r.example/c@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}'
V2='{"version":2,"pins":[],"pending_default":null}'
# The two journal shapes an interrupted `image set-default` leaves, with the
# trailing newline the old writer stored.
JOURNAL_PREV="$(jq -n --arg a "$DA"$'\n' --arg b "$DB"$'\n' '{previous:$a,proposed:$b}')"
JOURNAL_NOPREV="$(jq -n --arg b "$DB"$'\n' '{previous:null,proposed:$b}')"

# fixture NAME JOURNAL DEFAULT|absent -> prints the HOME
fixture() {
    local h="$WORK/home-$1"
    mkdir -p "$h/.config/agent-vm"
    jq -n --argjson p "$2" '{version:1,pins:[{reference:"r.example/x:1",platform:{os:"linux",architecture:"arm64",variant:null},manifest_digest:"sha256:1111111111111111111111111111111111111111111111111111111111111111",revision:1}],pending_default:$p}' \
        >"$h/.config/agent-vm/image-pins.json"
    : >"$h/.config/agent-vm/image-pins.lock"
    if [ "$3" != absent ]; then printf '%s\n' "$3" >"$h/.config/agent-vm/default-image.json"; fi
    printf '%s' "$h"
}
# run HOME BLOCK [TOOLBOX] — the block's text, unchanged, under the outer shell.
run() {
    local path="${3:-$(toolbox default)}"
    rm -f "$1/cmp-calls"
    (cd "$1" && HOME="$1" PATH="$path" CMP_CALLS="$1/cmp-calls" "$OUTER_SH" "$WORK/$2.sh") >"$WORK/out" 2>&1
}
cfg() { printf '%s' "$1/.config/agent-vm"; }
pins() { cat "$(cfg "$1")/image-pins.json" 2>/dev/null || echo "<absent>"; }
dflt() { cat "$(cfg "$1")/default-image.json" 2>/dev/null || echo "<absent>"; }
arch_pins() { cat "$(cfg "$1")/$2/image-pins.json" 2>/dev/null || echo "<absent>"; }
arch_dflt() { cat "$(cfg "$1")/$2/default-image.json" 2>/dev/null || echo "<absent>"; }
no_archive() { ! ls -d "$(cfg "$1")"/v1-archive >/dev/null 2>&1; }
said() { grep -qF -- "$1" "$WORK/out"; }
untouched() { [ "$(pins "$1")" = "$2" ] && [ "$(dflt "$1")" = "$3" ]; }

echo "# nominal upgrade"
h=$(fixture plain null "$DA")
orig=$(pins "$h")
check "no journal: upgrade succeeds" 'run "$h" upgrade'
check "no journal: pair archived byte-identical" '[ "$(arch_pins "$h" v1-archive)" = "$orig" ] && [ "$(arch_dflt "$h" v1-archive)" = "$DA" ]'
check "no journal: live store gone, lock and default kept" '[ "$(pins "$h")" = "<absent>" ] && [ -e "$(cfg "$h")/image-pins.lock" ] && [ "$(dflt "$h")" = "$DA" ]'
check "no journal: rerun refuses" '! run "$h" upgrade && said "no image-pins.json to upgrade"'
h=$(fixture plain-absent null absent)
check "no default record: upgrade succeeds and creates none" 'run "$h" upgrade && [ "$(pins "$h")" = "<absent>" ] && [ "$(dflt "$h")" = "<absent>" ] && [ "$(arch_pins "$h" v1-archive)" != "<absent>" ]'
h=$(fixture v2-store null "$DA")
printf '%s\n' "$V2" >"$(cfg "$h")/image-pins.json"
check "a version 2 store is refused" '! run "$h" upgrade && said "not a version 1 store" && [ "$(pins "$h")" = "$V2" ]'
h=$(fixture not-an-object null "$DA")
printf 'null\n' >"$(cfg "$h")/image-pins.json"
check "a store that is not an object is refused" '! run "$h" upgrade && said "not a version 1 store" && [ "$(pins "$h")" = "null" ]'

echo "# an interrupted image set-default is refused, not replayed"
# Deciding the default from `pending_default` means deciding authority from JSON,
# which shell can only approximate: every attempt either accepted bytes the old
# reader rejects or refused bytes it accepts. The block refuses the state whole
# and hands the decision to the release that owns the journal.
h=$(fixture journal "$JOURNAL_PREV" "$DB")
orig=$(pins "$h")
check "a journal is refused, nothing written" '! run "$h" upgrade && said "interrupted image set-default" && untouched "$h" "$orig" "$DB" && no_archive "$h"'
check "the refusal names the release and the command to run next" 'said "agent-vm 0.7.38" && said "agent-vm image set-default --image"'
check "the refusal says nothing was changed" 'said "nothing was changed"'
# Repeating `set-default` with a moved tag resolves other content and does not
# finish this intent, so the command it prints takes the digest the journal
# already holds; the run that finishes it needs the registry.
check "the refusal names the digest the journal holds, not a tag" 'said "pending_default.proposed | fromjson | .image" && said "agent-vm image set-default --image \"\$digest\""'
check "the refusal says the recovery run needs network access" 'said "needs network access"'
h=$(fixture journal-noprev "$JOURNAL_NOPREV" "$DB")
orig=$(pins "$h")
check "a journal with no previous default is refused the same way" '! run "$h" upgrade && said "interrupted image set-default" && untouched "$h" "$orig" "$DB" && no_archive "$h"'
h=$(fixture journal-absent "$JOURNAL_PREV" absent)
orig=$(pins "$h")
check "a journal beside no default record is refused too" '! run "$h" upgrade && said "interrupted image set-default" && untouched "$h" "$orig" "<absent>" && no_archive "$h"'
hostile_journal="$(jq -n --arg p '{"version":1,"image":"r.example/unapproved:latest"}'$'\n' --arg q "$DB"$'\n' '{previous:$p,proposed:$q}')"
h=$(fixture hostile-journal "$hostile_journal" "$DB")
orig=$(pins "$h")
check "a journal side no reader would keep is refused as a journal, not read" '! run "$h" upgrade && said "interrupted image set-default" && untouched "$h" "$orig" "$DB" && no_archive "$h"'
h=$(fixture journal-archive "$JOURNAL_PREV" "$DB")
orig=$(pins "$h")
mkdir "$(cfg "$h")/v1-archive"
printf '%s\n' "$orig" >"$(cfg "$h")/v1-archive/image-pins.json"
check "a journal is refused even when an archive already exists" '! run "$h" upgrade && said "interrupted image set-default" && [ "$(pins "$h")" = "$orig" ]'

echo "# refusals before any write"
h=$(fixture busy null "$DA")
orig=$(pins "$h")
box=$(toolbox busy)
stub busy pgrep 'exit 0'
check "agent-vm running: refused, nothing written" '! run "$h" upgrade "$box" && said "close every agent-vm" && untouched "$h" "$orig" "$DA" && no_archive "$h"'
h=$(fixture pgrep-error null "$DA")
orig=$(pins "$h")
box=$(toolbox pgrep-error)
stub pgrep-error pgrep 'exit 3'
check "pgrep error: refused, nothing written" '! run "$h" upgrade "$box" && said "pgrep failed (status 3)" && untouched "$h" "$orig" "$DA" && no_archive "$h"'
for t in pgrep jq cmp mktemp; do
    h=$(fixture "missing-$t" null "$DA")
    orig=$(pins "$h")
    box=$(toolbox "missing-$t" "$t")
    check "missing $t: refused, nothing written" '! run "$h" upgrade "$box" && said "$t is required" && untouched "$h" "$orig" "$DA" && no_archive "$h"'
done
h=$(fixture not-json null "$DA")
printf 'not json\n' >"$(cfg "$h")/image-pins.json"
check "unparseable store (jq status 5): refused, nothing written" '! run "$h" upgrade && untouched "$h" "not json" "$DA" && no_archive "$h"'

echo "# the store is archived by its version, not by its shape"
# The store is copied, never interpreted: a shape the old reader would refuse is
# still the user's own file, restored byte for byte by the rollback block. Only
# the version decides, and only because version 1 and version 2 mean different
# things to the binary that reads the file next.
h=$(fixture odd-pins null "$DA")
printf '%s\n' '{"version":1,"pins":"not a list","pending_default":null}' >"$(cfg "$h")/image-pins.json"
orig=$(pins "$h")
check "a store whose pins field is not a list: archived byte-identically" 'run "$h" upgrade && [ "$(arch_pins "$h" v1-archive)" = "$orig" ] && [ "$(pins "$h")" = "<absent>" ]'
h=$(fixture extra-field null "$DA")
jq '.extra = true' "$(cfg "$h")/image-pins.json" >"$WORK/extra.json"
mv "$WORK/extra.json" "$(cfg "$h")/image-pins.json"
orig=$(pins "$h")
check "an unknown store field: archived, not refused" 'run "$h" upgrade && [ "$(arch_pins "$h" v1-archive)" = "$orig" ]'
h=$(fixture duplicate-key null "$DA")
printf '{"version":1,"version":1,"pins":[],"pending_default":null}\n' >"$(cfg "$h")/image-pins.json"
orig=$(pins "$h")
check "a duplicate store key: archived, not refused" 'run "$h" upgrade && [ "$(arch_pins "$h" v1-archive)" = "$orig" ]'
h=$(fixture two-documents null "$DA")
printf '%s\n%s\n' '{"version":1,"pins":[],"pending_default":null}' '{"version":1,"pins":[],"pending_default":null}' >"$(cfg "$h")/image-pins.json"
orig=$(pins "$h")
check "two JSON documents in one store: refused as not one version 1 file" '! run "$h" upgrade && said "not a version 1 store" && untouched "$h" "$orig" "$DA" && no_archive "$h"'

echo "# a pre-placed name or symlink is never written through"
canary="$WORK/canary"
printf 'canary\n' >"$canary"
h=$(fixture symlink-live null "$DA")
rm "$(cfg "$h")/default-image.json"
ln -s "$canary" "$(cfg "$h")/default-image.json"
orig=$(pins "$h")
check "a symlinked live default: refused before any write" '! run "$h" upgrade && said "default-image.json is not an ordinary file" && [ "$(cat "$canary")" = "canary" ] && [ "$(pins "$h")" = "$orig" ] && no_archive "$h"'
h=$(fixture symlink-store null "$DA")
orig="$(cat "$(cfg "$h")/image-pins.json")"
mv "$(cfg "$h")/image-pins.json" "$WORK/store-target.json"
ln -s "$WORK/store-target.json" "$(cfg "$h")/image-pins.json"
check "a symlinked live store: refused before any write" '! run "$h" upgrade && said "image-pins.json is not an ordinary file" && [ "$(cat "$WORK/store-target.json")" = "$orig" ]'
h=$(fixture symlink-archive null "$DA")
orig=$(pins "$h")
mkdir "$WORK/elsewhere-archive"
printf '%s\n' "$orig" >"$WORK/elsewhere-archive/image-pins.json"
ln -s "$WORK/elsewhere-archive" "$(cfg "$h")/v1-archive"
check "a symlinked v1-archive is refused" '! run "$h" upgrade && said "v1-archive is not a plain directory" && [ "$(pins "$h")" = "$orig" ]'
h=$(fixture rb-symlink-staging null "$DB")
orig=$(pins "$h")
run "$h" upgrade
printf '%s\n' "$V2" >"$(cfg "$h")/image-pins.json"
printf '%s\n' "$DC" >"$(cfg "$h")/default-image.json"
ln -s "$canary" "$(cfg "$h")/image-pins.json.new"
check "rollback: a symlink at its staging name is not written through" 'run "$h" rollback && [ "$(cat "$canary")" = "canary" ]'
check "rollback: a symlink at its staging name still restores a real file" '[ -f "$(cfg "$h")/image-pins.json" ] && [ ! -L "$(cfg "$h")/image-pins.json" ] && [ "$(pins "$h")" = "$orig" ]'
h=$(fixture rb-symlink-archive null "$DB")
run "$h" upgrade
printf '%s\n' "$V2" >"$(cfg "$h")/image-pins.json"
mv "$(cfg "$h")/v1-archive/image-pins.json" "$WORK/archive-target.json"
ln -s "$WORK/archive-target.json" "$(cfg "$h")/v1-archive/image-pins.json"
check "rollback: a symlinked archive member is refused" '! run "$h" rollback && said "v1-archive/image-pins.json is missing or not an ordinary file" && [ "$(pins "$h")" = "$V2" ]'
h=$(fixture rb-symlinked-v1-dir null "$DB")
orig=$(pins "$h")
run "$h" upgrade
printf '%s\n' "$V2" >"$(cfg "$h")/image-pins.json"
mkdir "$WORK/elsewhere-v1"
mv "$(cfg "$h")/v1-archive" "$WORK/elsewhere-v1/v1-archive"
ln -s "$WORK/elsewhere-v1/v1-archive" "$(cfg "$h")/v1-archive"
before=$(dflt "$h")
check "rollback: a symlinked v1-archive is refused, nothing restored" '! run "$h" rollback && said "v1-archive is not a plain directory" && untouched "$h" "$V2" "$before"'

echo "# a dangling symlink is a present entry, not an absent file"
# `-e` is false for a link whose target does not exist, so a guard written with it
# stepped over the link: the upgrade archived a file set without the default it
# was told to keep, and a rollback read a dangling archived member as "no default"
# and deleted the one it was meant to restore.
h=$(fixture dangling-live null absent)
ln -s "$WORK/never-created" "$(cfg "$h")/default-image.json"
orig=$(pins "$h")
check "a dangling live default: refused before any write" '! run "$h" upgrade && said "default-image.json is not an ordinary file" && untouched "$h" "$orig" "<absent>" && [ -L "$(cfg "$h")/default-image.json" ] && no_archive "$h"'
h=$(fixture dangling-rolled-back null "$DA")
run "$h" upgrade
printf '%s\n' "$(arch_pins "$h" v1-archive)" >"$(cfg "$h")/image-pins.json"
mv "$(cfg "$h")/default-image.json" "$WORK/restored-default.json"
ln -s "$WORK/never-created" "$(cfg "$h")/default-image.json"
check "rollback: a dangling live default is not read as absent" '! run "$h" rollback && said "default-image.json is not an ordinary file" && [ -L "$(cfg "$h")/default-image.json" ]'
h=$(fixture dangling-archived null "$DB")
run "$h" upgrade
mv "$(cfg "$h")/v1-archive/default-image.json" "$WORK/archived-default.json"
ln -s "$WORK/never-created" "$(cfg "$h")/v1-archive/default-image.json"
printf '%s\n' "$V2" >"$(cfg "$h")/image-pins.json"
before=$(dflt "$h")
check "rollback: a dangling archived default is refused, not read as absent" '! run "$h" rollback && said "v1-archive/default-image.json is not an ordinary file" && untouched "$h" "$V2" "$before"'

echo "# every archive directory must be a plain directory"
h=$(fixture symlinked-v1-dir-rerun null "$DA")
orig=$(pins "$h")
run "$h" upgrade
printf '%s\n' "$orig" >"$(cfg "$h")/image-pins.json"
mkdir "$WORK/elsewhere-v1-rerun"
mv "$(cfg "$h")/v1-archive" "$WORK/elsewhere-v1-rerun/v1-archive"
ln -s "$WORK/elsewhere-v1-rerun/v1-archive" "$(cfg "$h")/v1-archive"
check "upgrade rerun: a symlinked v1-archive is refused" '! run "$h" upgrade && said "v1-archive is not a plain directory" && [ "$(pins "$h")" = "$orig" ]'

echo "# no record shape is refused for being unusual"
# With nothing decoded, nothing can be refused for looking wrong: the archive
# keeps whatever the old binary wrote, including the shapes a shell validator
# used to reject and the sandbox measured the launcher accepting.
SHA512_D="$(jq -cn '{version:1,image:("r.example/a@sha512:"+("b"*128))}')"
SHA384_D="$(jq -cn '{version:1,image:("r.example/a@sha384:"+("c"*96))}')"
LONG_D="$(jq -cn '{version:1,image:("r.example/"+("a"*250)+"@sha256:"+("a"*64))}')"
h=$(fixture sha512-default null "$SHA512_D")
check "a SHA-512 default is archived and kept" 'run "$h" upgrade && [ "$(arch_dflt "$h" v1-archive)" = "$SHA512_D" ] && [ "$(dflt "$h")" = "$SHA512_D" ]'
h=$(fixture sha384-default null "$SHA384_D")
check "a SHA-384 default is archived and kept" 'run "$h" upgrade && [ "$(arch_dflt "$h" v1-archive)" = "$SHA384_D" ]'
h=$(fixture long-name-default null "$LONG_D")
check "a reference of 250 characters is archived and kept" 'run "$h" upgrade && [ "$(arch_dflt "$h" v1-archive)" = "$LONG_D" ]'
h=$(fixture sha512-store null "$DA")
jq '.pins[0].manifest_digest = "sha512:" + ("c"*128)' "$(cfg "$h")/image-pins.json" >"$WORK/sha512-store.json"
mv "$WORK/sha512-store.json" "$(cfg "$h")/image-pins.json"
orig=$(pins "$h")
check "a SHA-512 store record is archived, not refused" 'run "$h" upgrade && [ "$(pins "$h")" = "<absent>" ] && [ "$(arch_pins "$h" v1-archive)" = "$orig" ]'

echo "# quiescence covers renamed agent-vm binaries"
# `pgrep -x agent-vm` missed `agent-vm-dev`, `agent-vm-0.7.38` and a copy on
# another path, so a concurrently running old or renamed binary could write the
# pair mid-sequence. The stub checks the pattern the block actually passes.
h=$(fixture pattern null "$DA")
box=$(toolbox pattern)
stub pattern pgrep '
[ "$1" = -f ] || { echo "injected: pgrep without -f: $*" >&2; exit 3; }
pattern="$2"
for line in "agent-vm --image x" "/usr/local/bin/agent-vm-dev shell" \
    "agent-vm-0.7.38 --no-git" "/tmp/avm-review-bundle/bin/agent-vm --image y"; do
  printf "%s\n" "$line" | grep -Eq -- "$pattern" ||
    { echo "injected: the pattern misses $line" >&2; exit 4; }
done
for line in "tail -f agent-vm.log" "grep agent-vm" "vim agent-vm-store.txt" \
    "bash -euo pipefail"; do
  if printf "%s\n" "$line" | grep -Eq -- "$pattern"; then
    echo "injected: the pattern matches $line" >&2
    exit 5
  fi
done
exit 1'
check "the quiescence pattern matches renamed agent-vm binaries" 'run "$h" upgrade "$box" && [ "$(pins "$h")" = "<absent>" ]'
# The pattern is also valid for the host pgrep: status 0 or 1 means it ran, 2 or
# more means pgrep rejected the expression.
blocked_pattern="$(sed -n "s/^pattern='\(.*\)'$/\1/p" "$WORK/upgrade.sh")"
[ -n "$blocked_pattern" ] || {
    echo "FAIL: the upgrade block has no pgrep pattern" >&2
    exit 2
}
pattern_status=0; pgrep -f "$blocked_pattern" >/dev/null || pattern_status=$?
check "the host pgrep accepts the documented pattern" '[ '"$pattern_status"' -le 1 ]'
h=$(fixture rb-pattern null "$DA")
run "$h" upgrade
printf '%s\n' "$V2" >"$(cfg "$h")/image-pins.json"
box=$(toolbox rb-pattern-box)
stub rb-pattern-box pgrep 'exit 0'
check "rollback: a renamed binary in the block also stops it" '! run "$h" rollback "$box" && said "close every agent-vm" && [ "$(pins "$h")" = "$V2" ]'

echo "# jq failing (status 2) at each of its calls stops the block"
# The patterns are the calls' own argument lists, quoted because a pattern with
# spaces in it is what makes the fault land on the intended call. These are the
# upgrade block's only two reads of its store.
for spec in \
    'version|"-r if .version == 1"*' \
    'pending|"-r if .pending_default == null"*'; do
    name="${spec%%|*}"
    match="${spec#*|}"
    h=$(fixture "jq-$name" null "$DA")
    orig=$(pins "$h")
    box=$(toolbox "jq-$name")
    stub "jq-$name" jq "case \"\$*\" in $match) echo 'injected jq failure' >&2; exit 2;; esac"
    check "jq fails on $name: stops, store live, default kept" '! run "$h" upgrade "$box" && said "injected jq failure" && untouched "$h" "$orig" "$DA" && no_archive "$h"'
done

echo "# rollback: jq failing (status 2) at each of its calls stops the block"
# The rollback makes two reads of the archived store: its version, always, and
# its journal, only when no default was archived. The second is the call that
# decides a pair can be restored, so it needs its own row (AC8).
h=$(fixture rb-jq-version null "$DA")
run "$h" upgrade
printf '%s\n' "$V2" >"$(cfg "$h")/image-pins.json"
box=$(toolbox rb-jq-version)
stub rb-jq-version jq 'case "$*" in "-r if .version == 1"*) echo "injected jq failure" >&2; exit 2;; esac'
check "rollback: jq fails on the version: stops with the v2 store live" '! run "$h" rollback "$box" && said "injected jq failure" && [ "$(pins "$h")" = "$V2" ] && [ "$(dflt "$h")" = "$DA" ]'
h=$(fixture rb-jq-journal "$JOURNAL_PREV" "$DB")
mkdir "$(cfg "$h")/v1-archive"
mv "$(cfg "$h")/image-pins.json" "$(cfg "$h")/v1-archive/image-pins.json"
box=$(toolbox rb-jq-journal)
stub rb-jq-journal jq 'case "$*" in *elif*) echo "injected jq failure" >&2; exit 2;; esac'
check "rollback: jq fails on the archived journal: stops, nothing restored" '! run "$h" rollback "$box" && said "injected jq failure" && [ "$(pins "$h")" = "<absent>" ] && [ "$(dflt "$h")" = "$DB" ]'

# cmp_fail_at BOX N — a cmp that fails (status 2) on its Nth call only. A stub
# that always fails never reaches a later comparison, so "each call" is covered
# by counting.
cmp_fail_at() { # BOX N
    stub "$1" cmp "calls=0
[ -f \"\$CMP_CALLS\" ] && calls=\$(cat \"\$CMP_CALLS\")
calls=\$((calls + 1))
printf '%s' \"\$calls\" >\"\$CMP_CALLS\"
[ \"\$calls\" -eq $2 ] || exec \"\$REAL\" \"\$@\"
echo \"injected cmp failure on call \$calls\" >&2
exit 2"
}
# The state a stopped rollback leaves: v2-archive/ holds the pair it archived.
rollback_rerun() { # rollback_rerun NAME
    h=$(fixture "$1" null "$DB")
    orig="$(pins "$h")"
    run "$h" upgrade
    printf '%s\n' "$V2" >"$(cfg "$h")/image-pins.json"
    printf '%s\n' "$DC" >"$(cfg "$h")/default-image.json"
    mkdir "$(cfg "$h")/v2-archive"
    printf '%s\n' "$V2" >"$(cfg "$h")/v2-archive/image-pins.json"
    printf '%s\n' "$DC" >"$(cfg "$h")/v2-archive/default-image.json"
}

echo "# cmp failing (status 2) at every call site stops the block"
h=$(fixture cmp-fresh null "$DA")
orig=$(pins "$h")
box=$(toolbox cmp-fresh)
stub cmp-fresh cmp 'echo "injected cmp failure" >&2; exit 2'
check "cmp always failing: stops with the v1 store live" '! run "$h" upgrade "$box" && said "could not compare" && untouched "$h" "$orig" "$DA"'
check "cmp always failing: the rerun completes" 'run "$h" upgrade && [ "$(pins "$h")" = "<absent>" ] && [ "$(dflt "$h")" = "$DA" ]'
for site in \
    '1|the archived store on a rerun' \
    '2|the archived default on a rerun' \
    '3|the archive before the store is removed'; do
    call="${site%%|*}"
    name="${site#*|}"
    h=$(fixture "cmp-r$call" null "$DA")
    orig=$(pins "$h")
    run "$h" upgrade
    printf '%s\n' "$orig" >"$(cfg "$h")/image-pins.json"
    box=$(toolbox "cmp-r$call")
    cmp_fail_at "cmp-r$call" "$call"
    check "cmp error at $name: stops, live pair unchanged" '! run "$h" upgrade "$box" && said "could not compare" && [ "$(pins "$h")" = "$orig" ] && [ "$(dflt "$h")" = "$DA" ]'
done

echo "# rollback: cmp failing (status 2) at every call site stops the block"
rollback_rerun cmp-rb1
box=$(toolbox cmp-rb1)
cmp_fail_at cmp-rb1 1
check "rollback: cmp error at the rolled-back check: stops with the v2 store live" '! run "$h" rollback "$box" && said "could not compare" && [ "$(pins "$h")" = "$V2" ] && [ "$(dflt "$h")" = "$DC" ]'
h=$(fixture cmp-rb2 null "$DB")
orig=$(pins "$h")
run "$h" upgrade
printf '%s\n' "$orig" >"$(cfg "$h")/image-pins.json"
printf '%s\n' "$DB" >"$(cfg "$h")/default-image.json"
box=$(toolbox cmp-rb2)
cmp_fail_at cmp-rb2 2
check "rollback: cmp error at the restored-default check: stops, pair unchanged" '! run "$h" rollback "$box" && said "could not compare" && [ "$(pins "$h")" = "$orig" ] && [ "$(dflt "$h")" = "$DB" ]'
rollback_rerun cmp-rb3
box=$(toolbox cmp-rb3)
cmp_fail_at cmp-rb3 2
check "rollback: cmp error at the v2-archive store: stops with the v2 store live" '! run "$h" rollback "$box" && said "could not compare" && [ "$(pins "$h")" = "$V2" ] && [ "$(dflt "$h")" = "$DC" ]'
rollback_rerun cmp-rb4
box=$(toolbox cmp-rb4)
cmp_fail_at cmp-rb4 3
check "rollback: cmp error at the v2-archive default: stops with the v2 store live" '! run "$h" rollback "$box" && said "could not compare" && [ "$(pins "$h")" = "$V2" ] && [ "$(dflt "$h")" = "$DC" ]'
rollback_rerun cmp-rb5
printf '%s\n' "$DB" >"$(cfg "$h")/default-image.json"
box=$(toolbox cmp-rb5)
cmp_fail_at cmp-rb5 4
check "rollback: cmp error at the v1-archive default fallback: stops, default kept" '! run "$h" rollback "$box" && said "could not compare" && [ "$(pins "$h")" = "$V2" ] && [ "$(dflt "$h")" = "$DB" ]'

echo "# failure mid-sequence, then a resumed rerun"
h=$(fixture cp-fail null "$DA")
orig=$(pins "$h")
box=$(toolbox cp-fail)
stub cp-fail cp 'case "$*" in *default-image.json*v1-archive*) echo "injected cp failure" >&2; exit 1;; esac'
check "cp fails while archiving: stops, nothing replaced, no archive" '! run "$h" upgrade "$box" && untouched "$h" "$orig" "$DA" && no_archive "$h"'
check "cp fails while archiving: rerun completes" 'run "$h" upgrade && [ "$(pins "$h")" = "<absent>" ] && [ "$(arch_dflt "$h" v1-archive)" = "$DA" ]'
h=$(fixture mv-fail null "$DA")
orig=$(pins "$h")
box=$(toolbox mv-fail)
stub mv-fail mv 'case "$*" in *v1-archive) echo "injected mv failure" >&2; exit 1;; esac'
check "mv fails installing the archive: stops, store live, no archive" '! run "$h" upgrade "$box" && untouched "$h" "$orig" "$DA" && no_archive "$h"'
check "mv fails installing the archive: rerun completes" 'run "$h" upgrade && [ "$(pins "$h")" = "<absent>" ] && [ "$(arch_pins "$h" v1-archive)" = "$orig" ]'
h=$(fixture rm-fail null "$DA")
orig=$(pins "$h")
box=$(toolbox rm-fail)
stub rm-fail rm 'case "$*" in image-pins.json) echo "injected rm failure" >&2; exit 1;; esac'
check "rm fails after the pair was archived: stops, v1 store live" '! run "$h" upgrade "$box" && [ "$(pins "$h")" = "$orig" ] && [ "$(arch_pins "$h" v1-archive)" = "$orig" ]'
check "the rerun after a failed rm completes" 'run "$h" upgrade && [ "$(pins "$h")" = "<absent>" ] && [ "$(dflt "$h")" = "$DA" ]'

echo "# a rerun validates the whole archived pair"
for kind in changed absent added; do
    if [ "$kind" = added ]; then h=$(fixture "pair-$kind" null absent); else h=$(fixture "pair-$kind" null "$DA"); fi
    orig=$(pins "$h")
    run "$h" upgrade
    printf '%s\n' "$orig" >"$(cfg "$h")/image-pins.json"
    case "$kind" in
        changed)
            printf '%s\n' "$DC" >"$(cfg "$h")/default-image.json"
            want="$DC"
            ;;
        absent)
            rm "$(cfg "$h")/default-image.json"
            want="<absent>"
            ;;
        added)
            printf '%s\n' "$DC" >"$(cfg "$h")/default-image.json"
            want="$DC"
            ;;
    esac
    check "archive present, live default $kind: refused, nothing changed" '! run "$h" upgrade && said "differs from v1-archive" && untouched "$h" "$orig" "$want"'
done
h=$(fixture pair-other null "$DA")
run "$h" upgrade
jq '.pins[0].revision = 2' "$(cfg "$h")/v1-archive/image-pins.json" >"$(cfg "$h")/image-pins.json"
check "archive holds a different store: refused" '! run "$h" upgrade && said "holds a different store"'

echo "# rollback"
h=$(fixture rb null "$DB")
orig=$(pins "$h")
run "$h" upgrade
printf '%s\n' "$V2" >"$(cfg "$h")/image-pins.json"
printf '%s\n' "$DC" >"$(cfg "$h")/default-image.json"
check "after v2 changed the default: rollback succeeds" 'run "$h" rollback'
check "rollback restores the v1 pair byte-identical" '[ "$(pins "$h")" = "$orig" ] && [ "$(dflt "$h")" = "$DB" ]'
check "rollback archives the v2 pair" '[ "$(arch_pins "$h" v2-archive)" = "$V2" ] && [ "$(arch_dflt "$h" v2-archive)" = "$DC" ]'
check "rollback rerun is a no-op" 'run "$h" rollback && said "already rolled back"'
check "re-upgrade after rollback resumes" 'run "$h" upgrade && [ "$(dflt "$h")" = "$DB" ]'
h=$(fixture rb-absent null absent)
run "$h" upgrade
printf '%s\n' "$V2" >"$(cfg "$h")/image-pins.json"
printf '%s\n' "$DC" >"$(cfg "$h")/default-image.json"
check "rollback removes a default v2 created" 'run "$h" rollback && [ "$(dflt "$h")" = "<absent>" ] && [ "$(arch_dflt "$h" v2-archive)" = "$DC" ]'
h=$(fixture rb-mv null "$DB")
orig=$(pins "$h")
run "$h" upgrade
printf '%s\n' "$V2" >"$(cfg "$h")/image-pins.json"
printf '%s\n' "$DC" >"$(cfg "$h")/default-image.json"
box=$(toolbox rb-mv)
stub rb-mv mv 'case "$2" in image-pins.json) echo "injected mv failure" >&2; exit 1;; esac'
check "rollback: mv fails restoring pins: stops with v2 store live" '! run "$h" rollback "$box" && [ "$(pins "$h")" = "$V2" ] && [ "$(dflt "$h")" = "$DB" ]'
check "rollback rerun accepts the restored-default state and completes" 'run "$h" rollback && [ "$(pins "$h")" = "$orig" ] && [ "$(dflt "$h")" = "$DB" ]'
h=$(fixture rb-neither null "$DA")
run "$h" upgrade
printf '%s\n' "$V2" >"$(cfg "$h")/image-pins.json"
printf '%s\n' "$DC" >"$(cfg "$h")/default-image.json"
mkdir "$(cfg "$h")/v2-archive"
printf '%s\n' "$V2" >"$(cfg "$h")/v2-archive/image-pins.json"
printf '%s\n' "$DB" >"$(cfg "$h")/v2-archive/default-image.json"
check "rollback: v2-archive present, default matches neither archive: refused" '! run "$h" rollback && said "matches neither archive" && untouched "$h" "$V2" "$DC"'

echo "# a hand-archived journal store is restorable only with its default"
# The documented manual route. Archived alone, a journal-bearing store restores
# to a pair the old reader refuses ("requires recovery"), and the rollback used
# to remove the live default as it did so: no data lost, wrong state.
h=$(fixture rb-hand-archive-journal "$JOURNAL_PREV" "$DB")
mkdir "$(cfg "$h")/v1-archive"
mv "$(cfg "$h")/image-pins.json" "$(cfg "$h")/v1-archive/image-pins.json"
check "rollback refuses a hand-archived journal store with no default archived" '! run "$h" rollback && said "records an interrupted image set-default and no default was archived" && [ "$(pins "$h")" = "<absent>" ] && [ "$(dflt "$h")" = "$DB" ] && [ ! -e "$(cfg "$h")/v2-archive" ]'
h=$(fixture rb-hand-archive-pair "$JOURNAL_PREV" "$DB")
orig=$(pins "$h")
mkdir "$(cfg "$h")/v1-archive"
mv "$(cfg "$h")/image-pins.json" "$(cfg "$h")/v1-archive/image-pins.json"
mv "$(cfg "$h")/default-image.json" "$(cfg "$h")/v1-archive/default-image.json"
check "rollback restores a hand-archived journal pair byte for byte" 'run "$h" rollback && [ "$(pins "$h")" = "$orig" ] && [ "$(dflt "$h")" = "$DB" ]'
# A journal that names no previous default needs none: the old reader accepts an
# absent default as that side, so the guard must not refuse it.
h=$(fixture rb-hand-archive-noprev "$JOURNAL_NOPREV" absent)
orig=$(pins "$h")
mkdir "$(cfg "$h")/v1-archive"
mv "$(cfg "$h")/image-pins.json" "$(cfg "$h")/v1-archive/image-pins.json"
check "a journal with no previous default is not refused for a missing default" 'run "$h" rollback && [ "$(pins "$h")" = "$orig" ] && [ "$(dflt "$h")" = "<absent>" ]'

h=$(fixture rb-restored-diff null "$DA")
orig=$(pins "$h")
run "$h" upgrade
printf '%s\n' "$orig" >"$(cfg "$h")/image-pins.json"
printf '%s\n' "$DC" >"$(cfg "$h")/default-image.json"
check "rollback: pins restored but default differs: refused" '! run "$h" rollback && said "differs from v1-archive" && untouched "$h" "$orig" "$DC"'
# A rollback that stopped after creating its archive: the live store was already
# absent (there was no v2 store to keep), so `v2-archive/` holds no store.
h=$(fixture rb-empty-v2 null absent)
orig=$(pins "$h")
run "$h" upgrade
mkdir "$(cfg "$h")/v2-archive"
check "rollback resumes when neither the live nor the archived store exists" 'run "$h" rollback && [ "$(pins "$h")" = "$orig" ] && [ "$(dflt "$h")" = "<absent>" ]'
h=$(fixture rb-bad-archive null "$DA")
run "$h" upgrade
printf '%s\n' "$V2" >"$(cfg "$h")/image-pins.json"
printf '%s\n' "$V2" >"$(cfg "$h")/v1-archive/image-pins.json"
check "rollback refuses an archive that is not a version 1 store" '! run "$h" rollback && said "v1-archive/image-pins.json is not a version 1 store" && [ "$(pins "$h")" = "$V2" ]'
h=$(fixture rb-busy null "$DA")
run "$h" upgrade
printf '%s\n' "$V2" >"$(cfg "$h")/image-pins.json"
box=$(toolbox rb-pgrep)
stub rb-pgrep pgrep 'exit 2'
check "rollback: pgrep error refused" '! run "$h" rollback "$box" && said "pgrep failed" && [ "$(pins "$h")" = "$V2" ]'
for t in pgrep jq mktemp; do
    box=$(toolbox "rb-missing-$t" "$t")
    check "rollback: missing $t refused" '! run "$h" rollback "$box" && said "'"$t"' is required" && [ "$(pins "$h")" = "$V2" ]'
done
box=$(toolbox rb-cmp)
stub rb-cmp cmp 'exit 2'
check "rollback: cmp error stops" '! run "$h" rollback "$box" && said "could not compare" && [ "$(pins "$h")" = "$V2" ]'

echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
