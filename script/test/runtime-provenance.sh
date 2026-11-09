#!/usr/bin/env bash
# Contract tests for the deterministic provenance parser.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/agent-vm-runtime-provenance.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

libkrunfw_version=b5ff2425abd98c4d3bf409b057cf9d5852391657

base=(python3 script/check-runtime-provenance.py
    --root-lock Cargo.lock --nested-lock vendor/microsandbox/Cargo.lock
    --root-manifest Cargo.toml --nested-manifest vendor/microsandbox/Cargo.toml
    --constants vendor/microsandbox/crates/utils/lib/lib.rs
    --firmware-dir vendor/microsandbox/vendor/libkrunfw
    --gitlink "$libkrunfw_version"
    --gitlink-mode 160000
    --firmware-head "$libkrunfw_version")

"${base[@]}" >/dev/null
expect_failure() {
    local expected="$1"
    shift
    local output status
    set +e
    output="$("${base[@]}" "$@" 2>&1)"
    status=$?
    set -e
    [[ $status -ne 0 ]] || { echo "expected failure: $expected" >&2; exit 1; }
    [[ "$output" == *"$expected"* ]] || { echo "missing $expected in: $output" >&2; exit 1; }
}

cp Cargo.lock "$tmp/root.lock"
python3 - "$tmp/root.lock" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text(); start = s.index('name = "msb_krun"'); end = s.index('[[package]]', start + 1)
p.write_text(s[:start] + s[start:end].replace('version = "0.1.42"', 'version = "0.1.40"', 1) + s[end:])
PY
expect_failure 'msb_krun is 0.1.40' --root-lock "$tmp/root.lock"

cp Cargo.lock "$tmp/source.lock"
python3 - "$tmp/source.lock" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text(); start = s.index('name = "msb_krun"'); end = s.index('[[package]]', start + 1)
p.write_text(s[:start] + s[start:end].replace('registry+https://github.com/rust-lang/crates.io-index', 'git+https://example.invalid/msb', 1) + s[end:])
PY
expect_failure 'non-registry source' --root-lock "$tmp/source.lock"

# A checksum is pinned to the published release, not merely compared between the
# locks: replacing it must fail on its own, naming the recorded expectation.
cp Cargo.lock "$tmp/checksum.lock"
python3 - "$tmp/checksum.lock" <<'PY'
import pathlib
p = pathlib.Path(__import__('sys').argv[1])
s = p.read_text()
start = s.index('name = "msb_krun"')
end = s.index('[[package]]', start + 1)
part = s[start:end].replace('checksum = "', 'checksum = "different-', 1)
p.write_text(s[:start] + part + s[end:])
PY
expect_failure 'msb_krun 0.1.42 has checksum' --root-lock "$tmp/checksum.lock"

# The three independently published crates resolve to different releases in the
# two locks, so `compare_locks` never compares their checksums to each other —
# the recorded expectation is all that ties them to a published release, on
# either side. Both sides are covered because a version is only pinned by the
# lock that actually resolves it.
for side in root nested; do
    case "$side" in
        root) lock=Cargo.lock; crate=msb_krun_arch_gen; version=0.1.45 ;;
        nested) lock=vendor/microsandbox/Cargo.lock; crate=msb_krun_smbios; version=0.1.42 ;;
    esac
    cp "$lock" "$tmp/$side-split-checksum.lock"
    python3 - "$tmp/$side-split-checksum.lock" "$crate" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text(); start = s.index(f'name = "{sys.argv[2]}"'); end = s.index('[[package]]', start + 1)
p.write_text(s[:start] + s[start:end].replace('checksum = "', 'checksum = "different-', 1) + s[end:])
PY
    expect_failure "$crate $version has checksum" "--$side-lock" "$tmp/$side-split-checksum.lock"
done

cp Cargo.toml "$tmp/patch.toml"
printf '\n[patch.crates-io]\nmsb_krun = "0.1.42"\n' >>"$tmp/patch.toml"
expect_failure 'overrides cohort crate' --root-manifest "$tmp/patch.toml"

# The pins are per lock: the outer workspace is the only root allowed to be
# ahead, and only for the three independently published crates. So each lock must
# drift neither to an unpublished version nor to the other lock's release, which
# a per-crate set of accepted versions would have allowed.
for side in root nested; do
    case "$side" in
        root) lock=Cargo.lock; crate=msb_krun_arch_gen; from=0.1.45; to=0.1.42 ;;
        nested) lock=vendor/microsandbox/Cargo.lock; crate=msb_krun_smbios; from=0.1.42; to=0.1.45 ;;
    esac
    for target in "$to" 0.1.44; do
        cp "$lock" "$tmp/$side-version.lock"
        python3 - "$tmp/$side-version.lock" "$crate" "$from" "$target" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text(); start = s.index(f'name = "{sys.argv[2]}"'); end = s.index('[[package]]', start + 1)
p.write_text(s[:start] + s[start:end].replace(f'version = "{sys.argv[3]}"', f'version = "{sys.argv[4]}"', 1) + s[end:])
PY
        expect_failure "$crate is $target" "--$side-lock" "$tmp/$side-version.lock"
    done
done

# One release in both locks is still one published artifact. The recorded
# checksums catch a differing one before this comparison runs, so what is left
# for it to compare is the source string beyond the registry prefix both locks
# are checked against.
cp Cargo.lock "$tmp/source-suffix.lock"
python3 - "$tmp/source-suffix.lock" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text(); start = s.index('name = "msb_krun_utils"'); end = s.index('[[package]]', start + 1)
p.write_text(s[:start] + s[start:end].replace('crates.io-index', 'crates.io-index#other', 1) + s[end:])
PY
expect_failure 'disagree on msb_krun_utils source/checksum' --root-lock "$tmp/source-suffix.lock"
cp vendor/microsandbox/Cargo.lock "$tmp/nested-checksum.lock"
python3 - "$tmp/nested-checksum.lock" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text(); start = s.index('name = "msb_krun_utils"'); end = s.index('[[package]]', start + 1)
p.write_text(s[:start] + s[start:end].replace('checksum = "', 'checksum = "different-', 1) + s[end:])
PY
expect_failure 'msb_krun_utils 0.1.42 has checksum' --nested-lock "$tmp/nested-checksum.lock"
expect_failure 'firmware gitlink mode is' --gitlink-mode 100644
expect_failure 'expected gitlink deadbeef' --gitlink deadbeef
expect_failure 'recursive submodule is not initialized' --firmware-head ''
expect_failure 'source is dirty' --firmware-dirty

cp vendor/microsandbox/crates/utils/lib/lib.rs "$tmp/constants.rs"
sed -i.bak 's/LIBKRUNFW_ABI: &str = "5"/LIBKRUNFW_ABI: \&str = "9"/' "$tmp/constants.rs"
expect_failure 'ABI constant is not 5' --constants "$tmp/constants.rs"

echo "runtime provenance contract tests passed"
