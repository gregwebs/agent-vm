#!/usr/bin/env bash
# Contract tests for the deterministic provenance parser.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/agent-vm-runtime-provenance.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

libkrunfw_version=1efc0dfd24f0f7cb4829735d3e5b97d298823afd

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
p.write_text(s[:start] + s[start:end].replace('version = "0.1.32"', 'version = "0.1.31"', 1) + s[end:])
PY
expect_failure 'msb_krun is 0.1.31' --root-lock "$tmp/root.lock"

cp Cargo.lock "$tmp/source.lock"
python3 - "$tmp/source.lock" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text(); start = s.index('name = "msb_krun"'); end = s.index('[[package]]', start + 1)
p.write_text(s[:start] + s[start:end].replace('registry+https://github.com/rust-lang/crates.io-index', 'git+https://example.invalid/msb', 1) + s[end:])
PY
expect_failure 'non-registry source' --root-lock "$tmp/source.lock"

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
expect_failure 'locks disagree' --root-lock "$tmp/checksum.lock"

cp Cargo.toml "$tmp/patch.toml"
printf '\n[patch.crates-io]\nmsb_krun = "0.1.32"\n' >>"$tmp/patch.toml"
expect_failure 'overrides cohort crate' --root-manifest "$tmp/patch.toml"
expect_failure 'firmware gitlink mode is' --gitlink-mode 100644
expect_failure 'firmware gitlink is' --gitlink deadbeef
expect_failure 'recursive submodule is not initialized' --firmware-head ''
expect_failure 'source is dirty' --firmware-dirty

cp vendor/microsandbox/crates/utils/lib/lib.rs "$tmp/constants.rs"
sed -i.bak 's/LIBKRUNFW_ABI: &str = "5"/LIBKRUNFW_ABI: \&str = "9"/' "$tmp/constants.rs"
expect_failure 'ABI constant is not 5' --constants "$tmp/constants.rs"

echo "runtime provenance contract tests passed"
