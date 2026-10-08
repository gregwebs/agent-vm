#!/usr/bin/env bash
# Negative controls for no-image-source-dependency.sh (#265). Proves the guard
# fails on a real dependency and still passes for the references that are
# deliberately out of scope (tests, docs, contributor scripts).
set -euo pipefail

ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/av-imgdep.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

guard="$ROOT/script/test/no-image-source-dependency.sh"

# The real checkout must pass: this is the guard's actual subject.
bash "$guard"

# A miniature checkout with one compiled source, one build script, one shipped
# npm file, plus the out-of-scope locations the guard must ignore.
mkdir -p "$WORK/crates/agent-vm/src" "$WORK/crates/agent-vm/tests" \
    "$WORK/npm-dist/agent-vm/bin" "$WORK/script" "$WORK/docs"
printf 'pub fn launch() {}\n' > "$WORK/crates/agent-vm/src/lib.rs"
printf 'fn main() {}\n' > "$WORK/crates/agent-vm/build.rs"
printf '#!/usr/bin/env node\nconsole.log("launch");\n' > "$WORK/npm-dist/agent-vm/bin/agent-vm.js"
printf '{"name":"agent-vm","files":["bin/agent-vm.js"]}\n' > "$WORK/npm-dist/agent-vm/package.json"

reject() {
    if bash "$guard" "$WORK" >"$WORK/result" 2>&1; then
        echo "FAIL: guard accepted $1" >&2
        exit 1
    fi
    grep -Fq 'references image sources' "$WORK/result" || {
        cat "$WORK/result" >&2
        exit 1
    }
}

pass() {
    bash "$guard" "$WORK" >"$WORK/result" 2>&1 || {
        cat "$WORK/result" >&2
        echo "FAIL: guard rejected $1" >&2
        exit 1
    }
}

pass 'a clean miniature checkout'

printf 'pub const SOURCES: &str = "vendor/agent-vm-images/images/Dockerfile";\n' \
    >> "$WORK/crates/agent-vm/src/lib.rs"
reject 'a compiled source naming the image-source submodule'
printf 'pub fn launch() {}\n' > "$WORK/crates/agent-vm/src/lib.rs"

printf 'fn main() { println!("{}", "images/build.sh"); }\n' >> "$WORK/crates/agent-vm/build.rs"
reject 'a build script naming a retired recipe path'
printf 'fn main() {}\n' > "$WORK/crates/agent-vm/build.rs"

printf '{"image":"images/recipe-contract/run-install.sh"}\n' > "$WORK/npm-dist/agent-vm/config.json"
reject 'a shipped package file naming a retired recipe path'
rm "$WORK/npm-dist/agent-vm/config.json"

# A contributor script may read the pinned sources, a test may name them, and a
# doc may describe them: none of those is a runtime dependency.
printf 'cat vendor/agent-vm-images/images/standard/version\n' > "$WORK/script/pin.sh"
printf '# sources live in vendor/agent-vm-images\n' > "$WORK/README.md"
printf 'const PATH: &str = "images/Dockerfile";\n' > "$WORK/crates/agent-vm/tests/contract.rs"
pass 'test, doc and contributor-script references out of scope'

echo 'no-image-source-dependency negative controls passed'
