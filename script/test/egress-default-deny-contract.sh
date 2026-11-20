#!/usr/bin/env bash
# Boot-free §6.7 join. Host-only controls are not native VM/egress evidence.
set -euo pipefail
REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
harness="${HARNESS_BIN_DIR:-$REPO_ROOT/target/debug}/harness"
if [[ ! -x "$harness" ]]; then
    printf 'egress-default-deny-contract: harness not found at %s; run: cargo build --locked -p agent-vm-harness --bins\n' \
        "$harness" >&2
    exit 2
fi

# An unrelated cwd must still reach every owning command: the fixture cluster,
# the resolver calibration, the ingress driver, the exec shim and the owned
# launch are all this binary's subcommands now, not a copied Python supervisor.
scratch=$(mktemp -d "${TMPDIR:-/tmp}/egress-outside.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
(cd "$scratch" && "$harness" egress-fixtures self-test)

# The independent §10.2 inventory: deriving it from the case table would allow a
# deleted case to disappear from both the builder and its expected output.
"$harness" egress-default-deny --plan-inventory --repo-root "$REPO_ROOT"

# Primitive status/wire controls and dispatcher expectations are complementary:
# neither mocks of dispatcher routes nor owned-supervisor fakes prove framing.
"$harness" egress-probe --self-test --repo-root "$REPO_ROOT"

# #694's supervisor controls still run their own Python. Everything above is a
# harness subcommand.
python3 "$REPO_ROOT/script/test/lib/egress-supervisor-contract.py"

# Run the actual guard, then remove each required membership independently.
# Mutated copies live only in owned scratch; the working tree is never edited.
bash "$REPO_ROOT/script/test/ci-contracts.sh" --guard-only
"$harness" egress-default-deny --guard-mutations --repo-root "$REPO_ROOT"

echo 'host-only egress default-deny contract passed (six §6.7 items; no VM run)'
