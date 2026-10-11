#!/usr/bin/env bash
# N1a: hard-link laundering (L1), append-through-link-then-unlink. This runs in
# the guest only; the host refuses before boot, so GUEST_EXECUTED must never
# appear. AUX_DIR overrides /aux so config-dir-guard-contract.sh can prove on
# the host that this snippet really does mutate the original through the link
# and then remove the second name.
set -eu
aux="${AUX_DIR:-/aux}"
printf '\n# planted\n' >>"$aux/cfg.toml"
rm "$aux/cfg.toml"
echo GUEST_EXECUTED
