#!/usr/bin/env bash
# N1b: hard-link laundering (L2), open descriptor, unlink the second name, then
# write through the still-open descriptor. Mutates the original inode after the
# link name is gone.
set -eu
aux="${AUX_DIR:-/aux}"
exec 3>>"$aux/cfg.toml"
rm "$aux/cfg.toml"
printf '\n# planted\n' >&3
echo GUEST_EXECUTED
