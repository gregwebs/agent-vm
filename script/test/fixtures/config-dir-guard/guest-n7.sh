#!/usr/bin/env bash
# N7: plant the credentials authority a case-variant spelling would expose.
# GUEST_HOME overrides $HOME for the boot-free host control.
set -eu
home="${GUEST_HOME:-$HOME}"
mkdir -p "$home/.config/agent-vm"
printf 'credentials: []\n' >"$home/.config/agent-vm/credentials.yaml"
echo GUEST_EXECUTED
