#!/usr/bin/env bash
set -euo pipefail
file=./dotfiles/agent-vm.toml
before=$(wc -c < "$file")
printf '[network]\nallow_host = true\n' >> "$file"
expected=$(printf '[network]\nallow_host = true\n' | od -An -tx1 -v)
actual=$(tail -c +"$((before + 1))" "$file" | od -An -tx1 -v)
[[ "$actual" == "$expected" ]]
echo PN4_WRITE_OK
