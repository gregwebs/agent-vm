#!/bin/sh
# PROTOTYPE: open a new host terminal showing one session's blocks.
# Navigation only; nothing here approves anything.
# Pick the terminal with: echo ghostty > /tmp/PROTOTYPE-agent-vm-blocks/terminal
set -eu
here=$(cd "$(dirname "$0")" && pwd)
dir=/tmp/PROTOTYPE-agent-vm-blocks
session=${1:-}
case $session in "" | *[!A-Za-z0-9._-]*) echo "refusing session id: $session" >&2; exit 2 ;; esac
term=$(cat "$dir/terminal" 2>/dev/null || echo terminal)
cmd="/usr/bin/env python3 -I '$here/blocks.py' '$session'; exec \"\${SHELL:-/bin/zsh}\" -l"
echo "$(date +%T) open-terminal $term $session" >> "$dir/notifier.log"
case $term in
  terminal)   # a .command file runs in Terminal.app without Apple-events permission
    f=$dir/show-$session.command
    printf '#!/bin/sh\n%s\n' "$cmd" > "$f"; chmod +x "$f"
    open -a Terminal "$f" ;;
  ghostty)    open -na Ghostty --args -e /bin/sh -c "$cmd" ;;
  wezterm)    open -na WezTerm --args start --always-new-process -- /bin/sh -c "$cmd" ;;
  alacritty)  open -na Alacritty --args -e /bin/sh -c "$cmd" ;;
  linux)      # untested: proposed standard first, then Debian's alternative, then GNOME
    if command -v xdg-terminal-exec >/dev/null; then xdg-terminal-exec /bin/sh -c "$cmd" &
    elif command -v x-terminal-emulator >/dev/null; then x-terminal-emulator -e /bin/sh -c "$cmd" &
    else gnome-terminal -- /bin/sh -c "$cmd" &
    fi ;;
  *) echo "unknown terminal: $term" >&2; exit 2 ;;
esac
