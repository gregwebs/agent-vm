#!/bin/bash
set -euo pipefail

[ "$#" = 3 ] || { echo "usage: $0 BASE_IMAGE LAYER_IMAGE API1_LAYER_IMAGE" >&2; exit 2; }
base=$1
layer=$2
api1_layer=$3

# The API-2 base must not retain a partial browser integration.
docker run --rm --security-opt seccomp=unconfined "$base" sh -ec '
    ! command -v chromium
    ! test -e /usr/bin/google-chrome
    ! getent passwd chrome
    ! test -e /home/chrome
    ! test -e /etc/sudoers.d/agent-vm-chrome
    ! test -e /usr/local/bin/agent-vm-chrome-mcp
    ! test -e /etc/agent-vm-capabilities/chrome-devtools-mcp
    test "$(cat /etc/agent-vm-image-version)" = 2
'

# The derived image advertises only after all security-sensitive artifacts work.
docker run --rm --security-opt seccomp=unconfined "$layer" sh -ec '
    chromium --version
    test "$(readlink -f /usr/bin/google-chrome)" = /usr/bin/chromium
    test "$(readlink -f /usr/bin/google-chrome-stable)" = /usr/bin/chromium
    test "$(readlink -f /opt/google/chrome/chrome)" = /usr/bin/chromium
    test "$(getent passwd chrome | cut -d: -f3,4,6,7)" = 9999:9999:/home/chrome:/bin/bash
    test "$(getent group chrome | cut -d: -f3)" = 9999
    grep -q "^chrome:!:" /etc/shadow
    test "$(stat -c "%u:%g:%a" /home/chrome)" = 9999:9999:755
    visudo -cf /etc/sudoers.d/agent-vm-chrome
    sudo -n -u chrome -- id -u | grep -qx 9999
    ! sudo -n -u chrome -- sudo -n id -u
    test -x /usr/local/bin/agent-vm-chrome-mcp
    sudo -u chrome -H -- test -w /home/chrome/.pki/nssdb
    test -e /etc/agent-vm-capabilities/chrome-devtools-mcp
'

# Root switches to chrome without forwarding identity/home; arbitrary guests do not gain sudo.
docker run --rm --security-opt seccomp=unconfined -e HOME=/root -e USER=root -e LOGNAME=root "$layer" \
    /usr/local/bin/agent-vm-chrome-mcp sh -ec 'test "$(id -u)" = 9999; test "$HOME" = /home/chrome; test "$USER" = chrome; test "$LOGNAME" = chrome'
docker run --rm --security-opt seccomp=unconfined --user 12345:12345 -e HOME=/tmp "$layer" \
    /usr/local/bin/agent-vm-chrome-mcp sh -ec 'test "$(id -u)" = 12345; test "$HOME" = /tmp; ! sudo -n -u root -- id -u'
# This is deliberately a non-root browser smoke test: no insecure Chromium flags are needed.
docker run --rm --security-opt seccomp=unconfined --user 12345:12345 -e HOME=/tmp "$layer" sh -ec \
    'timeout 30s /usr/local/bin/agent-vm-chrome-mcp chromium --headless --disable-gpu --dump-dom about:blank | grep -q "<html"'

# Composing on the retained API-1 image must reuse, not duplicate, its records.
docker run --rm --security-opt seccomp=unconfined "$api1_layer" sh -ec '
    test "$(getent passwd chrome | wc -l)" = 1
    test "$(getent group chrome | wc -l)" = 1
'
echo 'chrome layer runtime contract: OK'
