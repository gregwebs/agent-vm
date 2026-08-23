ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-template:latest
FROM ${BASE_IMAGE}

RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium fonts-liberation sudo libnss3-tools \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf /usr/bin/chromium /usr/bin/google-chrome \
 && ln -sf /usr/bin/chromium /usr/bin/google-chrome-stable \
 && mkdir -p /opt/google/chrome \
 && ln -sf /usr/bin/chromium /opt/google/chrome/chrome \
 && if getent group chrome >/dev/null; then \
      test "$(getent group chrome | cut -d: -f3)" = 9999; \
    elif getent group 9999 >/dev/null; then \
      echo 'chrome group ID 9999 is already assigned' >&2; exit 1; \
    else \
      echo 'chrome:x:9999:' >> /etc/group; \
    fi \
 && test "$(getent group 9999 | cut -d: -f1)" = chrome \
 && if getent passwd chrome >/dev/null; then \
      test "$(getent passwd chrome | cut -d: -f3,4,6,7)" = '9999:9999:/home/chrome:/bin/bash'; \
    elif getent passwd 9999 >/dev/null; then \
      echo 'chrome user ID 9999 is already assigned' >&2; exit 1; \
    else \
      echo 'chrome:x:9999:9999:Chrome MCP:/home/chrome:/bin/bash' >> /etc/passwd; \
      echo 'chrome:!:19000:0:99999:7:::' >> /etc/shadow; \
    fi \
 && test "$(getent passwd 9999 | cut -d: -f1)" = chrome \
 && grep -q '^chrome:!:' /etc/shadow \
 && mkdir -p /home/chrome/.pki/nssdb \
 && if ! test -f /home/chrome/.pki/nssdb/cert9.db; then certutil -d sql:/home/chrome/.pki/nssdb -N --empty-password; fi \
 && chown -R 9999:9999 /home/chrome \
 && echo 'root ALL=(chrome) NOPASSWD: ALL' > /etc/sudoers.d/agent-vm-chrome \
 && chmod 0440 /etc/sudoers.d/agent-vm-chrome

COPY --chmod=0755 agent-vm-chrome-mcp /usr/local/bin/agent-vm-chrome-mcp
RUN sudo -u chrome -H npx -y chrome-devtools-mcp@1.0.1 --help >/dev/null 2>&1 \
 || echo '==> pre-warm skipped (will lazy-fetch chrome-devtools-mcp at first MCP call)'
RUN chromium --version \
 && test "$(readlink -f /usr/bin/google-chrome)" = /usr/bin/chromium \
 && test "$(readlink -f /usr/bin/google-chrome-stable)" = /usr/bin/chromium \
 && test "$(readlink -f /opt/google/chrome/chrome)" = /usr/bin/chromium \
 && command -v certutil \
 && test "$(getent passwd chrome | cut -d: -f3,4,6,7)" = '9999:9999:/home/chrome:/bin/bash' \
 && test "$(getent group chrome | cut -d: -f3)" = 9999 \
 && grep -q '^chrome:!:' /etc/shadow \
 && test "$(stat -c '%u:%g:%a' /home/chrome)" = 9999:9999:755 \
 && test "$(stat -c '%u:%g' /home/chrome/.pki/nssdb)" = 9999:9999 \
 && visudo -cf /etc/sudoers.d/agent-vm-chrome \
 && sudo -n -u chrome -- id -u | grep -qx 9999 \
 && sudo -u chrome -H -- test -w /home/chrome/.pki/nssdb \
 && test -x /usr/local/bin/agent-vm-chrome-mcp \
 && mkdir -p /etc/agent-vm-capabilities \
 && : > /etc/agent-vm-capabilities/chrome-devtools-mcp
