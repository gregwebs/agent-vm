# Fixture images for the #258 marker-free custom-image e2e group.
#
# Base pinned by immutable multiarch index digest:
#   alpine:3.22 -> sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
#   (docker buildx imagetools inspect alpine:3.22, resolved 2026-10)
# Built native linux/arm64 on the Apple Silicon e2e host. Only the explicit
# `stamp-present` target below carries a /etc/agent-vm-image-version stamp;
# every other target is marker-free.
ARG ALPINE=alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8

# A compatible rootfs with no Bash anywhere on PATH: the negative image.
FROM ${ALPINE} AS no-bash
COPY --chmod=0755 hello-258 /usr/local/bin/hello-258
RUN ! command -v bash

# The positive minimal contract image: Alpine + Bash + one program, no stamp.
FROM ${ALPINE} AS marker-free
RUN apk add --no-cache bash
COPY --chmod=0755 hello-258 /usr/local/bin/hello-258
# A file on PATH that is deliberately NOT executable, so the setup verification
# diagnostic's "present but not executable" case is covered with real guest
# evidence (mode fixed here, not by the source file's mode).
COPY --chmod=0644 noexec-258 /usr/local/bin/noexec-258

# The same minimal base with a present, NON-numeric `/etc/agent-vm-image-version`.
# A stamp that is not a version must be ignored (the boot/image contract has no
# compatibility read), so the image still boots and runs its program. The literal
# body is asserted by the e2e check, which must keep it in sync with
# `CUSTOM_STAMP_LITERAL` in script/test/e2e.sh.
FROM marker-free AS stamp-present
RUN printf 'garbage-not-a-version-258' > /etc/agent-vm-image-version

# Supplies the wrapper without the capability marker: capability evidence is the
# artifact itself, not image identity.
FROM marker-free AS wrapper-provided
RUN apk add --no-cache jq
COPY --chmod=0755 chrome-wrapper-stub /usr/local/bin/agent-vm-chrome-mcp
COPY --chmod=0755 verify-mcp-258 /usr/local/bin/verify-mcp-258

# Advertises the capability explicitly and supplies an executable seed.d hook.
FROM wrapper-provided AS with-integrations
RUN mkdir -p /etc/agent-vm-capabilities && : > /etc/agent-vm-capabilities/chrome-devtools-mcp
COPY --chmod=0755 seed-258 /opt/agent-vm/seed.d/50-e2e-258

# Supplies only the named seed entry point (no seed.d), so success cannot be
# masked by the other clause.
FROM marker-free AS script-provided
COPY --chmod=0755 seed-258 /opt/agent-vm/seed-claude-plugins.sh

# A real app account with an OCI `USER`/`ENV HOME`: the launcher identity
# override must win in both modes.
FROM marker-free AS user-home-set
RUN addgroup -g 1234 app && adduser -D -u 1234 -G app app
ENV HOME=/home/app
USER app

# Bash and the program exist only under a nonstandard OCI PATH prefix.
FROM marker-free AS nonstandard-path
RUN mkdir -p /opt/e2e-258/bin && mv /bin/bash /opt/e2e-258/bin/bash \
    && mv /usr/local/bin/hello-258 /opt/e2e-258/bin/hello-258 \
    && test ! -e /bin/bash && test ! -e /usr/bin/bash
ENV PATH=/opt/e2e-258/bin:/usr/bin:/bin
