# Pi coding agent tool layer. See docs/adr/0003-project-tooling-layers.md for
# the layer image contract this file satisfies,
# docs/adr/0012-stable-pi-image-customization-seam.md for why the wrapper is
# separate from the installation, and images/Dockerfile for the facilities this
# layer inherits from the base (Node.js 22, jq, the host-CA shim).
#
# Unlike the other tool layers this one runs NO upstream installer and resolves
# NO version: the pin is the committed package.json + package-lock.json beside
# this file, and `npm ci` installs exactly that tree.
ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-base:latest
FROM ${BASE_IMAGE}

# Re-declared inside the stage: a global ARG is not visible to RUN.
ARG AGENT_INSTALL_SOFT_FAIL=

# No `ENV PATH`: the wrapper lands in /usr/local/bin, already first on the
# base's PATH (C2 is satisfied by adding nothing).

# The immutable installation. Copied first and installed in its own RUN so this
# ~150 MiB layer is invalidated only by a pin bump, not by an edit to the
# wrapper or the extension below.
#
# The install is a bind-mounted script, not an inline `npm ci`, for the same
# reason images/Dockerfile bind-mounts install-zellij.sh: the soft-fail decision
# and the integrity check have to sit AT the failure, inside the process that
# can see it. An inline `npm ci && …` aborts the build on a nonzero exit, which
# makes any later soft-fail branch unreachable. Bind-mounting (rather than
# COPYing) also keeps the script out of the shipped image and needs no execute
# bit, so the 0644-materialisation rule below does not apply to it.
COPY package.json package-lock.json /opt/agent-vm/pi/
RUN --mount=type=bind,source=install-pi.sh,target=/tmp/install-pi.sh,ro \
    sh /tmp/install-pi.sh

# Image-owned extensions. The directory is the seam: a later customization layer
# may add files here, and the wrapper keeps loading the mandatory one.
COPY extensions/guest-credential-warning.js /opt/agent-vm/pi-extensions/
RUN chmod -R a+rX /opt/agent-vm/pi-extensions

# The execute bit comes from `--chmod=0755`, NOT a `RUN chmod`: the embedded
# copy of images/tools/ in the agent-vm binary materialises every file mode 0644
# (src/tool_layer.rs), so a RUN chmod would make a locally composed layer hash
# differently from one built from a git checkout of the same bytes. Same reason
# as images/tools/claude/Dockerfile's seed hook.
COPY --chmod=0755 pi.sh /usr/local/bin/pi

# Build-time gates, reached in BOTH outcomes of install-pi.sh: a hard failure
# already aborted the build, and a soft failure exited 0 having deleted
# /opt/agent-vm/pi entirely -- so the `! -x` branch below is what turns a
# soft-failed install into "this image ships no pi", wrapper included.
#
# NOTE: no `#` comments inside the RUN body -- the Dockerfile parser strips the
# backslash-newlines first, so a comment would swallow the rest of the command.
#
# `timeout` bounds every Pi invocation so a future version that decides to
# prompt cannot hang the build. HOME/XDG point at a scratch dir and
# PI_TELEMETRY=0 keeps the gate hermetic: --version and --help must not read or
# write a config, and must not be the thing that creates /root/.pi in the image.
RUN set -eu; \
    if [ ! -x /opt/agent-vm/pi/node_modules/.bin/pi ]; then \
        if [ -n "${AGENT_INSTALL_SOFT_FAIL:-}" ]; then \
            echo "  pi: MISSING (soft-fail mode); removing the wrapper so nothing claims to be pi"; \
            rm -f /usr/local/bin/pi; rm -rf /opt/agent-vm/pi /opt/agent-vm/pi-extensions; exit 0; \
        fi; \
        echo "  pi: MISSING -- hard sanity failure" >&2; exit 1; \
    fi; \
    export HOME=/tmp/pi-gate XDG_CONFIG_HOME=/tmp/pi-gate/.config PI_TELEMETRY=0; \
    mkdir -p /tmp/pi-gate; \
    want=$(jq -r '.dependencies["@earendil-works/pi-coding-agent"]' /opt/agent-vm/pi/package.json); \
    got=$(timeout 60 /usr/local/bin/pi --version); \
    if [ "$got" != "$want" ]; then \
        echo "  pi: /usr/local/bin/pi --version reported '$got', lockfile pins '$want'" >&2; exit 1; \
    fi; \
    echo "  pi: $got (pinned)"; \
    helped=$(timeout 60 /usr/local/bin/pi --help | sed -n 's/^  pi \([a-z][a-z-]*\) .*/\1/p' | sort -u | tr '\n' ' '); \
    declared=$(sed -n 's/^PI_SUBCOMMANDS="\(.*\)"$/\1/p' /usr/local/bin/pi | tr ' ' '\n' | sort -u | tr '\n' ' '); \
    if [ "$helped" != "$declared" ]; then \
        echo "  pi: wrapper subcommands [$declared] != pi --help [$helped]" >&2; exit 1; \
    fi; \
    echo "  pi: subcommand allowlist matches pi --help"; \
    rm -rf /tmp/pi-gate; \
    if [ -n "$(find /opt/agent-vm/pi /opt/agent-vm/pi-extensions ! -perm -o+r -print -quit)" ]; then \
        echo "  pi: something under /opt/agent-vm is not world-readable (C7)" >&2; exit 1; \
    fi; \
    if [ -n "$(find /opt/agent-vm/pi /opt/agent-vm/pi-extensions -type d ! -perm -o+x -print -quit)" ]; then \
        echo "  pi: a directory under /opt/agent-vm is not world-searchable (C7)" >&2; exit 1; \
    fi; \
    for executable in /usr/local/bin/pi /opt/agent-vm/pi/node_modules/.bin/pi; do \
        [ -r "$executable" ] && [ -x "$executable" ] || { \
            echo "  pi: $executable is not a+rx (C7)" >&2; exit 1; }; \
    done; \
    echo "  pi: readable and executable by any uid"
