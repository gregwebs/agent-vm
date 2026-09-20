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

# Build-time gates. Bind-mounted (not COPYed), exactly like install-pi.sh
# above: the script stays out of the shipped image and needs no execute bit, so
# the 0644-materialisation rule the wrapper's `COPY --chmod=0755` works around
# does not apply to it. See verify-pi.sh for the checks and their rationale.
#
# Reached in BOTH outcomes of install-pi.sh: a hard failure already aborted the
# build, and a soft failure exited 0 having deleted /opt/agent-vm/pi entirely --
# so the gate's `! -x` branch is what turns a soft-failed install into "this
# image ships no pi", wrapper included.
RUN --mount=type=bind,source=verify-pi.sh,target=/tmp/verify-pi.sh,ro \
    sh /tmp/verify-pi.sh
