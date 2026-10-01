# GitHub Copilot CLI tool layer. See docs/adr/0003-project-tooling-layers.md
# for the layer image contract this file satisfies, and images/Dockerfile for
# the facilities this layer inherits from the base (Node.js 22, npm, jq).
ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-base:latest
FROM ${BASE_IMAGE}

# Re-declared inside the stage: a global ARG is not visible to RUN.
#
# The default is the exact committed version (see images/tools/README.md,
# "Exact versions"). An ordinary or release build installs exactly this and
# never resolves the npm `latest` dist-tag: the Dockerfile default is the only
# value an ordinary build supplies, and script/build/agent-versions.sh --write is
# the reviewed developer tool that bumps it. A launcher override passes the same
# argument name, so a shipped or overridden build is still exact.
ARG AGENT_VERSION_COPILOT=1.0.90
ARG AGENT_INSTALL_SOFT_FAIL=

# Selection, not health: this records the version the layer was asked to
# install. Whether the command is actually usable is the T5 audit's decision.
LABEL org.agent-vm.version.copilot="${AGENT_VERSION_COPILOT}"

# Copilot installs into the global npm prefix, already on the base's PATH, so
# this layer needs no additive `ENV PATH`.
#
# The spec is quoted and exact: `@github/copilot@1.0.90`, never `@latest` and
# never a range. install-copilot.sh validates the supplied slot as canonical
# semver before any network call. An npm install failure is hard -- a partial
# global tree is a broken agent, not a missing one -- so there is no
# AGENT_INSTALL_SOFT_FAIL branch here.
RUN --mount=type=bind,source=install-copilot.sh,target=/tmp/install-copilot.sh,ro \
    AGENT_VM_VERSION_COPILOT="${AGENT_VERSION_COPILOT}" \
    sh /tmp/install-copilot.sh

# Build-time gate. Bind-mounted, not COPYed, so it stays out of the image and
# needs no execute bit; the shared contract helpers it calls are bind-mounted
# too. See verify-copilot.sh for the checks and their rationale.
RUN --mount=type=bind,source=contract,target=/tmp/recipe-contract,ro \
    --mount=type=bind,source=verify-copilot.sh,target=/tmp/verify-copilot.sh,ro \
    AGENT_VM_VERSION_COPILOT="${AGENT_VERSION_COPILOT}" \
    AGENT_VM_INSTALL_STATUS_DIR=/opt/agent-vm/install-status \
    sh /tmp/verify-copilot.sh
