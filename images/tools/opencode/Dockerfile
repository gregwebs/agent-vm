# OpenCode CLI tool layer. See docs/adr/0003-project-tooling-layers.md for the
# layer image contract this file satisfies, and images/Dockerfile for the
# facilities this layer inherits from the base (curl, tar, coreutils timeout).
ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-base:latest
FROM ${BASE_IMAGE}

# Re-declared inside the stage: a global ARG is not visible to RUN.
#
# The default is the exact committed version (see images/tools/README.md,
# "Exact versions"). Ordinary and release builds install exactly this and never
# resolve a `latest` release; script/build/agent-versions.sh --write is the
# reviewed developer tool that bumps it.
ARG AGENT_VERSION_OPENCODE=v1.18.34
ARG AGENT_INSTALL_SOFT_FAIL=

# Selection, not health: this records the version the layer was asked to
# install. Whether the command is usable is the T5 audit's decision.
LABEL org.agent-vm.version.opencode="${AGENT_VERSION_OPENCODE}"

# Additive, per C2. `${PATH}` expands to the predecessor's value at build
# time, so this layer can never remove a directory the base put there.
ENV PATH=/opt/agent/.opencode/bin:${PATH}

# install-opencode.sh validates the exact `v` slot, then runs OpenCode's pinned
# vendored installer (images/tools/opencode/vendor/) through the shared
# run-install.sh envelope. It installs into $HOME/.opencode/bin and publishes a
# /usr/local/bin link, so non-login shells find it. Only a positively classified
# transport failure with a fresh receipt may degrade, and then only when
# AGENT_INSTALL_SOFT_FAIL is non-empty; anything else is hard. Bind-mounted,
# never COPYed.
RUN --mount=type=bind,source=contract,target=/tmp/recipe-contract,ro \
    --mount=type=bind,source=install-opencode.sh,target=/tmp/install-opencode.sh,ro \
    --mount=type=bind,source=vendor,target=/opt/agent-vm/recipe-vendor,ro \
    AGENT_VM_CONTRACT_DIR=/tmp/recipe-contract \
    AGENT_VM_VENDOR_DIR=/opt/agent-vm/recipe-vendor \
    AGENT_VM_VERSION_OPENCODE="${AGENT_VERSION_OPENCODE}" \
    AGENT_VM_INSTALL_STATUS_DIR=/opt/agent-vm/install-status \
    sh /tmp/recipe-contract/run-install.sh opencode /opt/agent-vm/install-status/opencode sh /tmp/install-opencode.sh

# Build-time gate. Bind-mounted, not COPYed. A hard install failure already
# aborted the build; a softened transport failure left an absence record and no
# command. The gate accepts that degraded state only when the record is present,
# and otherwise requires a bounded, status-checked `opencode --version` report to
# match the pin before auditing T5. See verify-opencode.sh.
RUN --mount=type=bind,source=contract,target=/tmp/recipe-contract,ro \
    --mount=type=bind,source=verify-opencode.sh,target=/tmp/verify-opencode.sh,ro \
    AGENT_VM_CONTRACT_DIR=/tmp/recipe-contract \
    AGENT_VM_VERSION_OPENCODE="${AGENT_VERSION_OPENCODE}" \
    AGENT_VM_INSTALL_STATUS_DIR=/opt/agent-vm/install-status \
    sh /tmp/verify-opencode.sh
