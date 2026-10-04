# Codex CLI recipe. See images/tools/README.md for the recipe conventions this
# file follows, and images/Dockerfile for the facilities this recipe inherits
# from the base (curl, jq, coreutils timeout).
ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-base:latest
FROM ${BASE_IMAGE}

# Re-declared inside the stage: a global ARG is not visible to RUN.
#
# The default is the exact committed version (see images/tools/README.md,
# "Exact versions"). Ordinary and release builds install exactly this and never
# resolve the GitHub `latest` release; script/build/agent-versions.sh --write is
# the reviewed developer tool that bumps it.
ARG AGENT_VERSION_CODEX=rust-v0.159.3
ARG AGENT_INSTALL_SOFT_FAIL=

# Selection, not health: this records the version the layer was asked to
# install. Whether the command is usable is the T5 audit's decision.
LABEL org.agent-vm.version.codex="${AGENT_VERSION_CODEX}"

# Additive, per C2. `${PATH}` expands to the predecessor's value at build
# time, so this layer can never remove a directory the base put there.
ENV PATH=/opt/agent/.local/bin:${PATH}

# install-codex.sh validates the exact `rust-v` slot, then runs OpenAI's pinned
# vendored installer (images/tools/codex/vendor/) through the shared
# run-install.sh envelope. Only a positively classified transport failure with a
# fresh receipt may degrade, and then only when AGENT_INSTALL_SOFT_FAIL is
# non-empty; anything else is hard. Bind-mounted, never COPYed.
RUN --mount=type=bind,source=contract,target=/tmp/recipe-contract,ro \
    --mount=type=bind,source=install-codex.sh,target=/tmp/install-codex.sh,ro \
    --mount=type=bind,source=vendor,target=/opt/agent-vm/recipe-vendor,ro \
    AGENT_VM_CONTRACT_DIR=/tmp/recipe-contract \
    AGENT_VM_VENDOR_DIR=/opt/agent-vm/recipe-vendor \
    AGENT_VM_VERSION_CODEX="${AGENT_VERSION_CODEX}" \
    AGENT_VM_INSTALL_STATUS_DIR=/opt/agent-vm/install-status \
    sh /tmp/recipe-contract/run-install.sh codex /opt/agent-vm/install-status/codex sh /tmp/install-codex.sh

# Build-time gate. Bind-mounted, not COPYed. A hard install failure already
# aborted the build; a softened transport failure left an absence record and no
# command. The gate accepts that degraded state only when the record is present,
# and otherwise requires a bounded, status-checked `codex --version` report to
# match the pin before auditing T5. See verify-codex.sh.
RUN --mount=type=bind,source=contract,target=/tmp/recipe-contract,ro \
    --mount=type=bind,source=verify-codex.sh,target=/tmp/verify-codex.sh,ro \
    AGENT_VM_CONTRACT_DIR=/tmp/recipe-contract \
    AGENT_VM_VERSION_CODEX="${AGENT_VERSION_CODEX}" \
    AGENT_VM_INSTALL_STATUS_DIR=/opt/agent-vm/install-status \
    sh /tmp/verify-codex.sh
