# Codex CLI tool layer. See docs/adr/0003-project-tooling-layers.md for the
# layer image contract this file satisfies, and images/Dockerfile for the
# `agent-vm-install` helper and the host-CA shim it inherits from the base.
ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-base:latest
FROM ${BASE_IMAGE}

# Re-declared inside the stage: a global ARG is not visible to RUN.
ARG AGENT_VERSION_CODEX=
ARG AGENT_INSTALL_SOFT_FAIL=

# Additive, per C2. `${PATH}` expands to the predecessor's value at build
# time, so this layer can never remove a directory the base put there.
ENV PATH=/opt/agent/.local/bin:${PATH}

RUN : "codex ${AGENT_VERSION_CODEX}" \
 && HOME=/opt/agent agent-vm-install codex sh \
        https://github.com/openai/codex/releases/latest/download/install.sh \
 && chmod -R a+rX /opt/agent

# Direct invocation, never `command -v`: a present-but-broken binary must fail
# the build. Honors AGENT_INSTALL_SOFT_FAIL exactly as the old combined check.
RUN if codex --version; then :; \
    elif [ -n "${AGENT_INSTALL_SOFT_FAIL:-}" ]; then echo "  codex: MISSING (soft-fail mode)"; \
    else echo "  codex: MISSING — hard sanity failure" >&2; exit 1; fi
