# GitHub Copilot CLI tool layer. See docs/adr/0003-project-tooling-layers.md
# for the layer image contract this file satisfies, and images/Dockerfile for
# the `agent-vm-install` helper and the host-CA shim it inherits from the base.
ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-base:latest
FROM ${BASE_IMAGE}

# Re-declared inside the stage: a global ARG is not visible to RUN.
ARG AGENT_INSTALL_SOFT_FAIL=

# Copilot installs into the global npm prefix, which is already on the base's
# PATH, so this layer needs no additive `ENV PATH`.
RUN npm install -g @github/copilot

# Direct invocation, never `command -v`: a present-but-broken binary must fail
# the build. Honors AGENT_INSTALL_SOFT_FAIL exactly as the old combined check.
RUN if copilot --version; then :; \
    elif [ -n "${AGENT_INSTALL_SOFT_FAIL:-}" ]; then echo "  copilot: MISSING (soft-fail mode)"; \
    else echo "  copilot: MISSING — hard sanity failure" >&2; exit 1; fi
