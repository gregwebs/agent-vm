# OpenCode CLI tool layer. See docs/adr/0003-project-tooling-layers.md for the
# layer image contract this file satisfies, and images/Dockerfile for the
# `agent-vm-install` helper and the host-CA shim it inherits from the base.
ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-base:latest
FROM ${BASE_IMAGE}

# Re-declared inside the stage: a global ARG is not visible to RUN.
ARG AGENT_VERSION_OPENCODE=
ARG AGENT_INSTALL_SOFT_FAIL=

# Additive, per C2. `${PATH}` expands to the predecessor's value at build
# time, so this layer can never remove a directory the base put there.
ENV PATH=/opt/agent/.opencode/bin:${PATH}

# Installs into $HOME/.opencode/bin (= /opt/agent/.opencode/bin); PATH already
# includes it. Symlink into /usr/local/bin so non-login shells find it too. The
# symlink is best-effort — under soft-fail mode the install may have been
# skipped, in which case there's nothing to link.
RUN : "opencode ${AGENT_VERSION_OPENCODE}" \
 && HOME=/opt/agent agent-vm-install opencode bash https://opencode.ai/install \
 && { [ -x /opt/agent/.opencode/bin/opencode ] \
        && ln -sf /opt/agent/.opencode/bin/opencode /usr/local/bin/opencode \
        || true; } \
 && chmod -R a+rX /opt/agent

# Direct invocation, never `command -v`: a present-but-broken binary must fail
# the build. Honors AGENT_INSTALL_SOFT_FAIL exactly as the old combined check.
RUN if opencode --version; then :; \
    elif [ -n "${AGENT_INSTALL_SOFT_FAIL:-}" ]; then echo "  opencode: MISSING (soft-fail mode)"; \
    else echo "  opencode: MISSING — hard sanity failure" >&2; exit 1; fi
