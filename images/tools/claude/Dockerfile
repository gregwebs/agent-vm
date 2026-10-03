# Claude Code CLI recipe. See images/tools/README.md for the recipe conventions
# this file follows, and images/Dockerfile for the facilities this recipe
# inherits from the base (Node.js, curl, jq, coreutils timeout).
ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-base:latest
FROM ${BASE_IMAGE}

# Re-declared inside the stage: a global ARG is not visible to RUN.
#
# The default is the exact committed version (see images/tools/README.md,
# "Exact versions"); ordinary and release builds install exactly this, never a
# moving channel. script/build/agent-versions.sh --write is the reviewed
# developer tool that bumps it.
ARG AGENT_VERSION_CLAUDE=2.1.286
ARG AGENT_INSTALL_SOFT_FAIL=

# Selection, not health: this records the version the layer was asked to
# install. Whether the command is usable is the T5 audit's decision.
LABEL org.agent-vm.version.claude="${AGENT_VERSION_CLAUDE}"

# Additive, per C2. `/opt/agent/.local/bin` also appears on the codex layer's
# PATH; duplicating it is harmless because C2 checks membership, not order.
ENV PATH=/opt/agent/.local/bin:/opt/agent/.claude/local/bin:${PATH}

# The install hook validates the exact version, then runs Anthropic's pinned
# vendored installer (images/tools/claude/vendor/) through the shared
# run-install.sh envelope. Only a positively classified transport failure with
# a fresh receipt may degrade, and then only when AGENT_INSTALL_SOFT_FAIL is
# non-empty; the hook removes the recipe's own partial artifacts and writes an
# absence record. Everything else is hard. Bind-mounted, never COPYed, so no
# helper becomes a shipped entry point.
RUN --mount=type=bind,source=contract,target=/tmp/recipe-contract,ro \
    --mount=type=bind,source=install-claude.sh,target=/tmp/install-claude.sh,ro \
    --mount=type=bind,source=vendor,target=/opt/agent-vm/recipe-vendor,ro \
    AGENT_VM_CONTRACT_DIR=/tmp/recipe-contract \
    AGENT_VM_VENDOR_DIR=/opt/agent-vm/recipe-vendor \
    AGENT_VM_VERSION_CLAUDE="${AGENT_VERSION_CLAUDE}" \
    AGENT_VM_INSTALL_STATUS_DIR=/opt/agent-vm/install-status \
    sh /tmp/recipe-contract/run-install.sh claude /opt/agent-vm/install-status/claude sh /tmp/install-claude.sh

# Claude Code LSP plugins (C/C++, Python, TypeScript, Go) baked in so
# in-VM Claude has code intelligence on first launch. Ports the four
# language servers the original `setup` installed (claude-vm.sh:348-362):
# clangd-lsp / pyright-lsp / typescript-lsp / gopls-lsp from the
# claude-plugins-official marketplace.
#
# Marketplace registration first: `claude plugin marketplace add` clones
# https://github.com/anthropics/claude-plugins-official.git into Claude's
# plugin state, then each `claude plugin install <name>@<marketplace>`
# resolves against it. The bare repo URL is what the original git-cloned
# by hand; `marketplace add` lets the CLI manage the clone + index for us.
#
# Best-effort: a transient
# registry/clone blip during the build must not fail the whole
# image. Each step is guarded with `|| echo skipped`; a missing plugin
# costs in-VM code intelligence for that language, not a broken image —
# Claude still boots and the user can re-run `claude plugin install`.
#
# Must come AFTER the Claude install above — `claude` didn't exist before
# it. node/npm (from the base's nodejs RUN) and git (from the base's apt
# RUN) are both already present, which the marketplace clone + plugin
# resolution need.
#
# Invoke claude by ABSOLUTE PATH (/opt/agent/.local/bin/claude): the
# installer drops the binary there but Docker RUN uses a non-login /bin/sh
# that never sources the shell profile the installer edits, so a bare
# `claude` risks command-not-found (rc 127) if PATH resolution ever
# changes. The absolute path matches the `--version` gate at the end of
# this file.
#
# HOME=/opt/agent on every invocation: `claude plugin install` writes
# plugins to $HOME/.claude/plugins, and the base image's global
# `ENV HOME=/root` is otherwise still in effect for this RUN. Without this,
# claude would keep writing plugins to /root/.claude/plugins — invisible to
# the stash below, which reads from the relocated
# /opt/agent/.claude/plugins — silently shipping the guest with ZERO LSP
# plugins (seed-claude-plugins.sh would find nothing to seed and no-op).
#
# A `claude plugin list` runs after the loop so the build log shows which
# plugins actually landed — without it the best-effort guards would hide a
# total no-op behind a clean build. If `marketplace add` ever rejects the
# `owner/repo` shorthand, swap in the explicit URL
# https://github.com/anthropics/claude-plugins-official.git.
RUN { HOME=/opt/agent /opt/agent/.local/bin/claude plugin marketplace add anthropics/claude-plugins-official \
        || echo "==> LSP marketplace add skipped (will lazy-add at first plugin use)"; } \
 && for lsp in clangd-lsp pyright-lsp typescript-lsp gopls-lsp; do \
        HOME=/opt/agent /opt/agent/.local/bin/claude plugin install "${lsp}@claude-plugins-official" \
        || echo "==> LSP plugin ${lsp} skipped (install at runtime if needed)"; \
    done \
 && echo "==> LSP plugins installed at build time:" \
 && { HOME=/opt/agent /opt/agent/.local/bin/claude plugin list || true; } \
 && chmod -R a+rX /opt/agent

# The running guest symlinks $HOME/.claude -> /agent-vm-state/claude
# (persistence, run.rs — /root/.claude in root mode, <state_dir>/home/.claude
# in the default non-root mode), which shadows the plugin tree baked just
# above so the booted guest's `claude plugin list` shows nothing. Stash the
# plugins + settings to a NON-shadowed path and ship a first-boot seed
# script; the launcher prelude runs it before exec'ing the agent. Source is
# /opt/agent/.claude/... (relocated above, alongside HOME=/opt/agent), not
# /root/.claude — reading the old root path here would silently make this
# stash (and thus every non-root guest's LSP plugins) a no-op.
# Best-effort like the LSP install above: if a transient blip skipped the
# plugins, stash nothing rather than hard-failing the image — the first-boot
# seed then becomes a no-op and plugins lazy-install at runtime.
RUN mkdir -p /opt/agent-vm/claude-seed \
 && if [ -d /opt/agent/.claude/plugins ]; then \
        cp -a /opt/agent/.claude/plugins /opt/agent-vm/claude-seed/plugins; \
        [ -f /opt/agent/.claude/settings.json ] \
            && cp -a /opt/agent/.claude/settings.json /opt/agent-vm/claude-seed/settings.json; \
        echo "==> stashed claude LSP plugins for first-boot seeding"; \
    else \
        echo "==> no /opt/agent/.claude/plugins to stash (LSP install skipped); seed is a no-op"; \
    fi \
 && chmod -R a+rX /opt/agent-vm/claude-seed

# First-boot seed hook (run.rs's RUN_IMAGE_SEED_HOOKS runs every executable
# under /opt/agent-vm/seed.d/). The committed source is mode 0644, so the execute
# bit is established here by `--chmod=0755` rather than inherited from the build
# context; the hook must be executable.
COPY --chmod=0755 seed-claude-plugins.sh /opt/agent-vm/seed.d/10-claude-plugins

# Build-time gate. Bind-mounted, not COPYed. A hard install failure already
# aborted the build; a softened transport failure left an absence record and no
# command. The gate accepts that degraded state only when the record is present,
# and otherwise requires a bounded, status-checked `claude --version` report to
# match the pin before auditing T5. See verify-claude.sh.
RUN --mount=type=bind,source=contract,target=/tmp/recipe-contract,ro \
    --mount=type=bind,source=verify-claude.sh,target=/tmp/verify-claude.sh,ro \
    AGENT_VM_CONTRACT_DIR=/tmp/recipe-contract \
    AGENT_VM_VERSION_CLAUDE="${AGENT_VERSION_CLAUDE}" \
    AGENT_VM_INSTALL_STATUS_DIR=/opt/agent-vm/install-status \
    sh /tmp/verify-claude.sh
