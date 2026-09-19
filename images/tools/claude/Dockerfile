# Claude Code CLI tool layer. See docs/adr/0003-project-tooling-layers.md for
# the layer image contract this file satisfies, and images/Dockerfile for the
# `agent-vm-install` helper and the host-CA shim it inherits from the base.
ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-base:latest
FROM ${BASE_IMAGE}

# Re-declared inside the stage: a global ARG is not visible to RUN.
ARG AGENT_VERSION_CLAUDE=
ARG AGENT_INSTALL_SOFT_FAIL=

# Additive, per C2. `/opt/agent/.local/bin` also appears on the codex layer's
# PATH; duplicating it is harmless because C2 checks membership, not order.
ENV PATH=/opt/agent/.local/bin:/opt/agent/.claude/local/bin:${PATH}

RUN : "claude ${AGENT_VERSION_CLAUDE}" \
 && HOME=/opt/agent agent-vm-install claude bash https://claude.ai/install.sh \
 && chmod -R a+rX /opt/agent

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
# under /opt/agent-vm/seed.d/). The execute bit is granted here by
# `--chmod=0755`, NOT by a `RUN chmod`: the embedded copy of this directory
# in the agent-vm binary materialises every file mode 0644 (see
# src/tool_layer.rs), so a RUN chmod would make the locally-built layer hash
# differently from one built from a git checkout of the same bytes.
COPY --chmod=0755 seed-claude-plugins.sh /opt/agent-vm/seed.d/10-claude-plugins

# Direct invocation, never `command -v`: a present-but-broken binary must fail
# the build. Honors AGENT_INSTALL_SOFT_FAIL exactly as the old combined check.
RUN if claude --version; then :; \
    elif [ -n "${AGENT_INSTALL_SOFT_FAIL:-}" ]; then echo "  claude: MISSING (soft-fail mode)"; \
    else echo "  claude: MISSING — hard sanity failure" >&2; exit 1; fi
