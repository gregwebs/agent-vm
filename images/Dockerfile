# agent-vm TOOL-FREE BASE image — the OCI image that tool layers build
# FROM and that the agent-vm tool boots *inside* its per-project
# microVM when the configured tool set is composed locally. NOT the
# agent-vm tool itself (that's the Rust binary published as
# @wirenboard/agent-vm on npm).
#
# Contents: Debian 13 slim + the docker engine (docker.io + containerd
# + runc + fuse-overlayfs), network/diagnostic CLIs, the
# `agent-vm-install` helper, and the host-CA shim. It carries NO agent
# CLI: the five shipped agents live in standalone tool layers under
# images/tools/ (pi, codex, opencode, claude, copilot), each building FROM
# this base per ADR-0003's layer image contract. The WB C/C++
# build-essentials family and armhf/arm64 cross toolchains live as an
# opt-in example tooling layer at examples/layers/wirenboard-cpp/
# instead of in this base image — see
# docs/adr/0003-project-tooling-layers.md. Other heavy extras (LSPs,
# additional MCP servers, docker-buildx) are deliberately deferred too.
#
# The tool layers are composed two ways. CI chains base + the five
# default layers and publishes the result as
# ghcr.io/wirenboard/agent-vm-template (the "composed default image"),
# which is what a default-config launch boots verbatim. A launch whose
# configured tool set differs composes from this base locally. Both are
# published by the hourly CI workflow
# (.github/workflows/build-image.yml); source-checkout users can build
# locally and push to a host-local registry via images/build.sh.
#
# Layer ordering (most frequently changed content last) is now the tool
# layers' concern, not this file's — see images/tools/README.md. This
# base's own steps (Debian, docker engine, diag tooling) change rarely
# and stay cached across rebuilds.

FROM debian:13-slim

LABEL org.opencontainers.image.title="agent-vm tool-free base"
LABEL org.opencontainers.image.description="Tool-free OCI base image that agent-vm tool layers build FROM and that the agent-vm tool (npm: @wirenboard/agent-vm) boots inside each per-project microVM. Contains Debian 13 + docker engine + diag tooling (ssh/ping/etc.) but NO agent CLI — see images/tools/ for the per-tool layers. NOT the agent-vm runtime itself — install that via `npm install -g @wirenboard/agent-vm`."

# LANG=C.UTF-8: debian:slim ships with NO locale set, leaving the guest in
# C/POSIX — which renders a non-ASCII (e.g. Cyrillic) cwd as `M-P…` meta-
# escapes in bash/readline AND makes locale-driven filesystem encodings
# default to ASCII, so Python/Node/ripgrep mis-handle or error on a non-ASCII
# path even when it mounted fine. C.UTF-8 is always present in glibc (no
# locale-gen needed), ASCII-sorting + English-messages but UTF-8-aware.
# agent-vm's launcher also sets this for every exec; having it in the image
# makes any other use of the image correct too.
ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/root \
    PATH=/usr/local/bin:/usr/bin:/usr/sbin:/bin \
    LANG=C.UTF-8

# Image-API contract version. Bump on BREAKING image changes only
# (new required mount points, changed env-var contracts, removed
# binaries, renamed in-VM paths). Routine agent-version refreshes
# and tooling additions (build-essential, ssh, etc.) do NOT change
# this — they're additive. See `crates/agent-vm/src/defaults.rs`
# for the matching range in the binary.
RUN echo 3 > /etc/agent-vm-image-version

# Conditionally trust a host-supplied CA bundle. Only fires when
# `images/build.sh` is invoked on a host that sits behind a TLS-
# intercept proxy (e.g. agent-vm-inside-agent-vm during local dev,
# or a corporate egress MITM). The build script passes the host CA
# via `--secret id=hostca` IF it exists at
# `/usr/local/share/ca-certificates/microsandbox-ca.crt`. In CI
# (no such file → no secret → empty mount), the `-s` test fails
# and this is a no-op — the production image is unchanged.
#
# `--mount=type=secret` keeps the CA file in the buildkit secret
# store, not in the layer; what IS persisted is the merged
# /etc/ssl/certs/ca-certificates.crt. That's fine: the launcher
# re-imports its per-boot CA at /usr/local/share/ca-certificates/
# at runtime anyway, so a stale build-time CA in the bundle is
# inert (and removed if a user runs update-ca-certificates).
#
# `CA_SHIM_CACHEBUST`: buildkit does NOT include secret content in
# the RUN cache key (by design — secrets shouldn't bake into
# images). So toggling secret presence across builds doesn't
# invalidate this layer on its own. `images/build.sh` passes the
# CA file's mtime (`stat -c %Y …`) when the secret is included, so
# any change to the CA file (or going from "secret absent" → "secret
# present") shifts the ARG and rebuilds. In CI (no secret, empty
# arg) the layer also no-ops and stays cached.
ARG CA_SHIM_CACHEBUST=
RUN --mount=type=secret,id=hostca,target=/tmp/hostca.crt,required=false \
    : "${CA_SHIM_CACHEBUST}" \
 && if [ -s /tmp/hostca.crt ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends ca-certificates \
        && install -d /usr/local/share/ca-certificates \
        && install -m 0644 /tmp/hostca.crt /usr/local/share/ca-certificates/agent-vm-build.crt \
        && update-ca-certificates \
        && rm -rf /var/lib/apt/lists/* \
        && echo "==> host CA trusted for this build"; \
    fi

# Base apt — interpreters, fetchers, search/text utilities, AND
# network/diagnostic CLIs. Bundling these into the existing base
# layer (instead of spinning up a new layer for "ssh + ping") keeps
# the layer count down: every additional layer costs a small
# per-layer materialize overhead in microsandbox even when nothing
# changes, so we only earn a new layer when we can articulate why
# it'd be invalidated independently.
#
# Network/diag tools rationale (engineers debug WB devices over
# SSH and serial; the in-VM agent often needs to confirm a host is
# reachable before chasing logs):
#   - iputils-ping, iputils-tracepath, traceroute, mtr-tiny:
#     reachability + per-hop latency.
#   - net-tools: legacy `ifconfig`, `netstat`, `route` — still
#     muscle-memory for most embedded engineers, and many WB docs
#     reference them by name.
#   - iproute2: modern `ip`, `ss`. Usually preinstalled, listed
#     explicitly so an upstream slimming doesn't silently drop it.
#   - openssh-client: `ssh`, `scp`, `sftp`, `ssh-keygen`. No server
#     — the agent should never accept inbound connections.
#   - sshpass: scripted password-auth SSH (lab fixtures, factory
#     test rigs); also used by some WB CI scripts.
#   - dnsutils: `dig`, `nslookup`, `host`.
#   - netcat-openbsd: `nc` for ad-hoc TCP/UDP poking.
#   - tcpdump: rare but invaluable when an HTTP MITM looks wrong.
#   - gnupg: needed below to add the GitHub CLI apt key (and any
#     user-side apt sources `.agent-vm.runtime.sh` adds).
#   - less, vim-tiny, file, unzip, zip, rsync, htop, lsof, strace,
#     tmux: standard "I'm in a shell, I need a tool" muscle-memory
#     set. Each is <5 MB; the bundle is well under 30 MB. The second
#     multiplexer, zellij, is NOT in Debian's archive and is bigger
#     than anything in this list — it comes from an upstream release
#     tarball in its own RUN further down, where its size is argued.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl wget \
        git \
        jq \
        bash \
        python3 python3-pip \
        ripgrep fd-find \
        gnupg \
        iputils-ping iputils-tracepath traceroute mtr-tiny \
        net-tools iproute2 \
        openssh-client sshpass \
        dnsutils netcat-openbsd tcpdump \
        less vim-tiny file unzip zip rsync \
        htop lsof strace tmux \
 && rm -rf /var/lib/apt/lists/*

# GitHub CLI from the official apt repo (Phase 6).
RUN install -dm 755 /etc/apt/keyrings \
 && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        > /etc/apt/keyrings/githubcli-archive-keyring.gpg \
 && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends gh \
 && rm -rf /var/lib/apt/lists/*

# Node.js 22 from NodeSource — needed by MCP servers and by several tool
# layers' installers (the agents themselves are not in this base).
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*

# Docker engine — dockerd + cli + containerd + runc.
#
# Why each piece:
#   - docker.io / docker-cli: the daemon and the CLI a user actually
#     invokes; no buildx (legacy builder is fine for the small builds
#     agents do in-VM; +20 MB compressed isn't worth the polish).
#   - containerd / runc: the OCI runtime stack the daemon delegates to.
#     Both are kernel-required (runc=container init, containerd=image
#     management); without them dockerd refuses to start.
#   - fuse-overlayfs: the storage driver we pin in daemon.json below.
#     Native overlay2 doesn't work because the VM rootfs is already
#     overlay (libkrun rootfs design), and overlay-on-overlay returns
#     EINVAL inside dockerd's snapshotter. fuse-overlayfs sidesteps
#     that at userspace level.
#   - iptables: dockerd installs NAT rules on every container start;
#     missing binary makes the daemon log a warning and disable bridge
#     networking. The kernel-side iptables/nf_tables support comes
#     from the libkrunfw-overrides patch (see libkrunfw-overrides/
#     README.md).
#
# Storage-driver choice (daemon.json): see comment above. iptables
# alternative left at debian's default (iptables-nft) — both nft and
# legacy backends are functional in the patched kernel.
#
# Auto-start: not done in the image. The launcher (or a per-project
# `.agent-vm.runtime.sh`) is the right place to `dockerd &` if the
# session needs it — most sessions won't, so paying ~50 MB RSS at
# every boot would be wasteful.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        docker.io docker-cli \
        containerd runc \
        fuse-overlayfs \
        iptables \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /etc/docker \
 && printf '%s\n' '{' '  "storage-driver": "fuse-overlayfs"' '}' \
        > /etc/docker/daemon.json

# zellij is shipped beside tmux because Debian 13 does not package it. The
# statically linked musl release asset keeps working if the Debian base moves.
# This dedicated layer stays below the agent installers so their hourly
# rebuilds do not re-fetch it, and above larger later installs. Changing a pin
# or the mounted installer invalidates this layer and later layers; a cache
# miss in any earlier parent layer still invalidates it through Docker's layer
# cascade. The pins are literal distributed-archive checksums, so reviewing a
# bump does not trust a checksum fetched from the same network source.
ARG ZELLIJ_VERSION=0.45.0
ARG ZELLIJ_SHA256_AMD64=ab8b2494d80c20c07da4361041a25b96b93c73df992d2d54143e70fb9b1a1063
ARG ZELLIJ_SHA256_ARM64=d8b311d0f9ec7a03f3341563331aac12c9f52990ecc96a36ed44b1add9dfa035
RUN --mount=type=bind,source=install-zellij.sh,target=/tmp/install-zellij.sh,ro \
    bash /tmp/install-zellij.sh

# Per-agent cache keys (the three `ARG AGENT_VERSION_*` below, one
# per installer RUN). The workflow resolves each agent's current
# UPSTREAM version and passes it in, so an installer layer is rebuilt
# only when that agent actually released — not on every hourly cron
# run.
#
# This replaces the old single `AGENT_INSTALL_CACHEBUST=<timestamp>`
# arg, which changed every hour and re-emitted all three
# `curl … install.sh | bash` layers (plus the sanity check) on every
# build. Because those installs aren't reproducible, each rebuild
# produced fresh layer blobs → a brand-new ~200 MiB-of-agent-layers
# image every hour even when no agent version had changed, so
# `:latest` consumers re-downloaded those layers hourly for nothing.
# Keying on the real version makes an unchanged hourly build a pure
# cache hit (identical layer digests → nothing to re-pull). Local
# `images/build.sh` builds leave the defaults empty and get normal
# Docker layer-cache behaviour.

ARG AGENT_INSTALL_SOFT_FAIL=
# Shared helper for the three agent installer RUNs below. Downloads
# the upstream `install.sh`, runs it under the requested shell, and
# emits a uniform soft-fail or hard-fail diagnostic depending on
# `AGENT_INSTALL_SOFT_FAIL`. Keeping the policy in one place means
# any future tweak (extra retries, log format, soft-fail discrimina-
# tion) lives in exactly one spot — the three RUNs that call it are
# trivial one-liners.
#
# Why curl-only (no python3-urllib fallback): both curl and python3's
# `ssl` module link against the same system OpenSSL, so a real TLS-
# layer failure (the curl 56 "SSL_read: unexpected eof" we see from
# inside MITM-proxied dev sandboxes) hits the fallback identically.
# `--retry 5 --retry-all-errors --http1.1` covers the transient cases
# that ARE recoverable. The MITM-sandbox case is what
# `AGENT_INSTALL_SOFT_FAIL=1` exists for.
#
# Written via `printf '%s\n'` because debian-slim's `/bin/sh` is
# POSIX dash, no heredoc niceties. The script is small enough that
# adding a layer for it is essentially free (well under 1 KB).
RUN printf '%s\n' \
        '#!/bin/sh' \
        '# agent-vm-install <name> <shell> <url>' \
        '#   <name>  - agent identifier (codex, opencode, claude)' \
        '#   <shell> - sh|bash; the interpreter used to run the installer' \
        '#   <url>   - upstream installer URL' \
        '# Honors $AGENT_INSTALL_SOFT_FAIL: when non-empty, a download or' \
        '# install failure becomes a warning + exit 0 instead of exit 1.' \
        'set -eu' \
        'name=$1; shell=$2; url=$3' \
        'tmp=$(mktemp)' \
        'trap "rm -f \"$tmp\"" EXIT INT TERM' \
        'if curl -fsSL --retry 5 --retry-all-errors --http1.1 "$url" -o "$tmp" \' \
        '        && "$shell" "$tmp"; then' \
        '    exit 0' \
        'fi' \
        'msg="==> $name installer FAILED — install in-VM with: curl -fsSL $url | $shell"' \
        'if [ -n "${AGENT_INSTALL_SOFT_FAIL:-}" ]; then' \
        '    echo "$msg (soft-fail mode; image will ship without $name)"' \
        '    exit 0' \
        'fi' \
        'echo "$msg" >&2' \
        'exit 1' \
        > /usr/local/bin/agent-vm-install \
 && chmod 0755 /usr/local/bin/agent-vm-install \
 && test -s /usr/local/bin/agent-vm-install

# Tool layers build FROM this base and install into /opt/agent, a shared,
# world-readable prefix — NOT /root, which is mode 0700 and unreadable by the
# non-root guest user agent-vm boots by default (crates/agent-vm/src/run.rs).
# The tool layer sets HOME=/opt/agent for the duration of the install (so the
# upstream installer drops its files there) and re-asserts a+rX afterward, in
# case the installer narrowed permissions on something. The prefix lives here,
# not in each layer, because it is tool-agnostic and C7 (a+rX) requires it to
# be world-traversable. See images/tools/README.md.
RUN mkdir -p /opt/agent && chmod 755 /opt/agent

# The `agent-vm-install` helper above and the host-CA shim near the top of
# this file are inherited by every tool layer that builds FROM this base; a
# tool layer must not re-declare them or thread `CA_SHIM_CACHEBUST` into its
# own build. See images/tools/README.md.
#
# First-boot seed hooks. A tool layer that bakes state which the guest's
# runtime persistence symlinks would shadow (e.g. the claude LSP plugin tree
# under ~/.claude) drops an executable here; the launcher's prelude runs every
# entry once per boot (run.rs's RUN_IMAGE_SEED_HOOKS). Empty in this tool-free
# base.
RUN mkdir -p /opt/agent-vm/seed.d && chmod -R a+rX /opt/agent-vm

# Sanity check at build time. Every command is invoked directly
# (`tool --version >/dev/null`) so a present-but-broken binary —
# corrupt download, broken symlink target, missing libc symbol —
# fails the build instead of slipping through a `command -v` exists-
# check. `set -e` propagates the first failure.
#
# The agent CLIs are NOT checked here any more: they are not in this base.
# Each tool layer carries its own `--version` gate (see images/tools/). zellij
# follows the AGENT_INSTALL_SOFT_FAIL policy (its RUN above also honors it,
# scoped to the network fetch only — see the zellij RUN's comment for why a
# checksum mismatch is never soft-failable even though a download failure is).
RUN set -e \
 && echo "== HARD requirements ==" \
 && dockerd --version >/dev/null \
 && docker --version >/dev/null \
 && containerd --version >/dev/null \
 && runc --version >/dev/null \
 && ssh -V >/dev/null 2>&1 \
 && sshpass -V >/dev/null 2>&1 \
 && ping -V >/dev/null 2>&1 \
 && { if zellij --version >/dev/null 2>&1; then \
          echo "  zellij: $(zellij --version 2>&1 | head -1)"; \
      elif [ -n "${AGENT_INSTALL_SOFT_FAIL:-}" ]; then \
          echo "  zellij: MISSING (soft-fail mode)"; \
      else \
          echo "  zellij: MISSING — hard sanity failure" >&2; exit 1; \
      fi; } \
 && echo "== sanity OK =="

# Smoke entrypoint; the launcher overrides this in Phase 2.
CMD ["/bin/bash"]
