# DeepSeek Harness (dsh) recipe. See images/tools/README.md for the recipe
# conventions this file follows, and images/Dockerfile for the facilities this
# recipe inherits from the base (Node.js 22, npm, jq, the host-CA shim).
#
# Unlike the codex/claude/opencode installer layers, dsh is installed from a
# COMMITTED lockfile, not a floating installer — the pi shape. That is
# load-bearing, not tidiness: `npm install -g @deepseek-ai/dsh` resolves the app
# at the current `latest` (0.1.5-rc.2), whose `^0.1.5-rc.2` range pulls
# `dsh-base` 0.1.5-rc.3, and npm may then nest `dsh-sandbox-local` under
# `dsh-base/node_modules`. dsh's plugin loader cannot resolve that package from
# the app root, so `dsh web` fails to boot. The lock freezes the working layout
# (the package under the app's own `node_modules`) and every transitive
# integrity hash. Bump the pin by editing `package.json` and regenerating the
# lock — see images/tools/README.md.
#
# Two independent version slots live in that one lock: dsh itself and pnpm
# (`dsh plugin … add …` forwards to pnpm). An ordinary build installs the
# committed pins; an explicit AGENT_VERSION_DSH / AGENT_VERSION_PNPM supplies an
# exact version for that slot. prepare-lock.sh rewrites only those
# `dependencies` entries and check-lock-update.js freezes every location
# outside the changed root, so an override cannot silently drift a shared or
# hoisted record. See images/tools/dsh/prepare-lock.sh.
ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-base:latest
FROM ${BASE_IMAGE}

# Re-declared inside the stage so `images/build.sh`'s unconditional build-arg is
# consumed rather than warned about. dsh deliberately ignores it: `npm ci` below
# is a hard failure, because a partial `node_modules` is a broken agent, not a
# missing one — the same "no silently-cached hole" rule the policy exists for.
ARG AGENT_INSTALL_SOFT_FAIL=

# The two version slots. Both defaults are EMPTY on purpose: an empty slot
# reuses the committed lock byte-for-byte with no registry lookup, and the
# Dockerfile must never duplicate the pin as a nonempty ARG. The LABEL fallbacks
# below are generated mirrors of the committed manifest pins (a build cannot run
# jq inside a LABEL), kept in sync by upgrade-dsh.sh and asserted by the
# image_sources guards.
ARG AGENT_VERSION_DSH=
ARG AGENT_VERSION_PNPM=

# Selection, not health: these record the versions the layer was asked to
# install. Whether the commands are usable is the T5 audit's decision.
LABEL org.agent-vm.version.dsh="${AGENT_VERSION_DSH:-0.1.5-rc.2}" \
      org.agent-vm.version.pnpm="${AGENT_VERSION_PNPM:-11.11.0}"

# `npm ci` installs exactly the committed (or prepared) tree into a private
# prefix (there is no `-g` form that takes a lockfile); dsh and pnpm are linked
# onto PATH below.
#
# `--ignore-scripts` mirrors the pi layer. All five packages in this tree that
# declare an install script only fetch a prebuilt, restore a mode bit, or write
# metadata — none compiles anything here: node-pty and koffi ship per-platform
# prebuilds, protobufjs' postinstall writes a version file, @google/genai's
# preinstall is a no-op, and dsh-subprocess-local's postinstall just chmods
# node-pty's macOS `spawn-helper`. Verified on linux/arm64 by booting `dsh web`
# and spawning a PTY from the `--ignore-scripts` image.
#
# The hook runs through the recipe-local run-install.sh envelope (which owns the
# status record and the classified-transport receipt) with the bind-mounted
# contract, install hook, lock preparation and freeze checker. Nothing here is
# COPYed, so no helper becomes a shipped entry point.
COPY package.json package-lock.json /opt/agent-vm/dsh/
RUN --mount=type=bind,source=contract,target=/tmp/recipe-contract,ro \
    --mount=type=bind,source=install-dsh.sh,target=/tmp/install-dsh.sh,ro \
    --mount=type=bind,source=prepare-lock.sh,target=/tmp/prepare-lock.sh,ro \
    --mount=type=bind,source=check-lock-update.js,target=/tmp/check-lock-update.js,ro \
    AGENT_VM_CONTRACT_DIR=/tmp/recipe-contract \
    AGENT_VM_PREPARE_LOCK=/tmp/prepare-lock.sh \
    AGENT_VM_VERSION_DSH="${AGENT_VERSION_DSH}" \
    AGENT_VM_VERSION_PNPM="${AGENT_VERSION_PNPM}" \
    AGENT_VM_INSTALL_STATUS_DIR=/opt/agent-vm/install-status \
    sh /tmp/recipe-contract/run-install.sh dsh /opt/agent-vm/install-status/dsh sh /tmp/install-dsh.sh

# dsh and pnpm live in the private prefix, so their bins are not on PATH. Link
# them into the base's existing `/usr/local/bin` (already first on PATH), which
# also keeps C2 satisfied without rewriting PATH. `dsh plugin --profile … add …`
# forwards to pnpm, which is why pnpm is pinned in the lock too.
RUN ln -s /opt/agent-vm/dsh/node_modules/.bin/dsh /usr/local/bin/dsh \
 && ln -s /opt/agent-vm/dsh/node_modules/.bin/pnpm /usr/local/bin/pnpm

# Build-time gate. Bind-mounted (not COPYed), exactly like the pi layer's
# install/verify scripts: the script stays out of the shipped image and needs
# no execute bit. It checks both
# slots, audits command access as an arbitrary uid, and records `installed`.
RUN --mount=type=bind,source=contract,target=/tmp/recipe-contract,ro \
    --mount=type=bind,source=verify-dsh.sh,target=/tmp/verify-dsh.sh,ro \
    AGENT_VM_CONTRACT_DIR=/tmp/recipe-contract \
    AGENT_VM_VERSION_DSH="${AGENT_VERSION_DSH}" \
    AGENT_VM_VERSION_PNPM="${AGENT_VERSION_PNPM}" \
    AGENT_VM_INSTALL_STATUS_DIR=/opt/agent-vm/install-status \
    sh /tmp/verify-dsh.sh
