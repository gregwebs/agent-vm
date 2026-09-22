# DeepSeek Harness (dsh) tool layer. See
# docs/adr/0003-project-tooling-layers.md for the layer image contract this
# file satisfies, and images/Dockerfile for the facilities this layer inherits
# from the base (Node.js 22, npm, jq, the host-CA shim).
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
ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-base:latest
FROM ${BASE_IMAGE}

# Re-declared inside the stage so `images/build.sh`'s unconditional build-arg is
# consumed rather than warned about. dsh deliberately ignores it: `npm ci` below
# is a hard failure, because a partial `node_modules` is a broken agent, not a
# missing one — the same "no silently-cached hole" rule the policy exists for.
ARG AGENT_INSTALL_SOFT_FAIL=

# `npm ci` installs exactly the committed tree into a private prefix (there is
# no `-g` form that takes a lockfile); dsh and pnpm are linked onto PATH below.
#
# `--ignore-scripts` mirrors the pi layer. All five packages in this tree that
# declare an install script only fetch a prebuilt, restore a mode bit, or write
# metadata — none compiles anything here: node-pty and koffi ship per-platform
# prebuilds, protobufjs' postinstall writes a version file, @google/genai's
# preinstall is a no-op, and dsh-subprocess-local's postinstall just chmods
# node-pty's macOS `spawn-helper`. Verified on linux/arm64 by booting `dsh web`
# and spawning a PTY from the `--ignore-scripts` image.
#
# `NODE_EXTRA_CA_CERTS` points Node at the host-CA shim's merged system bundle
# (images/Dockerfile installs a TLS-intercept proxy's CA there). Node otherwise
# trusts only its bundled roots, so without this the documented MITM escape of
# building the layer locally would fail at `npm ci` — and unlike the installer
# layers there is no soft-fail path back from that.
#
# One RUN so the ~80 MiB npm cache never lands in a committed layer — /root is
# unreadable by the non-root guest anyway.
COPY package.json package-lock.json /opt/agent-vm/dsh/
RUN cd /opt/agent-vm/dsh \
 && NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt \
        npm ci --ignore-scripts --no-audit --no-fund \
 && chmod -R a+rX /opt/agent-vm/dsh \
 && rm -rf /root/.npm

# dsh and pnpm live in the private prefix, so their bins are not on PATH. Link
# them into the base's existing `/usr/local/bin` (already first on PATH), which
# also keeps C2 satisfied without rewriting PATH. `dsh plugin --profile … add …`
# forwards to pnpm, which is why pnpm is pinned in the lock too.
RUN ln -s /opt/agent-vm/dsh/node_modules/.bin/dsh /usr/local/bin/dsh \
 && ln -s /opt/agent-vm/dsh/node_modules/.bin/pnpm /usr/local/bin/pnpm

# Build-time gate. Bind-mounted (not COPYed), exactly like the pi layer's
# install/verify scripts: the script stays out of the shipped image and needs
# no execute bit, so the 0644-materialisation rule the agent-vm binary applies
# to embedded sources (src/tool_layer.rs) does not apply to it.
RUN --mount=type=bind,source=verify-dsh.sh,target=/tmp/verify-dsh.sh,ro \
    sh /tmp/verify-dsh.sh
