# examples/layers/rust-dev — Rust development toolchain tooling layer.
#
# Install it into a project's chain, or try it directly, to build, test, lint
# and formally verify this repo's Rust code inside the microVM:
#
#   cp -r examples/layers/rust-dev .agent-vm/layers/10-rust-dev
#   agent-vm claude --yes
#   # or, without copying:
#   agent-vm shell --layer examples/layers/rust-dev --yes
#
# It provides the toolchain the repo pins (rust-toolchain.toml) with clippy and
# rustfmt, the musl target the guest agentd needs, the native libraries
# ci.yml installs, shellcheck for script/test/ci-contracts.sh, and the pinned
# Verus release CI verifies with. See examples/layers/README.md and
# docs/adr/0003-project-tooling-layers.md.
#
# The three steps that need real shell live as standalone, independently
# runnable scripts beside this file and are bind-mounted in at build time:
# install-rust.sh, install-verus.sh, verify-toolchain.sh. This file only wires
# the pins and locations into them.
#
# Layer image contract: C1 is the two lines below; C2 is satisfied because
# every ENV writes PATH=<new>:${PATH}; C3 by staying root; C7 by installing
# under world-readable /opt rather than a mode-0700 home.

ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-template:latest
FROM ${BASE_IMAGE}

# Pins. RUST_TOOLCHAIN is enforced against rust-toolchain.toml's channel, and
# VERUS_RELEASE/VERUS_SHA256 against .github/workflows/verus.yml, by
# script/check-rust-toolchain.sh. A bump moves this file, rust-toolchain.toml
# (or verus.yml), the `vstd` pin in crates/agent-vm/Cargo.toml, and
# CONTRIBUTING.md together.
ARG RUST_TOOLCHAIN=1.98.1
ARG VERUS_RELEASE=0.2026.09.20.aef82ed
ARG VERUS_SHA256=7b870fa12bc589015c2fab60a8b3d9f07c7b1adb3444eb0fadffcbf7f0447b33

# Where rustup keeps the toolchain and its shims. Both live under /opt so the
# arbitrary-uid guest (ADR-0001) can read them. RUSTUP_HOME is exported at
# runtime so the shims find the toolchain; CARGO_HOME is deliberately *not*,
# so cargo keeps its registry/build cache in the guest's own writable
# $HOME/.cargo instead of the read-only shared tree.
ARG RUSTUP_HOME=/opt/rustup
ARG CARGO_HOME=/opt/cargo

# Native build dependencies for cargo build/test/clippy on this workspace,
# mirroring ci.yml's "Install build dependencies" step (GitHub's runner
# already has build-essential; this slim base does not):
#   - build-essential, pkg-config: cc/pkg-config for the -sys crates
#     (libcap-ng, dbus) the microsandbox SDK links against;
#   - musl-tools: the *-unknown-linux-musl target the guest agentd needs;
#   - shellcheck: script/test/ci-contracts.sh lints the repo's scripts.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential pkg-config \
        libcap-ng-dev libdbus-1-dev \
        musl-tools \
        shellcheck \
 && rm -rf /var/lib/apt/lists/*

# Rust toolchain: pinned channel with clippy/rustfmt and the host musl target,
# installed world-readable under /opt for the arbitrary-uid guest.
RUN --mount=type=bind,source=install-rust.sh,target=/tmp/install-rust.sh,ro \
    bash /tmp/install-rust.sh

# Verus, the SMT-backed verifier for the verus! contracts (ADR-0018). Pinned
# release + digest on linux/amd64; a clean no-op where upstream publishes no
# asset (run the host's arm64-macos Verus there instead; see CONTRIBUTING.md).
ARG VERUS_DIR=/opt/verus
RUN --mount=type=bind,source=install-verus.sh,target=/tmp/install-verus.sh,ro \
    bash /tmp/install-verus.sh

# PATH stays additive (contract C2): the base's entries are preserved via
# ${PATH}, and the Verus directory is harmless on a host that skipped it.
ENV RUSTUP_HOME=/opt/rustup
ENV PATH=/opt/cargo/bin:/opt/verus/verus-x86-linux:${PATH}

# Post-install sanity: a present-but-broken binary fails the build here instead
# of surfacing as command-not-found in the guest, and the amd64 Verus check
# verifies a real contract rather than only `--version`.
RUN --mount=type=bind,source=verify-toolchain.sh,target=/tmp/verify-toolchain.sh,ro \
    bash /tmp/verify-toolchain.sh
