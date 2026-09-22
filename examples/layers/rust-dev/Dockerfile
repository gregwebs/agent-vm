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

# Rust toolchain. `--profile minimal` installs rustc/cargo/rust-std; the
# components add clippy + rustfmt (the two rust-toolchain.toml declares), and
# the host musl target is added for the guest agentd cross-build. The official
# rustup installer is used, as macos-build.md does, because only the toolchain
# version is part of the build identity.
RUN set -eux; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh; \
    sh /tmp/rustup-init.sh -y --no-modify-path --profile minimal \
        --default-toolchain "$RUST_TOOLCHAIN" \
        --component clippy,rustfmt; \
    rm -f /tmp/rustup-init.sh; \
    case "$(dpkg --print-architecture)" in \
        amd64) musl_target=x86_64-unknown-linux-musl ;; \
        arm64) musl_target=aarch64-unknown-linux-musl ;; \
        *) echo "unexpected architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    "$CARGO_HOME/bin/rustup" target add "$musl_target"; \
    chmod -R a+rX "$RUSTUP_HOME" "$CARGO_HOME"

# Verus, the SMT-backed verifier for the verus! contracts (ADR-0018).
# Upstream publishes no linux-arm64 asset, so on an Apple Silicon guest this is
# skipped: run the host's arm64-macos Verus there instead (CONTRIBUTING.md).
# The digest check is a hard failure, never soft-failable.
ARG VERUS_DIR=/opt/verus
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    if [ "$arch" = amd64 ]; then \
        asset="verus-${VERUS_RELEASE}-x86-linux.zip"; \
        curl -fSL --retry 3 -o "/tmp/$asset" \
            "https://github.com/verus-lang/verus/releases/download/release/${VERUS_RELEASE}/${asset}"; \
        echo "${VERUS_SHA256}  /tmp/${asset}" | sha256sum -c -; \
        mkdir -p "$VERUS_DIR"; \
        unzip -q "/tmp/$asset" -d "$VERUS_DIR"; \
        rm -f "/tmp/$asset"; \
        chmod -R a+rX "$VERUS_DIR"; \
    else \
        echo "==> no Verus linux-${arch} release; run Verus on the host instead"; \
    fi

# PATH stays additive (contract C2): the base's entries are preserved via
# ${PATH}, and the Verus directory is harmless on a host that skipped it.
ENV RUSTUP_HOME=/opt/rustup
ENV PATH=/opt/cargo/bin:/opt/verus/verus-x86-linux:${PATH}

# Build-time sanity: invoke tools directly so a present-but-broken binary
# (truncated download, missing libc symbol, absent component) fails the build
# instead of surfacing as command-not-found in the guest. `set -e` propagates
# the first failure. The toolchain equality check is exact, so a rustup that
# silently resolved a different version cannot ship. On amd64 the Verus check
# goes beyond `--version`: it verifies a trivial contract, so a Verus tree
# that cannot actually reach its bundled vstd + z3 fails the build.
RUN set -eux; \
    test "$(rustc --version | cut -d' ' -f2)" = "$RUST_TOOLCHAIN"; \
    cargo --version; \
    cargo clippy --version; \
    rustfmt --version; \
    if [ "$(dpkg --print-architecture)" = amd64 ]; then \
        verus="$VERUS_DIR/verus-x86-linux/verus"; \
        "$verus" --version; \
        "$VERUS_DIR/verus-x86-linux/z3" --version; \
        smoke=/tmp/verus-layer-smoke; \
        rm -rf "$smoke"; mkdir -p "$smoke"; \
        printf '%s\n' \
            'use vstd::prelude::*;' \
            '' \
            'verus! {' \
            'proof fn layer_smoke()' \
            '    ensures true,' \
            '{' \
            '}' \
            '}' \
            > "$smoke/smoke.rs"; \
        (cd "$smoke" && "$verus" --crate-type=lib smoke.rs); \
        rm -rf "$smoke"; \
    fi; \
    echo "== rust-dev layer sanity OK =="
