# examples/layers/wirenboard-cpp — WB C/C++ + armhf/arm64 cross toolchain
# tooling layer. Copy this directory to your project's .agent-vm/layer/
# (or point `agent-vm --layer <path>` at it) to build it FROM the base image.
# See docs/adr/0003-project-tooling-layers.md for the layer contract.

# Launcher overrides BASE_IMAGE with the digest-pinned base at build time
# (layer::digest_pinned_base). The default keeps a bare `docker build` of this
# directory working for smoke-testing.
ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-template:latest
FROM ${BASE_IMAGE}

# WB C/C++ build essentials. Ported verbatim from images/Dockerfile's former
# DEFERRED block (rationale for each package lives in this file's git history /
# the ADR). Sourced from the union of debian/control Build-Depends across
# wb-mqtt-serial, wb-mqtt-mbgate, wb-rules, wb-mqtt-confed and codestyle's
# cpp/local/linux-devenv.sh + cpp/ci/clang-*-subdirs.sh.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        debhelper devscripts equivs dpkg-cross \
        pkg-config \
        clang-format clang-tidy \
        libcurl4-openssl-dev \
        libgtest-dev libgmock-dev \
        libmodbus-dev \
        libsystemd-dev \
        gcovr \
        gdb-multiarch \
        cmake ninja-build \
        python3-cups python3-libgpiod python3-pycurl \
 && rm -rf /var/lib/apt/lists/*

# WB armhf + arm64 cross toolchains + qemu-user-static (binfmt) + sbuild path.
#
# Known limitation (not fixed here, matches the original DEFERRED block
# exactly): this installs the native-host dev-libs above and the cross
# *compilers* below, but does not `dpkg --add-architecture armhf/arm64` or
# install foreign-arch `-dev` packages. The canonical WB build path is
# `sbuild` inside a `schroot`, which supplies its own sysroot for that —
# out of scope for this layer.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        crossbuild-essential-armhf \
        crossbuild-essential-arm64 \
        qemu-user-static \
        debootstrap schroot sbuild \
 && rm -rf /var/lib/apt/lists/*

# No `ENV PATH` here: everything above installs into /usr/bin, which is
# already on the base image's PATH. Omitting `ENV PATH` entirely is the
# safest way to satisfy the layer contract's "keep PATH additive" rule
# (docs/adr/0003-project-tooling-layers.md) — there is nothing to prepend,
# and no way to accidentally clobber the base's agent/dockerd PATH entries.

# Build-time sanity probes (re-added per the note in the former DEFERRED block).
# Each tool is invoked directly so a present-but-broken binary fails the layer
# build loudly instead of surfacing as command-not-found in the guest. set -e
# propagates the first failure.
RUN set -e \
 && clang-format --version \
 && arm-linux-gnueabihf-gcc --version \
 && aarch64-linux-gnu-gcc --version \
 && qemu-arm-static --version \
 && echo "== wirenboard-cpp layer sanity OK =="
