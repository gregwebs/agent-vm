# Example tooling layers

A **tooling layer** is a project-owned `.agent-vm/layer/Dockerfile` (plus its
build context) that adds project-specific tools on top of the agent-vm base
image — compilers, cross-toolchains, anything the base doesn't carry. See
`docs/adr/0003-project-tooling-layers.md` and the "Tooling layer" / "Derived
image" entries in `CONTEXT.md` for the full mechanism.

The directories under `examples/layers/` are worked examples, not activated
by default. To use one in your project:

```sh
cp -r examples/layers/wirenboard-cpp .agent-vm/layer
```

or point at it directly without copying:

```sh
agent-vm shell --layer examples/layers/wirenboard-cpp
# or
export AGENT_VM_LAYER=examples/layers/wirenboard-cpp
```

The first launch after a layer is declared (or edited) prompts to build it:
`Build project tooling layer '<tag>'? [y/N]`. Pass `--yes` (or set
`AGENT_VM_YES=1`) for non-interactive/CI use. A later launch with an
unchanged layer reuses the already-built derived image with no rebuild and
no prompt.

## Writing your own layer

Follow the layer Dockerfile contract in
`docs/adr/0003-project-tooling-layers.md` ("The layer Dockerfile contract"):
start with `ARG BASE_IMAGE=...` / `FROM ${BASE_IMAGE}`, keep `ENV PATH`
additive (or don't set it at all), install tools world-readable
(`a+rX`, not under a `0700` home), stay glibc/arch-portable, and leave
`/etc/agent-vm-image-version`, `/bin/bash`, `/etc/passwd`/`/etc/group`, and
`ENTRYPOINT`/`CMD` untouched.

## Index

| Example | Adds |
|---|---|
| [`wirenboard-cpp`](wirenboard-cpp/) | WB C/C++ build-essentials (debhelper, clang-format/clang-tidy, libcurl/libgtest/libmodbus/libsystemd-dev, cmake/ninja, ...) plus the armhf/arm64 cross toolchains, qemu-user-static, and the sbuild/schroot/debootstrap path. |
