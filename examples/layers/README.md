# Example tooling layers

A **tooling layer** is a project-owned `Dockerfile` (plus its build context)
that adds project-specific tools on top of the previous step in the
project's **layer chain** — compilers, cross-toolchains, anything the base
doesn't carry. A project's chain lives under `.agent-vm/layers/`, one
numbered subdirectory per step, built in order. See
`docs/adr/0003-project-tooling-layers.md` and the "Tooling layer" / "Layer
chain" / "Derived image" entries in `CONTEXT.md` for the full mechanism.

The directories under `examples/layers/` are worked examples, not activated
by default. To use one in your project, copy it into place as a numbered
step:

```sh
cp -r examples/layers/wirenboard-cpp .agent-vm/layers/10-wirenboard-cpp
```

Copying into `.agent-vm/layers/` is the only way to use an example — there
is no `--layer` flag or `$AGENT_VM_LAYER` to point at a directory directly;
the chain is always read from the project's own `.agent-vm/layers/`.

The first launch after a chain is declared (or a step is edited) prompts to
build it: `Build project tooling layer '<tag>'? [y/N]` for a single-step
chain, or a multi-line prompt listing every step for a longer one. Pass
`--yes` (or set `AGENT_VM_YES=1`) for non-interactive/CI use. A later launch
with an unchanged chain reuses the already-built derived image with no
rebuild and no prompt.

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
| [`chrome-devtools`](chrome-devtools/) | Chromium, Chrome DevTools MCP wrapper, scoped NSS CA trust, and the Chrome capability marker. |

## Chrome DevTools

Copy `examples/layers/chrome-devtools` to `.agent-vm/layers/10-chrome-devtools`
(or any numbered step) and run `agent-vm claude --yes`. It installs Chromium
and the Chrome DevTools MCP integration. Root guests use the dedicated
`chrome` account; non-root guests run Chromium as their guest user. The
layer pre-warms the npm cache for root mode only: arbitrary non-root guest
homes remain persistent but download on first use.

## Composing several layers

A project chain can combine `chrome-devtools` with its own toolchain — the
motivating case for the chain in the first place. Copy both examples into
numbered steps, choosing the order that matches what each depends on
(neither of these two depends on the other, so either order works):

```sh
cp -r examples/layers/wirenboard-cpp   .agent-vm/layers/10-wirenboard-cpp
cp -r examples/layers/chrome-devtools  .agent-vm/layers/20-chrome-devtools
```

The `NN-` numbering is what fixes the build order — steps are sorted
byte-lexicographically by directory name, so `10-` always builds before
`20-`. Number with gaps (`10`, `20`, `30`, ...) so a step can be inserted
later without renaming its neighbors. Each step's `Dockerfile` must still
start `ARG BASE_IMAGE=...` / `FROM ${BASE_IMAGE}` — the launcher rewrites
`BASE_IMAGE` per step (the base image for the first step, the previous
step's built image for every step after it), so a step's own Dockerfile
never names a fixed base or its neighbors directly.
