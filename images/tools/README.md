# Tool layers

One standalone tooling layer per shipped agent CLI. Each directory holds a
`Dockerfile` that builds `FROM` the tool-free base
(`ghcr.io/wirenboard/agent-vm-base:latest`, produced by `images/Dockerfile`)
and installs exactly one agent. The directories are embedded into the
`agent-vm` binary at compile time (`crates/agent-vm/src/tool_layer.rs`) so a
launch whose configured tool set differs from the shipped default can compose
them locally without a repo checkout.

## The layer image contract

Every `Dockerfile` here obeys [ADR-0003](../../docs/adr/0003-project-tooling-layers.md)'s
**layer image contract** (C1–C8). The enforced clauses, checked on every built
step by `crates/agent-vm/src/layer/contract.rs`:

- **C1** — a global `ARG BASE_IMAGE` before the first `FROM`, and the final
  `FROM` resolves `${BASE_IMAGE}`. Text-linted before the build and verified
  against `rootfs.diff_ids` after.
- **C2** — the built `PATH` is a superset of the predecessor's. Every layer
  here writes its prefix as `ENV PATH=<new>:${PATH}`, so it can never remove a
  directory the base put there.
- **C3** — the final image's `User` is unset/`root`/`0`.
- **C4** — no `--platform=` on the final `FROM` other than `$TARGETPLATFORM`.

Documented-only but still binding: never write `/etc/agent-vm-image-version`
(that is the base's job), never remove or rewrite `/opt/agent`, keep installed
files `a+rX`, and leave `ENTRYPOINT`/`CMD` inert (the launcher supplies the
command).

## Inherited from the base — do not duplicate

A tool layer builds `FROM` `images/Dockerfile` and therefore inherits:

- the **`agent-vm-install` helper** (`/usr/local/bin/agent-vm-install`), the
  repo's uniform "fetch-an-upstream-installer with a soft-fail policy" wrapper.
  A tool layer calls it; it must not re-declare it.
- the **host-CA shim**: the build-time CA (when `images/build.sh` detects a
  TLS-intercept proxy) is baked into the base rootfs, so every layer inherits
  host trust with no extra build arg. Do **not** thread `CA_SHIM_CACHEBUST`
  into a tool layer's Dockerfile.
- the **`/opt/agent` prefix** (`RUN mkdir -p /opt/agent && chmod 755 /opt/agent`)
  and the empty `/opt/agent-vm/seed.d/` hook directory.

## `AGENT_INSTALL_SOFT_FAIL`

The base's `agent-vm-install` helper honors `AGENT_INSTALL_SOFT_FAIL`: when
non-empty, a download/install failure becomes a warning instead of a hard
failure. `images/build.sh` auto-sets it on TLS-intercept dev hosts, and CI
never sets it. Each tool Dockerfile re-declares the `ARG` so those two paths
keep the policy.

The **launcher's** local-compose path deliberately does **not** pass this arg
(`layer.rs` passes exactly one build arg, `BASE_IMAGE=`). A soft-fail there
would ship a silently cached "healthy-looking image missing its toolchain",
which is the single outcome ADR-0003 exists to prevent. A source-checkout user
behind a TLS-intercept proxy has two documented escapes: build the tool layer
themselves with `images/build.sh` (which does set the arg) and pass
`--base-image` / `--layer`, or use the published composed template. See
USAGE.md.

## Declaration and cache ordering

The declaration order — and therefore the chain order and CI build order — is
`codex, opencode, claude, copilot`, matching
`crates/agent-vm/src/default-tools.toml` and the
`[[tools]]` chain.

The order is deliberate and is **not** by size. A change to any layer forces
every layer stacked above it to rebuild, so the **topmost** layer is re-emitted
on essentially every build that changes anything, while the **bottom** layer is
re-emitted only when it itself bumps. The agent that is both largest and most
frequently released belongs at the bottom:

- `codex` ~95 MiB, multiple stable cuts/day → bottom (first)
- `opencode` ~50 MiB, several per week → middle
- `claude` ~68 MiB, ~daily → top (of the three versioned layers)
- `copilot` ~installed via npm, no upstream version key → last

CI resolves each versioned agent's current upstream version and feeds it in as
a per-agent `AGENT_VERSION_*` build arg, so a layer is rebuilt only when that
agent actually released — an unchanged hourly build is a pure cache hit. This
is the policy that used to live in `images/Dockerfile`; it moved here with the
installs.
