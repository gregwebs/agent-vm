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

The `pi` layer honours the arg differently from the installer layers: because a
half-installed Pi (an executable that execs into a missing entry point) is worse
than an absent one, its `install-pi.sh` catches the `npm ci` / fetch failure at
the failure, deletes the partial tree, and the layer then **removes the wrapper
and both `/opt/agent-vm` trees** — so a soft-failed build ships no `pi` at all,
rather than a broken one. An **integrity mismatch is never soft-failable** (the
same rule `images/install-zellij.sh` applies).

## Declaration and cache ordering

The declaration order — and therefore the chain order, the order
`agent-vm doctor` lists the verbs in, and CI's build order — is
`pi, codex, opencode, claude, copilot`, matching
`crates/agent-vm/src/default-tools.toml`. That file is the single source of
truth: `config::shipped_tool_layers()` derives the launcher's order from it,
and `tool_layer::tests::tool_order_matches_the_ci_and_build_script_literals`
asserts both this directory's build order (`images/build.sh`) and CI's
(`.github/workflows/build-image.yml`) agree with it — including the chain
*edges*, so a step left building `FROM` the base digest instead of its
predecessor's cannot slip through.

The order is deliberate and is **not** by size. A change to any layer forces
every layer stacked above it to rebuild, so the **topmost** layer is re-emitted
on essentially every build that changes anything, while the **bottom** layer is
re-emitted only when it itself bumps. The agent that is both largest and least
frequently changed belongs at the bottom:

- `pi` ~150 MiB (`node_modules`), only when this repo bumps the pin → bottom (first)
- `codex` ~95 MiB, multiple stable cuts/day → next
- `opencode` ~50 MiB, several per week → middle
- `claude` ~68 MiB, ~daily → top (of the three installer layers)
- `copilot` ~installed via npm, no upstream version key → last

`pi` is the extreme case of "large and rarely changing": a ~150 MiB tree whose
only input is the committed pin, so at the bottom it is re-emitted only when the
pin moves — never on the daily claude churn above it. (Inserting it at position
zero invalidates the four existing layers' caches once and re-pushes the
template once; that one-time cost is worth the steady state.) CI resolves each
*installer* agent's current upstream version and feeds it in as a per-agent
`AGENT_VERSION_*` build arg, so a layer is rebuilt only when that agent actually
released — an unchanged hourly build is a pure cache hit. `pi` has no
`AGENT_VERSION_*` key and needs none: its cache key is the lockfile's content.
This is the policy that used to live in `images/Dockerfile`; it moved here with
the installs.

## The `pi` layer: a committed lockfile, not an installer

No other layer works this way. The installer layers resolve their version at
build time; `pi`'s version lives in a **committed** `package.json` +
`package-lock.json` (`images/tools/pi/`), and the layer runs
`npm ci --ignore-scripts`, which by construction resolves nothing. The build then
asserts `pi --version` equals the pin, so there is no moving-version lookup for
Pi anywhere. The installation is fronted by an agent-vm-owned wrapper at
`/usr/local/bin/pi` — see
[ADR-0012](../../docs/adr/0012-stable-pi-image-customization-seam.md).

**Bumping the pin** means editing `package.json` and regenerating the lock:

```bash
cd images/tools/pi
npm install --ignore-scripts --package-lock-only --no-audit --no-fund
```

That regenerated lock has **5 entries with no `integrity`**: npm inherits Pi's
published `npm-shrinkwrap.json`, which omits the hashes for its five
`@earendil-works` siblings (`chord`, `pi-agent-core`, `pi-ai`, `pi-telemetry`,
`pi-tui`). Refill them from the registry's published `dist.integrity`:

```bash
pin=$(jq -r '.dependencies["@earendil-works/pi-coding-agent"]' images/tools/pi/package.json)
for p in chord pi-agent-core pi-ai pi-telemetry pi-tui; do
    printf '%s %s\n' "$p" "$(npm view "@earendil-works/$p@$pin" dist.integrity)"
done
```

Paste each value into its lock entry (only the five; no other hand-edit). This is
not decorative: npm ignores our lock for that subtree, so `install-pi.sh` enforces
the five itself — it re-fetches each tarball, compares the sha512 to the committed
`integrity`, and compares the extraction against what `npm ci` installed with a
plain `diff -r` — **no `-x node_modules`**, because that basename exclusion would
blind the check to a shadow `node_modules` planted at *any* depth (for example
`pi-ai/dist/node_modules/…`, which wins Node's resolution from inside `pi-ai/dist`).
The only tolerated difference is the sibling's own nested dependency directories
as the committed lock declares them (`pi-ai`'s
`node_modules/{agent-base,https-proxy-agent}`, derived from the lock, not
hard-coded), which npm itself authenticated because they carry `integrity` in
Pi's shrinkwrap and are folded wholesale from the installed tree. So for every
path **inside one of the five siblings' own trees** and outside the sibling's
lock-declared nested dependency directories, the bytes that ship are the bytes
the hash was reviewed against. There, a mismatch — an extra file, directory or
symlink, a tampered file, or a missing one — is a **hard** build failure that
`AGENT_INSTALL_SOFT_FAIL` may not downgrade. (A path placed *beside* one of the
five, anywhere under `node_modules/@earendil-works/`, is outside every compared
sibling tree and is not looked at; npm extracts each sibling into its own
directory, so the unauthenticated sibling fetch cannot create one.) Two
`cargo test` guards
(`every_locked_package_carries_integrity`,
`the_build_verified_sibling_set_is_exactly_the_five_nested_earendil_packages`)
fail loudly if a regenerated lock drops the hashes or the nested layout moves.
