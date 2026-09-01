# ADR-0006: Adopt the clean Microsandbox v0.6.15 baseline; fail closed on unported fork features

## Status

Accepted. Superseded in part by ADR-0009 and ADR-0010: all four
previously deferred network capabilities are now active.

## Context

Through 0.5.7, `vendor/microsandbox` was a 25-commit `gw` fork of
upstream Microsandbox, pinned alongside a `[patch.crates-io]` block in
the root `Cargo.toml` pointing every `msb_krun_*` crate at a wirenboard
fork of `libkrun` (three fixes for the userspace split-irqchip /
virtio-mmio-cap / cmdline-overflow issues that fork needed). Both forks
were a growing maintenance liability: 386 upstream commits had landed
past the fork's merge-base by the time this ADR was written, and every
agent-vm release meant re-verifying agent-vm's patches against whatever
upstream had done in the meantime.

Investigating what the fork actually still contributed (agent-vm issue
#40's implementation plan) found most of it was moot: hickory DNS 0.26.1
and the macOS native allocator were upstreamed; the Linux jemalloc
allocator patch was never in baseline to begin with (tracked separately,
issue #44); the ext4-writable-overlay-size patch was superseded by
`SandboxBuilder::root_disk()`, which v0.6.15 unified the writable OCI
upper into. What remained fork-only and load-bearing: file-backed
(per-connection-refreshed) credential secrets, a per-route
intercept-hook dispatcher wired through `NetworkBuilder::intercept()`,
guest egress via a host HTTP-CONNECT proxy, `--auto-publish`, and
CIDR/group egress-override sugar methods — none of which exist on the
clean v0.6.15 baseline's `NetworkBuilder`/`SecretBuilder` API
(`crates/network/lib/config/builder.rs`).

Two paths were available: rebase the 25-commit fork stack across 386
commits of upstream drift and re-verify the wirenboard `libkrun` fork
against the new msb_krun cohort, or adopt the clean baseline outright
and either re-express or fail closed on whatever the fork alone
provided. The issue text was explicit that minimal boot should work
"without libkrun compatibility patches."

## Decision

**Adopt the clean `origin/baseline/v0.6.15` submodule tip directly**,
carrying exactly one re-ported commit on a thin
`integration/v0.6.15-agent-vm` branch: the agentd exit-on-shutdown fix
(teardown ~8.4s → ~0.45s in the fork; re-verified live on this baseline
at well under a second end-to-end for boot+exec+teardown). Every other
fork commit is dropped per the disposition above — upstreamed, moot, or
superseded.

**Delete the `[patch.crates-io]` libkrun-fork pin outright.** The
baseline's own `Cargo.lock` pins the official `msb_krun` 0.1.32 cohort
from crates.io. Live-verified: `agent-vm shell --no-git` boots and
executes a command with zero libkrun compatibility patches — the
single biggest risk this migration carried (issue #40's Q2) did not
materialize.

**Fail closed, not silently drop or half-port, every fork-only feature
minimal boot doesn't need.** `--auto-publish`, `--allow-lan`,
`--allow-host`, `--allow-egress`, a set guest-proxy env var, and
host-credential injection (when a launch actually needs it — see
`fail_closed.rs`'s doc comments for the exact per-guard criteria) each
refuse with an actionable error naming the option and this issue,
rather than either being silently ignored (weakening the security
behavior the flag implied) or crudely adapted (e.g. baking a credential
file's current contents into baseline's static `SecretBuilder::value()`,
which would silently drop the fork's per-connection token-rotation
guarantee). `intercept_hook.rs` and `secrets.rs` keep compiling
(`#[allow(dead_code)]` on what's now unreachable) rather than being
deleted, since re-porting credential injection onto baseline's
differently-shaped secrets API is follow-up work, not something minimal
boot needs to solve.

**Replace the `+agent-vm` patched-build version marker with an
official-identity check.** `msb_install.rs::verify_official_identity`
compares `msb --version`'s reported version against
`expected_msb_version()`, read via `include_str!` from
`vendor/microsandbox/Cargo.toml` at compile time so the check can never
drift from the gitlink a given build actually compiled against.

**Shorten the default macOS `MSB_HOME`.** See ADR-0004 for the prior
socket-path history; this migration found that ADR's "well under the
limit again" claim held only for short home directories (as little as
~21 bytes of headroom under the pre-#40 default, for macOS's 104-byte
`sun_path`) — not a real fix for every user. `msb_home_dir()` now
defaults to `$HOME/.agent-vm-msb` on macOS (was
`$HOME/.local/state/agent-vm/msb-home`) absent an explicit override,
plus a preflight (`ensure_socket_paths_fit`, reusing the runtime's own
`ipc::sandbox_socket_paths` derivation) that fails closed — never
truncates — on any path, default or overridden, that would still
overflow.

## Consequences

- agent-vm no longer carries or needs to track a `libkrun` fork; the
  device-workload matrix official `msb_krun` 0.1.32 needs to prove
  itself against (console stress, many-mount IRQ boundaries, firmware
  identity in CI) is issue #43's job, not re-litigated here.
- Guest-egress-via-proxy, auto-publish, egress overrides, and credential
  injection are consumed through the baseline APIs. ADR-0010 records the
  host-only file-source and request-policy constraints for credentials.
- A worktree building this baseline's newer sea-orm migration set
  (`m20260824_000001`, was `m20260606_000001`) must not share a
  `msb.db` with a worktree still building the pre-#40 fork (one-way
  migration; see ADR-0004 and `AGENTS.md`'s `AGENT_VM_STATE_DIR`
  guidance) — but note this collision can no longer happen via the
  *macOS default* alone, since the two now resolve to disjoint default
  `MSB_HOME` locations (`~/.agent-vm-msb` vs.
  `~/.local/state/agent-vm/msb-home`). It remains possible if either
  side sets an explicit `AGENT_VM_STATE_DIR` shared with the other.
- Issue #43 statically checks both Cargo resolution roots for the official
  crates.io `msb_krun*` 0.1.32 cohort, equal checksums, and the pinned
  firmware source gitlink. This is source identity, not binary/release
  attestation; signed artifacts and package provenance remain follow-up work.
- Apple Silicon/HVF is live-verified with the public `msb` compatibility
  harness. Darwin uses flattened-device-tree and guest-sysfs enumeration plus
  exact virtiofs mount and bidirectional marker checks: arm64 boot describes
  virtio-mmio devices through the device tree, so its approximately 202-byte
  `/proc/cmdline` is diagnostic rather than truncation. The recurring Darwin
  test policy is boundary 4/64, high 112, and stress 64. It does **not** claim
  128 as a maximum: 128 was the highest successful tested count, 256 was the
  first attempted failure (`RegisterFsDevice(IrqsExhausted)`), and 129--255
  were not exhaustively measured.
- Linux x86_64 KVM remains outstanding. It needs a real readable/writable
  `/dev/kvm` run of smoke, measure, reviewed Linux profile selection,
  boundary, and 100-run stress; the Linux-only >2 KiB/trailing
  `virtio_mmio.device=` command-line proof; device ordering/final-mount I/O;
  and split-irqchip/IOAPIC diagnostics. Neither Darwin device-tree evidence
  nor static checks substitutes for those items.
