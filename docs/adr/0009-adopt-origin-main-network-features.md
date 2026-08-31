# ADR-0009: Adopt `gregwebs/microsandbox` `origin/main` for the network features ADR-0006 fail-closed; wire features 1-3, defer feature 4

## Status

Accepted.

## Context

ADR-0006 adopted the clean Microsandbox v0.6.15 baseline and fail-closed
four fork-only features that had no baseline equivalent at the time:
guest egress via a host HTTP-CONNECT proxy, `--auto-publish`, CIDR/group
egress overrides (`--allow-lan`/`--allow-host`/`--allow-egress`), and
file-backed, per-connection-refreshed credential injection. Issue #47
tracked porting or dropping each of these.

An earlier draft of #47's plan proposed dropping features 1 and 2
(proxy, auto-publish) permanently, since neither had an equivalent on
the clean v0.6.15 baseline tip vendored at the time. Investigating
`vendor/microsandbox`'s configured remote (`gregwebs/microsandbox`)
found its `origin/main` branch already carries evidence-backed ports of
both features, plus the building blocks feature 4 needs, on top of the
same v0.6.15 merge-base the vendored `integration/v0.6.15-agent-vm`
branch was built from:

- `#9` establishes the v0.6.15 fork baseline.
- `#10` adds file-backed, per-connection-refreshed rotating
  `SecretSource`.
- `#11` adds outbound extension seams.
- `#13` ports fail-closed TLS request interception
  (`NetworkBuilder::intercept()`).
- `#14` adds the host HTTP proxy transport
  (`HostHttpProxyConnector::from_env()`), auto-installed by the netstack
  when `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` (either case) is set,
  honoring `NO_PROXY`.
- `#15` is a CI/doc fix.
- `#16` adds `--auto-publish`: `NetworkBuilder::auto_publish()`/
  `auto_publish_with(AutoPublishConfig)` plus `Sandbox::port_events()`
  streaming `PortEvent::{Added,Removed}`.

The vendored gitlink (on `integration/v0.6.15-agent-vm`) and
`origin/main` diverged at the v0.6.15 release merge-base; neither is a
superset. The integration line alone carries the agentd exit-on-shutdown
fix and issue #41's heartbeat keep-alive, both load-bearing for
agent-vm's boot/teardown behavior and absent from `origin/main`.
`origin/main` alone carries `#9`-`#16` above. A trial no-fast-forward
merge of `origin/main` into the integration line completed cleanly
during planning (zero conflicts, auto-resolved in
`crates/agentd/lib/agent.rs`, `crates/runtime/lib/vm.rs`,
`sdk/rust/lib/sandbox/mod.rs`).

## Decision

**Integrate `gregwebs/microsandbox` `origin/main` into the vendored
`integration/v0.6.15-agent-vm` line** with a no-fast-forward merge (done
by the maintainer directly on `origin`, landing at `a7487bb4`; this PR
records the resulting gitlink bump in the superproject). The merged tip
carries both the agentd exit fix / keepalive and `#9`-`#16`'s feature
ports — supersedes neither line, combines them.

**Wire features 1, 2, and 3 in agent-vm** through
`crates/agent-vm/src/network.rs`'s `network::Plan`, while `run.rs` retains
launch orchestration, now that the baseline underneath them exists:

- **Feature 1 (guest HTTP-CONNECT proxy).** The netstack already
  auto-installs the proxy from the operator's env at
  `NetworkStack::start()` time — agent-vm boots in-process via the SDK,
  so the operator's `HTTPS_PROXY`/etc. reaches it directly. Removing the
  `check_no_guest_proxy_env` guard is sufficient; a launch-time banner
  gives positive confirmation.
- **Feature 2 (`--auto-publish`).** Wire the existing flag to
  `NetworkBuilder::auto_publish()` (default `AutoPublishConfig`: 2s
  poll, host-private `127.0.0.1` bind) and re-add the
  `Sandbox::port_events()` subscriber #40 had stubbed out as dead code.
- **Feature 3 (egress overrides).** `network::Plan` translates
  `--allow-lan`/`--allow-host`/`--allow-egress` onto
  `NetworkPolicy::from_profiles([..])` plus prepended
  `Rule::allow_egress(Destination::Cidr(..))` rules, returning no custom
  policy (leave the SDK's `from_profiles([Public])` default untouched) when
  no override flag is passed — no silent widening of the default policy.

`.tls()` stays gated on `--publish` ports only (`TlsBuilder::new()`
defaults `enabled: true`, so calling it unconditionally would switch on
MITM interception for a pure egress-override or auto-publish launch that
asked for none of that).

**Defer feature 4 (credential injection) to a follow-up
(gregwebs/agent-vm#51), keep it fail-closed.** The baseline now has the
building blocks (`SecretSource`'s file-backed variant from `#10`,
`NetworkBuilder::intercept()` from `#13`), but agent-vm's `secrets.rs`
and `intercept_hook.rs` are not wired onto them — that rewiring, sized
as its own PR to preserve the fork's per-connection token-rotation,
OAuth-refresh, and GitHub REST path-scoping guarantees, is #51's job.
`fail_closed.rs`'s credential guard stays, repointed from the generic
"#47 tracks all four" framing to "#51 tracks this one, and the baseline
mechanism now exists — it's just not wired yet."

**Protocol generation 7 -> 8.** `#16` bumps the msb wire protocol so a
deployed gen-7 agentd cannot falsely claim auto-publish support. agentd
is a *host build artifact* embedded into agent-vm at compile time
(`AGENTD_BYTES`, written into the guest init inode at boot — not baked
into the OCI guest image; see `vendor/.../crates/protocol/VERSIONING.md`),
produced by `crates/filesystem/build.rs`. This PR does not touch
`image_api_version.rs` or republish the OCI image — agent-vm's
`MIN/MAX_SUPPORTED_IMAGE_API` tracks the unrelated userland
`/etc/agent-vm-image-version` contract. The task is ensuring the
*embedded* agentd is gen-8 (built from the integrated tree); a stale
gen-7 copy fails loud via the SDK send-gate's `UnsupportedOperation`,
not silently, so this needed no split from features 1/3.

**#47 stays addressed, not closed.** Once features 1-3 land and #51 is
filed, #47 has no remaining unassigned work, but whether to retitle it
to track only feature 4 or close it outright is a maintainer call this
PR doesn't make.

This explicitly **supersedes ADR-0006's fail-closed stance for features
1, 2, and 3**, and ADR-0006's Consequences bullet that tracked all four
features generically under issue #40 in the `fail_closed.rs` error
messages — #47 resolves that as adopt-origin-main + wire(1,2,3) +
defer(4, now tracked at #51).

## Consequences

- `vendor/microsandbox` carries substantially more vendored surface
  (`#9`-`#16`, roughly 8k lines) than ADR-0006's minimal-boot baseline
  did. This PR does not modify that vendored code, only integrates and
  consumes it; each of `#9`-`#16` is a separately merged, upstream-tested
  PR.
- `--auto-publish`, guest-proxy-via-env, and `--allow-lan`/
  `--allow-host`/`--allow-egress` are now functional rather than
  fail-closed. `fail_closed.rs` retains only the credential-injection
  guard.
- Host-credential injection (Anthropic/OpenAI/GitHub/Copilot token
  substitution) remains unavailable until gregwebs/agent-vm#51 wires
  agent-vm onto the baseline's `SecretSource`/`intercept()` APIs.
- V-P (proxy-env reaches the in-process netstack) and V-AP (auto-publish
  end-to-end, gen-8 embedded agentd) are e2e verifications this PR's
  code review establishes architecturally but could not run live in a
  macOS sandbox that can't boot Linux VMs; see the PR body / verification
  notes for what ran live vs. code-review-only.
