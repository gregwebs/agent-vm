# ADR-0027: Adopt the v0.7.4 fork baseline

## Status

Accepted. Supersedes in part
[ADR-0006](0006-adopt-clean-v0.6.15-baseline.md) (its baseline choice: the
`origin/baseline/v0.6.15` tip and the thin
`integration/v0.6.15-agent-vm` branch built on it),
in part [ADR-0008](0008-migrate-0.5.7-state-to-v0.6.15.md) (its naming of the
migration target and its evidence base: v0.6.15's 24-migration schema and the
"three of the thirteen pending" transform census), and in part
[ADR-0009](0009-adopt-origin-main-network-features.md) (its two-branch framing:
`integration/v0.6.15-agent-vm` integrating `origin/main`). ADR-0006's other
decisions (deleting the `libkrun`-fork pin, official-identity `msb`
verification, the shortened macOS `MSB_HOME` and its fail-closed socket-path
preflight, whose checked-path scope is restated below) and ADR-0008's actual
answer (rely on the SDK's forward migration, add no migration engine) are
unchanged and still current.

## Context

ADR-0006 adopted the clean `origin/baseline/v0.6.15` submodule tip directly,
carrying exactly one re-ported commit (the agentd exit-on-shutdown fix) on a
thin `integration/v0.6.15-agent-vm` branch. ADR-0009 then combined that branch
with `gregwebs/microsandbox` `origin/main`, which carried the fork-only network
features on the same v0.6.15 merge-base. From ADR-0009 until this ADR the
vendored gitlink was `7e69a388`: v0.6.15 plus fork features.

That is no longer what agent-vm builds against. Upstream released v0.7.4, and
the fork's `main` tip is now `4246606a` — "chore: sync onto upstream v0.7.4 and
re-apply fork features (#47)". PR #184 moved the vendored gitlink there, which
also nudged the nested `vendor/libkrunfw` gitlink to `b5ff2425` and the official
crates.io `msb_krun*` cohort to 0.1.39.

The consequence is a framing problem, not just a version number. ADR-0006's
title *is* its main decision ("adopt the clean v0.6.15 baseline"), and its
status note only claimed supersession for the four fork-only network
capabilities (ADR-0009/0010). The baseline itself is now the fork's v0.7.4 tip.
The forked-mount behaviour ADR-0013/0014 define, the credential interception
ADR-0010 wires, and the network features ADR-0009 wires are all maintained by
*re-application onto 0.7.4* rather than by a 0.6.15-era merge-base. Similarly,
ADR-0008's question was "is the forward migration sufficient?", and its answer
was correct and worth keeping — but it described the destination as v0.6.15's
24-migration schema, which no longer names the supported path.

PR #184 also settled three baseline-level questions that have no ADR of their
own, so nothing recorded why they are the way they are:

- the SDK feature set is `local,net,keyring` with `download-binaries` off;
- agent-vm no longer embeds the guest `agentd`;
- the macOS socket-path preflight's canonical-control-only check relies on the
  runtime publishing legacy compatibility socket symlinks alongside the
  canonical ones.

## Decision

**The vendored baseline is the `gregwebs/microsandbox` `main` tip `4246606a`**:
upstream Microsandbox v0.7.4 plus the fork features re-applied onto it. The
nested `vendor/libkrunfw` gitlink (`b5ff2425`) and the official crates.io
`msb_krun*` 0.1.39 cohort move with it. This remains *the fork*, exactly as
ADR-0009 established: the pin is `gregwebs/microsandbox`, not upstream
`superradcompany/microsandbox`, because that is where the fork features
ADR-0009/0010/0013/0014 depend on are maintained. What changed is which
upstream release the fork features are re-applied to. Fork features are now
advanced by re-applying them onto a new upstream release, not by rebasing a
0.6.15-era branch across upstream drift.

**The SDK feature set is `local,net,keyring`, with `download-binaries` off**
(`crates/agent-vm/Cargo.toml`). `download-binaries` is the feature that would
let a build fetch an upstream msb+libkrunfw bundle at compile time; keeping it
off is what makes the from-source `msb` the only runtime agent-vm can link
against. That `msb` is built with `--no-default-features` and
`embed-binaries` on, by `script/build/macos.sh`
(`--features embed-binaries,net,ssh -p microsandbox-cli`) and by the
`build-msb` job in `.github/workflows/release-npm.yml`
(`--features embed-binaries,net,keyring -p microsandbox-cli`). `net` alone is not a compilable
feature set in the vendored SDK, so `local` stays on:

```
cargo check --no-default-features --features net -p microsandbox
```

fails to compile `sdk/rust/lib/sandbox/mod.rs`, where `Sandbox::port_events` is
gated on `net` but calls `Sandbox::client()`, gated on `local`. That unguarded
cross-feature call is an upstream defect this ADR does not fix; agent-vm
records the combination it builds with rather than claiming it is the minimal
one.
`microsandbox-runtime` keeps `default-features = false, features = ["client"]`
for the `ipc` module.

**agent-vm no longer embeds the guest `agentd`.** Up to 0.6.15 the vendored
`crates/filesystem/build.rs` called `build_agentd(...)` unconditionally, so
every agent-vm build compiled the guest agent into the host binary. Under
0.7.4 that path is gated behind `embed-binaries`, which only the `msb` CLI
(`microsandbox-cli`) enables. agent-vm now links the SDK's `local` backend,
which spawns the external `msb` binary, and `msb` is the single carrier of the
guest agent. Two build consequences follow: CI and the Verus job no longer
stage an `agentd`/`musl-tools` artifact before building agent-vm, and
`release-npm` builds `agentd` for each leg's own architecture, because 0.7.4
rejects an `agentd` whose ELF machine differs from `msb`'s — which the arm64
leg, carrying an x86 `agentd`, would have hit behind `continue-on-error`.

**The socket-path preflight stays canonical-control-only, and that soundness
now depends on the runtime's legacy compatibility symlinks.**
`msb_install::ensure_socket_paths_fit` checks exactly one derived path,
`paths.control`, and fails closed on overflow rather than truncating. That is
sound only while every socket path whose overflow fails boot is no longer than
it. 0.7.4's runtime publishes two layouts: the canonical
`run/sandboxes/<24-hex>/agent.sock` + `control.sock`, and the legacy
compatibility symlinks `run/agent/<32-hex>.sock` and
`run/agent/<32-hex>.control.sock`. The canonical `control.sock` (48 bytes past
the run dir) is longer than the boot-fatal legacy `<32-hex>.sock` (44 bytes);
the one longer path, the legacy `<32-hex>.control.sock` (52 bytes), only logs a
warning when it does not fit (`runner/vm.rs`'s `publish_control_endpoint`, which
warns on the `InvalidInput` that
`client/ipc.rs::publish_legacy_control_link` returns) and agent-vm never dials
it. This is a dependency on a runtime layout agent-vm does not own, so it is
re-derived from the vendored runtime in a test rather than asserted in a
comment.

**ADR-0008's answer is kept; its target and its evidence base are
restated.** The bundled schema is now `m20260922_000001` — 28 migrations, of
which 0.5.7's 11 are still an exact prefix — and the 0.7.4 pin adds
`m20260922_000001_migrate_secret_config`, whose
`microsandbox_db::compat::config::to_current` pass normalizes older catalog
spellings, including renaming `image.bind` to `image.Bind`. Rely on the SDK's
`Migrator::up`, build no migration engine, keep the ahead / unsafe-path /
partial / locked fail-closed layering exactly as ADR-0008 specified.

ADR-0008 justified that answer with a census of the pending migrations: of the
thirteen then pending, three transformed existing rows in place. That census no
longer holds either. The forward set from the 0.5.7 prefix is now seventeen,
and four migrations have been added since
(`m20260818_000001_sandbox_network_slot`,
`m20260829_000001_split_snapshot_identity`,
`m20260910_000001_snapshot_groups`,
`m20260922_000001_migrate_secret_config`). Three of the four write row data in
`up()` as well as changing DDL:

- `sandbox_network_slot` backfills `network_slot = id` for sandboxes that are
  still active and clears it for terminal ones.
- `split_snapshot_identity` adds `snapshot_id` and `descriptor_digest` and
  backfills both from `digest`.
- `snapshot_groups` rebuilds `snapshot_index` and moves the primary key from
  `digest` to `artifact_path`, copying the shared column list verbatim. That key
  move is the one real hazard of the three: a pre-existing duplicate
  `artifact_path` would violate the new key. It fails loudly as a migration
  error rather than silently dropping a row.

`migrate_secret_config` is the fourth, and is the normalization described
above. Note that `sandbox_network_slot` carries `affects_user_data: false`
despite writing rows — the concrete instance of ADR-0008's warning that the
flag tracks `down()` impact, not `up()`, which is why the `up()` behaviour
above is read from the migrations themselves.

The hermetic test in `crates/agent-vm/tests/msb_migration_0_5_7.rs` drives the
whole chain over a seeded 0.5.7 database, so all four do run over the seeded
sandbox and snapshot rows and those rows survive. Its post-transform assertions
still cover only ADR-0008's three (plus the `image.Bind` shape the new
normalizer produces), leaving `sandbox_network_slot`'s `network_slot` backfill,
`split_snapshot_identity`'s backfilled values, and `snapshot_groups`'s rebuilt
key unasserted. That is a coverage gap by ADR-0008's own standard (assert the
post-transform shape, "not merely 'row present'"), and this ADR records it as
one rather than assuming the older analysis transfers.

### Pinned by

- `msb_install::tests::expected_msb_version_reads_the_vendored_workspace_version`
  pins the literal `"0.7.4"` that `verify_official_identity` compares `msb
  --version` against, deliberately not derived from `expected_msb_version()`,
  so a pin bump that leaves the check behind fails here.
- `msb_install::tests::canonical_control_socket_bounds_every_boot_fatal_socket_path`
  re-derives `sandbox_socket_paths` from the vendored runtime and asserts the
  checked canonical control socket is at least as long as every boot-fatal
  agent path, so a pin bump that changes the socket layout fails here.
- `crates/agent-vm/tests/msb_migration_0_5_7.rs` pins the 28-migration head, the
  11-migration 0.5.7 prefix, and the post-normalization `image.Bind` shape.
- `script/check-runtime-provenance.py` pins the `msb_krun*` 0.1.39 cohort and
  the firmware gitlink against both resolution roots.

## Alternatives considered

- **Edit ADR-0006, ADR-0008 and ADR-0009 in place** to describe v0.7.4 as their
  original decision. Rejected. It would rewrite history to claim a decision
  those ADRs did not make, and it discards the record of why the 0.6.15
  baseline was adopted at all — which is exactly the reasoning a future "should
  we re-fork `libkrun`?" question needs. The established convention here is a
  status line pointing forward (ADR-0006 → 0009/0010, ADR-0013 → 0014).
- **Status-line-only supersession** on 0006/0008/0009 with no new ADR.
  Rejected. It is cheaper, but it leaves the feature set, the `agentd`
  ownership change, and the socket-layout dependency uncaptured, and would have
  to hang them off an ADR that is only about Basic-auth substitution
  (ADR-0026).
- **Turn `download-binaries` on** so agent-vm could use a released upstream
  `msb`+`libkrunfw` pair instead of building one. Rejected for the same reason
  as in ADR-0006: agent-vm must not consume a binary bundle it did not build
  from the pinned submodule, and the provenance check exists to make that
  observable rather than assumed.
- **Require an explicit `MSB_AGENTD_PATH`** now that agentd is external.
  Rejected. It would move a working build-time invariant (the `msb` agent-vm
  already drives carries the matching agent) onto every operator.

## Consequences

- `docs/adr/0006-adopt-clean-v0.6.15-baseline.md`,
  `docs/adr/0008-migrate-0.5.7-state-to-v0.6.15.md` and
  `docs/adr/0009-adopt-origin-main-network-features.md` stay in place as
  historical records with a supersession pointer naming what no longer applies.
- A future upstream release is adopted by re-applying the fork features onto it
  in `gregwebs/microsandbox` and moving the gitlink — the same shape as PR #184.
  The fork features are no longer tied to a 0.6.15 merge-base, so ADR-0009's
  "diverged at the v0.6.15 release merge-base; neither is a superset"
  description of the two branches is historical too.
- The socket-path preflight now carries a cross-repository invariant: if a
  future pin stops publishing the legacy `<32-hex>.sock` symlink, or makes the
  canonical control socket shorter than a boot-fatal path, the re-derivation
  test fails and the preflight must be widened. This ADR does not claim the
  layout is stable.
- Reverting the vendored pin past 0.7.4 re-introduces the unconditional
  `agentd` embed, so the CI staging steps dropped here would have to come back
  with it.
- The `agentd` ELF-architecture rule means the release matrix now builds
  `agentd` per target rather than once, which is slower and is why the arm64
  leg's mismatch is no longer masked.
- The bundled schema id moved from v0.6.15's `m20260824_000001` to
  `m20260922_000001`. The ahead-guard's block message names it, so an operator
  rolling between builds sees the new id, and the existing recovery path
  (`doctor --reset-msb-db`) is unchanged.
- The 0.5.7 -> v0.7.4 forward path is exercised end to end, but three of the
  four migrations added after ADR-0008 have no assertion of the row data they
  write. Extending `msb_migration_0_5_7.rs` to cover `sandbox_network_slot`'s
  `network_slot` backfill, `split_snapshot_identity`'s backfilled
  `snapshot_id`/`descriptor_digest`, and `snapshot_groups`'s rebuilt
  `artifact_path` key is the obvious follow-up (asserting
  `group_name`/`group_path` would prove little — both are NULL for a migrated
  row); until it lands, ADR-0008's row-level evidence covers the older three
  migrations, not these.
