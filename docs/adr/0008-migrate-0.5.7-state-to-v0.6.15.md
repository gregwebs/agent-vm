# ADR-0008: Rely on the SDK's forward migration for the 0.5.7 -> v0.6.15 state upgrade; add no new migration engine

## Status

Accepted.

## Context

ADR-0006 adopted the clean, unforked Microsandbox v0.6.15 baseline.
Issue #42 asked agent-vm to migrate an existing agent-vm user's
Microsandbox state — `MSB_HOME/db/msb.db`, plus the on-disk image
cache and snapshot artifacts it indexes — from the pre-#40 `0.5.7`
fork's schema to v0.6.15's, "without silent loss," stable across
repeated restarts, and with fail-closed handling for ahead, partial,
locked, and unsafe-path state.

Two questions had to be answered before deciding what (if anything) to
build:

1. **Is 0.5.7's schema actually a strict subset of v0.6.15's?** If not,
   a real translation layer would be needed.
2. **What already prevents destructive behavior**, and where are the
   remaining gaps?

### The 0.5.7 schema is an exact 11-migration prefix of v0.6.15's 24

Verified directly from the vendored submodule: 0.5.7's release commit
(`4dbb712b`) carries exactly 11 sea-orm migrations, name-identical to
and in the same relative order as the first 11 entries of the vendored
v0.6.15 `Migrator::migrations()` (`crates/migration/lib/lib.rs`):

```
m20260305_000001_create_image_tables
m20260305_000002_create_sandbox_tables
m20260305_000003_create_storage_tables
m20260305_000004_create_sandbox_images_table
m20260410_000001_erofs_image_schema        <- already drops/replaces the
                                               migration-1/4 image tables
                                               with the EROFS-era catalog
                                               (manifest/image_ref/config/
                                               layer/manifest_layer/
                                               sandbox_rootfs) WITHIN 0.5.7
                                               itself
m20260501_000001_create_snapshot_index
m20260517_000001_drop_sandbox_metric
m20260527_000001_migrate_oci_rootfs_source
m20260531_000001_create_sandbox_labels
m20260531_000002_index_sandbox_labels_key_value
m20260606_000001_named_volume_kinds        <- 0.5.7 ends here
---
m20260621_000001_add_sandbox_ephemeral
m20260621_000002_create_maintenance_lease
m20260703_000001_add_sandbox_active_config
m20260708_000001_migrate_bind_rootfs_source     (transforms sandbox.config)
m20260710_000001_migrate_root_disk              (transforms sandbox.config)
m20260714_000001_add_snapshot_scope
m20260723_000001_snapshot_artifact_transition   (rebuilds snapshot_index)
m20260719_000001_create_cpu_allocations
m20260803_000001_create_writeback_allocations
m20260808_000001_create_memory_allocation_nodes
m20260810_000001_rebuild_sandbox_labels
m20260813_000001_share_cpu_allocations
m20260824_000001_mount_owner_config
```

sea-orm's own migration-status check is set-based
(`seaql_migrations`, one row per applied migration): a DB carrying a
strict subset of a build's known migration set is *behind*, never
*ahead*, and `Migrator::up` simply applies the remaining ones in
order. A 0.5.7 `msb.db`, opened by the vendored v0.6.15 `msb`, is
exactly this case. Three of the thirteen pending migrations transform
existing rows in place rather than only changing DDL
(`m20260708_000001_migrate_bind_rootfs_source`,
`m20260710_000001_migrate_root_disk`,
`m20260723_000001_snapshot_artifact_transition` — flagged
`affects_user_data: true` for *downgrade* purposes in
`schema_metadata.rs`, which happens to also identify them as the
forward-transform set here, though that is not a general rule: the
flag documents `down()` impact, not which migrations have a nontrivial
`up()`).

**One schema transition happens with no forward data carry-over**:
`m20260410_000001_erofs_image_schema` *drops* the `image`/`index`/
`sandbox_image` tables from migrations #1/#4 and creates a fully
different EROFS-era catalog. This is not an agent-vm-introduced loss —
it happened within 0.5.7's own migration history, before any 0.5.7
release existed, so every real 0.5.7 database is already on the
EROFS-era catalog schema by the time agent-vm ever sees it.

### What already exists to prevent destructive behavior

Prior work (#28/#30/#33/#36/#40, ADR-0004/0006) built detect-and-recover
scaffolding for the **ahead** direction and a fail-closed guard for
**unsafe** socket paths, but never exercised an actual 0.5.7-vintage
database through the vendored `Migrator`, and the "locked"/"partial"
mechanism descriptions in earlier planning conflated agent-vm's own
guard with the SDK's separate one (see Decision, "Layer ownership"
below).

## Decision

**Do not build a new migration engine, translation layer, or
namespaced-home scheme.** The SDK's own `Migrator::up`
(`microsandbox-migration`, already an agent-vm dependency) is the
entire forward-migration mechanism; agent-vm's job is verification
that it is safe for the 0.5.7 case, plus the fail-closed layer around
it agent-vm already owns.

**Verify the forward migration hermetically** in
`crates/agent-vm/tests/msb_migration_0_5_7.rs`, driving
`microsandbox_migration::Migrator::up` directly against a temp-file
SQLite DB (no `msb` binary, no VM, structurally incapable of touching
`MSB_HOME`):

- Build the pinned 0.5.7 schema (`up(Some(11))`), seed representative
  image/sandbox/volume/snapshot rows in the REAL 0.5.7 value shapes the
  three data-transform migrations consume (not a minimal
  constraint-satisfying shape, which those migrations' `up()`s would
  silently skip, leaving the assertion vacuously green), then run
  `up(None)` and assert: exactly the bundled 24 migrations applied
  (AC-1), the seeded rows survive with their *post-transform* shape
  intact — not merely "row present" (AC-3).
- Run `up(None)` twice more on the already-migrated DB and assert the
  applied set and the representative rows are unchanged (AC-2).
- Separately assert `schema_metadata::canonical_applied_prefix` (the
  set-based prefix check the SDK's `connect_and_migrate` actually runs,
  via `refuse_schema_ahead`, *before* `Migrator::up`) accepts the 0.5.7
  id set and every leading subset of it, and rejects an unknown/ahead
  id. Driving `Migrator::up` alone is not the full boot gate — a green
  `up()` test could still coexist with a red production boot if this
  set-based check ever rejected the 0.5.7 prefix, so this is tested
  directly rather than assumed.

**Layer ownership for the four fail-closed states (AC-4)** — unchanged
from ADR-0004/0006's existing boundaries, made explicit here:

| State | Trigger | Owner | Mechanism |
|---|---|---|---|
| ahead | an applied `seaql_migrations` row this build's `Migrator` doesn't know | agent-vm (`msb_preflight.rs`) | plain `SELECT`, compares against the bundled set, bails with a named message before the SDK ever opens the DB; `agent-vm doctor --reset-msb-db` moves `db/` aside, never deletes |
| unsafe-path | this sandbox's real `control.sock` path would overflow `sockaddr_un.sun_path` | agent-vm (`msb_install::ensure_socket_paths_fit`, issue #40) | fails before `session.ensure_dirs()`, i.e. before any state directory exists to touch; never truncates |
| partial | an incomplete self-downgrade journal, or an active install-exclusive lease | the SDK (`connect_and_migrate`'s `refuse_incomplete_self_downgrade` / `refuse_if_install_exclusive_held`) | named error, DB never opened |
| locked | another process holds the SDK's migration-lock flock (`db/msb.db.migration.lock`) | the SDK (`connect_and_migrate`'s `acquire_migration_lock`) | named error/blocks; agent-vm's own preflight is a *different*, unrelated `SELECT` against `msb.db` itself (not the lock file) and fails open on any reason it can't complete that read (missing table, corrupt file, or a locked file) rather than trying to detect the lock itself |

agent-vm's preflight deliberately does **not** attempt its own lock
probe: the migration lock is a separate flock file from `msb.db`, so a
probe here would race the SDK's own lock rather than observe it, and
risks a false block on a transient, benign contention. The existing
fail-open unit tests for an unreadable `msb.db` (missing
`seaql_migrations` table, non-SQLite/corrupt file) already cover the
generic "could not read, so proceed" branch a lock error would also
hit; a dedicated lock simulation would only be re-testing sqlx's
default `busy_timeout` retry/give-up behavior, not agent-vm logic.

No path in agent-vm or the SDK auto-deletes or auto-resets state.
Reset is only ever the operator running `doctor --reset-msb-db`, which
moves `db/` aside rather than deleting it.

**AC-5's "recovery guidance and doctor behavior identify the active
schema-scoped home"** is read as: *name the currently-active `MSB_HOME`
and the schema id this build understands*, not as a request to
reintroduce schema-namespacing of `MSB_HOME` — ADR-0004/0006
deliberately removed that, and this ADR does not revisit it. Issue #42
postdates both ADRs, so the wording is treated as loose, not a request
to relitigate. `agent-vm doctor` (no flag) now prints the resolved
`MSB_HOME`, the `db/msb.db` path, whether it exists, and this build's
bundled schema id (`doctor::describe_home`); the ahead-guard's block
message already named the db path and this build's schema
(`msb_preflight.rs::ahead_message`, unchanged here).

## Consequences

- No new schema-translation code, no new on-disk layout, no Cargo.toml
  production dependency changes: the upgrade path that already exists
  (SDK forward migration + agent-vm's existing ahead/unsafe-path
  guards) is now proven correct for the concrete 0.5.7 case rather than
  assumed.
- The hermetic `Migrator::up` test seam gives real row-level coverage
  for images (catalog rows untouched by the forward set), sandbox
  records (both `affects_user_data` config transforms), and named
  volumes (columns already final as of the 0.5.7 prefix, untouched
  after). **Snapshot *usability* is more weakly covered**: the seam
  proves the `snapshot_index` row survives `m20260723_000001`'s
  rebuild in its correct post-transform shape, but does not exercise
  the SDK's `reconcile_managed` on-disk artifact reconciliation
  (`connect_and_migrate`, after `Migrator::up`) — that remains a
  manual-live-boot-only check, the same posture ADR-0006 already took
  for Linux boot.
- Developers/operators who roll back to an older agent-vm build after a
  newer one has forward-migrated `msb.db` still hit the **ahead** guard
  and recover via `doctor --reset-msb-db`, per ADR-0004 — unchanged by
  this ADR.
- `docs/USAGE.md`/`README.md` gain a short note that the 0.5.7 -> v0.6.15
  upgrade is automatic on first boot, and that rolling *back* after a
  forward migration hits the same named ahead-guard as any other
  cross-build schema mismatch.
