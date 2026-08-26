# ADR-0005: Defer the sea-orm/sqlx major bump to the 0.6.15 cutover

## Status

Accepted.

## Context

Issue #39 asked agent-vm to align its toolchain and direct persistence
integration so it could later consume Microsandbox v0.6.15 (issue #40)
without changing the currently shipped Microsandbox 0.5.7 runtime — an
"expand" step ahead of that "contract"/cutover. The acceptance criteria
included "persistence dependencies compatible with the v0.6.15
migration."

`agent-vm` links `sea-orm`/`sqlx` directly (in
`crates/agent-vm/Cargo.toml`) *and* links the vendored microsandbox
crates (`microsandbox`, `microsandbox-migration`, `microsandbox-image`),
which are frozen this PR at fork commit `c296b30` (workspace version
`0.5.7`). `msb_schema.rs`/`msb_preflight.rs` name
`microsandbox_migration::Migrator` and `sea_orm::{Database, Statement,
...}` directly. For those types to unify at compile time, agent-vm's own
`sea-orm`/`sqlx` deps must resolve to the **same version** the vendored
0.5.7 crates use — currently `sea-orm = "1.1"`, `sqlx = "0.8"`.

Per the plan for #39, before touching any Cargo.toml/Cargo.lock we
inspected `superradcompany/microsandbox`'s actual `Cargo.toml` at the
`v0.6.15` tag (the fork `agent-vm` vendors tracks this upstream). Its
`[workspace.dependencies]` pins, verbatim:

```toml
sea-orm = { version = "2.0.0", default-features = false, features = [
    "macros", "runtime-tokio-rustls", "sqlite-use-returning-for-3_35",
    "sqlx-sqlite", "with-chrono",
] }
sea-orm-migration = { version = "2.0.0", default-features = false, features = [
    "runtime-tokio-rustls", "sqlx-sqlite",
] }
sqlx = { version = "0.9", default-features = false, features = [
    "runtime-tokio", "tls-rustls", "sqlite",
] }
```

`sea-orm` 1.1 -> 2.0.0 is a semver-major jump; `sqlx` 0.8 -> 0.9 is a
breaking bump under the pre-1.0 convention this project already treats
as significant. The feature sets also reshaped (sea-orm gained `macros`
and `with-chrono`; sqlx's runtime feature renamed from
`runtime-tokio-rustls`+`sqlite` to `runtime-tokio`+`tls-rustls`+`sqlite`).

Pre-adopting sea-orm 2.0.0 / sqlx 0.9 in agent-vm now, while still
linking the frozen 0.5.7 vendored crates (pinned to 1.1/0.8), would do
one of two things: fail to compile (the `Migrator`/connection types
would no longer unify across the two dependency graphs), or — worse —
silently resolve to **two** incompatible `sea-orm`/`sqlx` entries in
`Cargo.lock`, one used by agent-vm's own code and one used transitively
by the vendored crates. Neither outcome is acceptable, and the second is
the kind of silent split this ADR exists to rule out by name.

## Decision

**Do not touch agent-vm's `sea-orm`/`sqlx` version requirements or
`Cargo.lock` in the #39 expand step.** They stay at `sea-orm = "1.1"` /
`sqlx = "0.8"`, matching the frozen vendored 0.5.7 workspace exactly.
`Cargo.lock`'s persistence-stack entries are verified unchanged (`git
diff --stat Cargo.lock` is empty for this PR).

**The persistence-dependency bump (sea-orm 2.0.0, sea-orm-migration
2.0.0, sqlx 0.9, plus their reshaped feature sets) is deferred to issue
#40**, the actual runtime cutover, where the vendored `microsandbox`
submodule pin advances to v0.6.15 at the same time. At that point
agent-vm's direct deps move together with the vendored workspace's own
pins in one atomic change, so the two never disagree about which
`sea-orm`/`sqlx` version to link.

#39's deliverable is therefore narrowed to its toolchain half only: the
Rust 1.94 pin (`rust-toolchain.toml`, `script/build/macos.sh`,
`script/test/build-workflow.sh`, `macos-build.md`, CI). This still pays
down real cost ahead of #40 — the toolchain bump is independent of the
persistence-dep bump and doesn't need to wait for it.

## Consequences

- Issue #39's AC "persistence dependencies compatible with the v0.6.15
  migration" is *not* satisfied by a dependency-version change in this
  PR — it can't be, while the vendored crates stay frozen at 0.5.7. It is
  satisfied in the sense that matters for the expand step: the exact
  target versions are now known and recorded (this document + the PR
  body), so #40 has no discovery work left, only the mechanical pin
  bump + `cargo update -p sea-orm -p sqlx -p sea-orm-migration` (or
  equivalent) alongside the submodule advance.
- `msb_schema::identifier_matches_pinned_bundled_schema` and the full
  preflight/doctor/recovery test suite (`msb_preflight.rs`,
  `tests/preflight_boot.rs`, `tests/doctor_reset.rs`,
  `tests/msb_passthrough.rs`) all pass unchanged under Rust 1.94 with
  the persistence deps untouched — direct evidence that deferring this
  half caused no regression to the AC-3/AC-4 guarantees.
- #40 now carries slightly more scope than a "pure pin bump" might have
  suggested going in: it must bump agent-vm's `sea-orm`/`sqlx` deps *and*
  adapt any call site in `msb_preflight.rs`/`msb_schema.rs` that a
  sea-orm 2.0/sqlx 0.9 API break touches (e.g. `query_all`, `try_get`,
  `Statement::from_string`, `SqlitePoolOptions`), in the same change that
  advances the vendored pin. This is intentional: the plan's own
  failure-mode table anticipated exactly this branch and named it as the
  correct outcome rather than a plan defect.
