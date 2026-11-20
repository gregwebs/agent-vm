# agent-vm-harness

Test-harness tooling (ADR-0072). The shell suites run this binary instead of
Python, so building and testing the repository needs no `python3` on the host.

- **Independent oracle.** This crate does not depend on `agent-vm` and keeps its
  own model of every format it reads or writes. A format change that breaks it
  is meant to fail, not to be deduplicated away. `agent-vm` may dev-depend on
  this crate, not the other way round.
- **One `harness` binary, one subcommand per port.** Scripts never call `cargo
  run`.
- **Boot-free checks are `#[test]`s**, run by `script/test/ci-contracts.sh` via
  `cargo test -p agent-vm-harness --locked`.

## Calling the binary from shell

Build once, then call it by path:

```sh
cargo build --locked -p agent-vm-harness --bins
"${HARNESS_BIN_DIR:-$REPO_ROOT/target/debug}/harness" --version
```

`HARNESS_BIN_DIR` overrides where the binary is looked up; `ci-contracts.sh`
exports it, read from `cargo metadata`, because `CARGO_TARGET_DIR` and a
configured `build.target` both move the binary. A script that cannot find it
should fail with a message naming the build command above, rather than falling
back to `cargo run`.

## Shell or Rust?

Shell sequences commands, checks exit codes, sets environment and paths, runs
simple `grep`/`sed`, and uses `jq` one-liners. Anything involving PTYs, signals,
timing, sockets, servers, concurrency, non-trivial parsing, hashing or building
structured data, or branching worth testing belongs here in Rust. The rule lives
in `CODING_STANDARDS.md`.
