# ADR-0072: No host Python — repo tooling is Rust, or shell for straightforward automation

## Status

**Accepted, not yet implemented.** About 14k lines of test tooling are Python
(21 tracked `.py` files, about 120 inline `python3` calls in shell, and two Rust
tests that run `python3`). Each is ported one area at a time.

## Decision

Building and testing the repository must not need `python3` on the host.
Everything that is Python today becomes either Rust or shell.

- **Shell is limited to straightforward automation.** That means sequencing
  commands, checking exit codes, setting environment variables and paths, simple
  `grep`/`sed`, and `jq` one-liners that pull out fields. Anything involving PTYs,
  signals, timing races, sockets, servers, concurrency, non-trivial parsing,
  hashing or building structured data, or branching worth testing goes to Rust.
  `CODING_STANDARDS.md` states this rule.
- **The Rust lives in one crate, `crates/harness` (`agent-vm-harness`,
  `publish = false`).** It has a shared library and one `harness` binary whose
  subcommands replace the Python drivers, so shell calls one prebuilt path
  (`$HARNESS_BIN_DIR/harness`) and never `cargo run`. Boot-free **harness
  checks** are `#[test]`s, run from `script/test/ci-contracts.sh`.
- **The harness is an independent oracle.** It does not depend on the `agent-vm`
  crate, and it keeps its own minimal model of every format it reads or writes.
  A format change that breaks the harness is supposed to fail; it is not
  duplication to remove. In the other direction, `agent-vm` may dev-depend on
  the harness.
- **The harness is synchronous.** It uses std threads and sockets, `rustix`, and
  `rusqlite` linking the workspace's existing `libsqlite3-sys`. It uses no
  async runtime and no HTTP crate, because the fixtures deliberately control
  wire bytes.
- **A CI guard keeps Python out.** `script/test/no-host-python.sh` fails on a
  tracked `*.py` file, on a `python` call in a `*.sh` or `*.rs`, and on a
  `*.sh`/`*.rs` that reaches a `.py` file, unless
  `script/test/host-python-allowlist.txt` excuses it. The ledger records how many
  occurrences each listed file is allowed, so a new call in an already-listed
  file fails, and an entry that excuses too much or nothing fails as well: the
  list cannot outlive the Python it excuses.

## Exceptions

Python that runs inside the guest stays, and is on the guard's allowlist:

- the CPU-evidence workload (`WORKLOAD_SCRIPT` in
  `crates/agent-vm/src/cpu_evidence/native.rs`), because shell can't hold a
  precise duty cycle;
- the guest side of `script/test/fixtures/egress-probe.sh`, which uses Python
  for its TLS and socket probes and falls back to `node`.

In both cases a Rust replacement would need a guest cross-compile target.
Revisit these if the guest image drops Python.

One open hole, so it is recorded rather than hidden: the boot-free
`script/test/lib/egress-probe-contract.py` calls `tls_probe`, `opaque_send` and
`server_first` from `egress-probe.sh` **on the host**, against a local listener,
and each of those runs `python3`. When that suite becomes a harness check, the
probe's host half has to become Rust too, or the ported check has to drop the
host-run rows and leave them to the guest suite. That is the egress tickets'
problem to settle, and until then no host-only `python3` may hide in that file.

Upstream's own Python is out of scope, like the libkrunfw build's `pyelftools`:
`profiling/*.sh` run libkrunfw's `bin2cbundle.py`, which this repository does not
own.

## Migration

The port is bottom-up. When a shared Python module is ported, its Python copy
stays, still on the allowlist, until its last Python caller is ported. There
is no glue from Python to the new Rust.

## Considered options

- **Keep Python for test tooling.** It is terse and has a rich stdlib. Rejected:
  it adds a second language and toolchain that reviewers must know. Its
  failures show up at runtime rather than at compile time. And the PTY, signal
  and socket code is exactly where Rust's types catch mistakes.
- **Put the harness inside `crates/agent-vm`.** Rejected: test tooling would
  ship in release builds, and the tests would grade production code against
  production's own definitions.
