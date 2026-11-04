# ADR-0059: User tool requests as egress authority

## Status

Accepted design for [#506](https://github.com/gregwebs/agent-vm/issues/506), not
implemented. Partly reverses [ADR-0039](0039-non-authoritative-tool-network-requests.md)'s
"requests as authority" rejection; amends
[ADR-0040](0040-persisted-user-network-authority.md)'s shared verified read.

## Context

Users repeat a tool's `network_requests` by hand in `allow_egress`. ADR-0039
kept requests non-authoritative because a repository can declare them: granting
them would let a repo widen access.

## Decision

An `allow_egress` entry (persisted or `--allow-egress`) may be an **egress
reference**: `tool:NAME` grants that tool's own `network_requests`, each as an
exact `tcp://HOST:PORT` hostname allowance; `set:NAME` selects a user
`[egress_sets]` entry (second slice).

`tool:NAME` resolves **only** against tools declared in the user config file.
Never the project tier, even when the project's definition is the launchable
verb, and never the built-in catalog. A user who wants the shipped requests
prints the shipped tools (`agent-vm tools print`) into their own file. Granted
authority therefore changes only when that file is edited, never on upgrade or
by a repository.

- Own requests only, not the `tools` closure: `tool:shell` would otherwise
  grant every tool's requests.
- An unknown name, or a user tool with no requests, is a config error at load
  (or before boot, for the CLI).
- A CLI `tool:` reference requires the user file to pass ADR-0040's verified
  read, so a guest-plantable symlinked tools-only config cannot supply authority.
  Tools-only symlinks keep working when no reference is used.
- `[egress_sets]` is a fourth authority-bearing field in the shared presence
  check.
- Expanded names inherit ADR-0040's host-proxy refusal; the refusal names the
  reference.
- Notices and `doctor` attribute each expanded name to its reference(s).

## Considered options

- **Bare tool names** in `allow_egress`: `codex` is already a valid single-label
  hostname, so meaning would change when a tool is added.
- **Resolve through the merged catalog**: when only the project declares tools,
  the launchable `codex` is the repository's.
- **Built-in fallback** when the user declares no tools: a release could widen
  persisted authority without the user's file changing.
- **YAML anchors** instead of sets: file-local, define-before-use, cannot reach
  another file, and erase the named origins diagnostics report.

## Consequences

Declaring any user tool still replaces the whole built-in catalog, so using
`tool:` in practice means copying all shipped tools; the print command exists
to make that one paste.
