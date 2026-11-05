# ADR-0059: User tool requests as egress authority

## Status

`tool:NAME` implemented in [#506](https://github.com/gregwebs/agent-vm/issues/506);
`set:NAME` remains [#511](https://github.com/gregwebs/agent-vm/issues/511). Partly
reverses [ADR-0039](0039-non-authoritative-tool-network-requests.md)'s "requests
as authority" rejection; amends
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

## Implementation notes (#506)

The operational reference is [USAGE → Egress references (user
tools)](../../USAGE.md#egress-references-user-tools). What is worth recording
here is the shape, and the one part that is machine-checked.

**Routing is a proved kernel, and it is the only new contract.**
`egress_reference::reference_claim` decides which grammar one `allow_egress` text
is handed to: `tool:` in any ASCII case, not followed by `//`. It reuses
`egress_grammar::ci_prefix`/`lower`, so "case-insensitive" means one thing across
`tcp:`, `udp:` and `tool:`, and it excludes `//` exactly as `tcp_scheme` does, so
`tool://host` keeps the allowance grammar's `UnsupportedScheme`. Its
`ensures` also states `claimed ==> len >= 5`, which is what makes
`AllowanceEntry::parse`'s `&text[5..]` slice safe *and* a `char` boundary (the
five claimed bytes are ASCII). No existing `verus!` item changed; the repo gate's
verified count went from 202 to 203.

Two reasons the kernel is not inside `egress_grammar`: that module's contract is
"shared allowance syntax must not depend on launch authority", and
`NetworkRequests::parse` reuses `Allowance::parse` while requests must keep
rejecting references (R24).

**The name rule is shared, not restated.** `tool_name_rejection` was extracted from
`config::validate_name`, and `validate_name` now maps it back to the same
`declaration_error` bytes. A reference accepts `NAME` iff `[[tools]]` would, so
`tool:help` is *malformed* (one fixed text) while `tool:nosuchtool` is *unknown*.

**Expansion re-enters the proved grammar.** Each request is rendered as
`tcp://HOST:PORT` and parsed by the unchanged `Allowance::parse`, so a reference
cannot construct an allowance the grammar would refuse, and every expanded
hostname still passed `split_scheme`/`split_target`/`egress_hostname_bytes`/
`hostname_scope`. The port is always explicit, including 443, so an expanded name
is never bare and never inherits the launch's other intercepted ports. A37's
source guard pins the re-parse, and only the call site. `egress_reference.rs` is
production-only by construction — its tests and every test-only helper live in
`egress_reference/tests.rs` — and the guard reads that file twice: ten forbidden
tokens may not appear on any line that is not a leading `//` comment, and the
text from `fn expand(` through the next column-0 `}` must contain
`Allowance::parse(`. That is a token scan plus a formatting-limited region: not a
lexer, not an AST, not a proof. It does not show that the parsed allowance is the
one returned, it does not reason about macro expansion, it fails closed when it
cannot delimit the region, and an edit that also edits it defeats it. It exists
because no value test can tell a re-parse from an equivalent direct constructor;
the guard **plus review** are what pin the re-parse.

**Parsing and resolution are two steps, on purpose.** The persisted path must
report a `[network]` *syntax* error before a tool-validation error and a
*resolution* error after it, so `user_network::from_verified_table` returns a
`ParsedUserNetwork` and `config::read_file_tier` calls `ParsedUserNetwork::resolve`
once `validate_tools` has run. Both paths then call the same
`egress_reference::resolve` — nothing else turns a reference into allowances.

**The namespace is one construction site plus a runtime filter.**
`UserToolRequests` is built only in `read_file_tier`'s user arm, from that tier's
own validated tools, before the cross-tier merge and before the defaults catalog.
`UserToolRequests::new` then keeps a tool iff its origin is
`ToolOrigin::User(f)` for the file the trust verdict measured — a *runtime*
check, because two reads of one path carry equal `PathBuf`s and no type can tell
them apart. Project tools, the built-in catalog and the `shell` fallback are
therefore unreachable even when a project declares the launched verb.

**The verified read is measured on every user read.** `config_authority::verify`
now measures even when no authority-bearing field is present, and returns both
`authorized` (still `Some` only by presence, which is unchanged) and a
`ReferenceTrust` that owns its file and verdict. Load-time refusal is still by
presence, so a tools-only dotfile symlink loads as before; the verdict waits,
unused, for a CLI reference to consult it in `resolve`. That is what keeps
"one read, one observation" true for a decision (`--allow-egress`) that is only
known after argv is parsed.

**The compatibility break is disclosed, and it is not fail-closed.** Every
ASCII-case variant of `tool:P` for canonical decimal `P` in 1–65535 except 53 and
853 used to be the hostname `tool` on port `P`. If the user config declares a tool
named `P` with `network_requests`, the entry now silently grants that tool's
requests — possibly different hosts and ports. Otherwise it is an error. Formerly
invalid texts (`tool:0`, `tool:0443`, `tool:53`, `tool:65536`) can now resolve too.
USAGE carries an upgrade note; the fix is `tcp://tool:P`, written before
upgrading.

The reference rule is kept ahead of the grammar even though that is what makes the
break awkward: every `tool:` text is claimed first, and only then does the name
rule decide. So `tool:443` and `tool:0` are **both** references now —
`tool:443` names a tool called `443`, and the old hostname allowance `tool` on
port 443 is written `tcp://tool:443`. The **old** grammar read `tool:443` as that
hostname allowance and refused `tool:0` as an invalid port. A *hypothetical*
grammar-first rule would read `tool:443` as the hostname but `tool:0` as a
reference, so a numeric tool name would be referenceable only when it is not a
valid port: unpredictable, and worse than one disclosed rule.

**Diagnostics attribute each expanded name.** The hostname notice tag becomes
`persisted grants via tool:X` / `--allow-egress via tool:X`, with `directly and
via` when a literal spelling also grants the name, and `render_list`'s
`a, b and c` grammar for several references. Tags appear when a user `[network]`
exists (as before) or when any CLI reference was used; with no reference every
notice line is byte-identical to 0.7.30. The host-proxy refusal gains
`, including via tool:X,` in the same condition, and `doctor` gains a
`persisted egress references in "<file>" [network]:` block listing each
reference's expansion (user-authored authority, so it is listed, not bounded like
ADR-0039's repository metadata).
