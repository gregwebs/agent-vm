# ADR-0059: User tool requests as egress authority

## Status

`tool:NAME` implemented in [#506](https://github.com/gregwebs/agent-vm/issues/506);
`set:NAME` implemented in [#511](https://github.com/gregwebs/agent-vm/issues/511).
Partly reverses [ADR-0039](0039-non-authoritative-tool-network-requests.md)'s
"requests as authority" rejection; amends
[ADR-0040](0040-persisted-user-network-authority.md)'s shared verified read.

## Context

Users repeat a tool's `network_requests` by hand in `allow_egress`. ADR-0039
kept requests non-authoritative because a repository can declare them: granting
them would let a repo widen access.

## Decision

An `allow_egress` entry (persisted or `--allow-egress`) may be an **egress
reference**: `tool:NAME` grants that tool's own `network_requests`, each as an
exact `tcp://HOST:PORT` hostname allowance; `set:NAME` grants the closure of a
user `[egress_sets]` entry — its literals, its `tool:` expansions and its nested
sets, compiled once at load.

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
`EgressNamespace` is built only in `read_file_tier`'s user arm, from that tier's
own validated tools, before the cross-tier merge and before the defaults catalog.
`EgressNamespace::new` then keeps a tool iff its origin is
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

## Implementation notes (#511)

The operational reference is
[USAGE → Egress sets (user config)](../../USAGE.md#egress-sets-user-config). What
is worth recording is the shape, the two places this slice deliberately reuses a
proved rule, and the one compatibility claim.

**A second claim kernel, and the count.** `egress_reference::set_reference_claim`
is `reference_claim`'s exact shape over a four-byte `set:` prefix, `//` exclusion
included, because `set://host` is a scheme the allowance grammar refuses and must
keep refusing. The two claims are disjoint — the third byte differs — which is why
`AllowanceEntry::parse` may ask them in either order; A3 checks that
differentially and by construction. The repo gate's verified count went from
**203 to 206**: the pair `set_reference_claim_spec`/`set_reference_claim`, the
constant `MAX_EGRESS_SET_EXPANSION_WORK`, and
`egress_set_expansion_work_allowed`. (A `pub const` inside a `verus!` block counts
as one verified item; adding a probe constant took the count 206 → 207 and was
reverted. The expected 205 in the plan assumed the constant did not count.)

**The name rule is reused, not restated.** An egress-set name is accepted iff
`config_mounts::mount_set_name_bytes` accepts it, and nothing else is: one proved
byte rule for both named-set namespaces, checked differentially by
`set_reference_names_match_mount_set_names`. The *type* is separate
(`EgressSetName`), so a mount-set name cannot reach an egress lookup, and the
sentence is not shared (it says "an egress-set name"), so a refusal cannot name
the wrong table.

**Parse and compile are two steps, beside `[network]`'s two.**
`egress_reference::parse_sets(&AuthorizedConfig, &toml::Value)` is token-gated, so
no definition is read unverified: names (sorted, reserved, grammar), schema, every
entry through the one `AllowanceEntry::parse`, set→set binding and the cycle walk
all happen after the `[network]` *parse* block and before `validate_tools`;
`tool:` resolution inside a set and the budgeted closure merge happen inside
`EgressNamespace::new`, after `validate_tools`. The rule is: references **from
outside** the table resolve at use; references **within** it are bound at parse,
because the cycle walk needs edges.

**Streaming precedence, not a re-ordered pass.** Sets compile in the walk's
postorder and entries in declaration order, so the first failure — an entry error
or budget exhaustion — wins. A pre-resolution pass could promise "every syntax
error before any budget error", at the cost of a second traversal and a second
place the budget is spent; the tests pin the streaming order in both directions.

**One budget, charged before the probe.** `ExpansionWork` is created per load,
never reset, and admits one *candidate allowance*: a literal entry, each allowance
of a `tool:` expansion, each allowance of a child set's closure. A repeated
`tool:`/`set:` in one definition is skipped before it is charged, and dedup is a
`HashSet<Allowance>` — so the admitted work is 65,536 hash probes and inserts
rather than a quadratic scan. Two bounds follow: every closure in the file
together holds at most the admitted visits, and R23's one-application rule keeps a
tier's *insert* work proportional to its distinct references. The first is checked
by the boundary tests; the second is observed through `ResolvedAllowances.insertions`,
because re-applying a cached expansion per repeat grants exactly the same
allowances and would otherwise be invisible.

**What the second bound is not.** `insertions` counts `insert` calls; the row
lookup that decides a repeat is `reference_index`, and that is a linear scan over
the rows seen so far. So a repeat costs one probe *per repeat* — file-bounded, not
constant time — and a selected empty set costs no visits at all while still paying
one scan. Total resolver CPU is therefore not bounded by the reference count, and
`insertions` must not be read as one. An index over those rows is a follow-up
beside the pre-existing quadratic scan in `insert` that #511's non-goals leave
alone; neither is a grant bypass, because both are work, not authority.

**Cycles name the closing entry, and the walk is iterative.** The colour kernel is
reused (`config_mounts::sets::visit_decision`/`VisitState`), so "is this edge a
cycle, a descent, or shared structure?" has one proved answer for both graphs; the
traversal is a ~35-line explicit-stack walk over every definition as a root, so a
cycle in a component nothing references is still refused, and a 10,000-set chain
loads on a 2 MiB stack. `config_mounts::sets::validate_references_and_cycles` is
deliberately **not** reused: it is typed over mount definitions and pinned by its
own mutation rows, and two instances is under the "wait until 3" threshold.

**Attribution is entry level.** A set reference is an ordinary reference row whose
expansion is the precompiled closure, so `phrase`, `render_list`, `including_via`,
`hostname_authority` and `describe_egress_references` needed no change: the tag
names `set:agents` and never `set:corp`, and `doctor` shows what the nesting
grants by flattening it. Chains are not named because a diamond has several, depth
is bounded only by the number of sets, and the entry-level reference is the thing
a user deletes to revoke.

**The A37 guard grew one file, not one weaker rule.** `egress_reference/sets.rs`
is production-only by the same construction (its tests live in
`egress_reference/sets/tests.rs`), and it is scanned for the same ten forbidden
tokens plus one file-specific obligation, `Allowance::parse(`. The token means the
opposite in the two files — `egress_reference.rs` *must* call `Allowance::parse(`
in `fn expand` — which is why it is a separate list with its own oracle and its own
self-test cases.

**What that scan is, and is not.** It is a pattern check over the file's text, so
it catches the obvious edit and nothing more: a token split across lines, an `as`
alias, a `macro_rules!` wrapper, a helper in the parent module, and a `//`-leading
line that closes a block comment opened earlier all mint an allowance with the scan
green (five measured, review B). The test is named for what it checks
(`the_set_graph_source_contains_no_forbidden_token`); allowance provenance and
data flow are structural review, named in ADR-0018 with this hole recorded rather
than papered over, and listed in the PR's A46 checklist.

**R36's counter, and why it exists.** `ResolvedAllowances.insertions` is a plain
`usize`, not a `#[cfg(test)]` field, incremented on every `insert` call, and
equality ignores it through a hand-written `PartialEq`/`Eq`. The bound it makes
observable is invisible in output, and a work measure is not part of the value.

**The compatibility break is disclosed, and it is fail-closed.** Every ASCII-case
variant of `set:P` for canonical decimal `P` in 1–65535 except 53 and 853 used to
be the hostname `set` on port `P`; `set:0`, `set:0443`, `set:53` and `set:65536`
were errors and are now references too. Unlike `tool:`, **nothing is silently
re-granted**: an existing entry names a set, and a file that does not declare one
is refused — `UnknownSet` ordinarily, `NoUserSets` with no user file, and the
egress-reference refusal against an unsafe tools-only file. Only a later edit that
declares a set of that name can grant. USAGE carries an upgrade note; the fix is
`tcp://set:P`, written before upgrading.

**The CLI trust sentence is unchanged, and here is why it may stay that way.**
`resolve` runs `namespace.trust.require()` for **both** kinds before any lookup,
mapped by one `untrusted()` adapter, so a CLI `set:` against a refused verdict
prints `EntryError::Untrusted`'s bytes — which name `[[tools]] network_requests`.
That is reachable only in a file **without** `[egress_sets]`: a file that declares
the table was verified by presence at load, so it either failed there or carries
`verdict: Ok(())`. For such a file, `[[tools]] network_requests` is the honest
object of the sentence. **Do not "fix" the wording for sets**: it would change
#506's pinned bytes for an unreachable case and buy nothing.

**What is not proved.** The routing decision and the exhaustion polarity are the
only new contracts. The name rule, the cycle decision and the grammar are reused
proved rules; the traversal, the indexing, the charge-before-probe order, the
namespace association and every sentence are trusted adapters pinned by tests,
mutations and review. The overrun past the limit is bounded by one tool expansion
(≤ 64 parses) only because `expand` parses a whole tool list before its allowances
are charged — that is review, not a test.
