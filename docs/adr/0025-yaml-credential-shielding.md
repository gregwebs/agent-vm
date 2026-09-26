# 0025. YAML credential shielding

Status: Accepted (agent-vm #161; extended by #162).

## Context

A tool's `credentials = [...]` list could only name one of four compiled-in
providers. #159's spec adds a second kind: a credential the *user* authorizes —
an API key kept in agent-vm's own keychain namespace — injected host-side into
one exact HTTPS header, with a non-secret placeholder in the guest instead of
the value. The runtime half (origin scoping, the header write, the private
launch-config descriptor that carries the value across `fork`) is vendored
microsandbox's
`feat/175-origin-scoped-header-credentials`; this record covers the agent-vm
half. The spec of record is
[`docs/specs/credential-shielding.md`](../specs/credential-shielding.md).

## Decision

### Two authorities, neither of which can grow

The user's `~/.config/agent-vm/credentials.yaml` **authorizes**: it names a
keychain `service`, the exact origin (`domain`, bare host ⇒ 443) and the exact
`header` + `format` a value may occupy. A tool's `credentials = [...]`
**requests**: it can name a credential but cannot create, widen or override an
authorization, and a project config has no path to the file at all.

The two directions are asymmetric on purpose:

- A request with no authorization is a hard error that names both lookup
  locations — the user asked for something that will not be delivered.
- An authorization no launch requests is inert: it changes nothing, reads
  nothing and fails nothing.

Storing a value (`agent-vm secret set`) authorizes nothing either. The YAML
entry is the authorization, so editing it is the reauthorization gesture;
rotating the value at the same source is not (`docs/specs/credential-shielding.md`
§Configuration and authority).

### A load path that fails closed

`credential_yaml.rs` is the only place an untrusted file becomes an authority
decision, so it validates the grammar itself rather than trusting the parser,
mirroring the runtime's durable grammar byte for byte (`is_valid_origin_host`,
`validate_credential_header`, `validate_credential_format`). It parses in two
reject-biased passes: a `granit-parser` event guard that refuses anchors,
aliases, tags, `%YAML`/`%TAG` directives and additional documents, then a
`serde-saphyr` deserialization with a tight `Budget` and
`DuplicateKeyPolicy::Error` / `MergeKeyPolicy::Error` / `strict_booleans`.

The parser choice is a security decision, not an ergonomic one, and the
evidence was recorded when the dependency landed: `serde_yaml` is archived
(RUSTSEC-2024-0370); `serde_norway` is its maintained fork but is `unsafe`
C-libyaml with no configurable limits; `serde-saphyr` is pure Rust with
`#![forbid(unsafe_code)]`, MIT/Apache-2.0, no open advisory, and exposes the
deterministic controls above. Where a control was missing (tags), the guard
supplies it. "The crate allows it" is not a policy.

Diagnostics name an index and a constant schema label rather than a field value
— never the parser's `Display`/`Debug`/`source()`, never an unknown key, never a
field value. The one place a name is normally echoed (`secret ls`, launch
warnings) is user-controlled metadata, but a *rejected* credential name is not
echoed either, because the realistic mistake is pasting the key into the name
slot. (One exception is deliberate and value-free: a duplicate-`service` or
duplicate-`env`/origin error names the *other already-accepted* service, which
is authorization metadata, to make the collision actionable.)

Integrity decisions are taken on the descriptor the bytes came from: `O_NOFOLLOW`
open, then `fstat` owner/mode/type/size on that same descriptor. Group/other
*write*, a foreign owner, a symlink and a non-regular file are refusals;
group/other *read* warns, because the file holds no values.

### The value channel, and what is deliberately not claimed

Phase 1 (launch resolution, before any sandbox record is written) resolves each
authorized, requested service, proves it is available, and **drops the value**.
Phase 2 is a per-launch `microsandbox::CredentialResolver` the runtime calls
immediately before `fork`; the value travels only on the runtime's private
launch-config descriptor. The durable `SandboxConfig` carries a reference, not a
value, and its serialized shape has no value field to carry one. No plaintext
value is written to a file, a temp file, a state-dir value entry, argv or a
database row. (The credential *reference* is durable — it is part of the
`SandboxConfig` the runtime records — and the store creates its own lock file;
neither carries the value.)

The **application-level guarantee** is therefore: no plaintext value is written
to any durable artifact by agent-vm, and no diagnostic can render one. This is
*not* a claim about the operating system. Surviving copies are enumerated so
nobody mistakes this for erasure: agent-vm's process memory during both phases,
the serialized launch-config buffer, the memory-backed descriptor pages until
the child reads them, the runtime's parsed config, per-connection rendered
header buffers and TLS write buffers. `Zeroizing` wipes owned copies only. OS
swap, core dumps, hibernation and same-uid `ptrace`/descriptor inspection are
explicitly **not** covered; stronger platform controls would be a separate
proposal. (The inherited PENDING OWNER item on swap/dump policy is answered this
way, not deferred again.)

Keychain-read cost is **not** a fixed two per launch. Phase 1 reads each
authorized, requested YAML service once, however many rules it declares. Phase 2
is the runtime's per-launch resolver, which the SDK invokes once per reference
*occurrence* over every durable rule — so a service with two injection rules is
read twice there, and the two-origin USAGE example already costs three reads for
its one service. Consequences: rotation is launch-scoped (`agent-vm secret set`
does not reach a running sandbox, unlike the file-backed provider whose
per-connection re-read exists to pick it up); because phase 2 reads the store
per rule rather than once per service, a value rotated *between* two of a
service's rule resolutions can leave that service's rules holding different
snapshots within one launch; and the phase-2 read happens on a tokio worker
thread inside the SDK's spawn path, where a macOS Keychain prompt blocks that
thread (phase 1 runs first in the same process, so such a prompt surfaces
earlier).

### Guest environment ownership (AC 2)

`sentinelEnv` (Docker's `proxyManaged` is accepted as an alias and must agree)
controls only the guest variable named by `apiKey.name`. Injection is
independent of it. Because "publish nothing" is not "leave it unset", the name
is *owned* by the authorization from the moment it is validated, not from
resolution success:

- `sentinelEnv: true` and resolvable ⇒ the non-secret sentinel
  (`proxy-managed`) is published **last** of every emission point.
- otherwise ⇒ agent-vm publishes nothing, suppresses raw
  `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` forwarding *and* any provider-forwarded
  variable (`COPILOT_GITHUB_TOKEN`) for that name, and refuses a tool-declared
  `env` key for it. Names the launcher itself must publish (`IS_SANDBOX`,
  `LANG`, `PATH`, the guest identity, the `MSB_` namespace) are refused as
  authorizations at load time instead: "leave unset" cannot be honored for
  them.
- A `sentinelEnv: false` name the boot image itself defines is refused: the SDK
  builder appends guest env last-wins, so an image `ENV` can be overridden but
  not removed. When the image metadata cannot be read, the launch **fails
  closed** with a pull/inspect recovery instruction rather than assuming the
  name is unset.

The sentinel is Docker's literal. It carries no substitution authority and no
claim is made that it satisfies any consumer's key-shape validation.

### Same-named built-in replacement (#162)

A `credentials.yaml` entry named after a built-in provider (`anthropic`,
`openai`, `opencode-static`, `copilot`) is a precedence-setting authorization:
for a launch that requests that name, the authorization **completely replaces**
the built-in's *credential handling* — source acquisition, the guest
placeholder, proxy injection, and OAuth capture/refresh. There is deliberately
**no fallback**: an unavailable authorized value must never re-enable the
built-in, because that would silently downgrade a shielded credential to a
guest-visible placeholder the user never asked for. An authorization nobody
requests remains inert.

The rule is *credential facets vs. configuration and persistence facets*, not a
per-facet table. Suppression is **one predicate** — the capture gate,
`CredentialProvisioning::captures(provider) = provisioned && !replaced` — plus
**three** facets that are not derived from a captured token file and are
handled explicitly:

| Facet | Anthropic | OpenAI | OpenCode-static | Copilot |
|---|---|---|---|---|
| host capture (placeholder file, token file) | suppressed | suppressed | suppressed | suppressed |
| proxy `FileSecret` + OAuth `Route` | suppressed | suppressed | suppressed | suppressed |
| required hard bail (`missing_credential_error`) | skipped; YAML `required` governs | n/a | n/a | skipped; YAML `required` governs |
| raw-forwarded host variable | suppressed only if the authorization owns that exact `apiKey.name` (unchanged #161 rule — see the gap below) | same | same | n/a |
| guest-HOME links, eager state dirs, `persist` | kept | kept | kept | kept |
| onboarding bypass files | kept | kept | kept | kept |
| the OpenCode `model` pin | — | — | **argument conjoined with capture** | — |
| OpenCode BYO API-provider rows | — | **dropped with `openai`** | **dropped** | — |

- **Identity across providers is derived, not assumed.** Everything downstream
  of capture follows automatically, because `CredsState::wired()` is derived
  from `token_file(provider).is_some()`, `clear_unwired_placeholders` then
  removes a stale guest placeholder (ADR-0017), `Plan::new` registers neither a
  secret nor an OAuth route without a token file, and `provider_guest_env`
  conjoins wiring. That is why `credential_injection.rs` deliberately holds **no
  second `replaced` gate**: both gates would read the same `replaced` set, so a
  wrong `replaced` would defeat both, while the `token_file` gate already covers
  a wrong *capture*; a redundant gate would only mask a capture-gate regression.
  This is a deliberate trade against `CODING_STANDARDS.md` §Security *Defense in
  depth* ("consider how to add security at different boundaries and
  interfaces"). The second boundary the standard asks for is already here and it
  is a *different* fact: `Plan::new`
  (`crates/agent-vm/src/credential_injection.rs:99-118`) gates on
  `token_file(provider)`, not on `replaced`, so the decision is
  single-fact-*derived* from the captured token rather than unguarded. A second
  `replaced` read would add no boundary — it reads the same bit — only the blind
  spot the plan's §3 records.
- **Copilot is split, not gated wholesale.** `copilot/config.json` carries both
  the `github_token` placeholder and the non-secret `trusted_folders` trust
  configuration. Neither half may be written for *every* provisioned launch, so
  the writer was split into `write_copilot_bypass` (`trusted_folders`) and
  `write_copilot_guest_token` (the placeholder). Both run post-capture in
  `secrets::refresh`, with the gate each fact deserves: the placeholder only
  when the proxy captured a token to substitute, the trust config when the token
  was captured **or** a same-named authorization replaced the provider. Writing
  `trusted_folders` unconditionally — e.g. from the pre-capture
  `write_bypass_configs` pass — would breach AC2's "without a YAML match,
  built-in behavior remains unchanged": a launch with no `credentials.yaml`
  whose Copilot capture fails would create the file where it previously wrote
  nothing. The split is still what lets a replaced Copilot greet a **fresh**
  state dir without an interactive "do you trust this folder?" prompt.
- **The OpenCode `model` pin follows capture.** `write_opencode_model_default`
  keeps its `provisioned` gate so a stale pin from an earlier un-replaced launch
  is still retired, but its argument now conjoins capture. The reason is scope,
  stated honestly: agent-vm's capture gate has no visibility into the guest
  credentials a *YAML* authorization wires (`secrets::refresh` is handed only
  `provisioned`/`replaced`/`github_egress`, not the phase-1 `owned_env`
  dispositions), so a launch that replaced `opencode-static` is treated as
  having no OpenAI credential and the pin is retired. That is exact for a
  replaced entry that names a different `apiKey.name`, and conservative for a
  sentinel entry (`apiKey.name: OPENAI_API_KEY`, `inject: api.openai.com`), which
  *does* give the guest a working OpenAI key through the proxy — the shape this
  record's own examples use. For that shape the `openai/gpt-5.5` default is not
  re-asserted, so the user sets `model` in their own `opencode.json`. Wiring the
  pin to the real OpenAI-owned guest disposition instead of the capture bit is a
  larger change and is recorded as an **open decision** (S2 in the #162 code
  review; see `implementation-result.md`), not silently picked here.
- **One credential, one handling.** Replacing `openai` also drops OpenCode's
  synthetic `openai` row, because that row is derived from the same captured
  host token. Replacing `opencode-static` drops **every** BYO API-provider row
  and unlinks their host token files, because those rows are that provider's
  credential handling, sourced from the same host `auth.json` — a large
  consequence of one YAML line, hence documented in USAGE.md as well.
- **The raw-forwarding gap.** Ownership is by *variable name*. A YAML `anthropic`
  entry with `apiKey.name: MY_KEY` leaves the host's `ANTHROPIC_API_KEY`
  raw-forwarded (`run::RAW_FORWARDED_ENV`), so the user's belief that they
  shielded Anthropic is false. Before #162 that configuration was a hard error,
  so this is a newly reachable state, and it is **not** silent: the launch emits
  a notice naming the provider and the still-forwarded variable (never a value).
  Removing the forwarding outright is #163. The mapping from provider to
  forwarded variable is `CredentialProvider::raw_forwarded_env()`, pinned against
  `RAW_FORWARDED_ENV` by a test so the two cannot drift.
- **Ordering.** Phase-1 resolution now runs *before* host credential capture, so
  the `replaced` set exists when capture is gated and the `==> host credentials`
  notice reflects the post-replacement state. It does **not** move ahead of the
  tooling-layer build/confirmation or session/guest-home provisioning, which
  already ran earlier; the honest statement is that a malformed `credentials.yaml`
  is now refused before host credentials are read.
- **What is not deleted.** A host-only token file under `<state>.secrets/`
  written by an earlier un-replaced launch is left in place. It is 0600, in the
  never-bind-mounted host-only sibling directory, and unreferenced once the
  provider is un-wired; deleting it would be new destructive behaviour on data a
  concurrent launch may hold. The *guest-visible* placeholder **is** cleared.

#### Availability: `--allow-missing-credentials`

The host launch flag (never a project option, and deliberately with no
environment variable) selects a `MissingCredentialPolicy::Warn` for phase-1
resolution. It moves the availability of a **YAML** credential only — the case
the spec calls "missing authorization" (the name matches neither a built-in nor
an authorization) and "unavailable required credentials" (`required: true` whose
source cannot be read). Both become a warning that names the withheld service
and says the flag kept the launch alive, with the guest getting neither the
credential nor a fallback.

It cannot bypass, and both policies refuse identically for:

- a malformed, unsupported or rejected `credentials.yaml`, and an integrity
  refusal (foreign owner, group/other write);
- a stored value `SecretValue` rejects — *present but invalid* is a
  configuration error, not an unavailable source, so it is never a warning;
- a `sentinelEnv: false` name the boot image defines, or unreadable image
  metadata;
- a tool-declared `env` key colliding with an owned name;
- **the raw forwarding the spec's "forward raw values" clause names.** The flag
  does not *cause* it — the forwarding is #161 behaviour #163 removes, and the
  C6 notice above fires — but the *combination* is newly reachable: a
  `required: true` `anthropic` entry with `apiKey.name: MY_KEY` whose value
  cannot be read, plus the flag, skips the built-in bail (the name is in
  `replaced`) and launches with the host's raw `ANTHROPIC_API_KEY` still
  forwarded into the guest;
- **a built-in provider's own missing-credential bail.** The override's scope is
  the YAML authority. The built-in case degrades to agent-vm's own machinery
  being half-wired — the guest comes up signed out and in-guest `/login` cannot
  work, because the OAuth hook accepts only the placeholder refresh token — so a
  flag that opts into a knowingly broken session with a misleading error would be
  worse than a refusal. Widening it later is additive; narrowing it after it
  ships would not be.

#### The counted concurrency hazard

Two concurrent launches of the *same* project and tool, one replacing a provider
and one not, can have the non-replacing one write a built-in placeholder into the
shared guest state while the replacing one runs with no substitution entry for
it. The race is pre-existing in kind (`claude` and `codex` already race under
`REFRESH_LOCK_PROJECT`), but #162 makes it reachable from a **single** tool by
one YAML line, so it is recorded here rather than discovered later.

`source` is still parsed only far enough to be *rejected by name*: `source: env`
is #163, alongside the general removal of raw API-key forwarding (#162 suppresses
it only where a YAML authorization owns the name, and warns where a renamed
authorization leaves it in effect).

### Destination and header policy

- A bare `domain` means HTTPS 443; an explicit `:port` is exact and in
  `1..=65535`.
- The host must be an ASCII LDH name; it is lowercased and one trailing dot is
  stripped, then re-validated (the runtime's builder does the same, so the
  canonical form is idempotent under it). A non-ASCII name is refused with
  "write the A-label": IDNA conversion is a specification decision nobody has
  taken, and guessing is worse than refusing.
- IP literals are refused as deliberate policy: authorization is by TLS server
  name, and the runtime's origin grammar refuses them too, so accepting one
  would authorize something the runtime cannot match.
- A wildcard, a path, a cleartext scheme, userinfo, a query or a fragment is
  refused with its own message (AC 4).
- `header` must be a lowercase RFC 9110 token that is not framing or
  hop-by-hop; `format` must be ≤ 256 printable ASCII bytes with exactly one
  `%s`, counted the same non-overlapping way the runtime counts it.
- `scheme: bearer` desugars at parse time to `authorization` + `Bearer %s`, so
  downstream sees one representation.

Authorizing an origin does **not** open egress to it. The egress policy is
untouched; if it denies the origin the request never reaches injection, and a
well-formed request to an unapproved origin is forwarded uninjected rather than
blocked (AC 6/AC 7 are the runtime's behaviour, not agent-vm's).

### Intercepted ports are per-port, and declared explicitly

The runtime's TLS-intercepting proxy decides interception **per port**
(`intercepted_ports`, default `[443]`), not per host. A credential whose origin
port is not intercepted can never be injected, so the runtime fails **closed**
(`BuildError`/`NetworkInitError::HeaderCredentialPortNotIntercepted`) rather
than silently never injecting it. Ports are deliberately not derived upstream:
adding a rule's port automatically would MITM every unrelated host on it.

agent-vm therefore declares each credential origin's port when it registers
the credential, **unioning** it with the base network config's own list rather
than replacing it — so the default 443 (which a bare `domain` means) and any
port an existing network config already intercepts both survive. Because
interception is per-port, **declaring a port intercepts TLS for every host on
that port**, not only the credential's own origin; that wider interception is
the honest cost of the fail-closed decision, and it is why an explicit
non-443 origin is the caller's deliberate choice rather than a side effect.

### Restart by name: not applicable, verified

The runtime refuses `Sandbox::start`/`start_detached` on a reference-backed
sandbox with `RestartRequiresResolver`, because the resolver is per-create.
agent-vm never calls either (verified by grep across `src/` and `tests/`), and
`session.rs` derives a sandbox name carrying the PID, so every launch creates a
fresh sandbox. There is no agent-vm code path to change and no owner decision
outstanding: the safest behaviour is to document the upstream refusal, which
this record does.

A failed phase-2 resolve can leave a `Stopped` database row. The SDK inserts the
durable record before the resolver runs; the row carries the reference only,
never a value, and agent-vm adds no cleanup logic.

### Platform

Windows is refused upstream (`UnsupportedPlatform`) and the cloud backend
(`UnsupportedBackend`); agent-vm supports Linux+KVM and Apple Silicon hosts, and
adds no platform branch of its own. A stale locally built `msb` fails the
runtime's `__capabilities` probe (it must report
`header-credential-launch-v1`); the launcher translates that into a
rebuild-your-`msb` message naming `MSB_PATH`.

## Consequences

- The `Send + Sync` requirement on the runtime's resolver is met by a minimal
  `CredentialSource` seam, not by holding a `SecretStore`: the store is not
  `Sync` in a `cargo test` build (test-only fault-injection state), so a
  resolver that held one would fail to compile for tests rather than merely be
  hard to fake. `allowed` is scoped per launch, so configuration tampering
  between build and spawn cannot widen what is read.
- The debug-only `AGENT_VM_TEST_CREDENTIAL` seam
  (`credential_resolver::test_credential_override`) lets the subprocess tests
  reach a genuinely credential-bearing create without an OS keychain, which
  Linux CI does not have. Like the `AGENT_VM_TEST_SECRET_RECORD` recording
  backend (`secret_store::RecordingKeychain`), it is `debug_assertions`-gated
  and so compiled out of release builds. It is **not a value oracle and cannot
  widen the allowed set**: it never reads the store, it holds only the
  `(service, value)` pair the test process put in its *own* environment, and a
  service named only there but absent from `credentials.yaml` still gets the
  ordinary "no authorization" refusal. The value it supplies still goes
  through `SecretValue::try_parse`, so it cannot smuggle a rejected value.
- A launch whose requested names are all built-in providers constructs no
  keychain at all, so an unset `$HOME` or a missing Secret Service does not
  change its behaviour.
- #162's capture gate carries the machine-checked contract ADR-0018 now requires
  of it: `secrets::capture_decision(provisioned, replaced)` proves
  `capture == (provisioned && !replaced)` and, specifically,
  `replaced ==> !capture`. `CredentialProvisioning::captures` is its trusted
  adapter; the two `ProviderSet::contains` measurements are the untranslatable
  shell. Stated plainly, as ADR-0018's *verified surface* does for its
  restated-comparison rows: what is proved is that the decision **is** that
  comparison, **not** that the facets downstream of capture are wired correctly.
  Those rest on `CredsState::wired()` being derived from
  `token_file(p).is_some()`, on `clear_unwired_placeholders`, on `Plan::new`'s
  `(proxy_secret, token_file)` match and on `provider_guest_env`, none of which
  is verified. The contract is real but narrow: it pins the capture gate.
- The store gained exactly one authorized reader;
  [ADR-0024](0024-host-secret-inventory.md) is amended accordingly, and no
  exception is added to its "never render a value" rule.
- The new pure predicates (header-name bytes, format placeholders, origin-host
  bytes, guest-env-name bytes, and the count/depth limits) mirror
  `secret_store.rs`'s ADR-0018 pattern. Header-name, guest-env-name and the
  three resource-limit predicates carry machine-checked contracts; the origin
  host byte shape is additionally pinned against the runtime's checked-in
  accept/reject fixture. The format-placeholder counter and the origin-host
  byte shape now carry machine-checked contracts too (`count_placeholders` /
  `format_placeholder_count_is_one` and `host_prefix_ok` /
  `origin_host_is_exact_bytes`), closing the proof gap earlier drafts recorded;
  the fixture remains the regression that pins them against the runtime.
- The vendored submodule is bumped to the merged microsandbox commit in the
  same PR, after the companion PR merges.
