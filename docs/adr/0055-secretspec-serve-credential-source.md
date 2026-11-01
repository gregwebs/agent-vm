# ADR-0055: SecretSpec as a `secretspec serve --read-only` credential source

## Status

Accepted. Implementation decision for [agent-vm #202](https://github.com/gregwebs/agent-vm/issues/202).
Extends [ADR-0025](0025-yaml-credential-shielding.md) with a third credential source; the
authorization file, the two phases, the sentinel, the proxy and
[ADR-0024](0024-host-secret-inventory.md)'s "never render a value" rule are unchanged.

This record **is** the contract for `source: secretspec`. `USAGE.md`, `ARCHITECTURE.md` and
[`docs/specs/credential-shielding.md`](../specs/credential-shielding.md) state what a user needs and
link here rather than restating the rules, so one edit cannot make them disagree.

## Context

SecretSpec is a declaration, resolution and delivery layer over 34 provider backends (keyring,
Vault/OpenBao, 1Password, cloud secret managers, SOPS, age, Kubernetes, systemd credentials, …). Its
delivery contract is to hand the resolved value to the consuming process — child environment (`run`),
stdout (`get`/`export`), a temp file (`as_path`), or an IPC value/lease (`serve`) — and its own
`SECURITY.md` documents those plaintext deliveries as deliberate. It has no proxy, no origin-scoped
injection model and no authorization vocabulary: scopes narrow *which* secrets resolve, not whether a
resolved secret is delivered, and its documentation says scopes are not an authorization boundary.

agent-vm's whole point is the opposite one: the guest never receives a real value. So SecretSpec
cannot be the shielding layer and cannot be the authorization layer. It can be, and is here, **one
host-side source behind the existing `CredentialSource` seam** — the value is read on the host,
delivered to agent-vm's two-phase channel, and injected into the authorized header by the existing
TLS-intercept proxy.

The other two integration mechanisms:

- **Link SecretSpec's Rust SDK.** It pulls roughly 272 crates into agent-vm's tree; its API is
  blocking, so every call from the runtime's async resolve path would need `block_in_place`; and the
  returned value is an ordinary in-process Rust value, which the SDK formats with its own `Debug`
  and which ADR-0025's "no diagnostic can render one" rule would then have to defend across a
  third-party type it does not own. The process edge is what makes the value's lifetime
  inspectable — one buffer agent-vm allocates and zeroizes.
- **`secretspec get` per read.** A process per rule with no scope pin, no negotiated frame limit and
  no protocol version gate, so the only failure classification available is an exit status. It
  writes the value to stdout, which is a value-rendering surface agent-vm would have to own. And it
  can mint-and-write-back a `generate` secret, which contradicts "agent-vm is a reader, never a
  writer" at the source that has the write path.

`secretspec serve --read-only` is the one mechanism whose contract is narrow enough to bind: a
versioned JSON-RPC protocol (`secretspec.resolver/1`) over the child's own stdin/stdout, a documented
read-only mode, and a capability list to check before the first read. Everything the Rust SDK would
give in-process, this gives across a pipe — and nothing else crosses.

Wire facts below were measured against `secretspec 0.21.1` (the operator's Homebrew install; see the
plan's probe findings); the tests that do not need the real binary assert against a fake that speaks
the same frames.

## Decision

### Configuration: one source, one user-only table

```yaml
credentials:
  - service: deepseek
    source: secretspec                 # keychain (default) | env | secretspec
    secretspec:
      executable: /opt/homebrew/bin/secretspec
      manifest: /Users/me/.config/agent-vm/secretspec.toml   # required, absolute
      profile: default
      scope: agent-vm                  # optional (absent = whole profile)
      name: DEEPSEEK_API_KEY           # optional, default = apiKey.name
      reason: agent-vm launch          # optional SecretSpec audit reason
    required: true
    apiKey:
      name: DEEPSEEK_API_KEY
      sentinelEnv: true
      inject:
        - domain: api.deepseek.com
          scheme: bearer
```

- `source` is a closed enum (`keychain` when omitted, `env`, `secretspec`); anything else is refused
  with a message that lists all three. `source: keychain` is now accepted literally (it is the
  default), which is one of the two existing assertions this change rewrites.
- The `secretspec:` table is **required** with `source: secretspec` and **refused** otherwise, so a
  silently ignored table cannot look like a pinned source. It is user configuration only: a project
  config reaches `credentials.yaml` by no path and therefore cannot select this source.
- `service` still names the authorization; `secretspec.name` names the SecretSpec secret and
  defaults to `apiKey.name`. The two are deliberately distinct — a SecretSpec identifier may be
  `MSB_X` or contain `/`, which the guest-variable grammar would refuse.
- **No `provider` key.** The initialize application carries `provider: null`, so the provider comes
  from the user's own SecretSpec configuration. The supported mechanism is SecretSpec's
  manifest-level `providers = [...]` (on a secret or a profile); with `provider: null` a host
  `SECRETSPEC_PROVIDER` is not consulted, which is also why stripping `SECRETSPEC_*` from the child
  cannot hide a provider choice.
- Bounds are labelled by whose rule they are: `name`, `profile`, `scope` and `reason` follow
  SecretSpec's JSON-Schema `maxLength` (characters, no pattern — a 129-byte name and `work/team`
  resolve), and agent-vm **additionally** caps them at 4096 bytes, refuses ASCII control characters
  (all three are printed on one `doctor` line) and narrows `reason` to printable ASCII of 1..=256
  bytes. Recognized-but-unsupported keys (`provider`, `as_path`, `representation`, `generate`,
  `default`, `value`, `prompt`) are refused **by name** with a specific message rather than
  approximated.
- Paths (`executable`, `manifest`) must be absolute and normal: no `.`/`..`/empty component, no
  trailing `/`, at most 1024 bytes, no NUL. `manifest` is not opened or checked by agent-vm; it is
  passed to SecretSpec as the exact text the user wrote.

### The session: one child, one pinned key

For each distinct **session key** `(executable, manifest, profile, scope, reason)` among a launch's
requested, authorized `source: secretspec` services, agent-vm runs exactly
`<executable> serve --read-only`, and speaks `secretspec.resolver/1` to it:

- **Handshake.** `rpc.initialize` is the first frame with `versions: [1]`,
  `client {name: "agent-vm", version: <crate version>}`, `limits {max_frame_bytes: 16384,
  max_in_flight: 1}`, **no** `client_methods`, and the immutable application
  `{manifest: {kind: "path", path}, provider: null, profile, scope, reason}`. `rpc.discover` is not
  called: the initialize **result** is the version gate. A session is accepted iff

  1. `protocol == "secretspec.resolver"` and `version == 1`;
  2. `methods` contains **both** `resolver.get` and `resolver.release`;
  3. `methods` contains neither `resolver.set` nor `resolver.delete`;
  4. the echoed `limits` are usable — `max_frame_bytes` an integer in `4096..=16384` and
     `max_in_flight >= 1` — and the session then **stores and enforces
     `min(16384, negotiated max_frame_bytes)`** on every later read *and* write.

  Requiring `resolver.release` is a capability check, not a path lease: a `value` get creates no
  lease, and agent-vm never sends `release`. The server's own product name is deliberately not a
  gate input; protocol, version and the capability list are. The two halves are separate
  machine-checked kernels (`capability_satisfied`, `offers_no_write_method`) because their refusals
  carry different messages. Nothing is sent before the gate passes; a rejected session is killed.

- **Frames.** One UTF-8 JSON object + LF each way. An incoming frame over the session's frame limit
  is refused *before* parsing; an outgoing frame is checked against the same limit before it is
  written. The protocol's 1 MiB ceiling is never approached. A server-sent request (e.g.
  `client.prompt`) is answered `-32601`/`method_not_found` and the read continues; server
  notifications are ignored; more than 8 interleaved frames, a wrong or missing `id`, a non-`2.0`
  envelope or unparseable JSON ends the session. Every enclosing deadline is a `poll(2)` timeout
  rounded **up** to whole milliseconds, so a truncated 0 cannot busy-loop.

- **Reads.** One `resolver.get` per resolve call: `{name, representation: "value",
  purpose: {consumer: "agent-vm", operation: "launch"}}`, strictly sequential. Each request carries
  `_meta.deadline_unix_ms = now + bound` and agent-vm enforces the same bound locally on a monotonic
  clock — the keychain's attended/unattended bound (60 s with a terminal on stdin, 5 s otherwise) —
  with one value-free "still waiting" line after 2 s. On local expiry agent-vm sends
  `rpc.cancel {id}`, waits ≤ 200 ms, then kills the process group. Startup (spawn to accepted) is
  bounded by 5 s of local poll time.

- **Blocking, deliberately.** Both `CredentialSource` methods are synchronous: phase 1 runs in the
  root future of `Runtime::block_on`, phase 2 in the SDK's spawned create task immediately before
  `fork`. The keychain already blocks those threads the same way, so this client is `std::process`
  plus `libc::poll` and owns no Tokio types. A hung child costs its bound, not a wedged runtime.

- **What the budget does not bound.** `Command::spawn`, the `metadata` executable check and the
  notice write to agent-vm's own stderr cannot be interrupted by a poll budget, so a spawn that
  hangs is not recoverable by this design, and a full undrained stderr can park a read loop at its
  notice. Teardown of a wedged session costs up to 1 s + 200 ms + 1 s, and up to 32 sessions close
  sequentially, so a pathological launch can spend about a minute and a half closing. There is no
  global wall-clock bound on a launch.

### Processes

- **Absolute, pinned, direct.** The configured path is executed directly: no shell, no `PATH`
  lookup, `current_dir("/")`, own process group, stdin/stdout piped, stderr `Stdio::null`.
- **The narrow executable check** runs before spawning: the *target file* (symlinks followed) must
  be a regular file with an execute bit and must not be group- or other-writable. There is
  deliberately **no ownership rule and no ancestor-directory rule**. Measured on the operator's
  host, `/opt/homebrew/bin/secretspec` is a symlink into `Cellar/secretspec/0.21.1/bin`, mode
  `-r-xr-xr-x`, owned by a uid that is *not* the invoking one, under a `drwxrwxr-x` parent — so
  either rule would refuse the very executable these wire facts were observed against. Absolute
  pinning defeats `PATH` and working-directory shadowing; it is not a checksum against a compromised
  package manager, and the check-to-exec window is accepted (see Consequences).
- **Environment: agent-vm's, minus `SECRETSPEC_*`.** Not `env_clear`, for three reasons: provider
  CLIs need their own variables (`OP_*`, `VAULT_*`, `AWS_*`), an `env` provider's input *is* a host
  variable, and an env-sourced credential's captured variable is already removed before any child of
  the launch exists. Ambient provider input is therefore **trusted input**, documented as such, with
  its limits stated rather than papered over. Filtering one prefix cannot prove a provider was not
  redirected, and no such claim is made.
- **stderr is discarded** because third-party error text is uncontrolled and could carry anything.
  The remedy sentences point at `secretspec check --no-prompt` instead.

### Lifecycle

- Sessions start **lazily**, on the first read that needs them, so an unrequested SecretSpec
  authorization spawns nothing and a launch with no SecretSpec sources spawns nothing at all.
- **One session per key is reused across phase 1 → phase 2.** A fresh session per phase would double
  the spawns and the provider unlocks, so that alternative is rejected.
- A leader observed exited before a request (observed **without reaping**, so its pid — the pgid —
  stays reserved) is restarted transparently **once** for that request. A session that fails
  *during* a request is killed and the next read starts a fresh one. A failed **start** is sticky for
  the rest of the launch, so a broken executable costs one attempt rather than one per rule.
- `CredentialSessions::close()` runs when `create` returns, on both success and failure; reads after
  close fail without spawning, and closing twice is a no-op. `drop` proves only that no later read
  spawns or reads — it cannot withdraw a value the create task already acquired, because dropping a
  `JoinHandle` detaches its task.
- **Group-based teardown, one policy for every stop** (timeout, protocol violation, restart, normal
  close, drop): **observe without reaping** — `waitid(P_PID, …, WEXITED|WNOHANG|WNOWAIT)` — then
  **signal the group once** — one `kill(-pgid, SIGKILL)`, a one-shot entitlement that nothing
  re-arms — then **reap** the leader within a 1 s ceiling. `try_wait` returning `Err` is never read
  as "the leader was reaped", and only `ESRCH` establishes that the group is gone; `EPERM` leaves
  the guard armed with its entitlement spent rather than claiming a cleanup that did not happen. A
  normal close sends `rpc.shutdown` first (≤ 1 s) and closes stdin. The signal is sent even when the
  leader was already observed exited, because a `resolver.get` may have made the server start a
  provider helper (`op`, `vault`, a cloud CLI) that can outlive it holding a pipe, a credential or a
  network request.
- A distinct **session is closed, not snapshotted**: agent-vm keeps no value between reads, so
  rotation is launch-scoped and phase 2 sees whatever SecretSpec answers then.

### Outcomes

One closed failure class (`SecretspecFailure`, `Copy`, `&'static str` remedies) plus the existing
`Resolved` vocabulary. The mapping, which is the contract:

| server outcome | launch disposition |
|---|---|
| `resolved`, `representation: "value"`, value passes the accepted-value rule | value (phase 1 drops it; phase 2 hands it to the runtime) |
| `resolved` with `source: "generated"`, or `representation: "path"` | unavailable — protocol violation (a read-only server must never generate) |
| value fails the accepted-value rule, `message_too_large`, or a get answer over the frame limit | **hard error** regardless of `required` and `--allow-missing-credentials` |
| `missing` | missing |
| `undeclared` | **missing** — the issue's mapping. Covers both a name absent from the manifest and a name outside the session scope; the SecretSpec-specific missing remedy names both plus the out-of-scope case |
| `permission_denied`, `interaction_required` | unavailable — would need to generate or prompt, or the provider denied access |
| `representation_mismatch` | unavailable — `as_path` is not supported |
| `deadline_exceeded`, `cancelled`, local deadline | unavailable — unresponsive |
| `operation_failed`, `unavailable`, `internal`, `conflict`, unknown kind | unavailable — provider failed |
| `parse_error`, `invalid_request`, `method_not_found`, `invalid_params`, `capability_required`, malformed frame | unavailable — protocol violation |
| init `unsupported_version`, or a result failing the version gate | unavailable — unsupported protocol |
| init without `resolver.release` | unavailable — unsupported protocol (mandatory capability absent; no get is sent) |
| init `limits` missing, malformed or out of range | unavailable — protocol violation (no get is sent) |
| init advertising `resolver.set`/`resolver.delete` | unavailable — not read-only (no get is sent) |
| init `operation_failed`/`invalid_params` | unavailable — session rejected (manifest/profile/scope) |
| executable missing, not executable, spawn error | unavailable — executable missing |
| executable group/other-writable | unavailable — executable untrusted |
| child exits or closes stdout before the handshake | unavailable — startup failed ("needs SecretSpec 0.21 or newer") |
| no handshake within 5 s | unavailable — handshake timed out |
| child exits during a request | unavailable — session lost |

The deliberate departures from the issue's original mapping are two: `generated`/`path` results are
a protocol violation rather than a value, and `undeclared` maps to missing rather than to its own
class. Availability then follows the existing policy exactly as for the keychain: `required: true`
fails before boot, `required: false` warns and launches without the value,
`--allow-missing-credentials` turns a `required: true` failure into the override warning. Phase 2
maps missing (including `undeclared`) to the runtime's `not_found` and everything else to `failed`.
Every message names the service and a fixed remedy, and none can carry a value.

### Values

`Zeroizing` throughout, and structured so a value has as few copies as the borrow checker allows: the
frame buffer is pre-allocated at `frame_limit + one read chunk` and never grows, so a large answer
cannot leave an old allocation behind; the value is deserialized straight into `Zeroizing<String>`;
`serde_json` errors are dropped unrendered. Nothing in the module derives `Debug` over a value —
`SecretspecSource`'s `Debug` is hand-written and prints the service, secret name and profile.

### The test seam

`AGENT_VM_TEST_SECRETSPEC_FAKE` points the launch at a fake endpoint that speaks real
`secretspec.resolver/1` frames over the same pipe layout, and serves only values from a
test-supplied scenario file. It is compiled out of release builds (`cfg(any(test,
debug_assertions))`). One test, `a_release_binary_ignores_the_fake_environment`, branches at run
time on `cfg!(debug_assertions)` — not on a test-level `cfg` — and asserts the half that the binary
it is running can show: a release build rejects the activation-shaped argv and leaves no fake
transcript, while a debug build answers the same argv.

### Story 19 is waived, deliberately

The issue's user story 19 asks for "a throwaway `secretspec get` path available for prototyping". **It
was not undertaken, and no such path exists anywhere in the tree — not behind a flag, not in a test
binary.** Under the settled serve-only decision the prototype would have been a second, unreviewed
transport whose only purpose was exploration that the `serve` probe already completed. An ADR
recording `secretspec get` as a rejected alternative is not a prototype, and the debug fake endpoint
is not one either: it speaks the shipped protocol, not `secretspec get`. The story needs an explicit
operator waiver, which it has; it is not satisfied by re-reading this record.

## Consequences

- **Surviving copies** are added to ADR-0025's enumeration: the child's own process memory, the
  pipe's kernel buffer, `serde_json`'s scratch buffer while decoding an escaped string, and the
  zeroized frame buffer. Plus one this design adds by existing: the **idle child across the
  phase-1 → phase-2 window**, which holds whatever a provider left in its memory. Nothing here
  narrows ADR-0025's application-level-only guarantee: OS swap, core dumps and same-uid inspection
  are still out of scope.
- **Audit provenance is `purpose.consumer`.** Every get carries
  `purpose: {consumer: "agent-vm", operation: "launch"}`, and SecretSpec 0.21.1 records it (observed:
  `purpose` and `reason` are recorded, `--caller` is not). agent-vm adds no audit surface of its own.
- **One writer per SecretSpec entry.** agent-vm reads; it never sets, generates or prompts. A
  `generate`-shaped secret must be supplied by SecretSpec itself, and a service that is both a
  SecretSpec source and an `agent-vm secret set` target has two writers.
- **Two residual windows remain** and are accepted: a pgid can be reused after the group empties, and
  a leader can be reaped in a teardown whose group signal was not proven delivered. The one-shot rule
  bounds both — no second signal is ever issued and only `ESRCH` is read as absence — and neither can
  retarget a later kill. Both are strictly smaller than the defect the policy replaces: returning
  early because the leader was gone while a helper stayed alive.
- **No parent-death cleanup.** agent-vm is not a subreaper and installs no death signal. 0.21.1 exits
  on stdin EOF while idle, so an ordinary kill of agent-vm ends an idle session; a provider helper
  that inherited a pipe can retain it, and nothing here promises cleanup after `SIGKILL`.
- **A helper that leaves the process group survives the teardown.** The guarantee is scoped to the
  process group by design: one `kill(-pgid, SIGKILL)` reaches every member, but a provider helper
  that calls `setsid(2)` or daemonizes into a new group or session is outside it and outlives the
  session. Following it would need a subreaper or cgroup, which this design does not install (see
  the previous bullet); a daemonizing provider is the operator's to identify.
- **Descriptors agent-vm inherited without close-on-exec are inherited by the SecretSpec child and
  its provider helpers.** `std::process::Command` closes only the descriptors it created, so an
  inherited non-`CLOEXEC` descriptor is passed on. Every other agent-vm child (the runtime, `msb`)
  already inherits the same set, the descriptors in question were placed there by agent-vm's own
  invoker, and agent-vm's own pipes are `CLOEXEC`; closing them for every child with an
  async-signal-safe mechanism is a follow-up, not a change this decision makes.
- **Pre-1.0 protocol risk is fenced at the version gate**, not assumed away: a server that changes
  its frames is refused as `unsupported_protocol` at the handshake, which is a message telling the
  user what to install, not a parse of whatever came next.
- **`doctor` stays read-only** and now names the SecretSpec row and its own note; it spawns nothing,
  stats nothing and reads nothing but the authorization file, so its output is identical whether or
  not a value could be served.
- **The read is a capability, not a lease.** Requiring `resolver.release` to be *advertised* while
  never sending it keeps the check narrow: agent-vm proves the server implements the method the
  issue names, without opening a path that would let a value outlive the read.
- **A base64-declared secret yields its encoded text, not the bytes.** The plan expected a
  non-UTF-8 payload to be refused server-side as `operation_failed`. That is not what 0.21.1 does:
  with `providers = ["env"]` a secret declared `encoding = "base64"` whose payload is not UTF-8
  resolves with the base64 **text** as its value (observed: `//79`). agent-vm has no way to tell —
  it sends a name and receives a string — so it injects that text. Binary payloads were already out
  of scope; what this record adds is that they are not refused, so a service whose value is only
  meaningful as bytes must not be declared base64 in the manifest. A plain-text secret is
  unaffected.
