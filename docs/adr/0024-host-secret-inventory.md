# ADR-0024: A host-side secret inventory for `agent-vm secret`

## Status

Accepted. Implementation decision for
[agent-vm #160](https://github.com/gregwebs/agent-vm/issues/160), the first
child of [#159](https://github.com/gregwebs/agent-vm/issues/159). Implements the
"Secret-value CLI" section of
[docs/specs/credential-shielding.md](../specs/credential-shielding.md)
and its acceptance check 10. Builds on **Credential shielding**,
**Secret store** and **Secret inventory** in [CONTEXT.md](../../CONTEXT.md), and
adds the boundary predicates to [ADR-0018](0018-machine-checked-boundary-contracts.md)'s
verified surface. The store itself lives in `crates/agent-vm/src/secret_store.rs`
and the verbs in `crates/agent-vm/src/secret.rs`.

## Context

agent-vm had never stored a secret *value* of its own. It read host credential
files other agent CLIs wrote, handed the guest placeholders, and let the
microsandbox proxy substitute the real bytes on the way out
([ADR-0010](0010-wire-file-backed-credential-injection.md)). #159's credential
shielding adds a second kind of credential: one the *user* gives agent-vm, an
API key no agent CLI owns a file for. Its agreed home is the host OS credential
store — macOS Keychain, Linux Secret Service — in a namespace agent-vm owns.

Three facts shaped this ADR.

**1. `keyring` 3.6.3 exposes no portable enumeration API.** Its `src/lib.rs`
exports `Entry`, `set_default_credential_builder`, `credential` and `mock`.
There is no `Search`. The Secret Service backend has internal attribute-matching
helpers (`src/secret_service.rs`), but nothing public, nothing portable, and the
macOS backend has none at all. So `secret ls` cannot ask the OS "what does
agent-vm own?".

**2. The credential-store namespace is host-wide.** Every `agent-vm` process on
the machine addresses the same `dev.agent-vm.credentials` entries regardless of
`AGENT_VM_STATE_DIR`. CONTRIBUTING.md actively encourages a distinct state root
per worktree (`AGENT_VM_STATE_DIR="$HOME/.local/state/agent-vm-$(basename "$PWD")"`),
so any record of *which* names exist must not live under the state dir — one
worktree would then overwrite or delete a value another worktree's `ls` never
mentions.

**3. `keyring`'s macOS backend reports deletions it did not verify.** `delete()`
in `keyring` 3.6.3 (`src/macos.rs`) calls `item.delete()` and returns `Ok(())`
unconditionally, and `security-framework`'s `delete()` discards
`SecKeychainItemDelete`'s status. A naive `rm` could therefore report a removal
that did not happen *and* drop its record, leaving a live credential invisible
to `agent-vm secret ls` — the worst outcome this feature can produce.

## Decision

### D1 — A names-only inventory file, in the user-scoped config directory

`~/.config/agent-vm/secret-inventory.json` (mode 0600) records the **service
names** agent-vm has stored. `~/.config/agent-vm/.secret-inventory.lock` (0600)
is the `flock(2)` target, and the directory is created 0700 when absent.

```json
{"version": 1,
 "note": "service names only - this file is not an authorization list",
 "services": ["anthropic", "openai"]}
```

It holds **names only, never bytes**. That is what makes `ls` structurally
incapable of printing a value: the only value-shaped datum anywhere in the
command is the two-valued `Presence` a probe returns. The written `note` field
exists so a user who finds the file does not read it as authorization; it is
ignored on read.

`$HOME/.config/agent-vm/` rather than the state dir, because D2's namespace is
host-wide and because this is the directory #161's `credentials.yaml` will
occupy (`config.rs`'s `USER_CONFIG_DIR_RELATIVE`, deliberately not
`XDG_CONFIG_HOME`-overridable — a per-session environment variable must not move
host credential state). The path resolution reuses `config.rs`'s `$HOME`
discipline through one shared helper, so a set-but-empty or relative `$HOME` is
one explicit error rather than two diverging ones.

Load rules: a missing file is an empty inventory; an unparseable file, an
unknown `version`, or a name that fails the service-name rule is a **hard error
on every verb**, naming the path and the recovery ("delete this file to reset
the listing; the stored values are unaffected and `agent-vm secret rm NAME`
still works by name"). Never a silent reset of a file the user may have
hand-written, never an unvalidated name, never a quoted byte.

### D2 — The keychain namespace is `dev.agent-vm.credentials`

One constant, one construction site (`entry_key`), reverse-DNS like
microsandbox's `dev.microsandbox.registry` and deliberately unrelated to
Docker's `com.docker.sandboxes`: agent-vm neither reads nor writes Docker's
secrets. A test asserts the `(service, account)` pair at the `entry_key` seam —
not just the constant — so a future two-argument swap or a rename onto a
neighbour's namespace is caught. Changing the name before any user has stored a
value is free; afterwards it is a migration.

### D3 — Service names are folded to ASCII lowercase

A name is accepted as 1..=64 bytes of `[a-zA-Z0-9._-]` starting with a letter or
digit, and then ASCII-lowercased. The canonical form is the keychain account,
the inventory key and what `ls` prints, so `Anthropic`, `ANTHROPIC` and
`anthropic` are one credential rather than three invisible ones in a
case-sensitive keychain. Folding (rather than rejecting uppercase) is the
maintainer's decision on #160; #161 **must** fold a YAML `service:` the same
way, or the two sides can disagree about which credential a name selects.

Both halves are machine-checked (ADR-0018): the acceptance predicate, and a
contract proving that folding an accepted name leaves it accepted — which is
what makes "canonicalize, then key" equivalent to "validate, then canonicalize"
and lets the canonical form be stored and printed without a second check.

The trade-off, recorded deliberately: under this alphabet a realistic API key
(`sk-ant-api03-…`) *is* a valid service name, so "a secret typed in the name
slot" is no longer always rejected. It is a defence-in-depth loss, not a
guest-visible disclosure: the *value* is still never taken from argv, but the
name is user-controlled metadata printed by design (`ls` writes it to stdout,
`set`/`rm` to stderr) and written to the 0600 inventory, so it also reaches
anything that captures that terminal output or the inventory file. A key typed
in the name slot should be treated as exposed; a future ticket could warn when a
name looks like a credential.

### D4 — `set` writes the inventory first, then the value

```
set(name, value):                                   [under the lock]
  1. load inventory        (hard error if corrupt - no partial state)
  2. if name not listed: inventory |= {name}; create dir 0700; atomic_write 0600
  3. backend.set(name, value)
       ok  -> "stored a value for 'name' in the system keychain"
       err -> return the classified failure. The name stays listed.
```

The invariant is: **a stored value is always listed.** The reverse drift (a
listed name with no value) is visible, truthful and repairable via
`secret rm`; the opposite ordering produces the failure mode that actually hurts
— a value in the user's keychain that `secret ls` never mentions.

The failure message in step 3 says only that the value **was not updated**, never
that nothing is stored: a failed *replace* may leave the previous value in place.
What `ls` then reports is whatever the probe finds, which may legitimately be
`stored`.

### D5 — Every mutation is serialized, and so is `list`

An exclusive `flock(2)` on `.secret-inventory.lock`, acquired **after** the value
has been read from the user (so a hidden prompt never blocks holding the lock)
and released on drop (or by the kernel on process death). `secret set` is
documented as scriptable (`printf … | agent-vm secret set x`), so two concurrent
runs are a realistic way to lose an inventory row — and a lost row means a
stored value nobody can see. `list` takes the same exclusive lock (a shared one
would do) so it never observes a half-published file.

The primitive is `host_paths::flock_exclusive`, a new shared `EINTR`-looping
helper. `secrets::ProjectLock` and `mount::lock_exclusive` still carry their own
copies; migrating them is a deliberate follow-up, not part of this change.

### D6 — `rm` re-probes after the delete

```
remove(name):                                       [under the lock]
  1. load inventory
  2. backend.delete(name)  -> Present | Absent | Err
       Err -> return it; the inventory is untouched (nothing was deleted)
  3. backend.probe(name)   -> must be Absent
       Present -> error "the keychain reported success but the entry is still
                  present"; the row is KEPT so the value stays discoverable
       Err     -> the row is KEPT; the failure is reported
  4. inventory -= {name}; atomic_write 0600
       write fails -> "removed the stored value, but failed to update <path>"
  5. deleted in (2), or the name was listed -> Removed; neither -> NotStored
```

Step 3 is the answer to Context fact 3. The extra probe costs one more keychain
access (and possibly one more macOS access prompt); that is the right trade
against reporting a removal that did not happen. Step 5 means a name that
drifted *out* of the inventory is still removable by name, and a name that
drifted *in* (listed, no value) is still removable.

### D7 — The error boundary is closed

`keyring::Error` is `#[non_exhaustive]`, derives `Debug`, and carries
`BadEncoding(Vec<u8>)` plus arbitrary boxed platform errors. It is therefore
**dropped** at one boundary (`classify`) and replaced by a `Copy` enum:
`AccessDenied`, `Unavailable`, `Ambiguous`, `Rejected`, `Unknown`. Each maps to
a fixed message (`unavailable: …` in a listing row; a classified failure
elsewhere). The cost is a less specific message; the benefit is that no future
`keyring` variant can leak a value through agent-vm's stderr. Platform detail
that *is* safe (an OS status code) can be added later by explicitly extracting
it, one audited field at a time.

### D8 — No fallback, and no durability claim

If the platform credential store is unavailable the operation fails with a
classified message. There is **no** file-backed store, no plaintext
`$XDG_CONFIG_HOME` path, and no "degrade to an environment variable". Docker
falls back to a plaintext file on headless Linux; the spec rejects that
("Keychain source"; acceptance check 10, "Keychain unavailability never creates
plaintext storage").

Crash durability is **not** claimed: `host_paths::atomic_write` renames without
`fsync`ing the file or its directory, so a power loss can lose the most recent
inventory update. The consequence is a listing drift, not a lost value, and it
is repairable by re-running `secret set`. This is stated rather than implied
because the inventory-first ordering makes the other direction sound; it must not
be read as transactional durability.

## Consequences

- **`ls` is a listing, not a health check.** An empty inventory exits zero and
  means only "no names are tracked": no probe ran, so it says nothing about the
  keychain. A listing with any `unavailable:` row exits non-zero, so a script is
  never told everything is fine when agent-vm could not see the store. USAGE.md
  says both.
- **The inventory can drift from the keychain, in the direction that is safe.**
  Drift-in shows `missing` and is repairable by `set` or `rm`; drift-out (a
  value with no row) is repairable by `rm NAME` because `rm` does not require the
  row to exist.
- **A hand-written inventory is supported, and validated.** A name that fails the
  rule is a hard error, so an unvalidated name never reaches the keychain
  namespace; a duplicate row collapses, because the file records *which* names
  are tracked and the same fact twice is not two entries.
- **macOS resolves the login keychain from `$HOME`** (measured on the macOS
  verification run): overriding `$HOME` makes every verb report the store as
  `unavailable` rather than succeeding against a different keychain. That is the
  honest outcome, and USAGE.md notes it.
- **macOS access prompts are identity-dependent.** The keychain ACL is bound to
  the calling binary's code-signing identity, so a locally rebuilt unsigned
  `agent-vm` may be asked to use the item, and `ls` probes once per listed name.
  Documented as possible, not guaranteed.
- **The `SystemKeychain` adapter has no CI coverage.** `ci.yml` runs
  `cargo test -p agent-vm` on `ubuntu-latest` only, where there is no Secret
  Service. Everything except the ~50-line adapter is exercised through the
  `KeychainBackend` trait with an in-process fake stub for the three OS calls;
  the adapter gets an `#[ignore]`d round trip plus manual verification.
  `keyring`'s own `mock` backend is unusable: it returns a fresh, independent
  credential per `Entry::new`, so it cannot model a store that remembers
  anything.
- **The interactive branch has no automated regression test.** Driving a
  `termios` `ECHO`-off read needs a pty and this repo has no pty harness. The
  decision (`SecretValue::parse`) and the no-tty guard's error are tested; the
  `console::Term::read_secure_line` call was verified by hand under a pty during
  #160. A pty regression test is a worthwhile follow-up.
- **The dependency declaration adds no compilation.** `keyring 3.6.3` is
  already in the graph via the vendored SDK's `keyring` feature, with the same
  per-target features (`apple-native`; `crypto-rust` +
  `linux-native-sync-persistent`), so `cargo tree -p agent-vm -i keyring`
  resolves exactly one 3.6.3 and `Cargo.lock` gains no `[[package]]`. On Linux,
  `linux-native-sync-persistent` resolves to a plain Secret Service credential —
  the keyutils cache is not in the default path — so Linux storage is Secret
  Service only, which is what the spec names.
- **One user-visible compatibility consequence**: `secret` is now a reserved
  tool name (`config::RESERVED_TOOL_NAMES`), so a tool configuration that
  already declares a tool literally named `secret` fails validation with the
  existing "name is reserved for an agent-vm subcommand" error and must be
  renamed. That is the same behavior every other built-in verb already has.

## Alternatives

- **Enumerate the platform store natively.** `security-framework`'s
  `SecItemCopyMatching` or libsecret's search would remove the drift class
  entirely — the inventory would not exist. Rejected for #160: it adds two
  platform-specific code paths and a new direct dependency for a *listing*
  feature, and no acceptance criterion requires it. It also does not by itself
  answer "what does **agent-vm** own?" any better than a namespace the process
  controls: a native enumeration must still filter by the service name, and the
  Secret Service backend cannot be queried that way portably at all. Revisit if
  drift becomes a real support burden.
- **An index entry inside the keychain itself** (a sentinel account whose value
  is the name list). Rejected: it puts the *list* behind the same unavailability
  and the same per-item ACL as the values, so a locked keychain would make `ls`
  unable to say which names exist — exactly when a user most wants the listing.
  It also makes the listing a value, which is the thing this design avoids.
- **A state-dir-scoped inventory** (the first draft). Rejected: D2's namespace is
  host-wide, so separate worktrees would see different listings for the same
  entries, and one worktree could delete a value another never mentions.
- **Store the values in a host file, agent-vm-managed, 0600.** Rejected by the
  spec: it is plaintext credential storage, the thing "Keychain source" and
  acceptance check 10 exist to forbid. Docker's own fallback to a plaintext file
  on headless Linux is the precedent being declined.
- **Reject `agent-vm secret set SERVICE VALUE` with clap alone.** Rejected after
  the adversarial review: clap *does* render supplied values on some parse
  errors (`--help=SECRET` → `unexpected value 'SECRET' for '--help'`), and
  `cli::parse_from` hands those to `error.exit()`, where no handler can
  intervene. Two layers instead: declared refusal arguments for a *good* message,
  and an unconditional scrub of every non-help clap error inside the `secret`
  subtree (a whitelist of error *kinds*, so a future clap variant is scrubbed by
  default).
- **A pty-based test harness for the hidden prompt.** Not rejected on merit — it
  is a follow-up. It needs a new dev-dependency or a hand-rolled pty, which is
  more than this PR's scope.
