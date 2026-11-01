# ADR-0056: the macOS keychain item as a second Anthropic host credential location

## Status

Accepted. Implementation decision for [agent-vm
#492](https://github.com/gregwebs/agent-vm/issues/492). Amends nothing: the host-only
token file and its per-connection re-read ([ADR-0010](0010-wire-file-backed-credential-injection.md))
are unchanged, and the foreign item is **never** addressed through agent-vm's own
secret store ([ADR-0024](0024-host-secret-inventory.md)).

## Context

On macOS a host whose Claude Code login lives in the keychain could not run
`agent-vm pi`. The Anthropic provider read exactly one location — the **host
credential file** `~/.claude/.credentials.json` — and on that host the file is a
stale copy the CLI never rewrites. The launcher copied the stale `expiresAt` into
the guest placeholder, the proxy substituted the stale token on the wire, and
every turn failed with `401 … OAuth access token …` while `claude` in the same
terminal worked. `agent-vm doctor` said `ok (EXPIRED 61h31m ago)`.

Rotation could not recover either. The guest's refresh attempt reaches
`_intercept-hook`, which runs `claude -p hi --model sonnet`, which refreshes *the
keychain item*, after which the hook re-read the same stale file and answered a
typed `503`. The outage was permanent for that host: it survived relaunches, and
`/login` inside the guest is an authorization-code exchange the hook rejects by
design.

Both readers are host-side processes (the launcher, and the hook, which
microsandbox runs on the host), so the guest needs no keychain access for any of
this.

## Decision

Anthropic has two **host credential locations**: the file, and — on macOS only —
the generic-password item Claude Code maintains under the service name
`Claude Code-credentials`. Both are read, both are parsed by one parser
([`crates/agent-vm/src/host_credential.rs`](../../crates/agent-vm/src/host_credential.rs)),
and the **later `expiresAt` wins**. An absent or unparsable expiry sorts as
`i64::MIN`; an exact tie keeps the **file**, so a host whose Claude Code writes
only the file observes no change at all — the keychain is an additional
candidate, never a replacement.

```
file ─────┐
          ├─ eligible? (parses ∧ non-empty claudeAiOauth.accessToken)
keychain ─┘        │
                   ├─ neither  → Err, the *file's* reason (today's 503 vocabulary)
                   ├─ one      → that one
                   └─ both     → later expiresAt; tie → file
```

One module owns location, reader, selection and parse. Its three consumers keep
their own policy: capture decides what to install, the hook decides serve /
rotate / fail, doctor decides what to render. The hook re-reads **both**
locations at every re-read point, which is the actual fix: the store the host CLI
refreshes is the one the old rotation could not see.

Capture still writes exactly two things — the 0600 host-only token file and the
guest placeholder carrying the chosen `expiresAt` — and **agent-vm never writes
either location**. The read-once/write-only-the-host-copy invariant is unchanged.

### Selection is a freshness heuristic, not a validity check

A later `expiresAt` does not prove a bearer is still accepted, nor that it
belongs to the account the user meant. It is the only ordering two opaque blobs
offer, and it is right in the case that matters: the location the host CLI
refreshed most recently. Expired-but-parseable credentials stay **eligible**;
expiry only orders candidates, and the hook decides from the chosen one exactly
as before. That is why a stale launch does not bail: capture succeeds, and the
guest's refresh heals the session.

### Why `security`, not `keyring` or the Security framework

The item's ACL trusts the binary that created it, `/usr/bin/security`, because
Claude Code spawns that binary for every read and write. Measured on the
reporting host: `security … -w` returned immediately, while an equivalent read
from a non-Apple binary through the `keyring` crate (already a dependency)
**blocked for 25 s on a consent dialog**. A proxy hook must never do that, and
`kSecUseDataProtectionKeychain`-style non-interactive reads are not reachable
through the `security` CLI — which is the whole reason for reading through it.

### Why `PATH`, not a hardcoded `/usr/bin/security`

The OAuth hook already resolves `claude` and `codex` on `PATH`, and a fake binary
on `PATH` is the existing test seam. The threat level is unchanged: whoever can
shadow `PATH` can already edit the host credential file directly.

### Bounds

| Bound | Launch and `doctor` | Hook |
|---|---|---|
| Keychain polling budget | 5 s | 2 s |
| Budget coverage | **one** deadline across the account-qualified query and its bare retry | same |
| Item size | `MAX_HOST_CREDENTIAL_FILE_BYTES` (1 MiB) **on the item**; cap+1 bytes are collected so the newline `security -w` adds is not counted, and anything still over the item cap is oversized | same |
| stderr | drained to a sink, never logged, never in an error | same |
| child environment | `host_cli`'s allow-list: cleared, then `HOME`/`PATH`/`USER`/`LOGNAME`/`TMPDIR`/locale/proxy vars | same |
| trailing byte | at most one `\n` removed — the presentation byte `security -w` adds | same |

A timeout, a non-zero exit other than "item not found", a malformed blob or an
oversize makes the keychain candidate **ineligible** — never an error that fails
a launch, never a block.

What that buys is a **polling/wait budget, not an absolute deadline**. Each
attempt costs its share of the deadline plus the bounded kill/reap and collector
grace that follow it; process spawn and OS scheduling sit outside the arithmetic,
and the runner checks for a successful exit before it consults the elapsed time,
so a read that answers late but answers is kept rather than discarded to defend a
boundary. The cleanup is not free and is counted: every attempt ends in `finalize`,
which reaps within `REAP_CEILING` and waits up to `STDERR_GRACE` for each of the
two collectors, and the success path spends one more `STDERR_GRACE` on stdout
before that. The worst case for one read is therefore the polling deadline plus
one `REAP_CEILING`, four `STDERR_GRACE` waits (two per attempt) and two
`POLL_OVERSHOOT` granularity ticks — `HOOK_KEYCHAIN_NOMINAL_COST`, which the hook
assertion spends three times alongside the lock ceiling, the 45 s CLI timeout and
slack, and requires to fit microsandbox's 90 s handler budget; it does not claim a
hard real-time guarantee under arbitrary OS delay.

**Calls per attempt:** **two** is the maximum, and it is also the common
non-success number. A read that finds the item makes **one** call; a miss on the
account-qualified query falls through to the bare retry, so an item that is not
there costs **two** exit-44 calls, and a `security` that is not on `PATH` costs
two failed spawn attempts the same way. No call is made when the attempt starts
with its share of the shared deadline already spent, or in a build with no
keychain location at all (non-macOS, where the file is the whole answer).

`errSecItemNotFound` is exit status **44**; a `security` that is not on `PATH` is
treated the same way, so `doctor` stays byte-identical on a host without the item.

### The measured `security` contract

Established by an opt-in test against the real `/usr/bin/security` in a
**disposable** keychain (never the login keychain, never the default search list,
never the real item):

| Fact | Measured behaviour |
|---|---|
| Read shape | `security find-generic-password -a <acct> -w -s "<service>"`; the keychain is a positional argument on this macOS, which is how the contract test isolates itself |
| `-w` output | the item's data followed by exactly one `\n` |
| Writes | plaintext (`-w <data>`) and hex (`-X <hex>`, the option Claude Code passes through `security -i`) both round-trip to the intended bytes |
| `-w` and non-printable data | **hex-encodes** the data — a trailing `\n`, or any byte outside printable ASCII, is enough. Claude Code's credential JSON is printable, so this only makes a non-JSON item *ineligible* (the file location decides); it never becomes a silently misread credential |
| Missing item, or an item under a different account | exit status **44** |
| Bare query | finds an item when exactly one matches; with several matches the order is not specified, which is why the bare query is only a retry for a miss |

That hex behaviour is also why the "one newline retained" rule is stated as a
byte-level rule for the adapter: data the CLI would present as plaintext never
ends in a newline, because such data is presented as hex instead.

### Account precedence

The item is written for one account, so the query is account-qualified first,
mirroring Claude Code's own computation ($USER, then the passwd name, then its own
very small charset rule and its own literal fallback `claude-code-user` —
`$LOGNAME` is never consulted). `security` matches **any** account when `-a` is
omitted, so a miss falls through to the bare `-s` query as belt and braces; the
first match wins.

### Known risk, documented rather than solved

A locked login keychain can show an unlock dialog for `security` too. The polling
budget bounds **agent-vm's wait** — the process group is killed at the deadline —
and `doctor` then renders the item as
`macOS keychain UNUSABLE - timed out after 5s (is the login keychain locked?)`
rather than omitting it. It is not a guarantee about the dialog's own lifetime: a
resident GUI agent can keep that window in front of the user after agent-vm has
given up on the read.

### Known limitation

A custom `CLAUDE_CONFIG_DIR` (or a non-production environment) changes the
service name: Claude Code appends `-<sha256(config dir)[0..8]>` and an
environment suffix. agent-vm reads the default item only, which matches the
limitation its hard-coded `~/.claude/.credentials.json` already has for the file
location.

### No new Verus contract

[ADR-0018](0018-machine-checked-boundary-contracts.md) contracts are for leak
boundaries, resource limits and untrusted-input parsing. Selection here is an
*availability* decision over two already-bounded reads, and the bytes still go
through the existing serde parse; the cap comparison sits inside an I/O adapter,
the same way `read_bounded_regular_file` does it. Recorded so the omission is a
decision, not an oversight.

### Three `doctor` renderings change on a host with no keychain item

`doctor` now uses the hook's parser for the Anthropic row. Every valid credential
renders byte-identically, and the row shape and wording do not change, but three
*malformed* cases do:

| Credential | Before | After |
|---|---|---|
| empty `claudeAiOauth.accessToken` | `ok` | `UNUSABLE - claudeAiOauth has no accessToken` |
| `expiresAt <= 0` | `ok (EXPIRED …)` | `ok` (no expiry) |
| float `expiresAt` (e.g. `9999999999000.7`) | `ok` | `ok (expires in …)` — truncated to an integer millisecond value and rendered as an ordinary relative expiry against the current clock, not `ok` and not a literal float |

Keeping a second parser to preserve those three strings was rejected: calling an
empty token `ok` while capture writes it and the hook refuses it is a defect.

## Evidence

Probes run on the reporting Mac (macOS with a real `Claude Code-credentials`
item) before the implementation:

| Probe | Command | Result |
|---|---|---|
| Not-found status | `security find-generic-password -s "agent-vm-probe-<pid>-absent"` | **44** |
| Hermeticity with a temp `HOME` | `env -i HOME=$(mktemp -d) PATH=/usr/bin:/bin security find-generic-password -s "Claude Code-credentials"` | **44** — `security` resolves `$HOME/Library/Keychains/login.keychain-db` |
| Hermeticity with **no** `HOME` | `env -i PATH=/usr/bin:/bin security find-generic-password -s "Claude Code-credentials"` | **0** — the real item. `security` falls back to the passwd home, so a harness that unsets `$HOME` is *not* isolated |
| Item shape | `security find-generic-password -s "Claude Code-credentials"` | `acct="claude"` = `$USER`; `-w` prints the file-shaped JSON |
| `keyring` crate read from a non-Apple binary | reporter's measurement | blocked ≥ 25 s on a consent dialog |

**The CLI does persist a refresh to this item** — the assumption the self-heal
rests on. Recorded from the installed Claude Code 2.1.310 binary (fragments
quoted, not paraphrased): the store's service name is
`` `Claude Code${suffix}` `` built from `var zRe="-credentials"`; its write path is
`` `add-generic-password -U -a "${s}" -s "${n}" -X "${o}"` `` fed to `security -i`;
and the OAuth refresh calls that path through a compare-and-swap in a three-attempt
loop, logging `"OAuth refresh CAS save failed"` on failure. A rotated access token
therefore lands in the keychain item, not only in memory — so the hook re-read is
worth shipping, and the fallback ("ship capture only; mid-session expiry recovers
by relaunch") does not apply.

Test isolation, measured rather than argued: with a `security` on `PATH` that
logged its `$HOME` and answered "not found", a full `cargo test -p agent-vm` run
invoked it 710 times, every one with a temp `$HOME` (and, after the fix below, none
with `$HOME` unset). The first such run found four harnesses that launch with
**no `$HOME` at all** — `config_doctor`, `mount_follow_links`, `mount_fork`,
`mount_protected_pi` — where, per the probe above, macOS would have resolved the
developer's *real* login keychain. They now take
`support::path_without_host_keychain()`. Unit (`cfg(test)`) builds cannot spawn a
`security` at all: the program name comes from `AGENT_VM_TEST_SECURITY` and is
absent when that variable is unset.

## Alternatives rejected

- **Read the item through the `keyring` crate or Security.framework.** The 25 s
  consent dialog, above.
- **Hardcode `/usr/bin/security`.** Loses the `PATH` test seam for no security
  gain, since shadowing `PATH` already implies control of the credential file.
- **Let `credentials.yaml` name the foreign item.** A same-named entry is a
  **Replaced provider**, which drops the guest placeholder *and* the OAuth
  refresh route, so expiry would become unrecoverable without a relaunch.
- **Sync or repair `~/.claude/.credentials.json`** from the item. That makes
  agent-vm a writer of the vendor's login path — the one thing the invariant
  forbids — and re-stales wherever a user has two consumers.
- **`claude setup-token` / long-lived tokens.** A different credential with a
  different lifecycle; it does not fix a user's existing login.
- **Add a keychain location to the other three providers.** Out of scope: Codex's
  `~/.codex/auth.json` is a file on the reporting host, and Linux Secret Service
  is agent-vm's *own* store ([ADR-0024](0024-host-secret-inventory.md)), a
  namespace agent-vm owns. A foreign item is never addressed through it.

## Consequences

- A macOS user whose login is only in the keychain needs no manual file surgery,
  and a host that writes both locations uses whichever is fresher without
  configuring anything.
- A stale file can no longer shadow a live keychain login, and an expired access
  token recovers mid-session without relaunching the sandbox.
- A launch on macOS now attempts one `security` read (a second only when the
  account-qualified query misses, none when the location is unavailable), and
  `doctor` does the same within its 5 s budget: 5 s at launch and in `doctor`,
  2 s in the hook. A locked keychain **may** show an unlock dialog; agent-vm's
  wait for it is bounded by those budgets and then degrades to the file, while
  the dialog itself is the platform's behaviour and is not bounded here.
- `snapshot_host_creds` stays file-only — a keychain item has no hashable path —
  and the launch notice (`run::creds_notice`) is unchanged: once the fresher
  location wins, the anomaly it would warn about no longer affects the guest.
- `doctor` gains a source clause only when an item exists.
