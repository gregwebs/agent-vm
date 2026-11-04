# ADR-0058: Antigravity is a fifth credential provider, and its placeholder lives in the guest's Pi home

## Status

Accepted. Implementation decision for [agent-vm
#507](https://github.com/gregwebs/agent-vm/issues/507). Companion to the
image's own [ADR-0016](https://github.com/gregwebs/agent-vm-images) (the
`pi-antigravity` provider extension is image-owned), [ADR-0017](0017-provider-acceptance.md)
(the provider seam this joins), [ADR-0010](0010-wire-file-backed-credential-injection.md)
(placeholder + host-only token file) and [ADR-0020](0020-protect-host-pi-credential-files.md)
(the host files a guest never sees).

## Context

The image ships `pi-antigravity` as a third Pi `--extension`. It registers the
`antigravity/*` catalog **offline** and asks for a credential only when a
request needs one, so a guest without one simply has no Antigravity models.
`agent-vm pi` in a rebuilt image listed none, and the user's host had a working
Google login: the models were unreachable for exactly one reason — the
credential.

That provider reads Pi's own provider document, `<agent dir>/auth.json` →
`antigravity` = `{type, email, access, refresh, expires, projectId}`, refreshes
at `https://oauth2.googleapis.com/token` when `expires` is within five minutes,
and sends `Authorization: Bearer <access>` to `ANTIGRAVITY_BASE_URL` or
`https://daily-cloudcode-pa.googleapis.com` (falling back to
`daily-cloudcode-pa.sandbox.googleapis.com` and `cloudcode-pa.googleapis.com`).
`auth.json` is a protected host file, and a `:fork` seed omits it.

Measured, in the guest: one hand-written `antigravity` entry — placeholder
tokens, the host's `projectId`, a future `expires` — makes the provider register
and list its five models with no network at all. So the seam is the credential
document and nothing else.

One wrinkle decided the shape. The guest's Pi home is usually a `:fork` of the
host's `~/.pi`, mounted at the guest path that `~/.pi` resolves to, so the
lexical `<state>/pi` is shadowed. Every other provider writes its placeholder
under `<state>`, which is the guest's `$HOME` bind; doing that here would have
written a file the guest never reads.

## Decision

### One more row in the provider table

Antigravity is a `CredentialProvider`, complete with the four facets the seam
already names:

- **capture** — `~/.pi/agent/auth.json`, `antigravity.access` only. The real
  access token goes to `<state>.secrets/antigravity` (0600, never mounted).
- **guest placeholder** — `access`/`refresh` are new
  `ANTIGRAVITY_*_PLACEHOLDER` values; `projectId` and `email` are copied
  (neither is credential material); `expires` is **the host's own expiry**, so
  the provider's refresh is the rotation signal, exactly as for Anthropic and
  OpenAI.
- **proxy secret and route** — the placeholder is substituted on the three
  cloudcode hosts and answered on `oauth2.googleapis.com` (`/token`).
- **rotation** — `RotatableProvider::Antigravity` in
  `intercept_hook/oauth_refresh.rs`. There is no Antigravity CLI, so the
  host-side one-shot is a host Pi prompt against a cheap Antigravity model
  (`pi -p hi --model antigravity/gemini-3.8-flash`), which makes the host's
  provider refresh its own document. Same lock, stamp and re-read as its
  siblings.

No `missing_credential_error`: not every user has a Google login, and the tool
degrades to "no Antigravity models" rather than to a signed-in provider holding
an unsubstitutable placeholder.

### The placeholder is written into the Pi home the guest reads

`secrets::refresh` takes the host directory the guest sees as its Pi home. The
launcher resolves it from the prepared mount plan: a writable bind at the guest
`~/.pi` is a fork's data directory (a live bind there is refused by
[ADR-0020](0020-protect-host-pi-credential-files.md)), so the placeholder lands
inside the fork, and `<state>/pi` is used when no such mount exists. The
clearer is content-scoped and removes only our own `antigravity` entry, leaving
a guest-authored provider row — or any other key — intact.

`antigravity-accounts.json`, the provider's own multi-account store, is
protected as well ([#508](https://github.com/gregwebs/agent-vm/issues/508)): it
holds a live access token and a long-lived refresh token per account, and it is
not needed by the guest, since an `auth.json` entry alone is sufficient.

## Consequences

- `agent-vm pi` reaches Antigravity models whenever the host Pi is signed in;
  `agent-vm doctor` gains a `pi` host-credential row, and `agent-vm shell` (the
  wildcard) provisions the provider like the other four.
- The guest needs egress to `oauth2.googleapis.com` and to a cloudcode host.
  The shipped `pi` tool declares all three cloudcode hosts, so a user whose
  persisted grants name only `cloudcode-pa.googleapis.com` must either grant a
  `daily-` host or set `ANTIGRAVITY_BASE_URL` to the one it granted; the
  provider's default is the `daily-` endpoint.
- The quota dispatcher needs no change: its antigravity rails read the same
  `auth.json` and call `https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary`,
  so the same substitution makes them report real numbers in the guest.
- A rotated token reaches the proxy through the host-only token file, so a
  stale host token costs one refresh round-trip, not a relaunch.
- The placeholder's home is now a launch input. A future provider whose
  credential document lives in a host-visible tree needs the same treatment,
  and `run::pi_home_host_root` is where it is expressed.

## Alternatives considered

- **Point the guest at a state-dir Pi home (`PI_CODING_AGENT_DIR`).** Rejected:
  it relocates sessions, extensions and the user's whole Pi configuration, to
  solve a one-file problem.
- **A child bind of the placeholder over the fork.** Rejected: the prepared
  mount plan is closed on purpose, and a file bind whose host source does not
  exist until after capture inverts the order the plan is validated in.
- **Do vendor OAuth in Rust, with the plugin's public client id.** Rejected:
  every existing rotation re-runs the CLI that owns the credential, and this
  would make agent-vm a second OAuth client with its own failure modes.
- **Serve the placeholder from the state dir and leave the fork shadowed.**
  Rejected: it silently does nothing on the one configuration that matters.
