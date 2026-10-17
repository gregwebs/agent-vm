# ADR-0044: Pi reaches the host's Codex login through an image-owned provider

## Status

Accepted. Implementation decision for
[agent-vm #360](https://github.com/gregwebs/agent-vm/issues/360). Applies
[ADR-0017](0017-tool-declared-provisioning.md)'s alternative 2 the way #164
already did, ships through [ADR-0023](0023-image-owned-pi-extension-packages.md)'s
image-owned extension route and [ADR-0012](0012-stable-pi-image-customization-seam.md)'s
wrapper seam, and **amends [ADR-0011](0011-pi-mixed-credential-ownership.md)** —
see Consequences for what the amendment costs. Builds on **Credential provider**,
**Provisioning set** and **Placeholder** in [CONTEXT.md](../../CONTEXT.md).

Two repositories deliver it: the launcher half is here (`pi` provisions `openai`,
plus inventory, tests and docs), the extension and wrapper half is
`gregwebs/agent-vm-images` (`images/tools/pi/extensions/agent-vm-codex.js`,
`images/tools/pi/pi.sh`, `images/tools/pi/extensions/guest-credential-warning.js`).

PR A is pending implementation/merge. The pinned v0.1.3 image lacks its
extension, wrapper activation and registry-gated warning clause. Decisions
D2–D7 describe PR A's contract on an image carrying A, not delivered image
behaviour. PR B alone implements D1 and the launcher side effects below.

## Context

`agent-vm pi` had no way to reach a ChatGPT/Codex subscription. The `openai`
provider already captures the host `~/.codex/auth.json` and writes a guest
`codex/auth.json` whose `tokens.access_token` is
`msb-openai-placeholder-a-v2` and `tokens.refresh_token` is
`msb-openai-placeholder-r-v2` (`crates/agent-vm/src/secrets.rs`,
`refresh_openai`), keeping the real `tokens.account_id`. It does that on any
launch whose **provisioning set** contains `openai`. Before this ADR, a `pi`
launch's set was `{anthropic}`.

Giving `pi` the credential is therefore the easy half. Carrying the placeholder
from the guest to the wire is the hard half, and four facts about Pi 0.87.1's
pi-ai constrain every design:

**1. The apiKey must be a JWT.** `dist/api/openai-codex-responses.js:1250`
(`extractAccountId`) base64-decodes the apiKey with `atob` and needs
`["https://api.openai.com/auth"].chatgpt_account_id`. It throws if that fails.
The opaque placeholder cannot be the apiKey.

**2. Pi writes `Authorization` last.**
`buildBaseCodexHeaders` (l.1265) sets `Authorization: Bearer <apiKey>` and
`chatgpt-account-id` **after** the caller's headers, so neither can be
overridden through a `headers` option.

**3. Only SSE goes through `options.fetch`.** l.267 passes the SSE request
through `options?.fetch ?? globalThis.fetch`. The default `transport: "auto"`
(l.184-190) tries WebSocket first, and the WebSocket path builds its own socket
with no injection point. So a fetch wrapper sees inference requests only under
`transport: "sse"`.

**4. Replay identity is the api id, not the provider id.** The codex stream
stamps every returned assistant message with `api: "openai-codex-responses"`
(hardcoded, l.150) and `provider: model.provider` (l.151), and
`dist/api/transform-messages.js:68-109` keeps encrypted reasoning and
`call|item` tool ids only when `provider`, `api` **and** model id all match the
current model. A provider registered under a *custom* api id therefore loses
encrypted reasoning and normalizes tool-call ids on every turn. The **provider
id** is free to differ; the **api id** is not.
`dist/core/provider-composer.js:335-350` dispatches to an extension's
`streamSimple` when `model.api === extension.api`, per provider, so reusing the
built-in api id does not touch Pi's built-in `openai-codex` provider.

Two retry layers bound how many times any wrapper can run:

- **pi-ai's SSE loop** (`l.255-325`) retries up to `options.maxRetries`
  (`DEFAULT_MAX_RETRIES = 0`, l.22), which Pi passes from its
  `retry.provider.maxRetries` setting — unset by default. That loop's `catch`
  also retries its *own* non-2xx error, so under a nonzero setting a fetch
  wrapper is re-entered inside one stream.
- **Pi's session auto-retry** is enabled by default and re-runs a whole turn
  (a new `streamSimple`) up to three times when the error text matches
  `RETRYABLE_PROVIDER_ERROR_PATTERN` (`dist/utils/retry.js:20`, `503`,
  `service.?unavailable`, `timeout`, …). Error text is therefore load-bearing:
  a synthesized failure that reads like `503` would start another host refresh.

## Decision

`pi` names `codex`, and an image-owned extension registers a **separate** Pi
provider whose requests carry the guest placeholder.

```text
guest /agent-vm-state/codex/auth.json
  {"tokens":{"access_token":"msb-openai-placeholder-a-v2",
             "refresh_token":"msb-openai-placeholder-r-v2",
             "account_id":"acct-123"}}
        │ extension factory: exact-placeholder check → register "agent-vm-codex"
        ▼
Pi turn on agent-vm-codex/<openai-codex model id>   (api = "openai-codex-responses")
  apiKey = base64url-free synthetic JWT carrying only {"chatgpt_account_id":"acct-123"}
  pi-ai  → Authorization: Bearer <synthetic JWT>  (overwrites it, l.1265)
  fetch wrapper → Authorization: Bearer msb-openai-placeholder-a-v2   (transport forced "sse")
        ▼
proxy (host) → Bearer <real host token> → chatgpt.com/backend-api/codex/responses
401? wrapper → cancel the 401 body → POST auth.openai.com/oauth/token
                {grant_type:refresh_token, refresh_token:msb-openai-placeholder-r-v2}
       → _intercept-hook re-syncs the host token (host `codex exec` if near expiry)
       → 2xx: resend once ; otherwise: fixed `codex login` diagnostic, no resend
```

**D1 — Provisioning is `pi.tools = ["claude", "codex"]`.** ADR-0017
alternative 2: a named tool is provisioned, never required. `pi` keeps
`credentials = []`, so a host with no Codex login still launches. The rejected
alternative is `credentials = ["openai"]` on `pi`, which makes the login
mandatory and fails that acceptance criterion; a new provider variant for Pi is
the second credential path #360 forbids.

**D2 — The provider id is `agent-vm-codex`; the api id is Pi's built-in
`openai-codex-responses`.** The api id is what preserves encrypted reasoning
and `call|item` ids across turns (Context 4). The distinct provider id is what
keeps the host credential apart from a guest `openai-codex` entry, which is
ADR-0011's precedence rule — a distinct id can never shadow or replace one.

**D3 — The apiKey is a synthetic, non-secret JWT.** Standard base64, not
base64url: `atob` rejects `-`/`_`, and a payload whose base64url form contains
either would otherwise break every request. It carries only
`chatgpt_account_id` from the guest file, which is not a secret.

**D4 — Transport is forced to `sse` and headers are rewritten in a fetch
wrapper.** This is the only seam pi-ai exposes (Context 3). The wrapper also
refuses any URL whose host is not `chatgpt.com`, so a `models.json` `baseUrl`
override cannot send the placeholder to a host the proxy does not substitute.

**D5 — Refresh is host-side, at most once per stream, and resend happens only
after a 2xx.** On a 401 the wrapper cancels that response body, POSTs the
**placeholder** refresh grant to `auth.openai.com/oauth/token` — answered by
`_intercept-hook`, which re-reads the host file and runs host `codex exec` near
expiry — then inspects the refresh status, drains its body on success **and**
failure, and resends inference only after a 2xx. A rejected or failed refresh
returns a fixed, non-retryable 401 naming host `codex login`. The text contains
no status, no error code, no reply body and no exception, because Pi's session
classifier matches text (Context, retry layer 2) and untrusted text can both
leak and restart a host `codex exec`.

The wrapper allocates its state **once per `streamSimple`**, so for a provider
`maxRetries = N` the bound is one refresh and N+2 inference sends — the extra
send being the successful-refresh resend. A failed refresh is cached: later
entries return fresh diagnostic responses without any network request. No
proactive refresh: the guest never learns a real expiry, and the hook refuses
to rotate a token still above its margin.

**D6 — Registration is an exact-placeholder predicate on a fixed path.** The
extension reads `/agent-vm-state/codex/auth.json` and registers only when
`tokens.access_token` and `tokens.refresh_token` both equal the constants above
and `tokens.account_id` is a non-empty string. Anything else — absent,
malformed, a real guest `codex login`, an `OPENAI_API_KEY`-shaped host login —
registers nothing and never forwards or refreshes it. The path is fixed rather
than derived from `CODEX_HOME`: tool `env` belongs to the launched tool
(ADR-0016), and the placeholder is always written at the persisted path.

**D7 — The guest-credential warning's host-import clause is gated in code on
the registered provider.** The mandatory warning extension queries the model
registry at `session_start` and appends *"Credentials imported from your host
stay on the host and never appear in guest files."* only when
`agent-vm-codex` is registered. Pi flushes queued `registerProvider` calls
before `session_start`, so extension order does not matter; a failed
registration leaves the clause absent. The lookup sits in its own `try/catch`
that falls back to the base text, so the advisory can never throw or vanish
(ADR-0012). Deliberately **not** the alternatives: an unconditional string
gated only on image publication (a grep cannot establish when behaviour exists,
and #360 requires the warning to claim host import only once it is true), or
gating on the placeholder file (file I/O inside an extension that must never
throw, duplicating the codex extension's predicate instead of observing its
result).

## Consequences

- **The `auth.openai.com` intercept route is shared by every OpenAI client in
  the guest.** It answers placeholder refresh grants only, so on a `pi` launch
  from a host with a Codex login an in-guest `pi` `/login openai-codex` cannot
  complete (its authorization-code exchange gets 403), and an existing
  guest-managed `openai-codex` credential cannot refresh on later `pi`
  launches. The distinct provider id keeps the two credentials apart; it does
  **not** keep the guest one working. This is the documented cost of ADR-0011's
  amendment and is stated in `USAGE.md`, with the workaround: use
  `agent-vm-codex/*`, or launch from a host with no Codex login.
- **A launcher release without an image carrying the extension is
  security-safe but not feature-complete.** No bearer reaches the guest, but the
  side effects above apply anyway and `agent-vm-codex/*` does not exist on that
  image, so the advertised workaround is unavailable. ADR-0035 retention keeps
  users on older images after the launcher ships, so the window outlives the
  image release; `USAGE.md` names which image restores the workaround.
- **SSE only.** Pi's WebSocket session reuse is lost for this provider.
- **A cross-repo constant.** The extension compares against
  `msb-openai-placeholder-a-v2` / `-r-v2`. Renaming either to `-v3` needs a
  coordinated image release; the comment beside the Rust constants says so.
- **A host `codex exec` is now reachable from a `pi` launch.** The provider is
  legitimately provisioned, so this is the same exposure `codex` and `shell`
  launches already carry — not #91's blocker, which was a host-exec route
  *without* provisioning.
- **A successful capture overwrites `/agent-vm-state/codex/auth.json`** with
  the placeholder, including a guest credential stored there by a prior
  `agent-vm codex`/`shell` launch or explicit `CODEX_HOME`. Pi inherits neither
  `CODEX_HOME` nor a guest-HOME `.codex` link; this is not an overwrite of an
  arbitrary HOME-relative in-Pi login. Existing `refresh_openai` behaviour,
  now reachable from `pi`; a failed capture still spares that file.
- **`codex/config.toml` is written on every `pi` launch**, because
  `write_bypass_configs` follows the provisioning set, not capture.
- **The warning is advisory, not a boundary.** A guest-authored `models.json`
  or extension that registers the id `agent-vm-codex` would also trigger the
  host-import clause (ADR-0012).
- **`api.openai.com` is not added to `pi`'s `network_requests`.** Only Pi's
  built-in `openai` provider dials it, and only with a user-configured key. The
  inventory is evidence of what the shipped configuration reaches, never a
  projection of `ProxySecret::hosts` (ADR-0039).

## Alternatives

| Alternative | Why rejected |
|---|---|
| Pass the placeholder as the apiKey | `extractAccountId` throws (Context 1) |
| Make the *placeholder itself* a JWT and substitute the whole string | It would need the real account id inside a fixed constant. Per-user placeholders break `placeholders_are_pairwise_distinct`; substituting only the signature segment yields an invalid JWT |
| Override `headers` | Pi sets `Authorization` after caller headers (Context 2) |
| Register onto the built-in `openai-codex` provider | A stored guest `/login` owns that provider, so the override would have to tell a real guest token from ours and would replace the api for every `openai-codex` user — conflating host and guest credentials under one id, which ADR-0011's precedence rule exists to keep apart |
| A custom api id (`agent-vm-codex-responses`) | `transform-messages` treats every prior assistant turn as foreign: encrypted reasoning dropped, `call\|item` ids normalized (Context 4) |
| Copy or patch pi-ai's codex transport | ~1300 lines tied to a Pi version that every bump would have to re-verify; delegation preserves Pi's conversion, usage and abort behaviour |
| Keep WebSocket by supplying a custom socket | pi-ai offers no injection point |
| Read whatever token is in `codex/auth.json`, placeholder or not | It would forward — and on 401 *refresh* — a guest-managed real token. OpenAI refresh tokens are single-use, so this would silently break the user's in-guest `codex login` |
| Teach the proxy to rewrite `chatgpt-account-id` host-side | A second credential mechanism for one client's quirk; the account id is not a secret and the guest already holds it |
| Gate the warning on image publication instead of the registry | A string grep cannot establish that the behaviour exists; #360 requires the claim to be true when made |
| Gate the warning on the placeholder file | File I/O in an extension that must never throw, duplicating the codex extension's predicate |
