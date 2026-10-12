# Shipped default-tool network requests

Reviewed 2026-10-12 for [#328](https://github.com/gregwebs/agent-vm/issues/328).
The executable source is [default-tools.toml](../crates/agent-vm/src/default-tools.toml).
This completes four provider rows, **not all shipped tools**: Copilot's inventory
is deferred to [#340](https://github.com/gregwebs/agent-vm/issues/340).

## Contract and scope

These are potential **TLS over TCP 443** needs: exact lowercase names, not URLs,
wildcards, CDN aliases or an allowlist. They never grant egress authority,
provision credentials, authorize DNS, or enable TLS interception. Grants remain
user decisions. Coverage is syntactic, not proof of connectivity or login; see
[USAGE](../USAGE.md#tool-network-requests) and
[TLS client requirements](../USAGE.md#tls-client-requirements).

```text
catalog requests ──► bounded diagnostics ◄── protected user/CLI grants
                         │                          │
                    launch continues           network policy
```

The baseline includes provider inference, post-login account validation/refresh,
the shipped Claude relay and provider-catalog refresh. Claude/Pi here use a
launcher-provisioned API key or already-acquired first-party OAuth credential.
Interactive guest enrollment/login, remote sessions and artifact live subscriptions
are outside this baseline. The list is not a set of startup prerequisites or a
claim that each session contacts every name.

Excluded: host-browser sign-in, installers/updaters, arbitrary WebFetch/Git/MCP
servers, optional plugins/telemetry and user-configured providers/proxies.
No env/argv disables those features here. Empty metadata does not mean offline.
Custom catalogs replace defaults wholesale; `tools` provisioning never inherits
requests. Doctor and launch diagnostics show at most eight entries; consult the
source for the full set if future declarations overflow.

## Restricted built-in example

With already-provisioned Claude auth and no grants (`agent-vm claude`), launch
continues after this informational block; destinations remain denied:

```text
==> Tool network requests (built-in defaults): 3 of 3 not covered by this launch's public or same-name grants (no lookup; DNS, private-answer and TLS client limits still apply); requests never grant access and the launch continues
==>   unmet: api.anthropic.com
==>   unmet: mcp-proxy.anthropic.com
==>   unmet: platform.claude.com
==>   to grant: --allow-egress HOST or tcp://HOST:PORT, or --allow-internet-egress; IP/CIDR, --allow-lan and --allow-host grants are not matched to names
```

An API:443-only hostname allowance leaves two unmet. API:8443-only leaves all
three unmet; a public internet grant prints one all-three-covered header. None
of these reports proves authentication, resolution or TLS compatibility.

## Evidence matrix

All rows below are HTTPS/WSS origins on TLS/TCP 443. Source keys link to pinned
implementations or maintained primary documentation below.

| Tool / inspected version | Name | Role / condition | Source |
|---|---|---|---|
| Claude Code 2.1.286 | `api.anthropic.com` | Inference/feature flags; provisioned OAuth profile, validation and roles | A, A1 |
| Claude Code 2.1.286 | `mcp-proxy.anthropic.com` | claude.ai MCP connectors, default-enabled with that auth | A, A1 |
| Claude Code 2.1.286 | `platform.claude.com` | OAuth token exchange/refresh/revoke; already-provisioned baseline uses refresh | A, A1 |
| Codex 0.159.3 | `api.openai.com` | API-key inference default | B |
| Codex 0.159.3 | `auth.openai.com` | First-party OAuth refresh | B |
| Codex 0.159.3 | `chatgpt.com` | ChatGPT subscription inference | B |
| OpenCode 1.18.34 | `api.openai.com` | OpenAI API-key inference default | D |
| OpenCode 1.18.34 | `auth.openai.com` | OpenAI OAuth issuer/refresh | D |
| OpenCode 1.18.34 | `chatgpt.com` | OpenAI subscription inference | D |
| OpenCode 1.18.34 | `models.opencode.ai` | Credential-free provider-catalog refresh | D |
| Pi 0.87.1 + bridge 0.8.0 | `api.anthropic.com`, `mcp-proxy.anthropic.com`, `platform.claude.com` | Explicit shipped Claude bridge baseline under the same provisioned auth conditions, not all Pi adapters or a provisioning union | A, A1, E |
| Copilot 1.0.90 | omitted | **Incomplete evidence**, not absence of provider traffic; #340 | C |
| dsh | omitted | Dormant multi-provider adapter, no configured/required provider, no universal inference name; browser UI ingress is not egress | Embedded catalog |
| shell | omitted | General command shell, no universal provider destination despite wildcard provisioning | Embedded catalog |

API-key and subscription modes need different subsets. OpenCode may retire its
OpenAI default when only other static providers are wired. Self-update defaults
off locally (`or_insert(false)`), but a stored true value survives: updater
traffic is excluded, not guaranteed absent. `$schema` alone proves no fetch;
`opencode.ai` is not declared. `models.dev` is a module/log name, not this host.

### A — maintained Anthropic guidance

[Network access requirements](https://code.claude.com/docs/en/network-config#network-access-requirements),
rechecked 2026-10-12, lists the three names and their roles. Its wider enterprise
firewall table also lists browser sign-in, plugin/telemetry/artifact destinations
and **`claude.ai` account authentication**. That unversioned guidance must not be
misdescribed as categorically browser-only. A1 establishes the narrower supported
post-login guest path; it does not certify every feature in the firewall table.

### A1 — pinned guest account-auth audit and excluded candidate

Official [Linux/x64 Claude Code 2.1.286 artifact](https://registry.npmjs.org/@anthropic-ai/claude-code-linux-x64/-/claude-code-linux-x64-2.1.286.tgz),
registry SHA-512 integrity checked during evidence collection; implementation
rechecked tar/executable SHA-256:

- tar: `4887d7125e6c5ae5bf4dd5b0c5ae04469a9e387acb9e1281636d83d8d9a683e0`
- executable: `fe503f65c6289d59c23e5b21ae44f03583f997dd33a2cbfc75ab4f96fb8fc73f`

Embedded vendor JavaScript, not merely strings, separates production origins:

| Executable byte offset / function | Relevant excerpt |
|---|---|
| 196626753, production `cn()` config | `BASE_API_URL:"https://api.anthropic.com"`, `CLAUDE_AI_ORIGIN:"https://claude.ai"`, `TOKEN_URL:"https://platform.claude.com/v1/oauth/token"`, `ROLES_URL:"https://api.anthropic.com/api/oauth/claude_cli/roles"`, `MCP_PROXY_URL:"https://mcp-proxy.anthropic.com"` |
| 199633467, `FUe` | `let n=\`${cn().BASE_API_URL}/api/oauth/profile\`; ... await ht.get(n,...)` |
| 199634447, `Jc` | `let n=\`${cn().BASE_API_URL}/api/oauth/validate\`; ... await ht.post(n,null,...)` |
| 199749467, `QUt` | `await ht.get(cn().ROLES_URL,...)` |
| 199745954, `Ojr` | Authorization-code exchange: `await ht.post(cn().TOKEN_URL,S,...)` |
| 199746694, `Ede` | Refresh: `grant_type:"refresh_token"`; `await ht.post(cn().TOKEN_URL,T,...)`; optional account fetch calls `cYn(H)` |
| 199749051, `pk` | `await ht.post(\`${cn().TOKEN_URL}/revoke\`,...)` |
| 199751180 context, `cYn` | `let n=await FUe(e)`; maps subscription/account fields |

Thus the inspected already-provisioned profile/validation/roles/refresh path uses
API/platform, not `claude.ai`. Browser authorization uses
`https://claude.com/cai/oauth/authorize`; browser/account links and OAuth client
metadata at `claude.ai` do not establish a guest fetch on that path.

There **are genuine guest `claude.ai` uses outside scope**:
`uzo()` at 197982035 returns `oe()??cn().CLAUDE_AI_ORIGIN`, and `Rr` at
211297678 builds `EOn(new URL(\`/edge-api/frame-live/${e}/ws\`,uzo()))` for optional
artifact live subscriptions. This is why `claude.ai` is excluded only from this
baseline, not from all guest traffic. Never generalize to interactive guest login,
artifact/cloud features, older/custom images or future versions; re-audit changes.
This static audit executed no binary and collected no credentialed transport trace.

### B — Codex

Tag `rust-v0.159.3`, commit `01fc69f4026735edfdf6789820549727a4867b11`:
[provider bases, lines 77 and 420–438](https://github.com/openai/codex/blob/01fc69f4026735edfdf6789820549727a4867b11/codex-rs/model-provider-info/src/lib.rs#L420-L438)
choose `https://chatgpt.com/backend-api/codex` for ChatGPT and
`https://api.openai.com/v1` otherwise;
[refresh URL, line 212](https://github.com/openai/codex/blob/01fc69f4026735edfdf6789820549727a4867b11/codex-rs/login/src/auth/manager.rs#L212)
is `https://auth.openai.com/oauth/token`.
[defaults](https://github.com/openai/codex/blob/01fc69f4026735edfdf6789820549727a4867b11/codex-rs/config/defaults.toml#L13)
independently specifies the ChatGPT base. The attempted enterprise network doc
returned “Page not found” and is not evidence.

### C — deliberately deferred Copilot

The [official allowlist reference](https://docs.github.com/en/copilot/reference/copilot-allowlist-reference)
gives wildcard families, not a complete CLI-specific exact-name inventory.
Historical proxy hosts in `secrets.rs` constrain credential substitution and
cannot certify routing. Public `github/copilot-cli` does not expose transport.
Bounded static research of the official
[1.0.90 Linux/x64 artifact](https://registry.npmjs.org/@github/copilot-linux-x64/-/copilot-linux-x64-1.0.90.tgz)
matched registry SHA-512 integrity (tar SHA-256
`ffb3399216bccc7295cf2e7c579e6f161648fe355f6ec5eeea96ae736c1f30b1`).
Its Node SEA loader embeds `copilot.tgz`, `package/app.js`, `index.js` and
`prebuilds/linux-x64/runtime.node` (SHA-256
`d60c778cd03ef97cb261abf5f4cb9703f01fc60edfd95ba1f55693a95ae48160`).
Native strings include `https://api.githubcopilot.com`, `/mcp` and
`GITHUB_MCP_URL_OVERRIDE`; string presence/absence proves no complete inventory.
No executable, account or VM was run. **Copilot 1.0.90 is not certified.**

[#340](https://github.com/gregwebs/agent-vm/issues/340) owns the follow-up:
the Copilot image/integration upgrade maintainer, with release-review signoff,
needs version-specific readable transport evidence or a separate consented,
test-owned sanitized routing study covering individual/business/enterprise seats,
refresh/expiration, discovery and relay conditions. Accept evidenced names/ports,
roles/conditions/exclusions and docs+declarations+independent report tests together.
Never use operator credentials in this default-deny harness or widen proxy hosts
for probes. Do not guess aliases from historical credential destinations.

### D — OpenCode

Tag `v1.18.34`, commit `aec0b9a6d8898f68f923aaf08b7306d931fd9d76`:
[OpenAI plugin issuer/inference](https://github.com/anomalyco/opencode/blob/aec0b9a6d8898f68f923aaf08b7306d931fd9d76/packages/opencode/src/plugin/openai/codex.ts#L11-L12),
[responses API default](https://github.com/anomalyco/opencode/blob/aec0b9a6d8898f68f923aaf08b7306d931fd9d76/packages/llm/src/protocols/openai-responses.ts#L29),
[chat API default](https://github.com/anomalyco/opencode/blob/aec0b9a6d8898f68f923aaf08b7306d931fd9d76/packages/llm/src/protocols/openai-chat.ts#L28),
and [catalog](https://github.com/anomalyco/opencode/blob/aec0b9a6d8898f68f923aaf08b7306d931fd9d76/packages/core/src/models-dev.ts#L160-L185)
use these HTTPS origins. The catalog fetches `${source}/api.json` and
[refreshes in the background unless disabled](https://github.com/anomalyco/opencode/blob/aec0b9a6d8898f68f923aaf08b7306d931fd9d76/packages/core/src/models-dev.ts#L255-L257).

### E — shipped Pi bridge and version applicability

Image-source pin `087f8bad3de624a5dad38f1669e7dea96996371a`:
[wrapper](https://github.com/gregwebs/agent-vm-images/blob/087f8bad3de624a5dad38f1669e7dea96996371a/images/tools/pi/pi.sh)
forces `PI_SKIP_VERSION_CHECK=1` and loads the bridge unless opted out;
[seed](https://github.com/gregwebs/agent-vm-images/blob/087f8bad3de624a5dad38f1669e7dea96996371a/images/tools/pi/seed-claude-bridge-config.sh)
selects the image Claude executable;
[bridge pin](https://github.com/gregwebs/agent-vm-images/blob/087f8bad3de624a5dad38f1669e7dea96996371a/images/tools/pi/bridge/package.json)
is 0.8.0 and
[standard image labels](https://github.com/gregwebs/agent-vm-images/blob/087f8bad3de624a5dad38f1669e7dea96996371a/images/standard/Dockerfile#L41-L45)
record Pi 0.87.1. A1 therefore applies to its Claude child. Pi `--version` does
not certify auth routing. This source contract is not certification of every
retained standard archive or custom/older image; static artifact inspection is
Linux/x64, not a cross-architecture routing trace. Launcher declarations do not
automatically follow image-source upgrades or regional/custom providers.

## Maintenance and acceptance

The author of a provider/integration or image-source upgrade owns the endpoint
audit; the release PR reviewer signs off before release approval. The named
**default-tool endpoint evidence** step in [CONTRIBUTING](../CONTRIBUTING.md#release--version-bump)
requires rechecking versions, included roles and excluded candidates. Recheck
endpoint bug reports too. Update evidence, catalog declarations and independent
expectation tests together. No online CI equality/probe is added.

Requests stay independent of `ProxySecret::hosts`: those hosts authorize credential
substitution, not a traffic inventory. Claude's current overlap is independently
evidenced, not an equality invariant. Pi is explicit, not inherited; OpenCode's
credential-free catalog is a counterexample to deriving requests from credentials.

Native NR1/NR2 exercise genuine default Pi version stderr (unmet/covered); NR3
runs a default shell marker with no request block. They prove diagnostics and
continued execution, not inference/login or packet enforcement. They must pass
with paired LC1/HC1/I1 positives and D1/L1 denials, cleanup receipts and no default
image adoption against the exact candidate/native assets. Missing prerequisites
are **NOT RUN and block merge/release acceptance**, not host-only substitute
passes. See [the native harness procedure](../CONTRIBUTING.md#default-deny-egress-harness).
