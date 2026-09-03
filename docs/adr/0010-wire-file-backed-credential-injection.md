# ADR-0010: Wire file-backed credential injection

## Status

Accepted.

## Context

Host OAuth credentials must remain outside the guest while long-running agent
sessions need to survive access-token rotation. Microsandbox provides
host-only `SecretSource::File` references and fail-closed request interception;
agent-vm now consumes those baseline primitives.

## Decision

`credential_injection::Plan` owns credential-to-network mapping. `run` applies
the ordinary network plan first, then this overlay, preserving user policy,
ports, and auto-publish settings.

Each configured credential exposes only a stable placeholder in guest config.
The proxy re-reads its sibling `<project-hash>.secrets/` file for each eligible
connection and substitutes only on exact hosts. OpenCode static API keys use a
single seven-row provider table and are enabled only for OpenCode/shell
launches; they have exact-host file-backed substitution and no hook route.
OAuth and GitHub routes are intercepted with an HTTP/1.1 hook; unmatched
requests on a policed host fail
closed. OAuth validation repeats exact SNI, method, path, authority, encoding,
and refresh-placeholder checks before a host CLI can run. The hook adapter
crosses one private OAuth-module seam: raw request, SNI, and state directory in;
a framed response out. That module validates completely before any lock,
fingerprint, CLI, host-read, or host-write effect. Its bearer representation is
consumed only by the atomic 0600 host-only token-file writer, after which a
closed typed public-metadata reply is converted to placeholders. Shared HTTP
parsing and response framing live separately from OAuth policy. Stdout is the
interceptor protocol channel, not a logging sink; this explicit safe-reply flow
resolves CodeQL cleartext-logging alert #5 without suppression or dismissal.

```
guest placeholder request
        |
        v
TLS proxy -- exact host --> SecretSource::File --> upstream bearer
        |
        +-- OAuth route --> host CLI rotates token file --> placeholder response
                                                    |
next guest connection ------------------------------+
```

Same-provider, same-project refreshes use a host-only lock held through final
credential installation. After lock acquisition the hook re-reads credentials
against a fresh clock; it runs a bounded CLI only for a still-rotatable state
without a fresh 30-second attempt stamp. Missing or malformed re-reads never
spawn a CLI. The runner uses an empty 0700 sibling-secret working directory,
a cleared allow-listed environment, default CLI protections, and a bounded
process-group reap. Expected post-validation failures become typed
temporary-unavailable replies; no host credential or arbitrary operational
error crosses the hook boundary.

GitHub API and smart-HTTP routes retain the per-launch repository allow-list:
allow-listed REST routes receive the bearer, while off-list, malformed, and
unknown REST routes receive a synthesized 403. Off-list smart-HTTP alone may
continue anonymously with Authorization stripped. GraphQL mutations are denied
until a sound repository-scoped mutation design exists; this intentionally
reduces compatibility for `gh` mutation workflows. Copilot receives file-backed
substitution only for a selected Copilot launch.
It has no in-session OAuth refresh path; relaunch recaptures its token.

## Consequences

Credential files are never mounted into the guest and token bytes are not
serialized into sandbox configuration. Guest-state reads and replacements are
descriptor-relative beneath the opened state root, using portable Darwin/Linux
no-follow opens and random exclusive sibling temporary files. Missing, unsafe, or unreadable secret
files block substitution. Buffered OAuth/GitHub API requests are capped at
2 MiB; smart-HTTP is dispatched from headers and streams its body after policy
approval. Cross-project refreshes may duplicate CLI work and rely on provider
CLI locking.
