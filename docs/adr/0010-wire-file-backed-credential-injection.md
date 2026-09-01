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
connection and substitutes only on exact hosts. OAuth and GitHub routes are
intercepted with an HTTP/1.1 hook; unmatched requests on a policed host fail
closed. OAuth validation repeats exact SNI, method, path, authority, encoding,
and refresh-placeholder checks before a host CLI can run.

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

Same-provider, same-project refreshes use a host-only lock. A contended waiter
skips its CLI only when it observes a changed readable token digest; an
uncontended first refresh always rotates. The hook bounds and reaps host CLI
process groups without reporting their output.

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
serialized into sandbox configuration. Missing, unsafe, or unreadable secret
files block substitution. Buffered OAuth/GitHub API requests are capped at
2 MiB; smart-HTTP is dispatched from headers and streams its body after policy
approval. Cross-project refreshes may duplicate CLI work and rely on provider
CLI locking.
