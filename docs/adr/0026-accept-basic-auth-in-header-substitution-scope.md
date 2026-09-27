# ADR-0026: Accept Basic auth in the header substitution scope

## Status

Accepted.

## Context

Built-in credentials ([ADR-0010](0010-wire-file-backed-credential-injection.md))
register one file-backed `SecretEntry` per secret. Each entry can be
substituted only on its exact allow-listed hosts, and only over an intercepted
TLS connection. Under microsandbox 0.6.x an entry had separate scopes for
`headers` and `basic_auth`. The second scope decodes an
`Authorization: Basic <base64>` value, replaces the placeholder inside
`user:password`, and re-encodes it. agent-vm turned `basic_auth` on only for
the GitHub token, because git's credential helper sends it that way. The model
providers (Anthropic, OpenAI, OpenCode's static keys, Copilot) had it off.

microsandbox 0.7.4 (the `gregwebs/microsandbox` sync onto upstream v0.7.4)
removes the separate flag. Its `SecretSubstitution` is `{ headers, query, body }`,
and `headers` now covers a decoded Basic value as well as a plain header
(`crates/network/lib/engine/secrets/handler.rs`, `substitute_in_header_line`).
No per-secret setting keeps header substitution while refusing Basic.

## Decision

Accept the folded scope. agent-vm drops its per-secret `basic_auth` field and
gives every built-in secret `headers` only, as before. As a result, a provider
placeholder inside a Basic `Authorization` value is now substituted on that
provider's own hosts. Under 0.6.x it was left in place. Everything that bounds
where a value can go stays the same:

- **Hosts.** Substitution is still limited to the secret's exact hosts. On any
  other host every scope is off, and a placeholder anywhere in the request
  (including base64 inside Basic) is a `block-and-log` violation. That includes
  another built-in secret's host.
- **TLS identity.** Every built-in secret keeps `require_tls_identity`. A plain
  connection to an allowed host still refuses the placeholder.
- **Query and body.** Both stay off.

The widening therefore adds no new destination for a value. A guest could
already put the placeholder in any header, including `Authorization: Bearer`,
on these same hosts and have it substituted. Basic encoding is just another way
to reach the same header on the same origin.

YAML-authorized credentials ([ADR-0025](0025-yaml-credential-shielding.md)) are
not affected. They are `ResolvedHeaderCredential`s written into one exact header
on one exact origin, a separate engine path from `SecretEntry` substitution.

### Pinned by

`credential_injection::tests`:

- `basic_auth_placeholder_is_substituted_only_on_the_secrets_own_hosts` runs
  every secret from agent-vm's real `Plan` through the vendored
  `SecretsHandler`. It checks that Basic substitution happens on each allowed
  host, is refused over plain HTTP, and is blocked on a foreign host.
- `basic_auth_placeholder_is_blocked_on_another_secrets_host` checks that one
  secret's host never releases another secret's value.

## Alternatives considered

- **Carry a fork patch that restores `basic_auth`.** Rejected. It keeps a
  permanent divergence from upstream in the security-critical substitution
  code, to protect a narrowing that is not a leakage boundary.
- **Turn off `headers` for the providers.** Rejected. Providers authenticate
  with a header, so substitution would stop working entirely.
- **Refuse Basic in agent-vm's intercept hook for provider hosts.** Rejected
  for now. The hook currently routes only OAuth token endpoints and GitHub; the
  provider API hosts and OpenCode's static-key hosts have no route
  ([ADR-0010](0010-wire-file-backed-credential-injection.md)). This option
  would add a route on every provider host just to police an encoding that
  exposes nothing new. Revisit if a provider host ever treats Basic
  credentials differently from its bearer.

## Consequences

- One flag fewer in the credential tables (`credential_provider.rs`'s
  `ProxySecret`, `credential_injection.rs`'s `FileSecret`). The GitHub secret
  now has the same shape as every other secret.
- If upstream ever brings back a separate Basic scope, re-evaluate this
  decision. The tests above state the property to keep: host-scoped and
  TLS-bound, with no cross-secret release.
