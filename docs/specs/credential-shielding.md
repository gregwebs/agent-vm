# Credential shielding: user contract and UI

Status: agreed design, not implemented. This specification records the concluded
user interview; it does not describe current CLI or configuration support.

## Contract

The guest is untrusted, including after compromise. Agent-vm keeps authorized
credential values on the host and substitutes them into approved outgoing HTTPS
request headers. Guest applications never receive real credentials; when
`sentinelEnv` is enabled, they receive a non-secret placeholder in the named
environment variable.

Authorization is host-wide, not project-scoped. Any project may request a
user-authorized credential. Keeping its value secret does not prevent the guest
from exercising its account permissions or spending its allowance. Usage limits
and abuse detection belong to the credential issuer, not this feature.

Users must:

- Authorize sources and destinations through host user configuration.
- Trust approved remote destinations as recipients of the real credential.
- Avoid putting real credentials in guest-visible files, mounts, configuration,
  environment variables, or prompts.
- Prevent guest writes to host authorization configuration.

Agent-vm makes no general secret-detection claim and cannot exhaustively enforce
the mount/copy responsibilities. Approved services may disclose values in their
responses; response-body secret scanning is not part of this feature.

## Configuration and authority

User authorization lives in `~/.config/agent-vm/credentials.yaml`. Existing tool
configuration remains TOML. Only user configuration can define credential
sources and authorize injection. Project configuration can request credentials,
not create or broaden authorizations.

Source selection and authorization are co-located in each YAML credential entry.
Editing that user entry constitutes authorization or reauthorization. Changing
source identity, destinations, or injection locations requires an explicit edit;
rotating the secret value at the same source does not.

Known-provider examples/defaults must materialize explicit destinations and
injection rules in user YAML. Upgrades must not silently expand authorizations.
There is no separate approval registry or required policy-generation CLI.

```text
user credentials.yaml ── source + authorization ─┐
                                               ├─ host resolver/proxy
project/user tool TOML ── credential requests ──┘       │
                                                      ├─ placeholder → guest
host keychain or environment ── real value ─────────────┘
                                                      │
                              approved HTTPS header ←─┘
```

### Keychain source (default)

```yaml
credentials:
  - service: anthropic
    required: true
    apiKey:
      name: ANTHROPIC_API_KEY
      sentinelEnv: true
      inject:
        - domain: api.anthropic.com
          header: x-api-key
          format: "%s"
```

An omitted `source` selects the agent-vm-owned system keychain entry named by
`service`. Storage is macOS Keychain or Linux Secret Service. Agent-vm does not
share Docker's secret namespace or silently fall back to plaintext storage.

### Environment source (agent-vm extension)

```yaml
credentials:
  - service: openai
    source: env
    apiKey:
      name: OPENAI_API_KEY
      sentinelEnv: true
      inject:
        - domain: api.openai.com
          scheme: bearer
```

`source: env` selects the host environment variable named by `apiKey.name`.
When `sentinelEnv` is true, that same name specifies the guest environment
variable populated with a non-secret placeholder. Host and guest variable names
therefore match. There is exactly one source per entry, with no environment/
keychain fallback chain.

Environment sources are supported for specific workflows, but passing
credentials through environment variables is less desirable than keychain
storage; documentation and examples should favor the keychain source.

Read selected environment values before spawning child processes, then remove
them from agent-vm's environment and exclude them from child environments.
This cannot unset the parent shell's variables or guarantee erasure of previous
memory contents. Environment values are not automatically imported into the
keychain. Diagnostics must not disclose them.

Remove existing automatic raw forwarding of `ANTHROPIC_API_KEY` and
`OPENAI_API_KEY`; supported use of these variables goes through shielding.
Their presence alone never authorizes use or justifies raw forwarding.

### Placeholder shape

A placeholder is a **non-secret** value, and it must be **acceptable to the
guest program**. Some consumers validate the value's form before they will use
it, so a placeholder may have to be structurally valid: a stand-in that is
obviously not a legal value (for example `____`) is not sufficient when the
program rejects it and fails to start.

The built-in providers already learned this. `OPENAI_ID_PLACEHOLDER` in
`crates/agent-vm/src/secrets.rs` is a synthetic `alg:none` JWT because Codex
parses `tokens.id_token` client-side at startup and refuses to load a non-JWT
value, and `OPENCODE_OPENAI_ACCESS_PLACEHOLDER` is a JWT whose **28-byte
signature segment** is deliberately ≡ 0 mod 4 because strict JWT parsers reject
a *segment* where `len % 4 == 1`. (The whole JWT's length makes no such
requirement: the OpenCode placeholder is 169 bytes, ≡ 1 mod 4.) Most other
placeholders in that file are ordinary marker strings, not JWTs. A placeholder
must nevertheless stay **clearly fake and non-secret** — never mistakable for,
or containing, a real credential's value.

Reshaping an existing placeholder is a compatibility decision, not a cosmetic
one: the shape is load-bearing for the consumer, and long placeholders have
previously broken sandbox boot (`handshake read id_offset: timed out before
relay sent bytes`).

## Docker YAML compatibility boundary

Target reusable Docker **v2 API-key credential entries**, not all Docker kit
features or identical Docker runtime behavior. `source: env` is an agent-vm
extension. The public v2 schema is specified in prose and Go types; an official
JSON Schema and a public v3 credential schema were not verified in this research.

Supported credential concepts:

- `service`: named credential and default keychain lookup identity.
- `description`: human-readable credential description.
- `required`: optional boolean, default **false**.
- `apiKey.name`: guest environment placement, also host variable name when
  `source: env` is selected.
- `apiKey.sentinelEnv`: optional boolean, default `false`; when true, set the
  guest variable named by `apiKey.name` to a non-secret placeholder. Injection
  itself is independent of this guest-environment setting.
- `apiKey.proxyManaged`: accepted as a Docker-compatibility alias for
  `sentinelEnv`; prefer `sentinelEnv` in agent-vm configuration. If both are
  present, their values must agree or configuration is rejected.
- `apiKey.inject`: explicit destination/header definitions, using either
  `scheme: bearer` or `header` plus `format` containing exactly one `%s`.

Do not ignore unsupported functional fields. Reject configurations requesting:

- `permissions.network` or other non-credential kit functionality.
- Kit installation/startup hooks, images/builds, mounts, ports, privileges,
  composition, or other execution behavior.
- Basic authentication, credential exposure to the guest, request signing,
  body or query-parameter substitution, or new Docker-defined OAuth behavior.
- Wildcard credential destinations or destination paths.

Existing built-in OAuth functionality remains available; it is not removed by
rejecting Docker OAuth declarations in this new YAML surface.

### Injection semantics

`inject[].domain` accepts an exact hostname, optionally followed by a port.
A bare hostname means HTTPS port 443; an explicit port authorizes only that
HTTPS destination. Paths and cleartext HTTP are unsupported. An allowed network
connection does not itself authorize credential injection.

Credential injection is controlled by the authorized destination and header
rules, independently of whether the guest placeholder environment variable is set.
It is not arbitrary request-text replacement. `%s` describes secret formatting,
not a broader substitution permission. Redirected requests must independently
meet destination and header requirements.

The approved origin is trusted in its entirety; there are no endpoint/path
restrictions. Ordinary guest egress policy remains unchanged. In particular,
Docker's network-permission fields must not be reinterpreted as credential
restrictions or accepted as no-ops.

## Tool requests and built-in precedence

Reuse the existing tool field:

```toml
[[tools]]
name = "example"
command = "example-agent"
credentials = ["openai", "my-service"]
```

Resolve each name against user YAML first, then compiled-in credential providers.
Provision only requested credentials, including requests implied by the existing
tool/provisioning relationships; authorization alone does not provision a value.

A YAML definition with the same name as a built-in fully replaces that provider's
credential handling: source acquisition, credential placeholders, injection,
OAuth capture, and refresh. It does not supplement the built-in or fall back to
it when unavailable. Unrelated tool configuration and persistence remain intact.
Without a matching YAML definition, existing built-in behavior remains unchanged.

YAML entries use the YAML `required` semantics below, rather than inheriting the
old built-in requirement solely because their names appear in `credentials`.

## Availability and failure behavior

| Condition for a requested YAML credential | Default behavior |
|---|---|
| `required` omitted or false; source unavailable | Warn and launch without it |
| `required: true`; source unavailable | Fail before guest launch |
| Missing user authorization | Withhold credential; never infer authorization |
| Invalid or unsupported configuration, security violation | Hard error |

A locked/unavailable keychain, missing item, or unset environment variable is an
unavailable source. A request with no matching YAML authorization or built-in
provider fails by default; the explicit override can skip it. It must never
cause automatic discovery or creation of authorization.

`--allow-missing-credentials` is a host launch flag, not a project option. It may
skip missing authorization or unavailable required credentials and launch with
warnings naming those withheld. Other available credentials remain shielded.
It cannot bypass malformed configuration, expand destinations, forward raw
values, or select a fallback source. A guest application may subsequently fail
its own authentication.

This supersedes the interview's earlier proposal that every requested YAML
credential fail by default: matching Docker's `required: false` default won.
Docker's guide and normative spec disagree about enforcement of `required: true`;
this specification deliberately defines agent-vm behavior rather than claiming
verified equivalence with every Docker release.

## Secret-value CLI

Mirror Docker's core command vocabulary and input behavior:

```sh
agent-vm secret set anthropic
printf '%s' "$ANTHROPIC_API_KEY" | agent-vm secret set anthropic
agent-vm secret ls
agent-vm secret rm anthropic
```

- `set SERVICE` securely creates/updates the agent-vm keychain value, using
  hidden interactive input or piped stdin without requiring a `--stdin` flag.
- Do not accept `--token` or a positional secret value. Shell history and process
  argument exposure are reasons to reject that interface, not merely warn.
- `ls` reports names/storage status, never secret values or partial values.
- `rm SERVICE` removes the stored value; authorization is managed in YAML.
- Storing a value does not authorize credential usage or rewrite policy.
- Unsupported Docker options are errors, not silently approximated behaviors.
- Dynamic shell/vault sources, registry credentials, sandbox-specific stores,
  and OAuth enrollment commands are outside this initial CLI surface.

## Acceptance checks for implementation

1. Supported Docker credential entries can be copied unchanged into the user
   `credentials` list; unsupported functionality yields an explicit diagnostic.
2. Keychain defaults resolve by service name; environment sources resolve only
   by `apiKey.name`; neither source falls back to another.
3. Real values never appear in guest environment/configuration or diagnostic
   output through supported provisioning paths; `sentinelEnv: true` exposes only
   a non-secret placeholder, while false leaves the named guest variable unset.
4. Environment capture precedes child creation and values are not inherited.
5. Only approved exact HTTPS destinations and specified headers receive
   injection; wrong ports, cleartext, unrelated headers,
   paths in configuration, wildcards, bodies, and query injection are rejected
   or do not receive substitution as appropriate.
6. Missing optional credentials warn; required credentials fail unless skipped.
   The override cannot bypass configuration or security errors.
7. Project configuration cannot define authorization; merely storing a secret
   cannot authorize it.
8. YAML overrides suppress same-named built-in capture/refresh/injection, while
   unrelated tool behavior remains intact. No fallback occurs on failure.
9. Existing egress behavior is unchanged, and `permissions.network` is rejected.
10. Secret entry supports prompt/stdin, rejects argument-based values, and lists
    no secret bytes. Keychain unavailability never creates plaintext storage.

## Follow-ups, not part of this effort

- Consider configuring existing network egress controls through Docker-shaped
  YAML in a separate issue; other kit functionality needs separate decisions.
- Query injection, path restrictions, Basic auth, request signing, partial value
  display, and broader Docker compatibility are not included.
- During implementation, specify parser details (identity metadata/version
  envelope, duplicate/conflicting entries, hostname/header validation), CLI
  overwrite/error behavior, and how existing provider-owned persistence is
  separated from credential acquisition. These do not authorize silent fallback
  or expansion of the security contract.

## Sources and related documents

- [Domain vocabulary](../../CONTEXT.md).
- [Docker comparison and primary-source evidence](../research/docker-sandbox-credential-ui.md).
- [Docker credential guide](https://docs.docker.com/ai/sandboxes/configuration/credentials/): `proxyManaged` controls whether a proxy-managed placeholder is published to the guest environment; agent-vm prefers the clearer `sentinelEnv` spelling.
- [Docker v2 specification](https://github.com/docker/sbx-kits-contrib/blob/main/spec/SPEC-v2.md), especially §5.4 (`required` defaults to false).
- [Docker credential types](https://github.com/docker/sbx-kits-contrib/blob/main/spec/types.go).
- [Docker secret set CLI](https://docs.docker.com/reference/cli/sbx/secret/set/).

Existing architecture and ADRs describe the current built-in/file-based system.
This spec intentionally changes user authorization, environment-key forwarding,
and YAML override behavior; it is not a claim that those changes have shipped.
