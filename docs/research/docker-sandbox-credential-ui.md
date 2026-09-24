# Docker Sandboxes credential UI compatibility

Research date: 2026-09-23. Research only; no credential stores, actual user configuration, or credential values were accessed. Agent-vm baseline: `4fbaf11edda48c8ae81b0b971010763467d7d047`. The agent-vm goals below come from the design brief, **not** a claim that they are already implemented.

## Subsequent design decision

The completed interview is recorded in the
[credential shielding specification](../specs/credential-shielding.md), which
supersedes recommendations and the original design brief below. In particular,
block-level Docker v2 credential reuse is accepted, query injection is dropped,
`required` defaults to false, keychain lookup is implicit by service name, and
`source: env` selects the host variable named by `apiKey.name`. The earlier
blanket assessment that configuration compatibility was not feasible was too
broad: supported credential entries can be reused in user-owned YAML without
adopting all Docker kit semantics. No official JSON Schema was verified; the
public v2 schema is specified in prose and Go types.

## Bottom line

Docker offers useful shared vocabulary (`service`, `credentials`, `secret set/ls/rm`, `host`, `env`, `placeholder`), but copying its configuration would imply materially different authority and failure semantics. The nearest match is **v2 kit requests + host credential bindings**, not `set-custom` alone. Even that divides source and authorization between separate stores, delegates injection rules to kits, implicitly authorizes built-ins, and normally withholds unapproved credentials rather than failing launch. Agent-vm's user-only source-and-authorization record and explicit persisted defaults should remain distinct. This is a semantic compatibility assessment, not a claim that familiar words alone reduce measured switching costs. [D1][D2]

**Version matters:** the current starting page documents **`sbx`**, not just the older `docker sandbox` CLI. Stable release notes list **0.45.0 (2026-09-21)** and introduce v3 kits while retaining v2. The linked kit reference still primarily documents v2 and calls kits experimental. Do not advertise a generic “Docker-compatible” schema based on v2 examples. [D2][D6][D9]

## Evidence and limits

Retrieved the starting HTML page, its linked Docker-owned Markdown source, linked kit grammar, official CLI pages, settings, environment-file, security, architecture, and release documentation. No Docker binary was installed or run. The release repository describes its license as proprietary; this investigation verified public documentation/specification, **not the runtime proxy implementation**. [D9]

Important inconsistencies in the primary sources:

- Credential guide and kit reference say `required: true` with no binding **warns and withholds**, including unattended launches. The linked normative v2 specification instead says “fails fast if unbound.” That specification also describes bindings as locating the credential, whereas the credential guide explicitly says they **do not** locate it. Treat the current guide as the documented user behavior, but verify the installed release before depending on this distinction. [D1][D2][D3]
- `set-custom` guide says replacement occurs **anywhere in the request**, explicitly motivating request-body secrets. Its CLI reference says **request headers**. Neither provides a precise query-parameter replacement contract. [D1][D5]
- V2 kit reference lists `**` and port wildcard enforcement as pending; linked spec says those are enforced. Both distinguish network rules from injection declarations. This is not sufficient evidence for an exact credential host/port authorization contract. [D2][D3]
- Release notes announce v3 and HTTP method/path-scoped network permissions; the linked customization docs remain v2-oriented. An attempted `spec/SPEC-v3.md` at the public specification repository returned 404. Detailed v3 credential equivalence is therefore **not established**. [D6]
- CLI service list additionally includes `copilot` and `devin`, absent from the credential guide's built-in import table. Avoid treating that table as an exhaustive version-independent registry. [D1][D4]

## 1. Sources, selection, persistence

### Documented Docker behavior

`sbx secret set SERVICE` stores a value **or dynamic source** in Docker's OS credential store, keyed by service. macOS uses Keychain; Linux uses Secret Service (GNOME Keyring/KDE Wallet); Windows uses Credential Manager. Headless Linux automatically falls back to a file below `$XDG_CONFIG_HOME/com.docker.sandboxes` (default `~/.config/com.docker.sandboxes`) with a `0700` directory and a warning. A later available Secret Service receives new secrets again. This is not an explicit per-record choice between keychain and a named host environment variable. The reviewed docs expose no arbitrary existing Keychain service/account or Secret Service attribute selector. [D1]

Service secrets default to **global**, sandbox-specific records override them, and removing the scoped record restores the global value. Current docs say changes to service secrets, including command/reference sources, affect existing local sandboxes without restart. Stored secrets take precedence over other available sources; where both API key and OAuth resolve, the API key wins. This is a precedence model, not the proposed one-source-only model. [D1][D6]

Exact documented command examples (illustrative only, not executed):

```sh
sbx secret set anthropic
sbx secret set openai --sandbox my-sandbox
sbx secret set anthropic --ref 'op://Work/Anthropic/credential'
sbx secret set github --command 'gh auth token' --refresh on-demand
sbx secret import openai
sbx secret import --all
sbx secret ls
sbx secret rm github --sandbox my-sandbox
```

`--ref` supports 1Password references and AWS Secrets Manager ARNs; corresponding authenticated host CLIs are required. `OP_ACCOUNT`/`AWS_PROFILE` at registration can select the future resolver account/profile. `--command` is a host-shell command whose trimmed stdout becomes the secret; its command text is stored and replayed by the daemon. Service resolutions cache for **55 minutes** by default; custom secrets resolve **on demand** by default. `--refresh` changes these policies. `--ref` and `--command` are mutually exclusive and exclude literal-token/OAuth/registry modes. [D1][D4][D5]

`secret import` reads a **fixed built-in service-to-environment-variable mapping** and persists values into the store. It is not a named live environment source. Default import prompts for each entry; `--all` imports new entries without prompting; `--force` overwrites; `--dry-run` previews. For example `openai` maps to `OPENAI_API_KEY`, while `github` maps to `GH_TOKEN` and `GITHUB_TOKEN`. The reviewed page does not specify tie-breaking when both GitHub variables exist. [D1]

`secret ls` documentation shows a **partially masked value**, not merely presence. `sbx reset` deletes all stored secrets and sandbox state. These are significant UI differences from agent-vm's value-free diagnostic convention. [D1][A1]

### Compatibility

Keychain/Secret Service backing and named credentials align conceptually. Automatic plaintext fallback, global/scoped fallback chains, imported snapshots, and executable sources do **not** match the brief's explicitly selected single source (Keychain, Secret Service, or named host env). Adopting `--ref` would imply vault-URI resolution; adopting `--command` would introduce host execution not requested by the brief. Neither should silently stand in for a named env source.

## 2. User versus project authority

Docker's normal v2 split is:

```text
kit spec.yaml: service + guest sentinel placement + injection destinations/headers
                         |
user credentials.yaml: mechanism/domain approval
                         |
host secret store: service -> value or dynamic source
                         |
host proxy: apply injection to matching outbound requests
```

A kit cannot declare arbitrary host environment/file discovery in v2. Its service ID matches `sbx secret set`. The host approval file is `~/.config/sbx/credentials.yaml` (Windows `%APPDATA%\sbx\credentials.yaml`). Its documented shape is: [D1][D2]

```yaml
bindings:
  anthropic:
    apiKey:
      domains: [api.anthropic.com]
  github:
    apiKey:
      domains: [api.github.com, github.com]
```

These entries approve `apiKey`, `oauth`, or both; they contain **neither the value nor its locator**. Missing domain coverage triggers approval. Third-party v2 kits need bindings, including inherited built-in credentials. Embedded built-ins are authorized by provenance without entries; v1 kits inject without bindings. Interactive first-run approval persists entries; declining writes none. [D1]

**Project configuration has a second, broader route.** Experimental `sbxenv.yaml` supports both `secrets` and `bindings`. After plan approval it creates sandbox-scoped secret records and merges approvals into the user's **global** bindings. Exact documented fragments: [D8]

```yaml
secrets:
  anthropic:
    ref: op://Private/Anthropic/api-key
    refresh: 55m
  github:
    command: gh auth token
```

Each source has exactly one of `value`, `ref`, `command`; optional fields include `refresh`, `backend` (`sdk`/`cli`), and `noVerify`. Its `bindings` uses the same mechanism/domain structure shown above. Docker advises keeping this environment file **outside mounted workspaces**. Plans show host commands, sources and binding domains; interactive approvals are remembered, while `--auto-approve` applies to one invocation. Commands require renewed approval by default. Removing an environment leaves global bindings unless `--prune-bindings` is requested; failed create can leave provisioned secrets and bindings. [D8]

**Conflict with agent-vm:** v2 kit separation is similar, but source and authorization are not co-located. Kits supply injection rules, built-ins bypass persisted authorization, and approved environment files can provision sources and extend global authorization. Agent-vm's project file must only request names and guest placement; importing Docker environment files wholesale would exceed that authority even if all secret bytes stayed host-side.

## 3. Injection matching and exact schema

Documented v2 kit fragment: [D2][D3]

```yaml
credentials:
  - service: my-service
    apiKey:
      name: MY_SERVICE_TOKEN
      proxyManaged: true
      inject:
        - domain: api.my-service.com
          scheme: bearer
permissions:
  network:
    allow: [api.my-service.com]
```

`apiKey.name` names the **guest** env variable, not a host source. `proxyManaged` defaults false; true populates the literal `proxy-managed` sentinel. Header injection supports `header` plus `format` with exactly one `%s`, or `scheme: bearer`; Basic uses `scheme: basic` plus `username`. `format` and `scheme` are mutually exclusive. Example explicit header:

```yaml
inject:
  - domain: api.my-service.com
    header: x-api-key
    format: "%s"
```

The general credential guide says the proxy **overwrites** auth headers for matching destinations and injects regardless of the sandbox environment variable value. This is not conditional substitution of a designated placeholder in a designated header. The v2 API-key schema has **no dedicated query field**. OAuth is another mechanism, with token endpoint host/path, sentinels, resource hosts and optional credential-file rendering; `passthrough: true` deliberately exposes real token responses to the sandbox. [D1][D2]

The distinct experimental custom-secret interface is closer to placeholder substitution: [D1][D5]

```sh
sbx secret set-custom \
  --host api.example.com \
  --env API_KEY \
  --ref 'op://Work/Example/credential'
```

`--host` is repeatable; documented local forms include exact hosts, IPs and wildcards. `--placeholder 'sk-{rand}'` supplies a format instead of the generated `sbx-cs-<rand>` value. The guide claims replacement wherever that placeholder appears in requests to matching hosts; the CLI says headers only (see evidence limits). For an existing sandbox, documentation instructs users to place the returned placeholder using `sbx run -e` or `/etc/sandbox-persistent.sh`. Cloud mode has different semantics: exact DNS hosts only and unconditional `--header`/`--format` injection, not placeholder substitution. [D1][D5]

**Exact HTTPS host/port cannot be assumed.** The public v2 network grammar supports `host:port`, but a bare host matches **any port**. The credential binding and injection references describe domains, not a complete HTTPS-origin grammar or default-port normalization rule. The architecture covers HTTP **and** HTTPS. No reviewed source proves that credential authorization rejects cleartext HTTP or constrains a bare credential domain to port 443. Network allow rules are not a substitute for this credential contract. [D1][D2][D3][D10]

**Compatibility:** header names, service names and placeholder terminology transfer. Docker's host patterns, unconditional service-header overwrite, uncertain query matching and optional body substitution do not implement agent-vm's exact HTTPS-host/port + header/query-only substitution contract. V3 method/path network permissions and registry OAuth realm path validation are separate features, not reasons to add path filtering or signing to this design. [D1][D6]

## 4. Environment handling, failure modes, defaults

| Question | Documented Docker behavior | Consequence for the agreed agent-vm design |
|---|---|---|
| Consume source env before child creation, then remove it? | Import reads env and persists values; no guarantee of scrubbing inherited env. Host environment lifecycle commands explicitly inherit the `sbx` process environment. Settings daemon also inherits env at startup. [D1][D7][D8] | No demonstrated equivalence. Agent-vm's pre-child consumption/removal needs its own contract. |
| Does `--env NAME` shield a secret? | No: `sbx run/create -e NAME` copies its host value into guest environment. Values affect agent sessions and are baked in at creation. [D11] | Do not reuse this syntax for credential-source selection without an explicit distinction. |
| Requested credentials only? | Kit credentials declare needs, but service/custom secrets can be global, built-ins inject automatically and registry scope has separate rules. No reviewed guarantee says every unrequested source is left unread. [D1][D2] | A kit request list is useful vocabulary, not proof of requested-only capture. |
| Missing authorization? | Unattended third-party v2 kit starts with credential withheld; `required: true` adds warning per guide/reference (spec conflicts). [D1][D2][D3] | Direct conflict with fail-before-launch unless a host flag skips affected credentials. |
| Missing source? | Dynamic source registration verifies by default; `--no-verify` skips that check. Missing built-in login can trigger an agent-specific OAuth flow. General launch-time missing-source/error taxonomy is not specified. [D1][D4] | `--no-verify` is not the requested launch escape hatch; do not conflate them. |
| Malformed auth/security errors bypassable? | V2 strict decoding rejects unknown fields; release notes describe malformed injection validation. Sources do not establish an exhaustive nonbypassable authorization-error classification. [D3][D6] | Agent-vm must specify this independently; no inferred equivalence. |
| Explicit persisted provider defaults? | Built-in service endpoints and built-in provenance are implicit. `provider` in v2 is reserved, warns, has no runtime effect. [D1][D2] | Cannot use Docker's `provider` field to mean a persisted agent-vm provider preset. |
| Persistence of ordinary defaults? | `settings set` writes daemon-backed overrides, but setting a value equal to its default **removes** the stored override. Precedence is env > override > built-in default. [D7] | Opposite of materializing explicit defaults so upgrades cannot silently change them. |
| Usage restrictions or general detection? | Docker also exposes network/filesystem/MCP governance; credential docs describe matching/injection, not general secret detection. [D10] | Keep shielding separate from usage policy; do not imply exfiltration detection or action authorization. |

The reviewed `sbx run` flag list contains no equivalent of the proposed “skip affected missing/unauthorized credentials” host launch flag. This is a bounded documentation finding, not proof that every Docker release lacks such a feature. [D11]

## 5. Existing agent-vm UI and migration implications

Repository README/USAGE and actual raw config schema were read, not user credential files. Current agent-vm uses `agent-vm <tool>` (e.g. `agent-vm claude`), `doctor`, `setup`, `pull`, `msb`, and `clipboard`; it does not require Docker's `sbx run <agent>` hierarchy. Config is TOML at `$HOME/.config/agent-vm/config.toml` and `<cwd>/.agent-vm/config.toml`. User tool definitions win **wholesale**; project-only tools can be added. Both tiers are validated before merge. [A1][A2]

Current supported example:

```toml
[[tools]]
name = "mytool"
command = "mytool"
credentials = ["openai"]
env = { VAR = "value" }
```

Currently `credentials` accepts fixed provider config names (`anthropic`, `openai`, `opencode-static`, `copilot`), not arbitrary named source records. `tools` adds transitive provisioning, with required-versus-provisioned distinctions and a same-file wildcard default for `shell`. Tool `env` is literal guest configuration, not host variable expansion. `RawConfig` currently contains only `tools` and rejects unknown fields; a new user credential table is an actual schema extension, not existing functionality. Shipped defaults are embedded rather than persisted. [A1][A2]

Practical compatibility boundaries, derived from the evidence above:

1. **Vocabulary compatibility is feasible:** use named credentials/services, explicit guest env placement, safe list/remove operations, and explain host-side substitution. Preserve agent-vm's existing tool-launch shape; Docker's naming does not require adopting its daemon/sandbox lifecycle.
2. **Configuration compatibility is not presently honest:** mapping Docker `bindings` to agent-vm authorization loses the source; mapping a kit inject rule transfers authority to the project; mapping `set-custom` loses header/query placement restrictions and introduces wildcard/body expectations.
3. **A future import tool would need validation, not aliases:** combine source + approval into one user-only record; require explicit exact HTTPS ports and supported header/query placement; reject unsupported patterns, body replacement, OAuth passthrough, shell sources and project authority; explicitly persist presets. This is a possible translation boundary, not a proposed implemented feature.
4. **Keep failure terms distinct:** `--no-verify` means skip registration-time source checking in Docker, not skip only affected credentials at launch. Similarly `required` has incompatible documented behavior, and `provider` is a stub, not a source/default selector.
5. **Do not claim byte/schema compatibility for switching-cost reasons:** no primary source here measures switching costs. Shared nouns can improve recognition, but the security differences must remain visible in configuration, help and diagnostics.

## Primary sources

- [D1] [Docker: Manage credentials](https://docs.docker.com/ai/sandboxes/configuration/credentials/) — [linked Markdown source](https://github.com/docker/docs/blob/main/content/manuals/ai/sandboxes/configuration/credentials.md).
- [D2] [Docker: Kit spec reference](https://docs.docker.com/ai/sandboxes/customize/kit-reference/) — [source](https://github.com/docker/docs/blob/main/content/manuals/ai/sandboxes/customize/kit-reference.md).
- [D3] [Docker-owned normative v2 kit specification](https://github.com/docker/sbx-kits-contrib/blob/main/spec/SPEC-v2.md), especially §§1.2, 5.2, 5.4 and validation rules.
- [D4] [CLI: sbx secret set](https://docs.docker.com/reference/cli/sbx/secret/set/).
- [D5] [CLI: sbx secret set-custom](https://docs.docker.com/reference/cli/sbx/secret/set-custom/).
- [D6] [Docker Sandboxes release notes](https://docs.docker.com/ai/sandboxes/release-notes/) — [0.45.0 release](https://github.com/docker/sbx-releases/releases/tag/v0.45.0).
- [D7] [Docker Sandboxes settings](https://docs.docker.com/ai/sandboxes/configuration/settings/).
- [D8] [Sandbox environment files](https://docs.docker.com/ai/sandboxes/configuration/environment-files/), especially `secrets`, `bindings`, lifecycle, approval and cleanup.
- [D9] [Docker sbx release repository README](https://github.com/docker/sbx-releases/blob/main/README.md).
- [D10] [Docker security model](https://docs.docker.com/ai/sandboxes/security/) and [architecture](https://docs.docker.com/ai/sandboxes/architecture/).
- [D11] [CLI: sbx run](https://docs.docker.com/reference/cli/sbx/run/) and [usage: environment variables](https://docs.docker.com/ai/sandboxes/usage/#set-environment-variables).
- [A1] Agent-vm [README](../../README.md) and [USAGE](../../USAGE.md); [revision-specific USAGE source](https://github.com/gregwebs/agent-vm/blob/4fbaf11edda48c8ae81b0b971010763467d7d047/USAGE.md).
- [A2] Agent-vm [config.rs](../../crates/agent-vm/src/config.rs), module contract and `RawConfig`/`RawTool` (lines 1200–1232); [revision-specific source](https://github.com/gregwebs/agent-vm/blob/4fbaf11edda48c8ae81b0b971010763467d7d047/crates/agent-vm/src/config.rs).
