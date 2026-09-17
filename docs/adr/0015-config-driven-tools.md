# ADR-0015: Generate CLI subcommands from the resolved tool config

## Status

Accepted. Implementation decision for [agent-vm #82](https://github.com/gregwebs/agent-vm/issues/82), the consumption half of epic [#78](https://github.com/gregwebs/agent-vm/issues/78). Extends [ADR-0003](0003-project-tooling-layers.md) (a project's `.agent-vm/` is trusted executable surface) and completes the config work split across #80 (parse/merge/validate, read-only) and #81 (credential providers). Builds on the terms **Tool**, **Credential provider**, and **Tool config tier** in [CONTEXT.md](../../CONTEXT.md).

## Context

Until #82 the set of agents was a **compile-time fact**: `main.rs` had one clap variant per agent, and `run.rs`'s `Agent` enum knew each agent's guest command, default argv, and credential subsystem. Adding or renaming an agent meant editing and rebuilding Rust.

#80 added a strict TOML **tool config** (two tiers, union with user-wins) that *described* exactly those facts, but nothing on any launch path read it — the module header said so explicitly, and `tests/config_launch_unchanged.rs` proved it. #81 extracted the credential subsystems into a `CredentialProvider` enum and a `ProviderSet` bitset, giving a launch path that could take its provider set as data.

#82 is the consumption: the CLI stops knowing any tool by name. The launch verbs become a **runtime** fact read from the resolved config.

## Decision

- **Launch verbs are generated from the resolved catalog.** `config::ConfigReport::into_launch_catalog` yields a `LaunchCatalog`: the merge result plus the built-in `shell` appended when no declared tool claims that name. `cli::build_command` registers one clap subcommand per entry, each backed by the existing shared `run::Args`. `run::launch` takes a resolved `config::Tool`; `run::Agent` and the five `Cmd` launch variants are deleted.
- **Config is loaded before parsing, but its failure is deferred.** `main` calls `config::load` before `cli::parse_from`, because the catalog decides which subcommands exist. A *broken* config is carried as data, not `?`-propagated: on the failure path `cli` registers no tool subcommands and enables `allow_external_subcommands`, so `doctor`/`clipboard`/`_intercept-hook` keep working, `--help` still exits 0 on stdout with the built-ins plus a "run `agent-vm doctor`" note, and any launch verb reports the config error rather than clap's "unrecognized subcommand". A near-miss on a *built-in* (`agent-vm doctro`) keeps the config error primary and *appends* clap's did-you-mean as a hint, so the message points at the verb typo without displacing the real error; `help <verb>` (which clap validates before dispatch) is intercepted via clap's `InvalidSubcommand` context and routed the same way.
- **The `shell` fallback is conditional and lives in the launch catalog, not the merge result.** `ResolvedTools` stays the pure merge result (every merge test and proptest is defined against it). The fallback is a config that omits — or typos — `shell`; it does **not** fire when a config *declares* `shell`, and it does **not** fire on an unparseable config (see D4 below).
- **The union / user-wins rule from #80 is now load-bearing for the CLI.** The user tier is authoritative for any name it declares; the project tier may only add names the user did not write. A differing project declaration is a `doctor` warning, and the *whole* user definition wins — never a field overlay.
- **The credential-provider indirection from #81 carries the tool's provider set.** A tool names providers in config (`anthropic`, `openai`, `opencode-static`, `copilot`); `Tool::credential_providers` turns that into the `ProviderSet` `secrets::refresh` threads through launch. Providers (not tools) own capture, guest-HOME links, state dirs, bypass configs, and proxy wiring. The asymmetric legacy gating — `Anthropic`/`OpenAi` captured on *every* launch regardless of the selected tool — is preserved unchanged (narrowing it would break the identical-behaviour criterion; see the follow-up below).
- **Help text names no specific tool.** `TOP_AFTER_HELP` and the launch footers describe "the tool the verb names"; the per-verb footer examples interpolate the real verb. The byte-for-byte fixtures `shell-help-columns-100.txt` / `shell-short-help-columns-100.txt` are regenerated and their assertion pins an explicit `ConfigPaths`, so the fixture cannot depend on the developer's `$HOME` or cwd.
- **`interactive_shell` is an explicit config field.** The bash `-c` argument-joining keys off `Tool::is_interactive_shell`, defaulting to false, rather than `command == "bash"`. A string check would silently misbehave for a user-declared `zsh`, `/bin/bash`, or `sh`.
- **clap's `string` feature is required.** A launch subcommand's name is a runtime `String`; without `string`, `Command::new(name.to_owned())` does not compile. `Box::leak` is deliberately not used on a name read from an untrusted project config.

### Trust model

Running `agent-vm` in a directory means trusting that directory's `.agent-vm/`. Before #82 the project config was inert; now it is executable surface — a cloned repo can declare `name = "claude", command = "curl"`, or redefine `shell`. This is **not a new trust boundary**: [ADR-0003](0003-project-tooling-layers.md) already lets a project's `.agent-vm/layers/*/Dockerfile` build and boot an arbitrary image, and the guest runs the repo's code by design. This ADR records that it is now *newly reachable*, with three consequences:

1. The `shell` fallback is a **conditional** safety net, not an absolute one: a project may claim the name `shell`.
2. Legacy `Scope::Always` capture means Anthropic/OpenAi credentials are captured regardless of the launched tool, so a project-declared tool does not need to *ask* for them.
3. `credentials = [...]` is honoured from **both** tiers (D6). Restricting it to the user tier is a recorded Alternative, not taken.

## Consequences

- **Config is read on every invocation**, before parsing. `--help` is no longer a static fact about the binary: two users with the same version can see different verb lists. `--help` and `agent-vm doctor` render the same catalog, so they cannot disagree.
- **A config error cannot be reported by clap directly.** That is why the failure is deferred and `allow_external_subcommands` is enabled on the broken path: every unknown verb reaches the deferred config error, with a did-you-mean hint appended when the verb is a near-miss on a built-in. clap's `help <verb>` validates its positional before dispatch, so that path intercepts `ErrorKind::InvalidSubcommand` and applies the same rule — nothing degrades into "unrecognized subcommand".
- **Shell completions generated from a static `Cli` would be wrong.** None exist in-tree; generating correct ones needs the user's config and is not implemented.
- **A tool's `layer` is metadata until [#84](https://github.com/gregwebs/agent-vm/issues/84)**, and `persist` until [#83](https://github.com/gregwebs/agent-vm/issues/83). This ADR does not build or resolve either.
- **The verb list is the merge result, in chain order**, matching what `doctor` numbers. The fallback `shell` row is labelled so the user knows it was not declared.
- **`ToolName` is validated** (no whitespace/control characters, no leading `-`, no `/`, not reserved), so it is safe to interpolate into help. A tool's `command` is **not** equally validated and is therefore never rendered in help.
- **A tool also carries its own guest `env`.** [#119](https://github.com/gregwebs/agent-vm/issues/119) moved `CODEX_HOME` off `credential_provider::GENERIC_GUEST_ENV` onto a tool `env` field; the generic slot and `GuestEnvSlot` are gone. The precedence rule that makes a user-declarable `env` safe is [ADR-0016](0016-tool-declared-guest-env.md).

## Alternatives

- **Restrict `credentials = [...]` to the user tier.** Rejected: it would silently break a legitimate project that adds its own tool. Recorded here so the trade-off is explicit if the trust calculus changes.
- **Make `shell` a hard-coded clap subcommand independent of config.** Rejected: it would let a config's `shell` and the built-in collide, and it re-introduces a tool the CLI knows by name.
- **Narrow the asymmetric `Scope::Always` provider gating here.** Rejected: it is a behaviour change this ticket's "identical to `main`" criterion forbids. Tracked separately in [agent-vm #118](https://github.com/gregwebs/agent-vm/issues/118).
- **`command == "bash"` instead of an `interactive_shell` field.** Rejected (D5): it silently misbehaves for a user-declared shell binary with a different name or path.
