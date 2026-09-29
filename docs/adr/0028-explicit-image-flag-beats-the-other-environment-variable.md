# ADR-0028: An explicit image flag overrides the other flag's environment variable

## Status

Accepted.

## Context

`--image` (env `AGENT_VM_IMAGE_TAG`) and `--base-image` (env
`AGENT_VM_BASE_IMAGE`) are mutually exclusive: `--image` boots a published image
verbatim, `--base-image` chooses what the declared tool layers are composed
onto. [ADR-0019](0019-tool-free-base-and-per-tool-layers.md) put both flags and
the rejection in `tool_layer::chain_root`.

clap's `env = …` fallback writes an environment value into the *same*
`Option<String>` as a typed flag, so nothing downstream could tell the two
apart. `chain_root` therefore saw two supplied flags and rejected the pair
(issue #189). That made `--base-image` unusable on any host with
`AGENT_VM_IMAGE_TAG` exported — including the local-dev setup
`macos-build.md` documents — and symmetrically made `--image` unusable with
`AGENT_VM_BASE_IMAGE` exported. An empty `AGENT_VM_IMAGE_TAG=` (a common CI or
`docker -e` passthrough) was enough, because clap yields `Some("")` for it.

clap already resolves the same conflict *within* one argument: the command line
beats the environment (`--image X` wins over `AGENT_VM_IMAGE_TAG`). Only the
cross-argument case had no rule.

## Decision

An explicit flag wins over the **other** flag's environment variable.
`cli::ImageFlags::reconcile` drops the environment-supplied half of the pair
whenever the other half came from the command line, before the derived `Args`
reach `chain_root`. This extends clap's own per-argument precedence across the
pair rather than inventing a second rule.

The two genuinely ambiguous pairs still conflict, and `chain_root` still rejects
them: both flags typed (the user must choose), and both environment variables
set (nothing says which was meant).

An empty environment value counts as unset. `AGENT_VM_IMAGE_TAG=` is a
passthrough artifact, not a decision, and `Some("")` would otherwise select an
empty image reference and fail later with an unrelated error. An explicit
`--image ""` stays the user's own mistake and is not rewritten.

The rule lives at the CLI seam (`cli.rs`), not in `chain_root`: `chain_root`
stays pure and keeps owning the decision table, and provenance is only available
where clap's `ArgMatches` is.

## Alternatives considered

- **Keep rejecting the pair, and tell the user to unset the variable.**
  Rejected. The variable is often not the user's doing (a shell profile, a CI
  job, `macos-build.md`'s own documented export), and the error blames a flag
  they did not pass.
- **Let the environment win.** Rejected. It inverts precedence for the pair
  relative to every other flag, and it makes an explicit flag silently lose.
- **Drop clap's `env = …` and read the variables by hand.** Rejected for now.
  It would fix the same bug, but it removes the `[env: …]` labels from `--help`,
  which are part of the pinned CLI surface, and it spreads the environment read
  across the three verbs.
- **Make the pair a single clap argument.** Rejected. The two flags name
  different concepts (a verbatim image vs. a composition root) and both must
  keep their own `--help` entry and environment variable.

## Consequences

- The `[env: …]` labels, the flags' help text, and the `--help` fixtures stay
  as they were apart from the added precedence sentence.
- `ImageFlags::reconcile` runs in each `cli::parse_from` dispatch arm that can
  carry the pair: launch verbs, and `pull`/`setup` on both the ready-catalog and
  the broken-config paths. Three arms means three chances to drop the call
  silently, so `every_dispatch_arm_reconciles_the_image_pair` pins each one.
- `chain_root`'s `(set, set)` row now means exactly "both typed, or both
  ambient", which its doc comment records.

### Pinned by

- `crates/agent-vm/src/cli.rs::tests::an_explicit_image_flag_beats_the_others_environment_variable`
  — the whole precedence table through `parse_from`: both cross-flag cases, an
  empty environment value on each half and beside a set one, same-argument
  precedence, and the two still-ambiguous pairs. Those rows also fail if a clap
  argument id is renamed: clap panics on an unknown id under `debug_assertions`
  (which is what the tests run as), so the drift cannot pass unnoticed. A
  release build would drop the value silently — the test is the guard, because a
  type cannot be.
- `crates/agent-vm/src/cli.rs::tests::every_dispatch_arm_reconciles_the_image_pair`
  — one case per dispatch arm that carries the pair.
- `crates/agent-vm/tests/config_launch_driven.rs` —
  `an_explicit_base_image_beats_an_ambient_image_tag` (both the set and the
  empty ambient value), `an_explicit_image_beats_an_ambient_base_image`, and
  `an_image_choice_is_still_rejected_when_both_sides_are_equally_explicit`. These
  drive the real binary to the debug `SandboxConfig` dump, so they assert which
  image a launch actually booted, not just how the flags parsed.
