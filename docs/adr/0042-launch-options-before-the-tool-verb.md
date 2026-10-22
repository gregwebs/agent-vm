# ADR-0042: Launch options before the tool verb

## Status

Accepted. Breaking: **0.4.0**.

## Context

Launch options were parsed after the tool verb (`agent-vm pi --mount ~/.pi`),
sharing argv with the tool's own arguments. A tool flag that shared a name
with a launch option (`--root`, `--image`) was taken by `agent-vm`;
unrecognized flags fell through to the tool; `--help` showed `agent-vm`'s help;
and a literal `--` needed `agent-vm pi -- -- …`.

## Decision

`agent-vm [launch options] <tool> [tool arguments…]`. Every token after the
tool verb is forwarded verbatim, including `--help` and `--`. `agent-vm` only
locates the verb.

- Launch options are documented in `agent-vm --help`; `agent-vm help <tool>`
  shows a one-line description and examples.
- Built-in verbs (`setup`, `doctor`, …) keep their flags after the verb
  and reject launch options before it. `--image` is therefore written before
  the verb for a launch and after it for `image refresh`/`setup`.

> Amended by #389: the image operations are now `agent-vm image refresh
> [--image REF]` and `agent-vm image set-default --image REF`, so their flags
> follow the nested subcommand. `pull`/`upgrade` are no longer built-ins.

## Considered Options

- **Accept launch options in both positions.** Rejected: keeps the name
  collisions this removes.
- **Warn when a tool argument names a launch option.** Rejected: it fires on
  legitimate tool flags with the same name, and a first-token check misses the
  rest. Old-position flags are now forwarded to the tool silently; the minor
  bump and USAGE note carry the migration.

## Consequences

`agent-vm <tool> --help` reaches the tool, not `agent-vm`. Earlier ADRs keep
the old syntax as historical record.
