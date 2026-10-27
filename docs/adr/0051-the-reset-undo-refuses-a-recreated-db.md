# ADR-0051: The reset undo refuses a recreated db

## Status

Accepted. Resolves
[agent-vm #432](https://github.com/gregwebs/agent-vm/issues/432), found while
verifying #418 (PR #428).

## Context

`doctor --reset-msb-db` moves `msb-home/db` aside and prints an instruction to
put it back: `mv -- <backup> <db>`. That is a restore only while `<db>` is
absent. The same report says the database "will be recreated ... on the next
`agent-vm shell`/`run`", so reset → launch → undo is a reasonable order to do
things in. Once the db exists again, `mv` exits 0 and moves the backup *inside*
the new `db/`: the operator reads "restored" while the recreated database is
still where a launch will read it and the old one sits nested where nothing
looks.

The instruction is pasted later, from a terminal `agent-vm` is no longer
running in (#433), so any check has to be part of the printed command.

## Decision

**The printed instruction is a guard, not a bare move.** It is one line, one
command, and one report row:

```text
To undo: if [ -e <db> ]; then printf 'refusing to undo: %s exists; %s was not restored; move the existing db aside, then run this again\n' <db> <backup> >&2; false; else mv -- <backup> <db>; fi
```

- The test is `-e` on the original name, because the name being taken is what
  makes the move unsafe, not what the directory contains: an empty recreated
  `db/` is the same conflict.
- The refusal names both paths, on stderr, so the operator can tell which
  database is in the way and which backup was left unrestored, and can decide —
  move the current `db/` aside and paste again, or keep the new database.
- The exit status is nonzero whenever nothing was restored, so a no-op cannot be
  mistaken for a restore. `false` rather than `exit 1`: the instruction is
  pasted into an interactive shell, and `exit` would close it.
- Operands are still `PastedWord`s, so ADR-0049's dialect rule and the escaping
  policy are unchanged. The refusal takes each path as an argument to `printf`
  (`%s` in the format, the words after it), never inside the format string, so
  no byte of a name is read as a directive.
- The command is POSIX shell syntax — `if`/`then`/`fi` — so `sh`, bash and zsh
  run it. ADR-0049's shell note is about which shell reads the *words*; a
  plain-word variant keeps the documented promise that no shell reinterprets a
  path, and the `/bin/sh` test pins that the command itself needs no bashism.

## Rejected alternatives

**`mv -n`** — shorter, and no-clobber is the right instinct. Rejected because
`mv -n` exits 0 when it does nothing, which is the status lie #432 is about; its
meaning when the target is an existing *directory* has differed between
implementations; and a silent no-op is exactly the misreading reported.

**Restore into a distinct name and say so** — never refuses, but leaves two
databases present and the operator to choose which one the next launch reads.
The refusal does less and says more.

**Check in `agent-vm` rather than in the command** — not possible: the undo runs
after `agent-vm` exits, in a shell it does not control. The same reason the
operand encoding lives in the printed word (ADR-0049).

## Consequences

- An undo whose destination is free behaves exactly as before.
- An undo after a launch now fails loudly and changes nothing; USAGE.md says why
  and what to do.
- `config_doctor::the_undo_refuses_once_the_db_exists_again` seeds a recreated
  db, runs the printed instruction in Bash, and asserts the nonzero status, the
  named conflict, and both databases untouched — the same
  execute-what-was-printed oracle as the restore test.
