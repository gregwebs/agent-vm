# ADR-0049: One dialect rule for a printed command

## Status

Accepted. Resolves
[agent-vm #434](https://github.com/gregwebs/agent-vm/issues/434), which was
found while implementing #418 (PR #428). Follows the display policy of
[#419](https://github.com/gregwebs/agent-vm/issues/419)/#425 and does not
change it.

## Context

Two functions rendered a value as a shell word, each correct for its own case
and each documented in its own module:

- `run.rs`'s `shell_escape` — POSIX single quotes, for text embedded in the
  script agent-vm hands to the guest's `bash -c`. Nobody reads that script, a
  literal newline is valid, and one line is not required.
- `shell.rs`'s `bash_word` (#418) — ANSI-C `$'…'`, for a value printed as part
  of a command a human is asked to paste. There the command must stay on one
  line and may hold any path byte, which POSIX quoting cannot both do: a
  literal newline splits the command, and double quotes would let `$(…)`,
  backticks and `"` through.

The rule "which dialect does this printed command target" therefore lived only
in prose in two module docs, and the next caller chose by impression. Worse,
neither hint said which shell read it: `$'…'` is a Bash/zsh feature, and in
dash `$` is literal, so `$'a b'` arrives as the one word `$a b` — a reader
pasted a *different* reference, with no error, depending on which hint they had
seen.

## Decision

**The encoder follows who will run the text, not the module that prints it.**
`crates/agent-vm/src/shell.rs` owns every shell-word encoding, and its module
doc is the rule's one canonical place:

| Text | Encoder | Read by | What that buys |
|---|---|---|---|
| agent-vm's own guest script | `guest_script_word`, POSIX `'…'` | the guest's `bash -c` | any byte; one line is not required |
| a command a human pastes | `PastedWord::new`, ANSI-C `$'…'` | bash or zsh | arbitrary bytes **and** one line |
| a diagnostic a human reads | `crate::one_line` | eyes | one line, deliberately not invertible — never pasted |

The paste encoder's result is not a bare `String`: `PastedWord` carries the
word plus a private `Plain`/`BashZsh` dialect, and `bash_zsh_note` answers the
second half of #434's question. A hint prints the note **only when a word it
prints is `BashZsh`**; a plain word (`app:dev`) is read identically by every
shell, so naming one there would misdescribe the command. The note is one
sentence — `quoted for bash or zsh` — and each site wraps it in the grammar its
message needs:

```text
hint: an image that exists only in your local Docker daemon is not visible to
agent-vm until it is imported into agent-vm's own image cache:
  agent-vm image import --docker $'localhost:1/x:\xc3\xa9' --tag $'localhost:1/x:\xc3\xa9'
A completed OCI or Docker-save archive works too:
  agent-vm image import --input <FILE> --tag $'localhost:1/x:\xc3\xa9'
The commands above are quoted for bash or zsh.
The imported reference must match the --image value exactly.
```

`doctor --reset-msb-db` puts the note on its own line, so its `To undo: mv --
…` line stays a command and nothing else. The paths below hold a space: POSIX
single quotes could spell that (`'/state/my db'`), but the paste encoder takes
`$'…'` for every value outside its bare set, so a space alone earns the note:

```text
To undo: mv -- $'/state/my db.reset-1' $'/state/my db'
(quoted for bash or zsh)
```

`PastedWord`'s dialect field is private and set only by the encoder, so a word
cannot claim to be plain while holding bytes the encoding does not fit; the
answer `bash_zsh_note` gives is therefore a fact about the word, not a guess.
A hint still has to ask for the note — `Display` prints the word alone, because
some sentences carry the note differently — but it cannot get the *condition*
wrong.

## Rejected alternatives

**POSIX-first for pasted words** — spell every printable, valid-UTF-8 value as
`'app:é'` and fall back to `$'…'` only for control bytes and invalid UTF-8.
That would make most hints pasteable in any POSIX shell and more legible, but
it splits one encoder into three cases, emits raw non-ASCII bytes from an
encoder that currently guarantees ASCII, and does not remove the case that
needs the note. It changes reference text that is printed today for a benefit
the note already provides at the one site where it matters.

**Always name the shell** — every pasteable-command hint says bash/zsh.
Consistent, but it misdescribes `app:dev`, which dash reads correctly, and it
would put a shell caveat on the common path to pay for the rare one.

**Never name the shell** — document the dialect only. Smallest change, but a
dash user pasting an exotic reference still gets a silently wrong tag, which is
the failure #434 was filed about.

## Consequences

- Plain values print exactly as before, with no shell named; only a value that
  needs `$'…'` gains the note (one line in the multi-line hints, a trailing
  parenthetical in the one-line import notices).
- Each encoder is named for its executor and lives beside the rule that chooses
  between them, so a new call site has to say which one it is. That is a naming
  and adjacency guarantee, not a compile-time one: `guest_script_word` returns a
  `String`, and a pasted site that called it would still compile.
- The note names the dialect, not full paste safety: an interactive Bash with
  history expansion still scans for `!`, and Bash 3.2 can lose its place in
  `$'…'` after an escaped apostrophe. Those caveats and the NUL precondition
  live in the module doc, which is the canonical place.
- Plain means the shell reads the word as itself; it does not decide whether
  the word could look like an option. Each printed command owns that (`mv --`,
  `--image VALUE`), as it did before.
- Diagnostics keep `crate::one_line` and stay out of this decision: their
  output is read, not run, and is deliberately not invertible.
