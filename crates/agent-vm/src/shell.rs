//! Quoting a value as **one shell word**.
//!
//! # The one rule: the encoder follows who will run the text
//!
//! | Text | Encoder | Read by | What that buys |
//! |---|---|---|---|
//! | agent-vm's own guest script | [`guest_script_word`]: POSIX `'…'` | the guest's `bash -c` | any byte; one line is not required, a literal newline is valid |
//! | a command a human is asked to paste | [`PastedWord::new`]: ANSI-C `$'…'` | bash or zsh | arbitrary bytes *and* one line |
//! | a diagnostic a human only reads | [`crate::one_line`] | eyes | one line; deliberately **not** invertible, never pasted |
//!
//! A caller picks by asking which of those three the text is, never by which
//! encoder looks convenient. The two shell dialects are not interchangeable:
//! `guest_script_word` may emit a literal newline because the script spans lines
//! anyway, and `$'…'` is unnecessary there; a pasted command must stay on one
//! line, so a value holding a control byte has no POSIX spelling at all — a
//! literal newline would split the command, and double quotes would let `$(…)`,
//! backticks and `"` through. That is the whole reason the paste encoder exists.
//! Any byte outside the bare set takes `$'…'` for the whole word, not only the
//! bytes POSIX quoting cannot spell: `'a b'` would work, but a second branch
//! would buy legibility with two encodings and output that can hold raw
//! non-ASCII. The note follows the same set, so widening it changes both together.
//!
//! `$'…'` is a Bash/zsh feature, not promised for dash or fish, where `$` is
//! literal: `$'a b'` arrives as the one word `$a b` — no error, just the wrong
//! value. A hint that prints such a word therefore has to [`bash_zsh_note`] it; a
//! plain word needs no note, because every shell reads it as itself.
//!
//! One caveat applies to both dialects: an interactive Bash with history
//! expansion on scans for `!` before anything on the line runs, and Bash 3.2
//! (still macOS's `/bin/bash`) can lose its place in `$'…'` after an escaped
//! apostrophe, so a value containing `!` needs `set +H` on an earlier line, or
//! zsh.
//!
//! NUL is the one byte neither encoder spells: a Unix filename cannot contain
//! it, so the input is required to be NUL-free rather than given a lossy
//! conversion or an error branch for a path no filesystem can hold. The decision
//! and its rejected alternatives are in
//! `docs/adr/0049-one-dialect-rule-for-printed-commands.md`.

use std::fmt;

/// `s` as one POSIX-quoted word, for a script agent-vm itself hands to `bash`
/// in the guest.
///
/// Every value is quoted, even one that would need no quoting: a guest script
/// is never read by a human, so legibility is not worth a branch. Embedded
/// single quotes are split out with the standard `'\''` trick.
pub(crate) fn guest_script_word(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// A value as one word of a command a human is asked to paste into bash or zsh.
///
/// The field records what a hint needs to know — whether every shell reads the
/// word as itself ([`Dialect::Plain`]) or only bash and zsh do
/// ([`Dialect::BashZsh`]) — and it is private, so the two cannot disagree: a
/// value the encoding does not fit cannot be built as `Plain`, and
/// [`bash_zsh_note`] can trust the answer. A hint still has to *ask* for the
/// note; `Display` prints the word alone, because a caller may be printing it
/// where the sentence does not fit.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PastedWord {
    word: String,
    dialect: Dialect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialect {
    /// The value needed no quoting: `app:dev`, `localhost:5000/a/b:V1`.
    Plain,
    /// ANSI-C `$'…'`: ASCII only, one line, and only bash/zsh read it.
    BashZsh,
}

impl PastedWord {
    /// Empty input is one empty word, never zero arguments.
    pub(crate) fn new(bytes: &[u8]) -> Self {
        if !bytes.is_empty() && bytes.iter().copied().all(is_plain_byte) {
            return Self {
                word: bytes.iter().copied().map(char::from).collect(),
                dialect: Dialect::Plain,
            };
        }
        let mut word = String::from("$'");
        for byte in bytes.iter().copied() {
            match byte {
                b'\\' => word.push_str("\\\\"),
                b'\'' => word.push_str("\\'"),
                0x20..=0x7e => word.push(char::from(byte)),
                // Zero-padded: Bash and zsh read up to two hex digits, greedily. An
                // unpadded `\xa` followed by a literal `f` would parse as the single
                // escape `\xaf` — a different byte, with the `f` gone — renaming the
                // path.
                _ => {
                    use std::fmt::Write as _;
                    let _ = write!(word, "\\x{byte:02x}");
                }
            }
        }
        word.push('\'');
        Self {
            word,
            dialect: Dialect::BashZsh,
        }
    }
}

impl fmt::Display for PastedWord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.word)
    }
}

/// The sentence a hint adds when at least one word it prints is
/// [`Dialect::BashZsh`], so a reader about to paste into `sh`/`dash` knows to
/// switch. `None` when every word is plain: no shell reinterprets such a value,
/// so there is nothing to warn about. The note speaks about the *words* only —
/// a command's own syntax can still restrict which shells run it (ADR-0049).
pub(crate) fn bash_zsh_note(words: &[&PastedWord]) -> Option<&'static str> {
    words
        .iter()
        .any(|word| word.dialect == Dialect::BashZsh)
        .then_some("quoted for bash or zsh")
}

/// [`bash_zsh_note`] as a trailing parenthetical for a one-line notice:
/// ` (quoted for bash or zsh)`, or nothing when no word needs it.
pub(crate) fn note_parenthetical(words: &[&PastedWord]) -> String {
    bash_zsh_note(words)
        .map(|note| format!(" ({note})"))
        .unwrap_or_default()
}

/// The bytes that may stand unquoted: ASCII alphanumerics plus the delimiters a
/// result reference or a path uses. Everything else — including every control
/// byte, `"`, `'`, `\`, `$` and a backtick — takes the quoted form.
fn is_plain_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"._/:@-".contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Inputs a test must be able to hand a shell without the test itself
    /// deciding what "safe" means.
    const PAYLOADS: &[&[u8]] = &[
        // Empty input is one empty word. `printf '%s'` alone would accept zero
        // operands, so the oracle counts arguments.
        b"",
        b"app:dev",
        b"a\"b",
        b"a'b",
        b"a\\b",
        b"a b",
        // Substitutions that run if the word is ever interpolated.
        b"$(touch INJECTED)",
        b"`touch BACKTICKED`",
        b"a\rb",
        b"a\nb",
        b"a\tb",
        b"a\x1bb",
        b"a\x7fb",
        // A literal backslash-x0a must not decode to a newline…
        b"a\\x0ab",
        // …and a control byte must not swallow the hex digit after it.
        b"a\nf",
        "x:é".as_bytes(),
        "x:\u{200d}".as_bytes(),
        // Invalid UTF-8: display cannot spell this, argv still has to hold it.
        b"a\xffb",
    ];

    /// The shell half of the round trip. `set --` plus the argument count is the
    /// part that makes the empty case observable: `printf '%s'` would happily
    /// print nothing for zero operands.
    const ORACLE: &str = "set -- {WORD}; [ \"$#\" -eq 1 ] || exit 99; printf '%s' \"$1\"";

    fn run_shell(shell: &str, cwd: &Path, script: &str) -> std::process::Output {
        std::process::Command::new(shell)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .current_dir(cwd)
            .args(["-c", script])
            .output()
            .unwrap_or_else(|error| panic!("running {shell}: {error}"))
    }

    fn shell_present(shell: &str) -> bool {
        std::process::Command::new(shell)
            .arg("--version")
            .output()
            .is_ok()
    }

    fn assert_round_trips(shell: &str, cwd: &Path, cases: &[&[u8]]) {
        for input in cases {
            let word = PastedWord::new(input).to_string();
            assert!(word.is_ascii(), "not ASCII for {input:?}: {word:?}");
            assert!(
                !word.chars().any(char::is_control),
                "raw control byte in {word:?}"
            );
            let output = run_shell(shell, cwd, &ORACLE.replace("{WORD}", &word));
            assert!(
                output.status.success(),
                "{shell} failed on {word:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                output.stdout, *input,
                "{shell} did not reproduce {input:?} from {word:?}"
            );
        }
    }

    #[test]
    fn guest_script_word_quotes_simple_and_embedded_quotes() {
        assert_eq!(guest_script_word("foo"), "'foo'");
        assert_eq!(
            guest_script_word("--flag=value with spaces"),
            "'--flag=value with spaces'"
        );
        assert_eq!(guest_script_word("don't"), "'don'\\''t'");
        assert_eq!(guest_script_word(""), "''");
    }

    #[test]
    fn pasted_word_is_identity_for_plain_ascii() {
        for raw in [
            "app:dev",
            "localhost:5000/a/b_c:V1.2-x",
            "registry.example.com/x",
        ] {
            let word = PastedWord::new(raw.as_bytes());
            assert_eq!(word.to_string(), raw);
            assert_eq!(bash_zsh_note(&[&word]), None, "{raw}");
        }
    }

    /// The dialect is what every hint branches on, so it has to be right for the
    /// cases a hint actually prints: an empty value, a value POSIX quoting could
    /// spell, and one it cannot.
    #[test]
    fn pasted_word_says_whether_it_needs_bash_or_zsh() {
        for (bytes, needs_bash_zsh) in [
            (b"app:dev".as_slice(), false),
            (b"".as_slice(), true),
            (b"a b".as_slice(), true),
            (b"app:\xc3\xa9".as_slice(), true),
            (b"a\nb".as_slice(), true),
            (b"a\xffb".as_slice(), true),
        ] {
            let word = PastedWord::new(bytes);
            assert_eq!(
                bash_zsh_note(&[&word]).is_some(),
                needs_bash_zsh,
                "{bytes:?} rendered as {word}"
            );
        }
    }

    /// One exotic operand is enough: the whole line is then bash/zsh-only.
    #[test]
    fn the_note_covers_every_word_on_the_line() {
        let plain = PastedWord::new(b"/state/db");
        let exotic = PastedWord::new(b"/state/my db");
        assert_eq!(bash_zsh_note(&[&plain]), None);
        assert_eq!(
            bash_zsh_note(&[&exotic, &plain]),
            Some("quoted for bash or zsh")
        );
    }

    #[test]
    fn pasted_word_round_trips_through_bash_and_zsh() {
        let cwd = tempfile::tempdir().unwrap();
        for raw in ["app:é", "a'b", "a\\b", "a b", "a\nb", "x:\u{200d}"] {
            assert_round_trips("bash", cwd.path(), &[raw.as_bytes()]);
        }
        if shell_present("zsh") {
            for raw in ["app:é", "a'b", "a\\b", "a b", "a\nb", "x:\u{200d}"] {
                assert_round_trips("zsh", cwd.path(), &[raw.as_bytes()]);
            }
        } else {
            // Bash coverage above is unconditional; zsh is reported, not assumed.
            eprintln!("zsh not on PATH; skipping the zsh round trip");
        }
    }

    /// The encoder's contract against a shell that shares no code with it: one
    /// argument, holding the original bytes, for every byte a filename may hold.
    /// Nothing here decodes through [`PastedWord`] itself.
    #[test]
    fn pasted_word_round_trips_arbitrary_non_nul_bytes() {
        let cwd = tempfile::tempdir().unwrap();
        // Pinned, not just round-tripped: zero bytes take the quoted branch, so
        // the shell receives one empty word rather than nothing at all.
        assert_eq!(PastedWord::new(b"").to_string(), "$''");
        let mut cases: Vec<&[u8]> = PAYLOADS.to_vec();
        // Every byte a filename may contain. NUL is excluded by the interface's
        // precondition, not by an escape.
        let every_non_nul: Vec<u8> = (1..=255u8).collect();
        cases.push(&every_non_nul);

        // Bash is mandatory: this fails if it is missing rather than skipping.
        assert_round_trips("bash", cwd.path(), &cases);
        for marker in ["INJECTED", "BACKTICKED"] {
            assert!(
                !cwd.path().join(marker).exists(),
                "bash ran a substitution instead of reading the word literally"
            );
        }

        if shell_present("zsh") {
            assert_round_trips("zsh", cwd.path(), &cases);
            for marker in ["INJECTED", "BACKTICKED"] {
                assert!(
                    !cwd.path().join(marker).exists(),
                    "zsh ran a substitution instead of reading the word literally"
                );
            }
        } else {
            eprintln!("zsh not on PATH; skipping the zsh round trip");
        }
    }
}
