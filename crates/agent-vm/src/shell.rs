//! Quoting a value as **one executable word** for a command we ask a human to
//! paste into Bash or zsh.
//!
//! Two callers, both printing a command rather than a diagnostic: the image
//! success/import hints name a result reference
//! ([`crate::image_publish::ResultReference::shell_arg`]), and
//! `doctor --reset-msb-db` names the two paths its undo `mv` must move back
//! ([`crate::doctor`]). Here the text *is* argv, so it has to expand to exactly
//! one word holding exactly the original bytes — no substitution, splitting or
//! globbing.
//!
//! The dialect is `$'…'` (ANSI-C quoting) because it is the only one that keeps
//! the command on one line *and* names a path holding a control byte. POSIX
//! single quotes can carry a newline only by putting a literal newline in the
//! command — exactly the one-line requirement they would break — and a
//! double-quoted string would let `$(…)`, backticks and `"` through. `$'…'` is a
//! Bash/zsh feature, not promised for dash or fish — with one exception: an
//! interactive Bash with history expansion on scans for `!` before anything on
//! the line runs, and Bash 3.2 (still macOS's `/bin/bash`) can lose its place in
//! `$'…'` after an escaped apostrophe, so there a path containing `!` needs
//! `set +H` on an earlier line, or zsh. [`crate::one_line`], the display policy,
//! stays separate for its own reason: its output is read, is deliberately
//! **not** invertible, and must never be pasted as an argument.
//!
//! NUL is the one byte this does not encode: a Unix filename cannot contain it,
//! so the input is required to be NUL-free rather than given a lossy conversion
//! or an error branch for a path no filesystem can hold.

/// `bytes` as a single Bash/zsh word: the result is ASCII with no raw control
/// bytes, and evaluating it yields one argv element holding exactly `bytes`.
/// Empty input still yields one (empty) word, never zero arguments.
pub(crate) fn bash_word(bytes: &[u8]) -> String {
    // The fast path is what keeps an ordinary reference or path printed
    // unchanged — `app:dev`, not `$'app:dev'`. Empty input must not take it:
    // zero bytes would reach the shell as no word at all.
    if !bytes.is_empty() && bytes.iter().copied().all(is_safe) {
        return bytes.iter().copied().map(char::from).collect();
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
    word
}

/// The bytes that may stand unquoted: ASCII alphanumerics plus the delimiters a
/// result reference or a path uses. Everything else — including every control
/// byte, `"`, `'`, `\`, `$` and a backtick — takes the quoted form.
fn is_safe(byte: u8) -> bool {
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
            let word = bash_word(input);
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
    fn bash_word_is_identity_for_safe_ascii() {
        for raw in [
            "app:dev",
            "localhost:5000/a/b_c:V1.2-x",
            "registry.example.com/x",
        ] {
            assert_eq!(bash_word(raw.as_bytes()), raw);
        }
    }

    #[test]
    fn bash_word_round_trips_through_bash_and_zsh() {
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
    /// Nothing here decodes through [`bash_word`] itself.
    #[test]
    fn bash_word_round_trips_arbitrary_non_nul_bytes() {
        let cwd = tempfile::tempdir().unwrap();
        // Pinned, not just round-tripped: zero bytes take the quoted branch, so
        // the shell receives one empty word rather than nothing at all.
        assert_eq!(bash_word(b""), "$''");
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
