//! One-line rendering for text agent-vm did not choose.
//!
//! A launch notice is one line by contract: `==> ` marks agent-vm's own output,
//! so a second line starting at column 0 reads as another one. Declared
//! spellings honour that through [`crate::mount::Declaration`], which decides
//! between the byte-pinned argv rendering and the quoted config one. This module
//! is the other half: text that was **measured** — a canonical path, a directory
//! entry, a store path — where nobody chose the bytes and there is no
//! declaration that could attribute them.
//!
//! The policy is deliberately narrower than `config::escape_path`: only control
//! characters are escaped. That function exists for *config* text, where a value
//! is quoted and every non-ASCII byte must be spelled out so two config files
//! cannot look identical. A notice is the opposite case — it is unquoted prose
//! telling you where something is, and this repository explicitly supports
//! non-ASCII project paths (`run::resolve_project_guest_path`). Escaping
//! `/home/boger/проект` into `\xd0\xbf…` would make the notice unreadable and
//! uncopyable, and would be a regression for a user who has done nothing wrong.
//! Only *control characters* are escaped — the class a terminal acts on instead
//! of printing, which is what can turn one line into two (newline), move the
//! cursor (CR, BS, ESC), or shift the rest of the line (TAB). Backslashes and
//! quotes are printed as they are: in unquoted prose `\"` is noise, not
//! protection.
//!
//! The rendering is one line, not an invertible encoding: a directory literally
//! named `ok\x0aFORGED` prints exactly like one containing a newline. That is
//! accepted, because the requirement is that neither can end the line the reader
//! is looking at.

use std::fmt::Write as _;
use std::path::Path;

/// Render text for a single terminal line: every control character becomes
/// `\xNN`, every other character is printed as itself.
pub(crate) fn text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_control() {
            let _ = write!(out, "\\x{:02x}", ch as u32);
        } else {
            out.push(ch);
        }
    }
    out
}

/// [`text`] for a path.
///
/// Bytes that are not valid UTF-8 become U+FFFD rather than being spelled out:
/// they cannot be printed as themselves, the notice still has to describe the
/// file, and a replacement character keeps it one line. The alternative —
/// escaping every non-ASCII byte — is what this module exists to avoid.
pub(crate) fn path(value: &Path) -> String {
    text(&value.as_os_str().to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn a_control_character_cannot_break_the_line() {
        assert_eq!(text("ok\nFORGED"), "ok\\x0aFORGED");
        assert_eq!(text("a\tb"), "a\\x09b");
        assert_eq!(text("a\u{1b}[31mred"), "a\\x1b[31mred");
        assert_eq!(text("a\u{7f}b"), "a\\x7fb");
        assert_eq!(text("a\u{85}b"), "a\\x85b");
    }

    /// The regression this module was written to avoid: a Cyrillic project path
    /// must stay readable, because the repository supports and tests those paths.
    #[test]
    fn non_ascii_text_is_printed_as_itself() {
        assert_eq!(
            path(&PathBuf::from("/home/boger/проект-тест")),
            "/home/boger/проект-тест"
        );
        assert_eq!(path(&PathBuf::from("/home/boger/😀")), "/home/boger/😀");
        assert_eq!(text("café"), "café");
    }

    /// Quotes and backslashes cannot end a line, and in unquoted prose the
    /// escaping would be read as part of the name.
    #[test]
    fn quotes_and_backslashes_are_left_alone() {
        assert_eq!(text("/a\"b"), "/a\"b");
        assert_eq!(text("/a\\b"), "/a\\b");
    }

    #[test]
    fn an_ordinary_path_is_byte_identical() {
        let path = PathBuf::from("/private/tmp/v/s22/home/project");
        assert_eq!(super::path(&path), path.display().to_string());
    }
}
