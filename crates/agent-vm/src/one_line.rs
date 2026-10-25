//! One-line rendering for text agent-vm did not choose.
//!
//! A launch notice is one line by contract: `==> ` marks agent-vm's own output,
//! so a second line starting at column 0 reads as another one. Declared
//! spellings honour that through [`crate::mount::Declaration`], which decides
//! between the byte-pinned argv rendering and the quoted config one. This module
//! is the other half: text that was **measured** — a canonical path, a directory
//! entry, a store path — where nobody chose the bytes and there is no
//! declaration that could attribute them. Every measured path `doctor` renders
//! goes through here, including the config file locations and the config file a
//! load failure quotes (issue #420); `boot_image`'s source description and
//! selection errors follow. Error text built by modules that have not converted
//! yet (`session`, `protected_config_dir`, `egress_policy`, …) can still spell one
//! out byte by byte — `doctor`'s module doc lists which.
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
    escape_control_characters(value)
}

fn escape_control_characters(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            let _ = write!(out, "\\x{:02x}", character as u32);
        } else {
            out.push(character);
        }
    }
    out
}

/// [`text`] for a path.
///
/// Valid UTF-8 passes through the same policy as [`text`]. Bytes that are **not**
/// valid UTF-8 are escaped as `\xNN`: they cannot be printed as themselves, and
/// replacing them with U+FFFD would make two different directories — one holding
/// an invalid byte, one holding a real `�` — print identically. Escaping them keeps
/// the legibility this module exists for (a Cyrillic directory still reads as
/// itself) while leaving the bytes the filesystem actually holds distinguishable.
pub(crate) fn path(value: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let mut rest = value.as_os_str().as_bytes();
        let mut out = String::with_capacity(rest.len());
        loop {
            match std::str::from_utf8(rest) {
                Ok(text) => {
                    out.push_str(&escape_control_characters(text));
                    return out;
                }
                Err(error) => {
                    let (valid, after) = rest.split_at(error.valid_up_to());
                    out.push_str(&escape_control_characters(
                        std::str::from_utf8(valid).expect("a valid prefix by construction"),
                    ));
                    let invalid = error.error_len().unwrap_or(after.len());
                    for byte in &after[..invalid] {
                        let _ = write!(out, "\\x{byte:02x}");
                    }
                    rest = &after[invalid..];
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        text(&value.as_os_str().to_string_lossy())
    }
}

/// [`text`], safe inside double quotes: `\` and `"` are doubled so a quoted path
/// cannot end its own quoting. Still one line, and non-ASCII still prints as
/// itself.
pub(crate) fn quoted_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ if character.is_control() => {
                let _ = write!(out, "\\x{:02x}", character as u32);
            }
            _ => out.push(character),
        }
    }
    out
}

/// [`quoted_text`] for a path, already wrapped in double quotes.
///
/// This is the rendering for a **measured** path in a message that quotes it —
/// most often the config file a diagnostic is about. `config::quoted_path` is the
/// other one: it spells every non-ASCII byte out, because it renders paths a
/// config file *chose*, where two entries that differ only outside ASCII must not
/// print alike.
pub(crate) fn quoted_path(value: &Path) -> String {
    format!("\"{}\"", quoted_text(&value.as_os_str().to_string_lossy()))
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

    /// The quoted rendering keeps the property that matters inside quotes — a
    /// path cannot end its own quoting — without spelling non-ASCII out.
    #[test]
    fn quoted_rendering_keeps_the_quoting_and_the_legibility() {
        assert_eq!(quoted_text("a\"b"), "a\\\"b");
        assert_eq!(quoted_text("a\\b"), "a\\\\b");
        assert_eq!(quoted_text("a\nb"), "a\\x0ab");
        assert_eq!(
            quoted_path(&PathBuf::from("/home/дом/config.toml")),
            "\"/home/дом/config.toml\""
        );
    }

    /// A byte that is not valid UTF-8 is spelled out, so it cannot be confused
    /// with a real replacement character in the same position.
    #[cfg(unix)]
    #[test]
    fn an_invalid_byte_is_escaped_not_replaced() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;

        assert_eq!(
            path(&PathBuf::from(OsStr::from_bytes(b"/home/h\xffome"))),
            "/home/h\\xffome"
        );
        assert_eq!(
            path(&PathBuf::from("/home/h\u{fffd}ome")),
            "/home/h\u{fffd}ome"
        );
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
