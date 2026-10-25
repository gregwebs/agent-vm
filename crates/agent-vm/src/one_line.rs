//! One-line rendering for text agent-vm did not choose.
//!
//! A launch notice is one line by contract: `==> ` marks agent-vm's own output,
//! so a second line starting at column 0 reads as another one. Declared
//! spellings honour that through [`crate::mount::Declaration`], which decides
//! between the byte-pinned argv rendering and the quoted config one. This module
//! is the other half: text that was **measured** — a canonical path, a directory
//! entry, a store path — where nobody chose the bytes and there is no
//! declaration that could attribute them. Every path these modules print goes
//! through here: `doctor`'s report, `boot_image`'s source description and selection
//! errors, the config file locations and reader causes of a load failure (#420),
//! and the operation contexts in `session`, `protected_config_dir`, `guest_home`,
//! `network` and `egress_policy` (#422).
//!
//! Not every module has converted. `host_paths`, `credential_yaml`, `clipboard`,
//! `embedded_runtime` and others still interpolate `Path::display()` into an error
//! context, which escapes nothing at all; converting them is #419's subject, and
//! until then a module's own error text is only as safe as that module made it.
//!
//! The exceptions are *declaration* sentences: a message that attributes a config
//! entry — `mounts[N] in "<file>"`, a claim conflict, a mount's own host path
//! (`mount::Declaration`'s `host_path`, `fork_root`, `node_kind`,
//! `claim_clause`) — byte-escapes the path through `config::quoted_path`, because
//! there the path is the entry's own text and two entries that differ only outside
//! ASCII must not print alike.
//!
//! The policy is deliberately narrower than `config::escape_str`: only control
//! characters are escaped. That function exists for *config-chosen text*, where a
//! value is quoted and every non-ASCII byte must be spelled out so two config
//! files cannot look identical. A notice is the opposite case — it is unquoted prose
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
    render(value.as_bytes(), false)
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
    crate::one_line::render(bytes_of(value), false)
}

/// The bytes an `OsStr` holds, without a lossy conversion: a rendering policy
/// cannot recover a byte that `to_string_lossy` already replaced.
#[cfg(unix)]
fn bytes_of(value: &Path) -> &[u8] {
    use std::os::unix::ffi::OsStrExt as _;
    value.as_os_str().as_bytes()
}
#[cfg(not(unix))]
fn bytes_of(value: &Path) -> Vec<u8> {
    value
        .as_os_str()
        .to_string_lossy()
        .into_owned()
        .into_bytes()
}

/// The one walk all four renderings share: valid UTF-8 through the control-byte
/// policy (and, when quoted, through the two bytes that could end the quoting),
/// and each byte of an invalid sequence as `\xNN`, so an invalid byte never
/// collapses into a real U+FFFD.
fn render(bytes: impl AsRef<[u8]>, quoted: bool) -> String {
    let mut rest = bytes.as_ref();
    let mut out = String::with_capacity(rest.len());
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                push_valid(&mut out, text, quoted);
                break;
            }
            Err(error) => {
                let (valid, after) = rest.split_at(error.valid_up_to());
                push_valid(
                    &mut out,
                    std::str::from_utf8(valid).expect("a valid prefix by construction"),
                    quoted,
                );
                let invalid = error.error_len().unwrap_or(after.len());
                for byte in &after[..invalid] {
                    let _ = write!(out, "\\x{byte:02x}");
                }
                rest = &after[invalid..];
            }
        }
    }
    out
}

fn push_valid(out: &mut String, text: &str, quoted: bool) {
    for character in text.chars() {
        match character {
            '\\' if quoted => out.push_str("\\\\"),
            '"' if quoted => out.push_str("\\\""),
            control if control.is_control() => {
                let _ = write!(out, "\\x{:02x}", control as u32);
            }
            printable => out.push(printable),
        }
    }
}

/// [`text`] for a path, wrapped in double quotes: `\` and `"` are doubled so the
/// path cannot end its own quoting, and everything else keeps [`path`]'s policy.
///
/// This is the rendering for a **measured** path in a message that quotes it —
/// most often the config file a diagnostic is about. `config::quoted_path` is the
/// other one: it spells every non-ASCII byte out, because it renders paths a
/// config file *chose*, where two entries that differ only outside ASCII must not
/// print alike.
pub(crate) fn quoted_path(value: &Path) -> String {
    format!("\"{}\"", render(bytes_of(value), true))
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

    /// The conversion #422 finished is a property of these modules' *source*, not
    /// of the messages a fixture happens to reach: most of their sites are
    /// `with_context` on a syscall that only fails under conditions a fixture would
    /// have to contrive, and each of them can regress on its own. So it is checked
    /// at the source: a new site in the scanned code that interpolates
    /// `Path::display()` (which escapes nothing) or reaches for the byte policy
    /// fails here even though no test drives it.
    ///
    /// Two limits worth knowing. It reads source, not behaviour, so it cannot tell
    /// a diagnostic from anything else on the same line — the one exemption below
    /// is matched as a whole line for that reason, not as a substring. And it scans
    /// from the top of each file to the `#[cfg(test)] mod tests` that follows the
    /// production code, so code placed above that module is what it sees.
    ///
    /// `guest_home`'s one exempt line builds the guest-side symlink target rather
    /// than a diagnostic, so it has no reader to protect.
    #[test]
    fn converted_modules_render_every_path_through_this_module() {
        const ALLOWED_DISPLAY: &[&str] =
            &["format!(\"/agent-vm-state/{}\", self.state_relative.display())"];
        for (name, source) in [
            ("session", include_str!("session.rs")),
            (
                "protected_config_dir",
                include_str!("protected_config_dir.rs"),
            ),
            ("guest_home", include_str!("guest_home.rs")),
            ("network", include_str!("network.rs")),
            ("egress_policy", include_str!("egress_policy.rs")),
        ] {
            let production = &source[..source.find("\n#[cfg(test)]\nmod ").unwrap_or(source.len())];
            for (index, line) in production.lines().enumerate() {
                let allowed = ALLOWED_DISPLAY.iter().any(|ok| line.trim() == ok.trim());
                if line.contains(".display()") && !allowed {
                    panic!(
                        "{name}.rs:{} prints a path with display(), which escapes nothing: {line}",
                        index + 1
                    );
                }
                for banned in ["config::escape_str(", "config::quoted_path("] {
                    assert!(
                        !line.contains(banned),
                        "{name}.rs:{} reaches for the byte policy ({banned}), which is for \
                         config-chosen declarations, not for a path the runtime operates on: \
                         {line}",
                        index + 1
                    );
                }
            }
        }
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

    /// The quoted rendering keeps the property that matters inside quotes — the
    /// path cannot end its own quoting — without spelling non-ASCII out.
    #[test]
    fn quoted_rendering_keeps_the_quoting_and_the_legibility() {
        assert_eq!(
            quoted_path(&PathBuf::from("/home/дом/config.toml")),
            "\"/home/дом/config.toml\""
        );
        assert_eq!(
            quoted_path(&PathBuf::from("/home/a\"b")),
            "\"/home/a\\\"b\""
        );
        assert_eq!(
            quoted_path(&PathBuf::from("/home/a\\b")),
            "\"/home/a\\\\b\""
        );
        assert_eq!(
            quoted_path(&PathBuf::from("/home/a\nb")),
            "\"/home/a\\x0ab\""
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
        // The quoted form is the same policy plus the two bytes that could end
        // the quoting: it must not fall back to a lossy conversion, or one
        // directory would print two ways in the same refusal.
        assert_eq!(
            quoted_path(&PathBuf::from(OsStr::from_bytes(b"/home/h\xffome"))),
            "\"/home/h\\xffome\""
        );
        assert_eq!(
            quoted_path(&PathBuf::from(OsStr::from_bytes(b"/home/q\"uote"))),
            "\"/home/q\\\"uote\""
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
