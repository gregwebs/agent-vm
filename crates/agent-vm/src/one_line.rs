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
//! #419 converted the two producers its ticket named. `host_paths` renders every
//! descriptor-anchored read and write, and `credential_yaml` renders `file_error`
//! and the file-mode warning. Their messages now hold a [`Line`], not a `String`,
//! so the escaped bytes are fixed at construction. `clipboard`, `embedded_runtime`,
//! `mount`, `msb_install`, `run` and others still interpolate `Path::display()`
//! into an error context, which escapes nothing at all;
//! `every_module_stays_within_its_display_baseline` records each remaining count
//! (with the ticket that recorded it), so no module can grow a new site and no
//! converted module can regress.
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

use std::fmt::{self, Write as _};
use std::path::Path;

/// Text whose bytes are already one terminal line.
///
/// The field is private and there is no `From<String>`: the only doors are
/// [`text`], [`path`] and [`quoted_path`], and each applies the escape policy
/// itself. That is the whole point of the type. A message that interpolates a
/// `Line` cannot contain a control byte, so no consumer can forget to escape a
/// path it was handed; a consumer that wants the raw path for a non-display
/// purpose has to take the `Path` instead. With a `String` both mistakes compile,
/// which is exactly how the class kept recurring (#419).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Line(String);

impl fmt::Display for Line {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl PartialEq<&str> for Line {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Render text for a single terminal line: every control character becomes
/// `\xNN`, every other character is printed as itself.
pub(crate) fn text(value: &str) -> Line {
    Line(render(value.as_bytes(), false))
}

/// A borrowed path that renders through [`path`] wherever a `Display` is
/// wanted, so `format!("reading {display}")` cannot print an unescaped byte and
/// one path can serve several messages of the same function without allocating
/// once per message.
#[derive(Clone, Copy)]
pub(crate) struct PathInLine<'a>(&'a Path);

/// [`path`] as a borrowed `Display`.
pub(crate) fn path_in_line(value: &Path) -> PathInLine<'_> {
    PathInLine(value)
}

impl fmt::Display for PathInLine<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&path(self.0), formatter)
    }
}

/// [`text`] for a path.
///
/// Valid UTF-8 passes through the same policy as [`text`]. Bytes that are **not**
/// valid UTF-8 are escaped as `\xNN`: they cannot be printed as themselves, and
/// replacing them with U+FFFD would make two different directories — one holding
/// an invalid byte, one holding a real `�` — print identically. Escaping them keeps
/// the legibility this module exists for (a Cyrillic directory still reads as
/// itself) while leaving the bytes the filesystem actually holds distinguishable.
pub(crate) fn path(value: &Path) -> Line {
    Line(crate::one_line::render(bytes_of(value), false))
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
pub(crate) fn quoted_path(value: &Path) -> Line {
    Line(format!("\"{}\"", render(bytes_of(value), true)))
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

    /// The conversion #422 started and #419 completed is a property of these
    /// modules' *source*, not of the messages a fixture happens to reach: most of
    /// their sites are `with_context` on a syscall that only fails under conditions
    /// a fixture would have to contrive, and each of them can regress on its own. So
    /// it is checked at the source: a new site in the scanned code that interpolates
    /// `Path::display()` (which escapes nothing) or reaches for the byte policy
    /// fails here even though no test drives it.
    ///
    /// `production_code` removes only the items carrying `#[cfg(test)]`, so a site
    /// after a test-only import or a mid-file test module is still checked.
    ///
    /// One limit worth knowing: it reads source, not behaviour, so it cannot tell a
    /// diagnostic from anything else on the same line — the one exemption below is
    /// matched as a whole line for that reason, not as a substring.
    ///
    /// `guest_home`'s one exempt line builds the guest-side symlink target rather
    /// than a diagnostic, so it has no reader to protect.
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
            ("host_paths", include_str!("host_paths.rs")),
            ("credential_yaml", include_str!("credential_yaml.rs")),
        ] {
            let production = production_code(source);
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
        assert_eq!(super::path(&path).to_string(), path.display().to_string());
    }

    /// The borrowed adapter exists so a function can render one path in several
    /// messages without allocating once per message. It must not open a second
    /// policy, and the owned form a message carries must print the same bytes.
    #[test]
    fn a_borrowed_path_renders_through_the_same_policy() {
        let hostile = PathBuf::from("/home/a\nFORGED");
        assert_eq!(path_in_line(&hostile).to_string(), "/home/a\\x0aFORGED");
        assert_eq!(
            path_in_line(&hostile).to_string(),
            path(&hostile).to_string()
        );
        assert_eq!(
            format!("reading {}", path_in_line(&hostile)),
            "reading /home/a\\x0aFORGED"
        );
    }

    /// The production text of a module: every item carrying a `#[cfg(test)]`
    /// attribute is removed and everything else is kept — including production
    /// code before *and after* it.
    ///
    /// Truncating at the first marker (the guard as #422 wrote it, narrowed once
    /// by #424) is wrong twice.
    /// `mount.rs` opens with a test-only `use`, so thousands of production lines
    /// after it were invisible; `secrets.rs` declares a test module mid-file, so
    /// every diagnostic after it was invisible. Removing only the attributed item
    /// fixes both, whether the attribute is on a `mod tests { … }`, a
    /// `mod tests;`, a `use …;` or a `fn`.
    ///
    /// Removed text is replaced by its own line breaks, so a line number reported
    /// by a caller is the file's own line number.
    ///
    /// When the scanner cannot tell where the attributed item ends, it keeps the
    /// text instead of guessing: a parser bug may inflate a count, but it must
    /// never hide a site.
    fn production_code(source: &str) -> String {
        let bytes = source.as_bytes();
        let mut kept: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if let Some(end) = opaque_end(bytes, index) {
                kept.extend_from_slice(&bytes[index..end]);
                index = end;
                continue;
            }
            if let Some(attribute_end) = cfg_test_attribute_end(source, index)
                && let Some(item_end) = cfg_test_item_end(bytes, attribute_end)
            {
                kept.extend(bytes[index..item_end].iter().filter(|&&byte| byte == b'\n'));
                index = item_end;
                continue;
            }
            kept.push(bytes[index]);
            index += 1;
        }
        String::from_utf8(kept).expect("copied byte ranges end on ASCII boundaries")
    }

    /// The end of a comment, string or character literal starting at `start`, or
    /// `None` when ordinary code starts there. Braces, semicolons and attribute
    /// text inside these units are not syntax.
    fn opaque_end(bytes: &[u8], start: usize) -> Option<usize> {
        match *bytes.get(start)? {
            b'/' if bytes.get(start + 1) == Some(&b'/') => Some(
                bytes[start..]
                    .iter()
                    .position(|&byte| byte == b'\n')
                    .map_or(bytes.len(), |offset| start + offset),
            ),
            b'/' if bytes.get(start + 1) == Some(&b'*') => {
                // Rust block comments nest.
                let mut depth = 0_usize;
                let mut index = start;
                while index < bytes.len() {
                    if bytes[index..].starts_with(b"/*") {
                        depth += 1;
                        index += 2;
                    } else if bytes[index..].starts_with(b"*/") {
                        depth -= 1;
                        index += 2;
                        if depth == 0 {
                            return Some(index);
                        }
                    } else {
                        index += 1;
                    }
                }
                Some(bytes.len())
            }
            b'"' => Some(quoted_end(bytes, start + 1, b'"')),
            b'\'' => {
                // A lifetime (`'a`) has no closing quote; a character literal
                // (`'}'`, `'\''`) does.
                if bytes.get(start + 1) == Some(&b'\\') {
                    Some(quoted_end(bytes, start + 1, b'\''))
                } else if bytes.get(start + 2) == Some(&b'\'') {
                    Some(start + 3)
                } else {
                    None
                }
            }
            b'r' if is_raw_string(bytes, start) => Some(raw_string_end(bytes, start)),
            b'b' if bytes.get(start + 1) == Some(&b'r') && is_raw_string(bytes, start + 1) => {
                Some(raw_string_end(bytes, start + 1))
            }
            b'b' if bytes.get(start + 1) == Some(&b'"') => Some(quoted_end(bytes, start + 2, b'"')),
            b'b' if bytes.get(start + 1) == Some(&b'\'') => {
                Some(quoted_end(bytes, start + 2, b'\''))
            }
            _ => None,
        }
    }

    fn quoted_end(bytes: &[u8], mut index: usize, quote: u8) -> usize {
        while index < bytes.len() {
            if bytes[index] == b'\\' {
                index += 2;
                continue;
            }
            if bytes[index] == quote {
                return index + 1;
            }
            index += 1;
        }
        bytes.len()
    }

    fn is_raw_string(bytes: &[u8], start: usize) -> bool {
        if bytes.get(start) != Some(&b'r') {
            return false;
        }
        let mut index = start + 1;
        while bytes.get(index) == Some(&b'#') {
            index += 1;
        }
        bytes.get(index) == Some(&b'"')
    }

    fn raw_string_end(bytes: &[u8], start: usize) -> usize {
        let mut hashes = 0_usize;
        let mut index = start + 1;
        while bytes.get(index) == Some(&b'#') {
            hashes += 1;
            index += 1;
        }
        index += 1;
        while index < bytes.len() {
            if bytes[index] == b'"'
                && (index + 1..index + 1 + hashes).all(|offset| bytes.get(offset) == Some(&b'#'))
            {
                return index + 1 + hashes;
            }
            index += 1;
        }
        bytes.len()
    }

    /// The end (`]` + 1) of a `#[cfg(test)]` attribute at `start`, when that is
    /// exactly what stands there. Other `cfg` predicates (`any(test, …)`,
    /// `cfg_attr`) are left in production: they can compile code into a debug
    /// build, and keeping them can only inflate a count.
    fn cfg_test_attribute_end(source: &str, start: usize) -> Option<usize> {
        let bytes = source.as_bytes();
        if bytes.get(start) != Some(&b'#') || bytes.get(start + 1) != Some(&b'[') {
            return None;
        }
        let end = matching_delimiter(bytes, start + 1, b'[', b']')?;
        let inner: Vec<u8> = source[start + 2..end]
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        (inner == b"cfg(test)").then_some(end + 1)
    }

    /// The end of the item carrying an attribute that ends at `attribute_end`:
    /// the `;` for a `use`, a `mod name;` or a type declaration, the matching
    /// `}` for a `mod name { … }`, `fn`, `impl`, `struct` or macro body.
    fn cfg_test_item_end(bytes: &[u8], attribute_end: usize) -> Option<usize> {
        let mut index = attribute_end;
        loop {
            while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
                index += 1;
            }
            if bytes.get(index) == Some(&b'/') {
                index = opaque_end(bytes, index)?;
                continue;
            }
            if bytes.get(index) == Some(&b'#') && bytes.get(index + 1) == Some(&b'[') {
                index = matching_delimiter(bytes, index + 1, b'[', b']')? + 1;
                continue;
            }
            break;
        }
        while index < bytes.len() {
            if let Some(end) = opaque_end(bytes, index) {
                index = end;
                continue;
            }
            match bytes[index] {
                b';' => return Some(index + 1),
                b'{' => return matching_delimiter(bytes, index, b'{', b'}').map(|close| close + 1),
                _ => index += 1,
            }
        }
        None
    }

    fn matching_delimiter(
        bytes: &[u8],
        open: usize,
        open_byte: u8,
        close_byte: u8,
    ) -> Option<usize> {
        let mut depth = 0_usize;
        let mut index = open;
        while index < bytes.len() {
            if let Some(end) = opaque_end(bytes, index) {
                index = end;
                continue;
            }
            if bytes[index] == open_byte {
                depth += 1;
            } else if bytes[index] == close_byte {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            index += 1;
        }
        None
    }

    /// Every `.rs` file under `src`, test modules and nested modules included.
    fn rust_sources(root: &Path) -> Vec<PathBuf> {
        let mut sources = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("reading a source directory") {
                let path = entry.expect("a directory entry").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    sources.push(path);
                }
            }
        }
        sources
    }

    /// `.display()` calls the ratchet counts: every occurrence in production
    /// code, not every line that contains one (a second call added to an
    /// already-counted line is a second site), and no comment-only line.
    fn display_sites(source: &str) -> usize {
        production_code(source)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .map(|line| line.matches(".display()").count())
            .sum()
    }

    /// The guard's own history: each shape here hid a site from the truncating
    /// extractor, so the decision is tested directly as well as through every
    /// module's recorded count.
    #[test]
    fn the_extractor_keeps_production_around_test_items() {
        // Attribute on an import, production after it.
        assert_eq!(
            display_sites(
                "#[cfg(test)]\nuse crate::fixture::Thing;\n\
                 fn read(path: &Path) { let _ = path.display(); }\n"
            ),
            1
        );

        // A test module mid-file: production before and after it.
        assert_eq!(
            display_sites(
                "fn before(path: &Path) { let _ = path.display(); }\n\
                 #[cfg(test)]\nmod tests {\n    fn t(path: &Path) { let _ = path.display(); }\n}\n\
                 fn after(path: &Path) { let _ = path.display(); }\n"
            ),
            2
        );

        // Multiple test items, including a `mod tests;` declaration. The
        // `.display()` inside the second test module must not be counted.
        assert_eq!(
            display_sites(
                "#[cfg(test)]\nmod tests;\n\
                 fn first(path: &Path) { let _ = path.display(); }\n\
                 #[cfg(test)]\nmod more {\n    const A: &str = \".display()\";\n}\n\
                 fn second(path: &Path) { let _ = path.display(); }\n"
            ),
            2
        );

        // Braces and `"…"`/`r"…"` literals in the surrounding code must not
        // move the attributed item's end.
        assert_eq!(
            display_sites(
                "fn notice() { let _ = \"}\\n#[cfg(test)]\"; let _ = r\"}\"; let _ = r#\"}\"#; let _ = '}'; }\n\
                 #[cfg(test)]\nmod tests {\n    const OPEN: &str = \"{\";\n}\n\
                 fn after(path: &Path) { let _ = path.display(); }\n"
            ),
            1
        );

        // Attribute on a function.
        assert_eq!(
            display_sites(
                "#[cfg(test)]\nfn helper(path: &Path) { let _ = path.display(); }\n\
                 fn production(path: &Path) { let _ = path.display(); }\n"
            ),
            1
        );

        // The reviewer's exact attack: a site after the last test module.
        assert_eq!(
            display_sites(
                "#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n\
                 fn leaked(path: &Path) { let _ = path.display(); }\n"
            ),
            1
        );
    }

    /// A line is not a site: a second call on an already-counted line is a second
    /// way to print a path, so it must raise the count.
    #[test]
    fn the_ratchet_counts_calls_on_a_line() {
        assert_eq!(
            display_sites("fn f(a: &Path, b: &Path) { let _ = (a.display(), b.display()); }\n"),
            2
        );
        assert_eq!(
            display_sites(
                "// a.display() in prose is not a call\nfn f(a: &Path) { let _ = a.display(); }\n"
            ),
            1
        );
    }

    /// Modules whose every production diagnostic already renders through this
    /// module. A new site here is never acceptable, so the ratchet treats a
    /// non-zero count as a regression rather than as a baseline to raise.
    /// `guest_home` is absent on purpose: its one remaining site is the
    /// `ALLOWED_DISPLAY` symlink target the converted-module test names, so its
    /// count is recorded in [`BASELINE`] instead.
    const CONVERTED: &[&str] = &[
        "session.rs",
        "protected_config_dir.rs",
        "network.rs",
        "egress_policy.rs",
        "host_paths.rs",
        "credential_yaml.rs",
    ];

    /// Every production `.display()` call per module, each with the ticket that
    /// owns the count. #419 converted `host_paths` and `credential_yaml` and
    /// deliberately left every other module alone, so #419 is the ticket that
    /// recorded each count below; no module below has a conversion ticket yet. A
    /// module absent from this table is at zero, so its first `.display()` fails
    /// the ratchet unless it is recorded here with the ticket that owns it.
    ///
    /// The counts are calls in the *whole* production part of a file, including
    /// what follows a mid-file test module (`mount.rs` and `secrets.rs` interleave
    /// production and tests). `mount.rs`'s 8 are 4 diagnostics (declaration
    /// spellings, `ClaimError`) and 4 fork-manifest identity spellings whose
    /// `display()` bytes are stored and never printed; they count because the
    /// ratchet measures the call, not a guess about its reader.
    const BASELINE: &[(&str, usize, &str)] = &[
        ("clipboard.rs", 1, "#419 recorded; conversion unowned"),
        (
            "credential_injection.rs",
            1,
            "#419 recorded; conversion unowned",
        ),
        (
            "embedded_runtime.rs",
            2,
            "#419 recorded; conversion unowned",
        ),
        (
            "guest_home.rs",
            1,
            "#419 recorded; the ALLOWED_DISPLAY symlink target, not a message",
        ),
        ("image_publish.rs", 2, "#419 recorded; conversion unowned"),
        ("intercept_hook.rs", 1, "#419 recorded; conversion unowned"),
        ("mount.rs", 8, "#419 recorded; conversion unowned"),
        ("msb_cmd.rs", 1, "#419 recorded; conversion unowned"),
        ("msb_install.rs", 17, "#419 recorded; conversion unowned"),
        ("msb_preflight.rs", 2, "#419 recorded; conversion unowned"),
        ("run.rs", 7, "#419 recorded; conversion unowned"),
        ("secret_store.rs", 5, "#419 recorded; conversion unowned"),
        ("secrets.rs", 14, "#419 recorded; conversion unowned"),
        (
            "test_fixtures.rs",
            4,
            "#419 recorded; test-only module (declared #[cfg(test)] in main.rs)",
        ),
    ];

    /// The class does not stay fixed one producer at a time (#410 missed `run`'s
    /// warning channel, #414 missed doctor's detail, #419 missed `host_paths` and
    /// `credential_yaml`), so the remaining exposure is a recorded number rather
    /// than prose. A module may not exceed its baseline, and a module #419
    /// converted may not return above zero; a first site in a module nobody
    /// converted also fails, because an unrecorded count is a silent widening.
    #[test]
    fn every_module_stays_within_its_display_baseline() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut checked = Vec::new();
        for path in rust_sources(&root) {
            let module = path
                .strip_prefix(&root)
                .expect("every source was walked from src")
                .to_string_lossy()
                .replace('\\', "/");
            let source = std::fs::read_to_string(&path).expect("reading a source module");
            let count = display_sites(&source);
            let baseline = BASELINE.iter().find(|(name, _, _)| *name == module);
            let allowed = baseline.map_or(0, |(_, count, _)| *count);
            if CONVERTED.contains(&module.as_str()) {
                assert_eq!(
                    count, 0,
                    "{module} was converted to one_line (#419) and must not print a path with \
                     display(), which escapes nothing; found {count} production site(s). Render \
                     the path with one_line, or record the site in BASELINE with the ticket that \
                     owns it."
                );
            } else if count > allowed {
                let ticket = baseline.map_or("not yet recorded", |(_, _, ticket)| *ticket);
                panic!(
                    "{module} has {count} production .display() site(s), baseline {allowed} \
                     ({ticket}). A new path-bearing message must render through one_line (or the \
                     count must be recorded in BASELINE with the ticket that owns it)."
                );
            }
            checked.push(module);
        }
        for (module, _, _) in BASELINE {
            assert!(
                checked.iter().any(|seen| seen == module),
                "BASELINE records {module}, which no longer exists; remove the stale entry"
            );
        }
    }
}
