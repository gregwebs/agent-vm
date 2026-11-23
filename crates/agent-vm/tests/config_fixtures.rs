//! #735 B2: every `[[tools]]` fixture the VM suite writes must be authorized.
//!
//! A `[[tools]]` block is inert without an `allow_tools` entry (ADR-0075), so a
//! fixture that forgot the entry would launch nothing, and its rows would fail
//! for an unrelated reason — or, for a row that asserts absence, pass while
//! proving nothing. The VM rows themselves cannot run without Docker and an
//! image, so this is their boot-free half: the real `script/test/e2e.sh` is
//! scanned, every here-document that declares a tool is parsed as TOML, and each
//! declared name must appear in that document's own top-level `allow_tools`.
//!
//! The CM-T user documents have their own oracle in
//! `crates/harness/src/config_mounts.rs`, next to the documents themselves.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `(first body line number, lines)` for every here-document in `text`. Quotes
/// and the `<<-` tab-stripping form are both accepted, and a here-string (`<<<`)
/// is skipped.
fn heredocs(text: &str) -> Vec<(usize, Vec<String>)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut documents = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if let Some(delimiter) = heredoc_delimiter(lines[index]) {
            let start = index + 2;
            index += 1;
            let mut body = Vec::new();
            while index < lines.len() && lines[index].trim() != delimiter {
                body.push(lines[index].to_owned());
                index += 1;
            }
            documents.push((start, body));
        }
        index += 1;
    }
    documents
}

/// The delimiter of the first here-document opened on this line, if any.
fn heredoc_delimiter(line: &str) -> Option<String> {
    let mut rest = line;
    loop {
        let at = rest.find("<<")?;
        let after = &rest[at + 2..];
        if let Some(shorter) = after.strip_prefix('<') {
            // `<<<` is a here-string, which reads a value rather than a body.
            rest = shorter;
            continue;
        }
        let after = after.strip_prefix('-').unwrap_or(after);
        let name: String = match after.chars().next() {
            Some(quote @ ('\'' | '"')) => after[1..].chars().take_while(|c| *c != quote).collect(),
            _ => after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect(),
        };
        if !name.is_empty() {
            return Some(name);
        }
        rest = after;
    }
}

/// The `name = "…"` of every `[[tools]]` block, in declaration order.
fn declared_tools(body: &[String]) -> Vec<String> {
    body.iter()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("name = ")
                .and_then(|value| quoted(value).first().cloned())
        })
        .collect()
}

/// The `allow_tools` list a document declares, read only from the lines above the
/// first table header — the position TOML requires for a top-level key.
fn allowed_tools(body: &[String]) -> Option<Vec<String>> {
    for line in body {
        let line = line.trim();
        if line.starts_with('[') {
            return None;
        }
        if let Some(list) = line.strip_prefix("allow_tools = ") {
            return Some(quoted(list));
        }
    }
    None
}

/// Every `"…"` on one line, unescaped only for the plain names these fixtures use.
fn quoted(text: &str) -> Vec<String> {
    text.split('"')
        .enumerate()
        .filter(|(index, _)| index % 2 == 1)
        .map(|(_, name)| name.to_owned())
        .collect()
}

#[test]
fn every_tools_fixture_in_the_vm_suite_is_authorized() {
    let path = repo_root().join("script/test/e2e.sh");
    let text = std::fs::read_to_string(&path).expect("script/test/e2e.sh is readable");
    let mut fixtures = 0;
    let mut blocks = 0;
    for (start, body) in heredocs(&text) {
        let declared = declared_tools(&body);
        if declared.is_empty() {
            continue;
        }
        fixtures += 1;
        blocks += declared.len();
        let at = format!("script/test/e2e.sh:{start}");
        let allowed = allowed_tools(&body).unwrap_or_else(|| {
            panic!(
                "{at}: this document declares {declared:?} but writes no `allow_tools` above its \
                 first table header, so every block is inert"
            )
        });
        for name in &declared {
            assert!(
                allowed.contains(name),
                "{at}: {name:?} is declared but not authorized, so the block is inert \
                 (declared {declared:?}, allowed {allowed:?})"
            );
        }
    }
    // Coverage: a fixture written outside a here-document would escape the loop
    // above, so every `[[tools]]` line in the file must be one the scan counted.
    let written = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| line.contains("[[tools]]"))
        .count();
    assert_eq!(
        blocks, written,
        "a `[[tools]]` line in script/test/e2e.sh is not inside a checked here-document"
    );
    assert!(
        fixtures >= 13,
        "the scan found only {fixtures} tool fixtures; the here-document parser has drifted"
    );
}
