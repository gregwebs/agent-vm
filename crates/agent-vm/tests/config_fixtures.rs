//! #749: no `[[tools]]` fixture the VM suite writes may bring back the retired
//! `allow_tools` key.
//!
//! Every declaration is a launch verb now, so a fixture needs no separate list —
//! and one that still wrote the key would be refused at load, failing its row
//! for an unrelated reason. The VM rows themselves cannot run without Docker and
//! an image, so this is their boot-free half: the real `script/test/e2e.sh` is
//! scanned, every here-document that declares a tool is parsed as TOML, and none
//! may declare a top-level `allow_tools`.
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

/// Every top-level key a document declares above its first table header, as
/// `(name, line)`. This is where TOML requires a root key, and where #749's
/// retired `allow_tools` must never appear again.
fn top_level_keys(body: &[String]) -> Vec<(String, String)> {
    let mut keys = Vec::new();
    for line in body {
        let line = line.trim();
        if line.starts_with('[') {
            break;
        }
        if let Some((name, _)) = line.split_once(" = ") {
            keys.push((name.trim().to_owned(), line.to_owned()));
        }
    }
    keys
}

/// Every `"…"` on one line, unescaped only for the plain names these fixtures use.
fn quoted(text: &str) -> Vec<String> {
    text.split('"')
        .enumerate()
        .filter(|(index, _)| index % 2 == 1)
        .map(|(_, name)| name.to_owned())
        .collect()
}

/// #749: every `[[tools]]` declaration in the VM suite is a launch verb, so no
/// fixture writes the retired `allow_tools` key — and this oracle is inverted
/// from the #735 one on purpose: a fixture that re-adds the key would now be
/// refused at load, and the rows using it would fail for the wrong reason.
#[test]
fn no_tools_fixture_in_the_vm_suite_writes_allow_tools() {
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
        for (name, line) in top_level_keys(&body) {
            assert_ne!(
                name, "allow_tools",
                "{at}: the retired key must not return: {line}"
            );
        }
        for name in &declared {
            assert!(
                !name.is_empty(),
                "{at}: every [[tools]] block declares a name"
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
    // The live egress fixture is the one config outside the here-documents.
    let egress =
        std::fs::read_to_string(repo_root().join("script/test/fixtures/egress-config.toml"))
            .expect("the live egress seed is readable");
    let table: toml::Table = egress.parse().expect("the seed is TOML");
    assert!(
        !table.contains_key("allow_tools"),
        "the live egress seed must not write the retired key"
    );
    assert!(
        table.contains_key("tools"),
        "and it still declares its tools"
    );
}
