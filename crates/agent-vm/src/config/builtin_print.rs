//! `agent-vm tools print`: the built-in tool declarations as user-config TOML (#510).
//!
//! Renders the **raw** declarations of the embedded `default-tools.toml`, never a
//! validated [`super::Tool`]: the input is a compile-time constant, so no caller can
//! point this at a user's file, whose `args`/`env` values every diagnostic keeps out
//! of its output. Raw values are also the shipped spellings, where a `Tool` holds
//! normalized, folded and sorted forms.
//!
//! A hand-written emitter rather than `toml`'s `display` feature: that feature adds
//! `toml_writer` to the build and picks its own layout, for the few lines below whose
//! one subtle part — the basic-string escape — is property-tested against the parser
//! already shipped. Output uses only TOML 1.0 syntax.
//!
//! The source file's comments are not reproduced: its header describes the embedded
//! file's role, which is wrong once pasted into a user file. A generated header names
//! the build and where the comments live instead.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow};

use super::{DEFAULT_TOOLS_TOML, RawTool, builtin_raw_config, quoted_str};

/// Every built-in tool (`names` empty), or exactly `names` in the given order, as
/// user-config TOML. Fails, before anything is rendered, on a name that is not built
/// in or is given twice.
pub(crate) fn builtin_tools_toml(names: &[String]) -> Result<String> {
    let raw = builtin_raw_config(DEFAULT_TOOLS_TOML)?;
    Ok(render(&select(&raw.tools, names)?))
}

/// Unknown names are all reported at once, and before a repeat: a typo is the more
/// likely mistake, and its message carries the whole built-in list, which is what a
/// user with a typo needs.
fn select<'a>(tools: &'a [RawTool], names: &[String]) -> Result<Vec<&'a RawTool>> {
    if names.is_empty() {
        return Ok(tools.iter().collect());
    }
    let mut selected = Vec::with_capacity(names.len());
    let mut unknown: Vec<&str> = Vec::new();
    for name in names {
        match tools.iter().find(|tool| tool.name == *name) {
            Some(tool) => selected.push(tool),
            None => {
                // One entry per distinct name, in request order: `nope nope` is one
                // spelling mistake to fix, not two.
                if !unknown.contains(&name.as_str()) {
                    unknown.push(name);
                }
            }
        }
    }
    if !unknown.is_empty() {
        // The built-in names are the compile-time constant's, so they print raw;
        // only argv is escaped.
        let builtin: Vec<&str> = tools.iter().map(|tool| tool.name.as_str()).collect();
        let unknown: Vec<String> = unknown.iter().map(|name| quoted_str(name)).collect();
        return Err(anyhow!(
            "agent-vm tools print: no built-in tool is named {}; built-in tools: {}",
            unknown.join(", "),
            builtin.join(", ")
        ));
    }
    if let Some(repeated) = names
        .iter()
        .enumerate()
        .find_map(|(index, name)| names[..index].contains(name).then_some(name))
    {
        return Err(anyhow!(
            "agent-vm tools print: {} is named more than once; a config file declares each tool once",
            quoted_str(repeated)
        ));
    }
    Ok(selected)
}

/// The two facts a reader of a pasted block needs and cannot see in the TOML: that
/// pasting replaced the shipped catalog, and that a `tools` list resolves only
/// within its own file. Both are also why the source's rationale comments are
/// pointed at rather than reproduced.
fn header() -> String {
    // The rationale line names no revision: a dirty build's line 1 does name its base
    // commit, but that SHA cannot identify the local modifications the definitions may
    // include, and an `unknown` build names no commit at all — so "at that revision"
    // would be false for both.
    format!(
        "# Built-in tool definitions of agent-vm {}, printed by `agent-vm tools print`.\n\
         # Declaring any [[tools]] in a config file replaces the whole built-in catalog.\n\
         # A tool's `tools` list may name only tools declared in the same file.\n\
         # Rationale comments: crates/agent-vm/src/default-tools.toml.\n",
        env!("AGENT_VM_BUILD_VERSION")
    )
}

fn render(tools: &[&RawTool]) -> String {
    let mut out = header();
    for tool in tools {
        out.push('\n');
        render_tool(&mut out, tool);
    }
    out
}

fn render_tool(out: &mut String, tool: &RawTool) {
    // No `..`: a new schema field must be a compile error here, not a silent gap in
    // the printed definitions.
    let RawTool {
        name,
        command,
        args,
        credentials,
        tools,
        persist,
        interactive_shell,
        env,
        network_requests,
        // Refused for the built-in tier, by presence, in `builtin_raw_config`.
        mounts: _,
    } = tool;
    out.push_str("[[tools]]\n");
    line(out, "name", &basic_string(name));
    line(out, "command", &basic_string(command));
    if !args.is_empty() {
        line(out, "args", &array(args));
    }
    if !credentials.is_empty() {
        line(out, "credentials", &array(credentials));
    }
    // Omitted and empty differ: an omitted `shell` list is the wildcard, so printing
    // `tools = []` there would silently drop its provisioning.
    if let Some(tools) = tools {
        line(out, "tools", &array(tools));
    }
    if !persist.is_empty() {
        line(out, "persist", &array(persist));
    }
    if *interactive_shell {
        line(out, "interactive_shell", "true");
    }
    if !env.is_empty() {
        line(out, "env", &inline_table(env));
    }
    if !network_requests.is_empty() {
        line(out, "network_requests", &array(network_requests));
    }
}

fn line(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(" = ");
    out.push_str(value);
    out.push('\n');
}

fn array(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|value| basic_string(value)).collect();
    format!("[{}]", items.join(", "))
}

fn inline_table(pairs: &BTreeMap<String, String>) -> String {
    let items: Vec<String> = pairs
        .iter()
        .map(|(key, value)| format!("{} = {}", toml_key(key), basic_string(value)))
        .collect();
    format!("{{ {} }}", items.join(", "))
}

/// A bare key when TOML allows one, else a quoted key with the same escape.
fn toml_key(key: &str) -> String {
    let bare = !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    if bare {
        key.to_owned()
    } else {
        basic_string(key)
    }
}

/// A TOML basic string. Every character TOML forbids literally (`"`, `\`, and the
/// control characters, DEL included) is escaped; only TOML 1.0 escapes are used.
fn basic_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            control if control.is_control() => {
                out.push_str(&format!("\\u{:04X}", u32::from(control)));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ConfigPaths, RawConfig, Tool, default_launch_catalog, default_tools, load,
    };
    use proptest::prelude::*;

    /// `text` loaded as the **user** config, the tier a paste lands in, with no
    /// project file and no `$HOME`/cwd dependence.
    fn load_as_user(text: &str) -> crate::config::ConfigReport {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("config.toml");
        std::fs::write(&user, text).unwrap();
        load(&ConfigPaths {
            user: Some(user),
            project: dir.path().join("absent.toml"),
            home: None,
        })
        .expect("the printed catalog loads as a user config")
    }

    fn names(tools: &[&Tool]) -> Vec<String> {
        tools.iter().map(|tool| tool.name().to_owned()).collect()
    }

    fn assert_same_definitions(pasted: &[&Tool], shipped: &[&Tool]) {
        assert_eq!(
            pasted.len(),
            shipped.len(),
            "the paste covers every shipped tool"
        );
        for (pasted, shipped) in pasted.iter().zip(shipped) {
            let differing: Vec<&str> = pasted
                .differing_fields(shipped)
                .iter()
                .map(|field| field.as_str())
                .collect();
            assert!(
                pasted.same_definition(shipped),
                "{} differs after the round trip: {differing:?}",
                shipped.name()
            );
        }
    }

    /// The whole contract: the no-argument output pasted as a user file *is* the
    /// shipped catalog, down to the per-entry provisioning a launch folds. The
    /// `shell` entry is the trap — its omitted `tools` must stay omitted, or its
    /// wildcard provisioning silently disappears.
    #[test]
    fn printed_catalog_round_trips_as_a_user_config() {
        let printed = builtin_tools_toml(&[]).unwrap();
        let shipped = default_tools().unwrap();
        let report = load_as_user(&printed);
        assert!(
            !report.uses_defaults(),
            "a paste must declare the catalog, not fall back to the shipped one"
        );
        assert!(report.conflicts().is_empty());

        {
            let pasted: Vec<&Tool> = report.resolved().launch_tools().collect();
            let shipped: Vec<&Tool> = shipped.iter().collect();
            assert_eq!(names(&pasted), names(&shipped));
            assert_same_definitions(&pasted, &shipped);
        }

        let pasted_launch = report
            .into_launch_catalog()
            .expect("the pasted catalog resolves");
        let shipped_launch = default_launch_catalog().unwrap();
        assert_eq!(
            pasted_launch.as_slice().len(),
            shipped_launch.as_slice().len()
        );
        for (pasted, shipped) in pasted_launch
            .as_slice()
            .iter()
            .zip(shipped_launch.as_slice())
        {
            assert_eq!(pasted.tool().name(), shipped.tool().name());
            assert_eq!(
                pasted.provisioned(),
                shipped.provisioned(),
                "{}",
                shipped.tool().name()
            );
            assert_eq!(
                pasted.requested_names(),
                shipped.requested_names(),
                "{}",
                shipped.tool().name()
            );
            assert_eq!(
                pasted.persist(),
                shipped.persist(),
                "{}",
                shipped.tool().name()
            );
        }
        assert!(!pasted_launch.has_shell_fallback());
        assert!(!shipped_launch.has_shell_fallback());
    }

    #[test]
    fn a_named_subset_round_trips_in_request_order() {
        let printed = builtin_tools_toml(&["shell".to_owned(), "codex".to_owned()]).unwrap();
        let shipped = default_tools().unwrap();
        let report = load_as_user(&printed);
        let pasted: Vec<&Tool> = report.resolved().launch_tools().collect();
        assert_eq!(names(&pasted), ["shell", "codex"]);
        let expected: Vec<&Tool> = ["shell", "codex"]
            .iter()
            .map(|name| {
                shipped
                    .iter()
                    .find(|tool| tool.name() == *name)
                    .unwrap_or_else(|| panic!("{name} is shipped"))
            })
            .collect();
        assert_same_definitions(&pasted, &expected);
        assert!(report.into_launch_catalog().is_ok());
    }

    /// A subset is a fragment for a file that may already hold the rest: printing
    /// `pi` alone loads (syntax and schema are fine) but cannot resolve, and the
    /// header says why. Expanding the reference unasked would change what the user
    /// asked for.
    #[test]
    fn a_printed_reference_must_be_declared_in_the_same_file() {
        let printed = builtin_tools_toml(&["pi".to_owned()]).unwrap();
        let report = load_as_user(&printed);
        let error = report
            .into_launch_catalog()
            .expect_err("a dangling reference is a catalog error");
        let text = format!("{error:#}");
        assert!(
            text.contains("\"claude\" names no tool in this configuration file"),
            "{text}"
        );
    }

    #[test]
    fn unknown_names_are_reported_together_with_the_builtin_names() {
        let error = builtin_tools_toml(&["codex".to_owned(), "nope".to_owned(), "zz".to_owned()])
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "agent-vm tools print: no built-in tool is named \"nope\", \"zz\"; built-in tools: dsh, pi, codex, opencode, claude, copilot, shell"
        );
        // Each distinct name once, in request order, even when the request repeats
        // one: `zz nope zz` names two problems, not three.
        let error =
            builtin_tools_toml(&["zz".to_owned(), "nope".to_owned(), "zz".to_owned()]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "agent-vm tools print: no built-in tool is named \"zz\", \"nope\"; built-in tools: dsh, pi, codex, opencode, claude, copilot, shell"
        );
    }

    #[test]
    fn a_repeated_name_is_refused() {
        let error = builtin_tools_toml(&["pi".to_owned(), "codex".to_owned(), "pi".to_owned()])
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "agent-vm tools print: \"pi\" is named more than once; a config file declares each tool once"
        );
        // A typo is the likelier mistake, so an unknown name wins the message —
        // and its built-in list is what that user needs. The repeated name appears
        // once: it is one thing to fix.
        let error = builtin_tools_toml(&["nope".to_owned(), "nope".to_owned()]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "agent-vm tools print: no built-in tool is named \"nope\"; built-in tools: dsh, pi, codex, opencode, claude, copilot, shell"
        );
    }

    /// argv reaches a diagnostic here, so it must not be able to inject terminal
    /// control sequences.
    #[test]
    fn an_unknown_name_is_escaped() {
        let error = builtin_tools_toml(&["\u{1b}[31mx".to_owned()]).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("\\x1b"), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");
    }

    // Keys deliberately out of order, and an env value holding every escape.
    const SYNTHETIC: &str = r#"[[tools]]
network_requests = ["b.example", "a.example"]
name = "full"
env = { Z = "1", "A.B" = "q\"\\\n\u0007\u007F" }
interactive_shell = true
persist = [".p"]
tools = []
credentials = ["openai"]
args = ["-x", ""]
command = "c"

[[tools]]
name = "bare"
command = "b"
interactive_shell = false
args = []
"#;

    /// Literal output bytes: the escapes are what `basic_string` emits, not TOML
    /// source.
    const EXPECTED: &str = r#"[[tools]]
name = "full"
command = "c"
args = ["-x", ""]
credentials = ["openai"]
tools = []
persist = [".p"]
interactive_shell = true
env = { "A.B" = "q\"\\\n\u0007\u007F", Z = "1" }
network_requests = ["b.example", "a.example"]

[[tools]]
name = "bare"
command = "b"
"#;

    /// The header spelled out, independent of [`header`]: both the golden test and
    /// the header test compare against this, so a deleted or reordered sentence
    /// cannot hide behind either of them agreeing with itself.
    fn expected_header() -> String {
        format!(
            "# Built-in tool definitions of agent-vm {}, printed by `agent-vm tools print`.\n\
             # Declaring any [[tools]] in a config file replaces the whole built-in catalog.\n\
             # A tool's `tools` list may name only tools declared in the same file.\n\
             # Rationale comments: crates/agent-vm/src/default-tools.toml.\n",
            env!("AGENT_VM_BUILD_VERSION")
        )
    }

    #[test]
    fn emits_the_canonical_layout() {
        let raw: RawConfig = toml::from_str(SYNTHETIC).expect("the synthetic catalog parses");
        let selected: Vec<&RawTool> = raw.tools.iter().collect();
        assert_eq!(
            render(&selected),
            format!("{}\n{EXPECTED}", expected_header())
        );
    }

    #[test]
    fn the_header_states_the_two_rules_a_reader_needs() {
        assert_eq!(header(), expected_header());
    }

    fn any_char() -> impl Strategy<Value = char> {
        prop_oneof![
            any::<char>(),
            proptest::char::range('\0', '\u{9f}'),
            Just('"'),
            Just('\\'),
        ]
    }

    fn any_text() -> impl Strategy<Value = String> {
        proptest::collection::vec(any_char(), 0..8)
            .prop_map(|chars| chars.into_iter().collect::<String>())
    }

    proptest! {
        /// The parser we already ship is the oracle for the escape table: a table
        /// missing DEL or a C1 control would fail here, not in a user's config.
        #[test]
        fn basic_string_round_trips_through_the_parser(value in any_text()) {
            let document = format!("v = {}\n", basic_string(&value));
            let parsed: toml::Table =
                toml::from_str(&document).expect(&document);
            prop_assert_eq!(parsed.get("v").and_then(|value| value.as_str()), Some(value.as_str()));
        }

        #[test]
        fn key_round_trips_through_the_parser(key in any_text()) {
            let document = format!("{} = 1\n", toml_key(&key));
            let parsed: toml::Table =
                toml::from_str(&document).expect(&document);
            prop_assert_eq!(parsed.len(), 1);
            prop_assert!(parsed.contains_key(&key), "{document}");
        }
    }
}
