//! Image-source integrity gates.
//!
//! These read the **committed** image sources under `images/tools/` (and the CI
//! workflows and `images/build.sh`) directly from disk. They are the surviving
//! half of the old `tool_layer` embed tests: the launcher no longer embeds or
//! composes these sources (issue #259), but the sources are still built and
//! published by CI, so a drift in a pin, a lock hash, a version label or an
//! install flag must still fail `cargo test` rather than ship.
//!
//! Deliberately file-reading only: no `include_dir!`, no runtime catalog, no
//! materialisation. CI's existing `cargo test -p agent-vm` job runs this target.
//! The two gates that compare committed copies against committed copies
//! (`sync-recipe-contracts.sh --check` and the `*-installer.sh` patch
//! equivalence) live in `script/`, not here; see §5.7 of the #259 plan.

use std::path::{Path, PathBuf};

use serde_json::Value;

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn read_text(relative: &str) -> String {
    let path = repo_path(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn read_json(relative: &str) -> Value {
    let text = read_text(relative);
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{relative} is valid JSON: {error}"))
}

// ---------------------------------------------------------------------------
// Image build order and CI edges (source-only; the runtime catalog is not an
// input to image production — the launcher no longer chooses image sources)
// ---------------------------------------------------------------------------

/// The CI build order transcribed in `images/build.sh` and `build-image.yml`
/// must agree, and must chain each recipe `FROM` its predecessor's digest.
/// Nothing imports a Rust const into a workflow or shell script, so this gate
/// is the only thing tying them together.
#[test]
fn image_build_order_and_ci_edges_agree() {
    // Declared order, source-only (the launcher no longer chooses image sources).
    let expected: Vec<String> = ["dsh", "pi", "codex", "opencode", "claude", "copilot"]
        .iter()
        .map(|tool| (*tool).to_string())
        .collect();

    let workflow = read_text(".github/workflows/build-image.yml");
    let ci_order: Vec<String> = workflow
        .lines()
        .filter_map(|line| line.trim().strip_prefix("context: images/tools/"))
        .map(|tool| tool.trim().to_string())
        .collect();
    assert_eq!(
        ci_order, expected,
        "build-image.yml must chain the tool layers in the declared order"
    );

    let script = read_text("images/build.sh");
    let mut script_order: Vec<String> = Vec::new();
    for line in script.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("INTERMEDIATE_LAYERS=(") {
            script_order.extend(
                rest.trim_end_matches(')')
                    .split_whitespace()
                    .map(str::to_string),
            );
        } else if let Some(rest) = line.strip_prefix("FINAL_LAYER=") {
            script_order.push(rest.trim().to_string());
        }
    }
    assert_eq!(
        script_order, expected,
        "images/build.sh must chain the tool layers in the declared order"
    );

    // Order is not enough: a step left building FROM `steps.base` keeps every
    // `context:` line in order yet publishes a template missing a layer.
    let mut current: Option<&str> = None;
    let mut edges: Vec<(String, String)> = Vec::new();
    for line in workflow.lines() {
        let line = line.trim();
        if let Some(tool) = line.strip_prefix("context: images/tools/") {
            current = Some(tool.trim());
            continue;
        }
        if let Some(rest) = line.strip_prefix("BASE_IMAGE=${{ env.BASE }}@${{ steps.")
            && let Some(step) = rest.strip_suffix(".outputs.digest }}")
        {
            let tool = current.expect("every BASE_IMAGE edge follows a context line");
            edges.push((tool.to_string(), step.to_string()));
        }
    }
    let expected_edges: Vec<(String, String)> = expected
        .iter()
        .enumerate()
        .map(|(index, tool)| {
            let predecessor = if index == 0 {
                "base".to_string()
            } else {
                expected[index - 1].clone()
            };
            (tool.clone(), predecessor)
        })
        .collect();
    assert_eq!(
        edges, expected_edges,
        "build-image.yml must chain each tool layer FROM its predecessor's step digest, \
         starting from `steps.base`"
    );
}

// ---------------------------------------------------------------------------
// Pinned Pi layer: one home for the pin, and npm's one hole
// ---------------------------------------------------------------------------

fn pi_pin() -> String {
    read_json("images/tools/pi/package.json")["dependencies"]["@earendil-works/pi-coding-agent"]
        .as_str()
        .expect("the manifest pins pi")
        .to_string()
}

fn bridge_pin() -> String {
    read_json("images/tools/pi/bridge/package.json")["dependencies"]["pi-claude-bridge"]
        .as_str()
        .expect("the bridge manifest pins pi-claude-bridge")
        .to_string()
}

fn dsh_pin() -> String {
    read_json("images/tools/dsh/package.json")["dependencies"]["@deepseek-ai/dsh"]
        .as_str()
        .expect("the dsh manifest pins @deepseek-ai/dsh")
        .to_string()
}

/// The manifest/lock pair a lockfile gate reads. Named fields rather than two
/// adjacent `&Value` parameters, so a manifest/lock swap cannot compile
/// (`CODING_STANDARDS.md` → *Types*).
struct PackageFiles<'a> {
    manifest: &'a Value,
    lock: &'a Value,
}

/// One pinned package: the manifest that declares it, the dependency key and
/// the lock's resolved package key. Named fields rather than three adjacent
/// `&str` selectors (`CODING_STANDARDS.md` → *Types*).
struct PinSpec<'a> {
    manifest_relative: &'a str,
    dependency: &'a str,
    package_key: &'a str,
}

/// The dsh lock installs the pnpm the manifest pins; `dsh plugin` needs pnpm and
/// the Dockerfile links it out of this same lock.
fn check_pnpm_installed(files: PackageFiles) -> Result<(), String> {
    let pnpm = files.manifest["dependencies"]["pnpm"]
        .as_str()
        .ok_or_else(|| "the dsh manifest does not pin pnpm".to_string())?;
    if files.lock["packages"]["node_modules/pnpm"]["version"].as_str() != Some(pnpm) {
        return Err(format!(
            "the lock does not install the pinned pnpm ({pnpm})"
        ));
    }
    Ok(())
}

/// Every non-root entry in a committed lock carries `integrity`. A freshly
/// generated pi lock does NOT: npm inherits Pi's published `npm-shrinkwrap.json`
/// which omits the hashes for its five `@earendil-works` siblings, so those are
/// refilled by hand. This is what catches a regenerated lock that dropped them.
fn check_lock_integrity(lock: &Value) -> Result<(), String> {
    let packages = lock["packages"]
        .as_object()
        .ok_or_else(|| "the lock carries no `packages` object".to_string())?;
    let missing: Vec<&str> = packages
        .iter()
        .filter(|(key, value)| !key.is_empty() && value.get("integrity").is_none())
        .map(|(key, _)| key.as_str())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "these committed lock entries carry no `integrity` hash: {missing:?}"
        ))
    }
}

/// The lock's root dependency and the resolved package version both equal the
/// manifest pin.
fn check_pin_agrees(lock: &Value, spec: PinSpec) -> Result<(), String> {
    let manifest = read_json(spec.manifest_relative);
    let pinned = manifest["dependencies"][spec.dependency]
        .as_str()
        .ok_or_else(|| {
            format!(
                "{} does not pin {}",
                spec.manifest_relative, spec.dependency
            )
        })?;
    let root = lock["packages"][""]["dependencies"][spec.dependency]
        .as_str()
        .ok_or_else(|| format!("the lock's root does not record {}", spec.dependency))?;
    if root != pinned {
        return Err(format!(
            "the lock's root {} is {root}, the manifest pins {pinned}",
            spec.dependency
        ));
    }
    let locked = lock["packages"][spec.package_key]["version"]
        .as_str()
        .ok_or_else(|| format!("{} is not locked", spec.package_key))?;
    if locked != pinned {
        return Err(format!(
            "npm ci would install {locked}, but the manifest pins {pinned}"
        ));
    }
    Ok(())
}

/// `install-pi.sh` verifies exactly the five `@earendil-works` siblings nested
/// directly under pi-coding-agent's own `node_modules`, at the pi pin. The
/// selector is deliberately direct-children-only: pi-ai carries deeper nested
/// deps that DO carry npm-checked integrity, so a looser match over-matches.
fn check_pi_siblings(lock: &Value) -> Result<(), String> {
    const SIBLINGS: [&str; 5] = ["chord", "pi-agent-core", "pi-ai", "pi-telemetry", "pi-tui"];
    const PREFIX: &str =
        "node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/";
    let pinned = pi_pin();
    let packages = lock["packages"]
        .as_object()
        .ok_or_else(|| "the lock carries no `packages` object".to_string())?;
    let mut matched: Vec<(String, String)> = Vec::new();
    for (key, value) in packages {
        let Some(name) = key.strip_prefix(PREFIX) else {
            continue;
        };
        if name.contains('/') {
            continue;
        }
        matched.push((
            name.to_string(),
            value["version"].as_str().unwrap_or("<none>").to_string(),
        ));
    }
    matched.sort();
    let mut expected: Vec<(String, String)> = SIBLINGS
        .iter()
        .map(|name| (name.to_string(), pinned.clone()))
        .collect();
    expected.sort();
    if matched == expected {
        Ok(())
    } else {
        Err(format!(
            "the nested sibling set drifted: matched {matched:?}, expected {expected:?}"
        ))
    }
}

#[test]
fn the_pinned_pi_version_agrees_across_the_manifest_and_the_lockfile() {
    let lock = read_json("images/tools/pi/package-lock.json");
    check_pin_agrees(
        &lock,
        PinSpec {
            manifest_relative: "images/tools/pi/package.json",
            dependency: "@earendil-works/pi-coding-agent",
            package_key: "node_modules/@earendil-works/pi-coding-agent",
        },
    )
    .expect("the pi pin agrees with its lock");
}

#[test]
fn every_locked_package_carries_integrity() {
    let lock = read_json("images/tools/pi/package-lock.json");
    assert!(
        lock["packages"].as_object().is_some_and(
            |packages| packages.contains_key("node_modules/@earendil-works/pi-coding-agent")
        ),
        "the pi lock must actually carry pi"
    );
    check_lock_integrity(&lock).unwrap_or_else(|problem| {
        panic!(
            "{problem}\nA freshly generated lock omits integrity for pi's five @earendil-works \
             siblings. Refill them from the registry (see images/tools/README.md)."
        )
    });
}

#[test]
fn the_build_verified_sibling_set_is_exactly_the_five_nested_earendil_packages() {
    let lock = read_json("images/tools/pi/package-lock.json");
    check_pi_siblings(&lock).expect("the build-verified sibling set is exactly the five packages");
}

// ---------------------------------------------------------------------------
// Pinned bridge packages: full integrity and no second Pi
// ---------------------------------------------------------------------------

/// The bridge pin is an exact version (not a range): the tree has no shrinkwrap,
/// so a regenerated lock could otherwise move the installed version without this
/// repo moving the pin.
fn check_bridge_pin_locked(lock: &Value) -> Result<(), String> {
    let pinned = bridge_pin();
    let range_characters = ['^', '~', '>', '<', '=', '*', '|', ' ', 'x', 'X'];
    if pinned.split('.').count() < 3 || pinned.chars().any(|c| range_characters.contains(&c)) {
        return Err(format!(
            "the pi-claude-bridge pin must be an exact version, not a range: {pinned:?}"
        ));
    }
    let root = lock["packages"][""]["dependencies"]["pi-claude-bridge"]
        .as_str()
        .ok_or_else(|| "the lock's root does not record pi-claude-bridge".to_string())?;
    if root != pinned {
        return Err(format!(
            "the lock's root dependency {root} != the manifest pin {pinned}"
        ));
    }
    let locked = lock["packages"]["node_modules/pi-claude-bridge"]["version"]
        .as_str()
        .ok_or_else(|| "pi-claude-bridge is not locked".to_string())?;
    if locked != pinned {
        return Err(format!(
            "npm ci would install {locked}, but the manifest pins {pinned}"
        ));
    }
    Ok(())
}

/// No bridge-lock entry names a package Pi's extension loader aliases to its own
/// copies. The bridge was locked with `--legacy-peer-deps` precisely to avoid
/// dragging in a second, version-skewed `@earendil-works/pi-coding-agent`.
fn check_no_loader_aliased_pi_package(lock: &Value) -> Result<(), String> {
    const ALIASED: [&str; 5] = [
        "@earendil-works",
        "typebox",
        "pi-agent-core",
        "pi-tui",
        "pi-ai",
    ];
    let packages = lock["packages"]
        .as_object()
        .ok_or_else(|| "the lock carries no `packages` object".to_string())?;
    let offending: Vec<&str> = packages
        .keys()
        .map(String::as_str)
        .filter(|key| ALIASED.iter().any(|aliased| key.contains(aliased)))
        .collect();
    if offending.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the bridge lock installs a package Pi's loader aliases: {offending:?}"
        ))
    }
}

/// `--omit=optional` and `--legacy-peer-deps` are mandatory on the layer's
/// active `npm ci`: the lock carries the Claude Agent SDK's eight optional
/// native binaries, so dropping `--omit=optional` silently adds ~197 MiB, and
/// dropping `--legacy-peer-deps` lets npm drag in a second, version-skewed Pi.
///
/// Only **active** command text counts: a commented-out `npm ci` must neither
/// satisfy the requirement nor mask a later active invocation missing a flag.
/// A missing active invocation fails rather than letting an empty scan pass, and
/// **every** active `npm ci` invocation - bare or flagged - must carry all three
/// flags. Trailing shell comments are stripped first, so a mandatory flag that
/// exists only after a `#` is never accepted as present.
fn check_bridge_install_flags(script: &str) -> Result<(), String> {
    const MANDATORY: [&str; 3] = ["--ignore-scripts", "--omit=optional", "--legacy-peer-deps"];
    let installers: Vec<&str> = script
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .map(strip_shell_comment)
        .filter(|command| is_npm_ci(command))
        .collect();
    if installers.is_empty() {
        return Err("no active `npm ci` invocation in install-pi-packages.sh".to_string());
    }
    for line in &installers {
        for flag in MANDATORY {
            if !line.contains(flag) {
                return Err(format!("an active npm ci line dropped {flag}: {line}"));
            }
        }
    }
    Ok(())
}

/// The part of a shell line before an unquoted `#` comment, with the comment and
/// its `#` removed. A `#` opens a comment only at the start of a word (line start
/// or after whitespace), matching `/bin/sh`, so a `#` inside a word is literal.
/// This keeps a flag that lives only in a trailing comment out of the flag check.
fn strip_shell_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut word_start = true;
    for (index, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double && word_start => return &line[..index],
            _ => {}
        }
        word_start = ch.is_whitespace();
    }
    line
}

/// Whether the command text invokes `npm ci` (bare or with flags), as two
/// adjacent **unquoted** whitespace-separated tokens. A bare `npm ci` counts, so
/// a second unflagged install cannot hide behind an earlier valid one, while
/// `npm ci` inside a quoted string (an error message) is not an invocation.
fn is_npm_ci(command: &str) -> bool {
    let mut words: Vec<(String, bool)> = Vec::new();
    let mut current = String::new();
    let mut current_quoted = false;
    let mut in_single = false;
    let mut in_double = false;
    for ch in command.chars() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
                current_quoted = true;
            }
            '"' if !in_single => {
                in_double = !in_double;
                current_quoted = true;
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    words.push((std::mem::take(&mut current), current_quoted));
                    current_quoted = false;
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        words.push((current, current_quoted));
    }
    words
        .windows(2)
        .any(|pair| !pair[0].1 && !pair[1].1 && pair[0].0 == "npm" && pair[1].0 == "ci")
}

#[test]
fn every_bridge_locked_package_carries_integrity() {
    let lock = read_json("images/tools/pi/bridge/package-lock.json");
    assert!(
        lock["packages"]
            .as_object()
            .is_some_and(|packages| packages.contains_key("node_modules/pi-claude-bridge")),
        "the bridge lock must actually carry pi-claude-bridge"
    );
    check_lock_integrity(&lock).expect("every bridge lock entry carries integrity");
}

#[test]
fn the_bridge_pin_is_exact_and_the_lock_agrees() {
    let lock = read_json("images/tools/pi/bridge/package-lock.json");
    check_bridge_pin_locked(&lock).expect("the bridge pin is exact and the lock agrees");
}

#[test]
fn the_bridge_lock_installs_no_loader_aliased_pi_package() {
    let lock = read_json("images/tools/pi/bridge/package-lock.json");
    check_no_loader_aliased_pi_package(&lock)
        .expect("no loader-aliased package in the bridge lock");
}

#[test]
fn the_bridge_install_passes_npm_ci_the_mandatory_flags() {
    let script = read_text("images/tools/pi/install-pi-packages.sh");
    check_bridge_install_flags(&script).expect("install-pi-packages.sh passes the mandatory flags");
}

// ---------------------------------------------------------------------------
// Pinned dsh layer: full integrity, and pnpm installed
// ---------------------------------------------------------------------------

#[test]
fn the_pinned_dsh_version_agrees_across_the_manifest_and_the_lockfile() {
    let lock = read_json("images/tools/dsh/package-lock.json");
    check_pin_agrees(
        &lock,
        PinSpec {
            manifest_relative: "images/tools/dsh/package.json",
            dependency: "@deepseek-ai/dsh",
            package_key: "node_modules/@deepseek-ai/dsh",
        },
    )
    .expect("the dsh pin agrees with its lock");
    let manifest = read_json("images/tools/dsh/package.json");
    check_pnpm_installed(PackageFiles {
        manifest: &manifest,
        lock: &lock,
    })
    .expect("the lock installs the pinned pnpm");
}

#[test]
fn every_dsh_locked_package_carries_integrity() {
    let lock = read_json("images/tools/dsh/package-lock.json");
    assert!(
        lock["packages"]
            .as_object()
            .is_some_and(|packages| packages.contains_key("node_modules/@deepseek-ai/dsh")),
        "the dsh lock must actually carry dsh"
    );
    check_lock_integrity(&lock).expect("every dsh lock entry carries integrity");
}

// ---------------------------------------------------------------------------
// Exact shipped version slots: ARGs, labels, recipe sources
// ---------------------------------------------------------------------------

const RECIPES: [&str; 6] = ["dsh", "pi", "codex", "opencode", "claude", "copilot"];

/// All eight version labels: the label suffix, the recipe Dockerfile that owns
/// it, and the single-line `ARG` that selects the slot.
const VERSION_SLOTS: [(&str, &str, &str); 8] = [
    ("codex", "codex", "AGENT_VERSION_CODEX"),
    ("opencode", "opencode", "AGENT_VERSION_OPENCODE"),
    ("claude", "claude", "AGENT_VERSION_CLAUDE"),
    ("copilot", "copilot", "AGENT_VERSION_COPILOT"),
    ("dsh", "dsh", "AGENT_VERSION_DSH"),
    ("pnpm", "dsh", "AGENT_VERSION_PNPM"),
    ("pi", "pi", "AGENT_VERSION_PI"),
    ("pi-claude-bridge", "pi", "AGENT_VERSION_PI_CLAUDE_BRIDGE"),
];

fn dockerfile(recipe: &str) -> String {
    read_text(&format!("images/tools/{recipe}/Dockerfile"))
}

/// The one `ARG NAME=<value>` line's value (panics unless exactly one).
fn dockerfile_arg(text: &str, name: &str) -> String {
    let prefix = format!("ARG {name}=");
    let matches: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&prefix))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one `ARG {name}=` line, found {}: {matches:?}",
        matches.len()
    );
    matches[0][prefix.len()..].to_string()
}

/// The active `LABEL` key=value pairs of a Dockerfile, parsed the way a build
/// would see them. Comment lines are dropped before instruction joining, and a
/// trailing `\` joins the next line, so a commented-out or continued label is
/// resolved exactly as the built image resolves it.
fn active_label_values(text: &str) -> Vec<(String, String)> {
    let stripped: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect();
    let mut logical: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut continuing = false;
    for line in stripped {
        let line = line.trim();
        if continuing {
            current.push(' ');
        } else {
            current.clear();
        }
        current.push_str(line);
        if current.ends_with('\\') {
            current.pop();
            continuing = true;
        } else {
            logical.push(std::mem::take(&mut current));
            continuing = false;
        }
    }
    if !current.is_empty() {
        logical.push(current);
    }
    let mut pairs = Vec::new();
    for instruction in logical {
        let (verb, rest) = match instruction.split_once(char::is_whitespace) {
            Some(parts) => parts,
            None => continue,
        };
        if !verb.eq_ignore_ascii_case("LABEL") {
            continue;
        }
        pairs.extend(label_pairs(rest));
    }
    pairs
}

/// Split a `LABEL` body into `key=value` pairs; a quoted value keeps its bytes.
fn label_pairs(body: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut chars = body.chars().peekable();
    while chars.peek().is_some() {
        while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
            chars.next();
        }
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c.is_whitespace() {
                break;
            }
            key.push(c);
            chars.next();
        }
        if key.is_empty() {
            break;
        }
        if chars.peek() != Some(&'=') {
            continue;
        }
        chars.next();
        let mut value = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            while let Some(c) = chars.next() {
                if c == '"' {
                    break;
                }
                if c == '\\' {
                    if let Some(escaped) = chars.next() {
                        value.push(escaped);
                    }
                } else {
                    value.push(c);
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                value.push(c);
                chars.next();
            }
        }
        pairs.push((key, value));
    }
    pairs
}

/// The value of the single ACTIVE `LABEL KEY="..."`, or `None` when absent. A
/// duplicate active label is a failure (there is no defensible selection).
fn find_label_value(text: &str, key: &str) -> Option<String> {
    let values: Vec<String> = active_label_values(text)
        .into_iter()
        .filter(|(candidate, _)| candidate == key)
        .map(|(_, value)| value)
        .collect();
    match values.len() {
        0 => None,
        1 => Some(values.into_iter().next().expect("one value")),
        n => panic!("the {key} label must appear exactly once, found {n}"),
    }
}

fn label_value(text: &str, key: &str) -> String {
    find_label_value(text, key).unwrap_or_else(|| panic!("the {key} label is present"))
}

/// The active `org.agent-vm.version.*` keys of a Dockerfile.
fn active_version_labels(text: &str) -> Vec<String> {
    active_label_values(text)
        .into_iter()
        .map(|(key, _)| key)
        .filter(|key| key.starts_with("org.agent-vm.version."))
        .collect()
}

/// Canonical semver 2.0.0 parsing of the exact slot the owning hook accepts:
/// each core identifier is numeric with no leading zero; a pre-release
/// identifier is numeric (no leading zero) or alphanumeric; a build identifier
/// is digits (leading zeros allowed) or alphanumeric.
fn is_exact_semver(body: &str) -> bool {
    fn numeric(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
    }
    fn digits(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
    }
    fn alphanumeric(s: &str) -> bool {
        !s.is_empty()
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && s.chars().any(|c| !c.is_ascii_digit())
    }
    let (core_and_pre, build) = match body.split_once('+') {
        Some((head, build)) => (head, Some(build)),
        None => (body, None),
    };
    let (core, pre) = match core_and_pre.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (core_and_pre, None),
    };
    let core_ids: Vec<&str> = core.split('.').collect();
    if core_ids.len() != 3 || !core_ids.iter().all(|id| numeric(id)) {
        return false;
    }
    if pre.is_some_and(|p| p.is_empty() || !p.split('.').all(|id| numeric(id) || alphanumeric(id)))
    {
        return false;
    }
    if build.is_some_and(|b| b.is_empty() || !b.split('.').all(|id| digits(id) || alphanumeric(id)))
    {
        return false;
    }
    true
}

fn assert_exact_slot(value: &str, prefix: &str) {
    assert!(!value.is_empty(), "a selected slot must not be empty");
    let body = value
        .strip_prefix(prefix)
        .unwrap_or_else(|| panic!("the slot must start with {prefix:?}: {value:?}"));
    assert!(
        is_exact_semver(body),
        "the slot must be an exact semver version: {value:?}"
    );
    for forbidden in ['^', '~', '>', '<', '=', '*', '|', ' ', 'x', 'X', '@', '/'] {
        assert!(
            !value.contains(forbidden),
            "the slot must be exact, not a range/tag/URL: {value:?}"
        );
    }
}

#[test]
fn single_slot_recipes_pin_an_exact_default_and_reference_it_in_the_label() {
    for (label, recipe, arg) in &VERSION_SLOTS[..4] {
        let text = dockerfile(recipe);
        let value = dockerfile_arg(&text, arg);
        match *label {
            "codex" => assert_exact_slot(&value, "rust-v"),
            "opencode" => assert_exact_slot(&value, "v"),
            _ => assert_exact_slot(&value, ""),
        }
        assert_eq!(
            label_value(&text, &format!("org.agent-vm.version.{label}")),
            format!("${{{arg}}}"),
            "{recipe}: the version label must reference {arg}"
        );
    }
}

#[test]
fn multi_slot_args_are_empty_and_label_fallbacks_mirror_the_manifests() {
    let dsh = dockerfile("dsh");
    assert_eq!(dockerfile_arg(&dsh, "AGENT_VERSION_DSH"), "");
    assert_eq!(dockerfile_arg(&dsh, "AGENT_VERSION_PNPM"), "");
    let pnpm_pin = read_json("images/tools/dsh/package.json")["dependencies"]["pnpm"]
        .as_str()
        .expect("the dsh manifest pins pnpm")
        .to_string();
    assert_eq!(
        label_value(&dsh, "org.agent-vm.version.dsh"),
        format!("${{AGENT_VERSION_DSH:-{}}}", dsh_pin()),
        "the dsh label fallback must mirror images/tools/dsh/package.json"
    );
    assert_eq!(
        label_value(&dsh, "org.agent-vm.version.pnpm"),
        format!("${{AGENT_VERSION_PNPM:-{pnpm_pin}}}"),
        "the pnpm label fallback must mirror images/tools/dsh/package.json"
    );

    let pi = dockerfile("pi");
    assert_eq!(dockerfile_arg(&pi, "AGENT_VERSION_PI"), "");
    assert_eq!(dockerfile_arg(&pi, "AGENT_VERSION_PI_CLAUDE_BRIDGE"), "");
    assert_eq!(
        label_value(&pi, "org.agent-vm.version.pi"),
        format!("${{AGENT_VERSION_PI:-{}}}", pi_pin()),
        "the pi label fallback must mirror images/tools/pi/package.json"
    );
    assert_eq!(
        label_value(&pi, "org.agent-vm.version.pi-claude-bridge"),
        format!("${{AGENT_VERSION_PI_CLAUDE_BRIDGE:-{}}}", bridge_pin()),
        "the bridge label fallback must mirror images/tools/pi/bridge/package.json"
    );
}

#[test]
fn every_shipped_version_label_is_present_exactly_once() {
    let mut seen: Vec<String> = Vec::new();
    for recipe in RECIPES {
        seen.extend(active_version_labels(&dockerfile(recipe)));
    }
    let mut expected: Vec<String> = VERSION_SLOTS
        .iter()
        .map(|(label, _, _)| format!("org.agent-vm.version.{label}"))
        .collect();
    seen.sort();
    expected.sort();
    assert_eq!(
        seen, expected,
        "the shipped version labels drifted from the eight-slot contract"
    );
}

#[test]
fn commented_out_version_labels_fail_the_guards() {
    assert_eq!(
        active_label_values("FROM scratch\nLABEL a=1 b=\"2\"\n"),
        vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string())
        ],
        "active LABEL pairs must parse"
    );
    assert_eq!(
        label_value(
            "FROM scratch\nLABEL org.agent-vm.version.copilot=\"${AGENT_VERSION_COPILOT}\"\n",
            "org.agent-vm.version.copilot"
        ),
        "${AGENT_VERSION_COPILOT}",
        "the active copilot label value must parse"
    );

    let commented =
        "FROM scratch\n# LABEL org.agent-vm.version.copilot=\"${AGENT_VERSION_COPILOT}\"\n";
    assert!(
        active_label_values(commented).is_empty(),
        "a commented LABEL must not be read: {commented:?}"
    );
    assert_eq!(
        find_label_value(commented, "org.agent-vm.version.copilot"),
        None,
        "a commented LABEL must fail the guard"
    );

    let copilot = dockerfile("copilot");
    let mutated = copilot.replace(
        "LABEL org.agent-vm.version.copilot=",
        "# LABEL org.agent-vm.version.copilot=",
    );
    assert_ne!(mutated, copilot, "the mutation must change the text");
    assert!(
        !active_version_labels(&mutated).contains(&"org.agent-vm.version.copilot".to_string()),
        "the shipped-label set must notice the commented label"
    );
}

#[test]
fn continuations_join_and_the_exact_slot_grammar_rejects_bad_defaults() {
    let continued = "FROM scratch\nLABEL org.agent-vm.version.pi=\"x\" \\\n      org.agent-vm.version.pi-claude-bridge=\"y\"\n";
    assert_eq!(
        active_label_values(continued),
        vec![
            ("org.agent-vm.version.pi".to_string(), "x".to_string()),
            (
                "org.agent-vm.version.pi-claude-bridge".to_string(),
                "y".to_string()
            )
        ],
        "a continued LABEL must be joined"
    );

    for good in ["1.2.3", "0.159.3-alpha.1.2", "1.2.3-rc.1+build.01"] {
        assert!(is_exact_semver(good), "{good:?} is exact semver");
    }
    for bad in ["a.b.c", "01.2.3", "1.2.3-01", "1.2.3-a.", "1.2", "latest"] {
        assert!(!is_exact_semver(bad), "{bad:?} is NOT exact semver");
    }
}

// ---------------------------------------------------------------------------
// Recipe-source walkers: no base install helper, no upstream latest
// ---------------------------------------------------------------------------

/// Collect every committed file under `images/tools` as `(relative path, bytes)`.
fn image_source_files() -> Vec<(PathBuf, Vec<u8>)> {
    let root = repo_path("images/tools");
    let mut stack = vec![root.clone()];
    let mut out = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if entry.file_type().expect("file type").is_dir() {
                stack.push(path);
            } else {
                let relative = path.strip_prefix(&root).expect("under root").to_path_buf();
                let contents = std::fs::read(&path)
                    .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
                out.push((relative, contents));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// A recipe Dockerfile/hook/contract/JSON source (not docs, not the
/// `install.upstream.sh` provenance snapshots).
fn is_recipe_source(path: &Path) -> bool {
    if is_provenance_snapshot(path) {
        return false;
    }
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("Dockerfile")
    ) || matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("sh" | "js" | "py")
    )
}

fn is_provenance_snapshot(path: &Path) -> bool {
    path.to_string_lossy().ends_with("install.upstream.sh")
}

#[test]
fn no_shipped_recipe_calls_the_base_agent_vm_install_helper() {
    let mut offenders = Vec::new();
    for (path, contents) in image_source_files() {
        if !is_recipe_source(&path) {
            continue;
        }
        if String::from_utf8_lossy(&contents).contains("agent-vm-install") {
            offenders.push(path);
        }
    }
    assert!(
        offenders.is_empty(),
        "these shipped recipes still call the base agent-vm-install helper: {offenders:?}"
    );
}

/// A recipe `ENV PATH=<new>:${PATH}` line must keep the base's entries. ADR-0035
/// retires the runtime layer contract, but `images/tools/README.md` still
/// requires maintainers to prepend additively so a recipe can never drop a
/// directory the base put there; this source-only guard keeps that rule honest
/// now that the embed-time composer is gone (Standards S8).
fn check_additive_path(text: &str, recipe: &str) -> Result<(), String> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix("ENV ") else {
            continue;
        };
        // Parse each `KEY=value` assignment and require the PATH one itself to
        // carry `${PATH}`. Inspecting the whole line would accept a decoy that
        // inherits PATH in a sibling field (`OTHER=${PATH}`) while overwriting it.
        for assignment in rest.split_whitespace() {
            let Some((key, value)) = assignment.split_once('=') else {
                return Err(format!(
                    "{recipe}/Dockerfile uses an ENV form this guard cannot check: {line}"
                ));
            };
            if key == "PATH" && !value.contains("${PATH}") {
                return Err(format!(
                    "{recipe}/Dockerfile sets a non-additive ENV PATH: {line}"
                ));
            }
        }
    }
    Ok(())
}

#[test]
fn shipped_recipes_extend_path_additively() {
    for recipe in RECIPES {
        let text = read_text(&format!("images/tools/{recipe}/Dockerfile"));
        check_additive_path(&text, recipe).unwrap_or_else(|problem| panic!("{problem}"));
    }
}

#[test]
fn no_shipped_recipe_resolves_upstream_latest() {
    const FORBIDDEN: [&str; 6] = [
        "releases/latest",
        "/latest/download",
        "dist-tags.latest",
        "@latest",
        ":-latest",
        "claude-code-releases/latest",
    ];
    let mut offenders = Vec::new();
    for (path, contents) in image_source_files() {
        if !is_recipe_source(&path) || is_provenance_snapshot(&path) {
            continue;
        }
        let text = String::from_utf8_lossy(&contents);
        for (index, line) in text.lines().enumerate() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            for needle in FORBIDDEN {
                if line.contains(needle) {
                    offenders.push(format!("{}:{}: {needle}", path.display(), index + 1));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these shipped recipes still resolve upstream latest: {offenders:?}"
    );
}

/// The exact-install hooks and vendored runnable installers are shipped.
#[test]
fn exact_image_install_hooks_exist() {
    let expected = [
        "codex/install-codex.sh",
        "codex/verify-codex.sh",
        "codex/vendor/install.sh",
        "opencode/install-opencode.sh",
        "opencode/verify-opencode.sh",
        "opencode/vendor/install.sh",
        "claude/install-claude.sh",
        "claude/verify-claude.sh",
        "claude/vendor/install.sh",
        "copilot/install-copilot.sh",
        "copilot/verify-copilot.sh",
        "dsh/install-dsh.sh",
        "dsh/verify-dsh.sh",
        "dsh/prepare-lock.sh",
        "dsh/check-lock-update.js",
        "pi/install-pi.sh",
        "pi/install-pi-packages.sh",
        "pi/verify-pi.sh",
        "pi/prepare-lock.sh",
        "pi/bridge/prepare-lock.sh",
    ];
    for relative in expected {
        let path = repo_path(&format!("images/tools/{relative}"));
        assert!(
            path.is_file(),
            "{} must exist and be a regular file",
            path.display()
        );
    }
}

// ---------------------------------------------------------------------------
// Self-controls: on in-memory copies, each production gate must reject a
// deliberately broken input (the checked-in files must pass).
// ---------------------------------------------------------------------------

#[test]
fn image_source_guards_reject_mutations() {
    // A dropped bridge npm-ci flag must fail the mandatory-flags gate.
    let script = read_text("images/tools/pi/install-pi-packages.sh");
    assert!(check_bridge_install_flags(&script).is_ok());
    let without_omit = script.replace(" --omit=optional", "");
    assert_ne!(without_omit, script, "the mutation must change the script");
    assert!(
        check_bridge_install_flags(&without_omit).is_err(),
        "dropping --omit=optional must fail the gate"
    );

    // A commented-out command carrying every flag must not satisfy the gate:
    // there is no active `npm ci` to check.
    let commented_only = "# npm ci --ignore-scripts --omit=optional --legacy-peer-deps\n";
    assert!(
        check_bridge_install_flags(commented_only).is_err(),
        "a commented-only npm ci must not satisfy the gate"
    );

    // A commented valid command must not mask a later active command missing a
    // flag: every active invocation is inspected.
    let masked = "# npm ci --ignore-scripts --omit=optional --legacy-peer-deps\n\
                  npm ci --ignore-scripts --omit=optional\n";
    assert!(
        check_bridge_install_flags(masked).is_err(),
        "a commented valid npm ci must not mask an active invalid one"
    );

    // A second, bare `npm ci` with no flags must fail even when a valid
    // invocation precedes it: every active invocation is inspected, flagged or
    // not (permanent control for the previous `contains("npm ci --")` bypass).
    let bare_second = "npm ci --ignore-scripts --omit=optional --legacy-peer-deps\nnpm ci\n";
    assert!(
        check_bridge_install_flags(bare_second).is_err(),
        "an active bare npm ci must not hide behind a valid one"
    );

    // A mandatory flag that exists only in a trailing shell comment is never
    // passed to npm and must not satisfy the gate (permanent control for the
    // previous whole-line `contains(flag)` bypass).
    let flags_in_comment = "npm ci --ignore-scripts # --omit=optional --legacy-peer-deps\n";
    assert!(
        check_bridge_install_flags(flags_in_comment).is_err(),
        "a mandatory flag only in a trailing comment must not satisfy the gate"
    );

    // A pi lock entry with its integrity removed must fail the integrity gate.
    let mut pi_lock = read_json("images/tools/pi/package-lock.json");
    if let Some(packages) = pi_lock["packages"].as_object_mut() {
        for (key, value) in packages.iter_mut() {
            if key.is_empty() {
                continue;
            }
            if let Some(entry) = value.as_object_mut() {
                entry.remove("integrity");
                break;
            }
        }
    }
    assert!(
        check_lock_integrity(&pi_lock).is_err(),
        "a lock entry without integrity must fail the gate"
    );

    // A pi sibling at the wrong version must fail the sibling-set gate.
    let mut sibling_lock = read_json("images/tools/pi/package-lock.json");
    if let Some(packages) = sibling_lock["packages"].as_object_mut() {
        let key =
            "node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-tui";
        if let Some(entry) = packages.get_mut(key).and_then(Value::as_object_mut) {
            entry.insert("version".to_string(), Value::String("0.0.0".to_string()));
        }
    }
    assert!(
        check_pi_siblings(&sibling_lock).is_err(),
        "a sibling at the wrong version must fail the gate"
    );

    // An aliased package inserted into the bridge lock must fail the gate.
    let mut bridge_lock = read_json("images/tools/pi/bridge/package-lock.json");
    if let Some(packages) = bridge_lock["packages"].as_object_mut() {
        packages.insert(
            "node_modules/@earendil-works/pi-ai".to_string(),
            serde_json::json!({ "version": "0.0.0" }),
        );
    }
    assert!(
        check_no_loader_aliased_pi_package(&bridge_lock).is_err(),
        "an aliased bridge package must fail the gate"
    );

    // A pnpm pin that disagrees with the dsh lock must fail the pnpm gate.
    let dsh_manifest = {
        let mut manifest = read_json("images/tools/dsh/package.json");
        manifest["dependencies"]["pnpm"] = Value::String("0.0.0-mutated".to_string());
        manifest
    };
    let dsh_lock = read_json("images/tools/dsh/package-lock.json");
    assert!(
        check_pnpm_installed(PackageFiles {
            manifest: &dsh_manifest,
            lock: &dsh_lock,
        })
        .is_err(),
        "a pnpm pin that disagrees with the lock must fail the gate"
    );

    // A recipe `ENV PATH` that drops `${PATH}` must fail the additive-path gate.
    assert!(check_additive_path("ENV PATH=/opt/go/bin:${PATH}\n", "fixture").is_ok());
    assert!(
        check_additive_path("ENV PATH=/opt/go/bin\n", "fixture").is_err(),
        "a non-additive ENV PATH must fail the gate"
    );
    // A commented non-additive line is inert and must not trip the gate.
    assert!(
        check_additive_path("# ENV PATH=/opt/go/bin\n", "fixture").is_ok(),
        "a commented ENV PATH must not be inspected"
    );
    // A decoy that inherits the real PATH in an unrelated field must not satisfy
    // the guard while PATH itself is overwritten (permanent control for the
    // previous whole-line `${PATH}` substring bypass).
    assert!(
        check_additive_path("ENV PATH=/opt/custom OTHER=${PATH}\n", "fixture").is_err(),
        "a sibling field carrying ${{PATH}} must not make PATH additive"
    );
    assert!(
        check_additive_path("ENV OTHER=${PATH} PATH=/opt/custom\n", "fixture").is_err(),
        "a non-additive PATH after a sibling assignment must fail"
    );
    // An `ENV` form this guard cannot parse is rejected rather than skipped.
    assert!(
        check_additive_path("ENV PATH /opt/custom\n", "fixture").is_err(),
        "an unparseable ENV form must be rejected"
    );

    // Commenting a version label must drop it from the active set.
    let copilot = dockerfile("copilot");
    let commented = copilot.replace(
        "LABEL org.agent-vm.version.copilot=",
        "# LABEL org.agent-vm.version.copilot=",
    );
    assert!(
        !active_version_labels(&commented).contains(&"org.agent-vm.version.copilot".to_string()),
        "a commented label must fail the label guard"
    );
}
