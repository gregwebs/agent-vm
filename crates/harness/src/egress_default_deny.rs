//! The egress default-deny driver's boot-free items (#693).
//!
//! `script/test/egress-default-deny-contract.sh` is the §6.7 join. Two of its
//! six items were inline Python; they are here now:
//!
//! * the **plan inventory** — `egress-default-deny.sh --print-plan` is run and
//!   joined against an inventory this module writes out itself. Deriving it from
//!   the case table would let a deleted case disappear from both the builder and
//!   its expectation in the same edit, so the 85 (case, variant) pairs are
//!   spelled here, in two independent groups (guest cases and the admin objects).
//! * the **guard removal mutations** — each script the contract depends on is
//!   deleted from one guard list in a scratch copy of `ci-contracts.sh`, and that
//!   copy must refuse with the exact message naming the script and the list.
//!
//! The third item, `harness egress-fixtures self-test`, is already a harness
//! subcommand; it moved out of the heredoc unchanged.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use serde_json::Value;

use crate::egress_probe::run_command_bounded;

/// The environment every case row must carry, before declared extras.
const BASE_ENV: [&str; 7] = [
    "HOME",
    "XDG_CONFIG_HOME",
    "AGENT_VM_STATE_DIR",
    "PATH",
    "TERM",
    "AGENT_VM_SHARE_MSB_CACHE",
    "AGENT_VM_NO_NOTIFICATIONS",
];

/// The guest cases the plan must contain, in this module's own words.
fn expected_guest() -> Vec<(&'static str, &'static str)> {
    let mut expected: Vec<(&'static str, &'static str)> = "NR1 NR2 NR3 P0 LC1 HC1 I1 D1 D1f L1 \
         H1 I1a LH1 AD1 TP1 PA1 PA1x PA2 UP1 UP2 CI1 PX1 PX2 PX3 FL0 FL1 FL2 CR1c CR1 IN1 IN2 \
         HK1c HK1 HK2c HK2 CL1"
        .split_whitespace()
        .map(|case| (case, "ipv4"))
        .collect();
    for case in ["V6c", "DNS6c", "V6", "D1"] {
        expected.push((case, "ipv6"));
    }
    for variant in [
        "internet", "address", "tcp", "udp", "port", "tcp-port", "udp-port",
    ] {
        expected.push(("RB1", variant));
    }
    for variant in [
        "udp-hostname",
        "dns-port",
        "alias",
        "wildcard",
        "numeric-final",
        "cidr-port",
        "scheme",
    ] {
        expected.push(("RJ1", variant));
    }
    for case in "HNc HN1 HN2 HN3 HN4 HN5 HN5c HN6 OP1 OP1c OP2 OP2c OP3 OP3c \
         HP1 HP2 HP2c HP3 HP4 HP5 HP6 HP6c PXH1"
        .split_whitespace()
    {
        expected.push((case, "ipv4"));
    }
    for variant in ["hostname-only", "lan", "udp", "tcp", "port", "tcp-port"] {
        expected.push(("RB2", variant));
    }
    // ADR-0064: the refusal feed and its unclean-end variant.
    for variant in ["ipv4", "kill9"] {
        expected.push(("RF1", variant));
    }
    expected
}

/// The admin objects: the five image/lifecycle verbs and the four fixture ones.
const EXPECTED_ADMIN: [(&str, &str); 9] = [
    ("image-load", "admin"),
    ("list", "admin"),
    ("stop", "admin"),
    ("force-stop", "admin"),
    ("remove", "admin"),
    ("IN1", "curl"),
    ("IN2", "curl"),
    ("fixture-health", "admin"),
    ("fixture-start", "admin"),
];

const SMOKE_GUEST: [&str; 11] = [
    "P0", "LC1", "HC1", "I1", "D1", "L1", "NR1", "NR2", "NR3", "RF1", "RF1",
];

pub fn plan_inventory(repo_root: &Path) -> Result<(), String> {
    let rows = plan(repo_root, false)?;
    let cases: Vec<&Value> = rows
        .iter()
        .filter(|row| text(row, "kind") != "admin")
        .collect();
    let admins: Vec<&Value> = rows
        .iter()
        .filter(|row| text(row, "kind") == "admin")
        .collect();
    let expected = expected_guest();
    let observed: Vec<(&str, &str)> = cases
        .iter()
        .map(|row| (text(row, "case"), text(row, "variant")))
        .collect();
    assert_eq!(
        observed.len(),
        expected.len(),
        "the plan has {} cases, the inventory names {}",
        observed.len(),
        expected.len()
    );
    assert_eq!(expected.len(), 85, "the independent inventory is 85 cases");
    let observed_set: std::collections::BTreeSet<(&str, &str)> = observed.iter().copied().collect();
    let expected_set: std::collections::BTreeSet<(&str, &str)> = expected.iter().copied().collect();
    assert_eq!(observed_set, expected_set, "the plan's case set changed");

    for row in &cases {
        check_case(row);
    }

    let observed_admin: std::collections::BTreeSet<(&str, &str)> = admins
        .iter()
        .map(|row| (text(row, "case"), text(row, "variant")))
        .collect();
    let expected_admin: std::collections::BTreeSet<(&str, &str)> =
        EXPECTED_ADMIN.iter().copied().collect();
    assert_eq!(admins.len(), expected_admin.len());
    assert_eq!(observed_admin, expected_admin);
    for row in &admins {
        assert_eq!(
            row["tool"],
            Value::Null,
            "an admin row declares a guest tool"
        );
        let argv = strings(row, "argv");
        assert!(
            !argv
                .iter()
                .any(|word| *word == "egressprobe" || *word == "egresscreds"),
            "an admin row runs a guest tool: {argv:?}"
        );
    }

    // The readiness subset must be a faithful slice of the full plan: the NR rows
    // are compared whole, so argv, cwd, tool and grant semantics are pinned too.
    let smoke = plan(repo_root, true)?;
    let smoke_cases: Vec<&Value> = smoke
        .iter()
        .filter(|row| text(row, "kind") != "admin")
        .collect();
    let smoke_admin: Vec<&Value> = smoke
        .iter()
        .filter(|row| text(row, "kind") == "admin")
        .collect();
    let smoke_observed: Vec<(&str, &str)> = smoke_cases
        .iter()
        .map(|row| (text(row, "case"), text(row, "variant")))
        .collect();
    // `SMOKE_GUEST` names the nine numeric cases and both of RF1's variants, so
    // the row count is eleven and the distinct set is ten.
    assert_eq!(smoke_observed.len(), SMOKE_GUEST.len());
    let smoke_set: std::collections::BTreeSet<(&str, &str)> =
        smoke_observed.iter().copied().collect();
    let smoke_expected: std::collections::BTreeSet<(&str, &str)> = SMOKE_GUEST
        .iter()
        .map(|case| (*case, "ipv4"))
        .chain(std::iter::once(("RF1", "kill9")))
        .collect();
    assert_eq!(smoke_set, smoke_expected);
    assert_eq!(smoke_admin.len(), EXPECTED_ADMIN.len());
    let smoke_admin_set: std::collections::BTreeSet<(&str, &str)> = smoke_admin
        .iter()
        .map(|row| (text(row, "case"), text(row, "variant")))
        .collect();
    assert_eq!(smoke_admin_set, expected_admin);
    for row in &smoke_cases {
        if matches!(text(row, "case"), "NR1" | "NR2" | "NR3") {
            let full = cases
                .iter()
                .find(|full| text(full, "case") == text(row, "case"))
                .expect("the full plan has every smoke case");
            assert_eq!(*row, *full, "the smoke row differs from the full row");
        }
    }
    println!(
        "ok: plan inventory: {} cases, {} admin objects; smoke {} cases, {} admin objects",
        cases.len(),
        admins.len(),
        smoke_cases.len(),
        smoke_admin.len()
    );
    Ok(())
}

fn check_case(row: &Value) {
    let case = text(row, "case");
    let argv = strings(row, "argv");
    let tool = match case {
        "NR1" | "NR2" => "pi",
        "NR3" => "shell",
        "CR1" | "CR1c" => "egresscreds",
        _ => "egressprobe",
    };
    let index = argv
        .iter()
        .position(|word| *word == tool)
        .unwrap_or_else(|| panic!("{case}: argv names no {tool}: {argv:?}"));
    assert_eq!(text(row, "tool"), tool, "{case}: tool");
    assert_eq!(argv[index], tool, "{case}: argv tool");
    assert_eq!(
        text(row, "kind"),
        if case == "RJ1" || case == "PXH1" {
            "validation-only"
        } else {
            "guest"
        },
        "{case}: kind"
    );
    if matches!(case, "NR1" | "NR2" | "NR3") {
        let expected: Vec<&str> = if case == "NR3" {
            vec!["echo", "AGENT_VM_328_SHELL_STARTED"]
        } else {
            vec!["--version"]
        };
        assert_eq!(&argv[index + 1..], &expected[..], "{case}: tool argv");
        let cwd = Path::new(text(row, "cwd"));
        assert_eq!(
            cwd.file_name().and_then(|name| name.to_str()),
            Some("requests"),
            "{case}: cwd"
        );
        assert_eq!(row["expected_attempts"], Value::Array(Vec::new()));
        assert_eq!(row["controls"], serde_json::json!({}));
        assert_eq!(
            argv.contains(&"--allow-internet-egress"),
            case == "NR2",
            "{case}: the internet grant"
        );
        assert!(
            !argv.iter().any(|flag| flag.starts_with("--allow-host")
                || flag.starts_with("--allow-lan")
                || flag.starts_with("--allow-egress")),
            "{case}: declares an allowance it must not have: {argv:?}"
        );
    } else if !matches!(case, "RJ1" | "PXH1") {
        assert_eq!(argv[index + 1], case, "{case}: the tool's case argument");
    } else {
        assert!(!argv.contains(&"--"), "{case}: argv carries `--`");
    }
    let extras: std::collections::BTreeSet<&str> =
        strings(row, "declared_extras").iter().copied().collect();
    let allowed: std::collections::BTreeSet<&str> = if case.starts_with("PX") {
        ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"]
            .into_iter()
            .collect()
    } else if case.starts_with("FL") {
        ["MSB_CONFIG_PATH"].into_iter().collect()
    } else {
        std::collections::BTreeSet::new()
    };
    assert!(
        extras.is_subset(&allowed),
        "{case}: undeclared extras {extras:?}"
    );
    let env: std::collections::BTreeSet<&str> = row["env"]
        .as_object()
        .expect("a case's env")
        .keys()
        .map(String::as_str)
        .collect();
    let expected_env: std::collections::BTreeSet<&str> = BASE_ENV
        .iter()
        .copied()
        .chain(extras.iter().copied())
        .collect();
    assert_eq!(env, expected_env, "{case}: environment");
    assert!(
        !argv.contains(&"shell") || case == "NR3",
        "{case}: a shell argv"
    );
    assert!(!argv.contains(&"-c"), "{case}: `-c` in argv");
    assert!(number(row, "timeout") > 0.0, "{case}: timeout");
    assert!(number(row, "grace") > 0.0, "{case}: grace");
    assert!(!text(row, "supervisor").is_empty(), "{case}: supervisor");
    // The shim is a declared argv plus its identity and output paths, not a
    // string: a case without one would launch unwrapped.
    let shim = row["shim"].as_object().expect("a case's shim");
    assert!(!shim.is_empty(), "{case}: empty shim");
    assert!(
        shim.contains_key("argv") && shim.contains_key("output"),
        "{case}: shim"
    );
    assert!(!text(row, "cwd").is_empty(), "{case}: cwd");
    assert!(row["controls"].is_object(), "{case}: controls");
    assert!(row["prerequisites"].is_array(), "{case}: prerequisites");
    if case == "CR1" || case == "CR1c" {
        assert!(
            !strings(row, "setup").is_empty(),
            "{case}: synthetic seed lifecycle not declared"
        );
    }
    if case == "PA2" {
        // The live-allowance case declares the opposite of a seed and the
        // writer's own cleanup, and it probes through the host witness only: a
        // probe row here would be a second, unasserted inventory.
        assert_eq!(row["expected_attempts"], Value::Array(Vec::new()));
        assert_eq!(row["controls"], serde_json::json!({}));
        let setup = strings(row, "setup");
        assert!(!setup.is_empty(), "PA2: setup");
        assert!(setup[0].contains("no seed"), "PA2: {:?}", setup);
        assert!(setup[0].contains("allowances.lock"), "PA2: {:?}", setup);
        let cwd = Path::new(text(row, "cwd"));
        assert_eq!(
            cwd.file_name().and_then(|name| name.to_str()),
            Some("proj"),
            "PA2: cwd"
        );
    }
}

fn plan(repo_root: &Path, smoke: bool) -> Result<Vec<Value>, String> {
    let script = repo_root.join("script/test/egress-default-deny.sh");
    let mut command = Command::new("/bin/bash");
    command.arg(&script);
    if smoke {
        command.arg("--smoke");
    }
    command.arg("--print-plan");
    let output = run_command_bounded(command, Duration::from_secs(20))?;
    assert_eq!(
        output.status,
        0,
        "{} --print-plan: {}",
        script.display(),
        output.text()
    );
    Ok(output
        .stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| match serde_json::from_str::<Value>(line) {
            Ok(row) => row,
            Err(error) => panic!("a plan row is not JSON: {line}: {error}"),
        })
        .collect())
}

fn text<'a>(row: &'a Value, name: &str) -> &'a str {
    row[name]
        .as_str()
        .unwrap_or_else(|| panic!("{name} is not a string: {row}"))
}

fn strings<'a>(row: &'a Value, name: &str) -> Vec<&'a str> {
    row[name]
        .as_array()
        .unwrap_or_else(|| panic!("{name} is not an array: {row}"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("{name} holds a non-string: {row}"))
        })
        .collect()
}

fn number(row: &Value, name: &str) -> f64 {
    row[name]
        .as_f64()
        .unwrap_or_else(|| panic!("{name} is not a number: {row}"))
}

// --- Guard removal mutations ------------------------------------------------

/// The scripts the contract depends on: each must be in both guard lists, and a
/// copy of `ci-contracts.sh` without one entry must refuse by name.
const GUARDED: [&str; 3] = [
    "script/test/egress-default-deny.sh",
    "script/test/egress-default-deny-contract.sh",
    "script/test/fixtures/egress-probe.sh",
];

pub fn guard_mutations(repo_root: &Path) -> Result<(), String> {
    let source = fs::read_to_string(repo_root.join("script/test/ci-contracts.sh"))
        .map_err(|error| error.to_string())?;
    let run_list = source
        .split("# --- Shell guard rail")
        .next()
        .expect("a file has a prefix");
    assert!(
        run_list.contains("bash \"$REPO_ROOT/script/test/egress-default-deny-contract.sh\""),
        "ci-contracts.sh does not run the egress contract, so its guard entries mean nothing"
    );
    for (array, label) in [
        ("syntax_check", "bash -n"),
        ("shellcheck_files", "shellcheck"),
    ] {
        for script in GUARDED {
            let list = format!("{array}=(");
            let start = source
                .find(&list)
                .unwrap_or_else(|| panic!("ci-contracts.sh has no {array} list"));
            let end = source[start..]
                .find("\n)")
                .map(|offset| start + offset)
                .unwrap_or_else(|| panic!("the {array} list is unterminated"));
            let block = &source[start..end];
            let entry = format!("    {script}\n");
            assert_eq!(
                block.matches(entry.as_str()).count(),
                1,
                "the {array} guard list has no single entry for {script}"
            );
            let mutated = format!(
                "{}{}{}",
                &source[..start],
                block.replace(&entry, ""),
                &source[end..]
            );
            let directory = scratch()?;
            let path = directory.join("script/test/ci-contracts.sh");
            let outcome: Result<(), String> = (|| {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
                }
                fs::write(&path, mutated).map_err(|error| error.to_string())?;
                let output = run_command_bounded(
                    {
                        let mut command = Command::new("/bin/bash");
                        command.arg(&path).arg("--guard-only");
                        command
                    },
                    Duration::from_secs(20),
                )?;
                assert_eq!(
                    output.status, 1,
                    "removing {script} from the {array} list left the guard rail green: {}{}",
                    output.stdout, output.stderr
                );
                let message = format!("({script}) is missing from the {label} guard list");
                assert!(
                    output.stderr.contains(&message),
                    "the removal was not reported by name: {}{}",
                    output.stdout,
                    output.stderr
                );
                Ok(())
            })();
            let _ = fs::remove_dir_all(&directory);
            outcome?;
            println!("ok: guard removal mutation: {array}: {script}");
        }
    }
    Ok(())
}

fn scratch() -> Result<PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let directory = std::env::temp_dir().join(format!(
        "harness-guard-mutation-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    Ok(directory)
}

// --- CLI --------------------------------------------------------------------

#[derive(Debug, clap::Args)]
pub struct EgressDefaultDenyArgs {
    /// Join `egress-default-deny.sh --print-plan` against the independent inventory.
    #[arg(long, conflicts_with = "guard_mutations")]
    plan_inventory: bool,
    /// Remove each guard-list entry in a scratch copy and require a refusal.
    #[arg(long)]
    guard_mutations: bool,
    /// Repository root; `CARGO_MANIFEST_DIR/../..` when absent.
    #[arg(long, value_name = "PATH")]
    repo_root: Option<PathBuf>,
}

fn default_repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn run(args: EgressDefaultDenyArgs) -> Result<crate::Outcome, String> {
    let root = args.repo_root.clone().unwrap_or_else(default_repo_root);
    if args.plan_inventory {
        plan_inventory(&root)?;
        return Ok(crate::Outcome::Report(
            "egress default-deny plan inventory passed".to_owned(),
        ));
    }
    if args.guard_mutations {
        guard_mutations(&root)?;
        return Ok(crate::Outcome::Report(
            "egress default-deny guard removal mutations passed".to_owned(),
        ));
    }
    Err("usage: egress-default-deny --plan-inventory | --guard-mutations".to_owned())
}
