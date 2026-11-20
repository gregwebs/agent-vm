//! The egress case catalogue: one `Command` per case, and its JSONL plan.
//!
//! Ported from `script/test/lib/egress-fixtures.py` (the `Case`/`Command`
//! model, `CASES`, `build_command`, `expected_attempts`,
//! `attempt_expectations`, the hostname tier tables and `print_plan`).
//!
//! The plan is an *inventory*, not a description: `run --print-plan` prints one
//! JSON object per case and the boot-free §6.7 contract joins that output
//! against an expected set it builds itself, so a case that disappears from the
//! table disappears from the evidence too. That is why `CASES` is written out
//! below rather than derived from the rows: deriving it would let a deleted case
//! vanish from the builder and from its own expectation in the same edit.
//!
//! Two host-side diagnostics live here as well, because they need
//! `build_command`: the default-request report oracle and its mutants (block B
//! of `self_test`).

use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use serde_json::{Map, Value, json};

use crate::{
    egress_fixtures::{base_environment, monotonic_nanos},
    released_image_launch::{Bounds, LaunchError, LaunchSpec, exit_code, run_in_owned_group},
};

pub const IMAGE: &str = "av302:egress";
pub const CLEANUP_BOUND: f64 = 120.0;
pub const ADMIN_GRACE: f64 = 1.0;
/// A second test-owned address for HN2; the run overrides it with `--lan2`.
pub const DEFAULT_LAN2: &str = "192.0.2.2";
pub const HP4_PAIR: (&str, &str) = ("example.com", "www.example.com");

/// The cases whose grant is a project allowance record instead of a flag, and
/// therefore need a seed (ADR-0065).
pub const ALLOWANCE_CASES: [&str; 2] = ["PA1", "PA1x"];

/// One catalogue row: the case's own flags, tool and extras, before `{lan}` and
/// the hostname names are substituted.
#[derive(Debug, Clone, Copy)]
pub struct Case {
    pub case: &'static str,
    pub variant: &'static str,
    pub flags: &'static [&'static str],
    pub extras: &'static [&'static str],
    pub optional: &'static str,
    pub tool: &'static str,
    pub guest: bool,
}

const fn case(case: &'static str) -> Case {
    Case {
        case,
        variant: "ipv4",
        flags: &[],
        extras: &[],
        optional: "",
        tool: "egressprobe",
        guest: true,
    }
}

/// Order is significant: calibrations precede dependent probes, except I1a,
/// whose endpoint must first be decoded by H1.
pub static CASES: &[Case] = &[
    Case {
        tool: "pi",
        ..case("NR1")
    },
    Case {
        tool: "pi",
        flags: &["--allow-internet-egress"],
        ..case("NR2")
    },
    Case {
        tool: "shell",
        ..case("NR3")
    },
    case("P0"),
    Case {
        flags: &["--allow-lan"],
        ..case("LC1")
    },
    Case {
        flags: &["--allow-host"],
        ..case("HC1")
    },
    Case {
        flags: &["--allow-internet-egress"],
        ..case("I1")
    },
    case("D1"),
    Case {
        flags: &[
            "--allow-lan=false",
            "--allow-host=false",
            "--allow-internet-egress=false",
        ],
        ..case("D1f")
    },
    Case {
        flags: &["--allow-lan"],
        ..case("L1")
    },
    Case {
        flags: &["--allow-host"],
        ..case("H1")
    },
    Case {
        flags: &["--allow-internet-egress"],
        ..case("I1a")
    },
    Case {
        flags: &["--allow-lan", "--allow-host"],
        ..case("LH1")
    },
    Case {
        flags: &["--allow-egress", "1.1.1.1"],
        ..case("AD1")
    },
    Case {
        flags: &["--allow-egress", "tcp://{lan}:18080"],
        ..case("TP1")
    },
    // ADR-0065: the same grant, written as a project allowance record instead of
    // a flag -- and the same record under another project's digest.
    case("PA1"),
    case("PA1x"),
    // ADR-0066: the same grant again, but *changed while the guest runs*: refused,
    // allowed live with `access allow --project`, refused again after a live
    // `access revoke`. It seeds nothing (the case creates the record itself) and
    // the host witness performs the `access` work between its probes, so it
    // declares no probe attempts of its own.
    case("PA2"),
    Case {
        flags: &["--allow-egress", "udp://[{lan}/32]:19090"],
        ..case("UP1")
    },
    Case {
        flags: &["--allow-egress", "{lan}:18080"],
        ..case("UP2")
    },
    Case {
        flags: &["--allow-egress", "tcp://[{cidr}]:18080"],
        ..case("CI1")
    },
    Case {
        flags: &["--allow-egress", "tcp://{lan}:18080"],
        extras: &["HTTP_PROXY"],
        ..case("PX1")
    },
    Case {
        flags: &["--allow-egress", "tcp://{lan}:18080"],
        extras: &["HTTP_PROXY", "NO_PROXY"],
        ..case("PX2")
    },
    Case {
        extras: &["HTTP_PROXY", "HTTPS_PROXY"],
        ..case("PX3")
    },
    Case {
        flags: &["--allow-internet-egress"],
        extras: &["MSB_CONFIG_PATH"],
        ..case("FL0")
    },
    Case {
        flags: &["--allow-lan"],
        extras: &["MSB_CONFIG_PATH"],
        ..case("FL1")
    },
    Case {
        flags: &["--allow-egress", "tcp://{lan}:18080"],
        extras: &["MSB_CONFIG_PATH"],
        ..case("FL2")
    },
    Case {
        flags: &["--allow-internet-egress"],
        tool: "egresscreds",
        ..case("CR1c")
    },
    Case {
        tool: "egresscreds",
        ..case("CR1")
    },
    Case {
        flags: &["-p", "18556:8000"],
        ..case("IN1")
    },
    Case {
        flags: &["--auto-publish"],
        ..case("IN2")
    },
    Case {
        flags: &["--allow-lan"],
        ..case("HK1c")
    },
    case("HK1"),
    Case {
        flags: &["--allow-lan"],
        ..case("HK2c")
    },
    case("HK2"),
    Case {
        variant: "ipv6",
        flags: &["--allow-internet-egress"],
        optional: "ipv6",
        ..case("V6c")
    },
    Case {
        variant: "ipv6",
        flags: &["--allow-internet-egress"],
        optional: "ipv6",
        ..case("DNS6c")
    },
    Case {
        variant: "ipv6",
        flags: &["--allow-egress", "tcp://[2606:4700:4700::1111]:80"],
        optional: "ipv6",
        ..case("V6")
    },
    Case {
        variant: "ipv6",
        optional: "ipv6",
        ..case("D1")
    },
    Case {
        variant: "address",
        flags: &["--allow-internet-egress", "--allow-egress", "{cidr}"],
        optional: "rebind",
        ..case("RB1")
    },
    Case {
        variant: "tcp",
        flags: &["--allow-internet-egress", "--allow-egress", "tcp://{cidr}"],
        optional: "rebind",
        ..case("RB1")
    },
    Case {
        variant: "udp",
        flags: &["--allow-internet-egress", "--allow-egress", "udp://{cidr}"],
        optional: "rebind",
        ..case("RB1")
    },
    Case {
        variant: "internet",
        flags: &["--allow-internet-egress"],
        optional: "rebind",
        ..case("RB1")
    },
    Case {
        variant: "port",
        flags: &[
            "--allow-internet-egress",
            "--allow-egress",
            "[{cidr}]:18080",
        ],
        optional: "rebind",
        ..case("RB1")
    },
    Case {
        variant: "tcp-port",
        flags: &[
            "--allow-internet-egress",
            "--allow-egress",
            "tcp://[{cidr}]:18080",
        ],
        optional: "rebind",
        ..case("RB1")
    },
    Case {
        variant: "udp-port",
        flags: &[
            "--allow-internet-egress",
            "--allow-egress",
            "udp://[{cidr}]:18080",
        ],
        optional: "rebind",
        ..case("RB1")
    },
    Case {
        variant: "udp-hostname",
        flags: &["--allow-egress", "udp://reject.invalid"],
        guest: false,
        ..case("RJ1")
    },
    Case {
        variant: "dns-port",
        flags: &["--allow-egress", "reject.invalid:53"],
        guest: false,
        ..case("RJ1")
    },
    Case {
        variant: "alias",
        flags: &["--allow-egress", "host.microsandbox.internal"],
        guest: false,
        ..case("RJ1")
    },
    Case {
        variant: "wildcard",
        flags: &["--allow-egress", "*.reject.invalid"],
        guest: false,
        ..case("RJ1")
    },
    Case {
        variant: "numeric-final",
        flags: &["--allow-egress", "1.2.3"],
        guest: false,
        ..case("RJ1")
    },
    Case {
        variant: "cidr-port",
        flags: &["--allow-egress", "{cidr}:18080"],
        guest: false,
        ..case("RJ1")
    },
    Case {
        variant: "scheme",
        flags: &["--allow-egress", "http://1.1.1.1:80"],
        guest: false,
        ..case("RJ1")
    },
    // #306 hostname tier (ADR-0037). Names are sslip.io renderings of the LAN
    // address so the host resolver returns the fixture answer; the ladder and the
    // gate live in `run`. Each entry in `flags` is either a raw flag token (it
    // starts with `--`) or an allowance, which the builder emits as
    // `--allow-egress ALLOWANCE`. `{admission}` expands to the HNc ladder step's
    // private-answer admission: a port-less UDP CIDR, or the diagnostic
    // `--allow-lan` of step (b).
    Case {
        flags: &["{admission}", "tcp://{hnc}:18443"],
        ..case("HNc")
    },
    Case {
        flags: &[
            "{admission}",
            "tcp://{hn1a}:18443",
            "tcp://{hn1b}:18444",
            "{hn1c}",
        ],
        ..case("HN1")
    },
    Case {
        flags: &["{admission}", "tcp://{hn2a}:18443", "tcp://{hn2b}:18443"],
        ..case("HN2")
    },
    Case {
        flags: &["{admission}", "tcp://{hn3}:18443"],
        ..case("HN3")
    },
    Case {
        flags: &[
            "--allow-internet-egress",
            "udp://{lan}/32",
            "tcp://{hn4a}:18443",
        ],
        ..case("HN4")
    },
    Case {
        flags: &["{admission}", "tcp://{lan}:18443", "tcp://{hn5}:18443"],
        ..case("HN5")
    },
    Case {
        flags: &["{admission}", "tcp://{lan}:18443"],
        ..case("HN5c")
    },
    Case {
        flags: &["{admission}", "tcp://{lan}:18080", "tcp://{hn6}:18443"],
        ..case("HN6")
    },
    // OP rows need no DNS lookup or private-answer admission: the guest dials the
    // numeric LAN grant, and the hostname entry only has to exist so the emitted
    // Domain rule makes `has_domain_rules()` true (D1). Each OPn has an OPnc
    // control without the hostname rule.
    Case {
        flags: &["tcp://{lan}:18090", "tcp://{op1}:18443"],
        ..case("OP1")
    },
    Case {
        flags: &["tcp://{lan}:18090"],
        ..case("OP1c")
    },
    Case {
        flags: &["tcp://{lan}:18090", "tcp://{op2}:18443"],
        ..case("OP2")
    },
    Case {
        flags: &["tcp://{lan}:18090"],
        ..case("OP2c")
    },
    Case {
        flags: &["tcp://{lan}:18091", "tcp://{op3}:18443"],
        ..case("OP3")
    },
    Case {
        flags: &["tcp://{lan}:18091"],
        ..case("OP3c")
    },
    Case {
        variant: "hostname-only",
        flags: &["tcp://{rb2}:18443"],
        optional: "rebind",
        ..case("RB2")
    },
    Case {
        variant: "lan",
        flags: &["tcp://{rb2}:18443", "--allow-lan"],
        optional: "rebind",
        ..case("RB2")
    },
    Case {
        variant: "udp",
        flags: &["tcp://{rb2}:18443", "udp://{cidr}"],
        optional: "rebind",
        ..case("RB2")
    },
    Case {
        variant: "tcp",
        flags: &["tcp://{rb2}:18443", "tcp://{cidr}"],
        optional: "rebind",
        ..case("RB2")
    },
    Case {
        variant: "port",
        flags: &["tcp://{rb2}:18443", "[{cidr}]:18080"],
        optional: "rebind",
        ..case("RB2")
    },
    Case {
        variant: "tcp-port",
        flags: &["tcp://{rb2}:18443", "tcp://[{cidr}]:18080"],
        optional: "rebind",
        ..case("RB2")
    },
    Case {
        flags: &["example.com"],
        ..case("HP1")
    },
    Case {
        flags: &["example.com"],
        ..case("HP2")
    },
    Case {
        flags: &["example.com"],
        ..case("HP2c")
    },
    Case {
        flags: &["example.com", "--allow-host"],
        ..case("HP3")
    },
    Case {
        flags: &["{hp4a}", "--allow-host"],
        ..case("HP4")
    },
    Case {
        flags: &["example.com"],
        ..case("HP5")
    },
    Case {
        flags: &["www.github.com", "--allow-host"],
        ..case("HP6")
    },
    Case {
        flags: &["www.github.com", "github.com", "--allow-host"],
        ..case("HP6c")
    },
    Case {
        flags: &["example.com"],
        guest: false,
        extras: &["HTTPS_PROXY"],
        ..case("PXH1")
    },
    case("CL1"),
    // ADR-0064: the read-only refusal feed. `kill9` is the same run with the
    // launcher killed during the guest's sleep, which is the only way to see
    // `ended (unclean)`: nothing writes the end.
    case("RF1"),
    Case {
        variant: "kill9",
        ..case("RF1")
    },
];

/// Exact positive controls for the #306 hostname tier: every denial/NX attempt
/// names a passing positive attempt it is joined against. Same-case positives
/// where the case proves its own framing; a sibling case otherwise.
const FLOW_CONTROLS: [(&str, &str); 9] = [
    ("lan-tcp80", "LC1:ipv4:lan-tcp80"),
    ("lan-tcp81", "LC1:ipv4:lan-tcp81"),
    ("lan-udp90", "LC1:ipv4:lan-udp90"),
    ("lan-udp80", "LC1:ipv4:lan-udp80"),
    ("host-tcp80", "HC1:ipv4:host-tcp80"),
    ("public-1111", "I1:ipv4:public-1111"),
    ("public-1001", "I1:ipv4:public-1001"),
    ("answer", "I1a:ipv4:answer"),
    ("public-v6-1001", "V6c:ipv6:public-v6-1001"),
];

/// Ordered `(label, protocol, expectation)` rows per hostname-tier case. The
/// probe emits exactly this sequence, so this table is the independent inventory
/// the attempt check joins against.
fn hostname_rows(case: &Case) -> Vec<(&'static str, &'static str, &'static str)> {
    let rows: &[(&str, &str, &str)] = match case.case {
        "RB2" => {
            let expected = if matches!(case.variant, "lan" | "udp" | "tcp") {
                "OK"
            } else {
                "NX"
            };
            return match case.variant {
                "hostname-only" => vec![
                    ("rb2-hostname-only-udp", "dns-udp", expected),
                    ("rb2-hostname-only-tcp", "dns-tcp", expected),
                ],
                "lan" => vec![
                    ("rb2-lan-udp", "dns-udp", expected),
                    ("rb2-lan-tcp", "dns-tcp", expected),
                ],
                "udp" => vec![
                    ("rb2-udp-udp", "dns-udp", expected),
                    ("rb2-udp-tcp", "dns-tcp", expected),
                ],
                "tcp" => vec![
                    ("rb2-tcp-udp", "dns-udp", expected),
                    ("rb2-tcp-tcp", "dns-tcp", expected),
                ],
                "port" => vec![
                    ("rb2-port-udp", "dns-udp", expected),
                    ("rb2-port-tcp", "dns-tcp", expected),
                ],
                _ => vec![
                    ("rb2-tcp-port-udp", "dns-udp", expected),
                    ("rb2-tcp-port-tcp", "dns-tcp", expected),
                ],
            };
        }
        "HNc" => &[("hnc-dns", "dns-udp", "OK"), ("hnc-tls", "tls", "0")],
        "HN1" => &[
            ("hn1a-dns", "dns-udp", "OK"),
            ("hn1b-dns", "dns-udp", "OK"),
            ("hn1c-dns", "dns-udp", "OK"),
            ("hn1a-18443", "tls", "0"),
            ("hn1a-18444", "tls", "1"),
            ("hn1b-18444", "tls", "0"),
            ("hn1b-18443", "tls", "1"),
            ("hn1c-18443", "tls", "0"),
            ("hn1c-18444", "tls", "0"),
            ("hn1d-dns", "dns-udp", "NX"),
            ("hn1d-18443", "tls", "1"),
        ],
        "HN2" => &[
            ("hn2a-dns", "dns-udp", "OK"),
            ("hn2b-dns", "dns-udp", "OK"),
            ("hn2a-lan", "tls", "0"),
            ("hn2b-lan2", "tls", "0"),
            ("hn2a-wrong", "tls", "1"),
            ("hn2b-wrong", "tls", "1"),
        ],
        "HN3" => &[
            ("hn3-dns", "dns-udp", "OK"),
            ("hn3-sni", "tls", "0"),
            ("hn3-nosni", "tls", "1"),
            ("hn3-plain", "opaque", "1"),
            ("lan-tcp80", "tcp", "1"),
        ],
        "HN4" => &[
            ("hn4a-dns", "dns-udp", "OK"),
            ("hn4b-dns", "dns-udp", "OK"),
            ("hn4a-tls", "tls", "0"),
            ("hn4b-tls", "tls", "1"),
        ],
        "HN5" => &[
            ("hn5-dns", "dns-udp", "OK"),
            ("hn5-numeric", "tls", "0"),
            ("hn5-name", "tls", "0"),
            ("hn5-plain", "opaque", "1"),
        ],
        "HN5c" => &[("hn5c-plain", "opaque", "0")],
        "HN6" => &[
            ("hn6-dns", "dns-udp", "OK"),
            ("lan-tcp80", "tcp", "0"),
            ("hn6-nohost", "tcp", "1"),
        ],
        "OP1" => &[("op-printable", "opaque", "1")],
        "OP1c" => &[("op-printable", "opaque", "0")],
        "OP2" => &[("op-binary", "opaque", "0")],
        "OP2c" => &[("op-binary", "opaque", "0")],
        "OP3" => &[("op-banner", "banner", "0")],
        "OP3c" => &[("op-banner", "banner", "0")],
        "HP1" => &[
            ("hp1-com-dns", "dns-udp", "OK"),
            ("hp1-https", "https", "0"),
            ("hp1-scope-udp", "dns-udp", "NX"),
            ("hp1-scope-tcp", "dns-tcp", "NX"),
            ("hp1-http", "https", "1"),
        ],
        "HP2" => &[("hp2-dns", "dns-udp", "OK"), ("hp2-switch", "held", "1")],
        "HP2c" => &[("hp2c-dns", "dns-udp", "OK"), ("hp2c-same", "held", "0")],
        "HP3" => &[
            ("hp3b-dns", "dns-udp", "OK"),
            ("hp3a-dns", "dns-udp", "OK"),
            ("hp3-control", "https", "0"),
            ("hp3-spoof", "https", "1"),
        ],
        "HP4" => &[
            ("hp4a-dns", "dns-udp", "OK"),
            ("hp4b-dns", "dns-udp", "OK"),
            ("hp4-a", "https", "0"),
            ("hp4-b", "https", "1"),
        ],
        "HP5" => &[
            ("hp5-dns", "dns-udp", "OK"),
            ("hp5-control", "https", "0"),
            ("hp5-nosni", "tls", "1"),
        ],
        "HP6" => &[
            ("hp6b-dns", "dns-udp", "OK"),
            ("hp6a-dns", "dns-udp", "OK"),
            ("hp6-first", "https", "301"),
            ("hp6-redirect", "https", "1"),
        ],
        "HP6c" => &[
            ("hp6b-dns", "dns-udp", "OK"),
            ("hp6a-dns", "dns-udp", "OK"),
            ("hp6-first", "https", "301"),
            ("hp6-redirect", "https", "0"),
        ],
        _ => &[],
    };
    rows.to_vec()
}

/// The hostname tier is every case whose flags name `sslip.io` renderings, plus
/// the two cases whose tier membership is a control relationship (RB2, PXH1).
pub fn hostname_tier(case: &Case) -> bool {
    matches!(case.case, "RB2" | "PXH1") || !hostname_rows(case).is_empty()
}

fn hostname_values(lan: &str, lan2: &str) -> BTreeMap<&'static str, String> {
    let dashed = lan.replace('.', "-");
    let dashed2 = if lan2.is_empty() { DEFAULT_LAN2 } else { lan2 }.replace('.', "-");
    let name = |prefix: &str, suffix: &str| format!("{prefix}.{suffix}.sslip.io");
    let cidr = format!(
        "{}.0/24",
        lan.rsplit_once('.').map(|(head, _)| head).unwrap_or(lan)
    );
    BTreeMap::from([
        ("lan", lan.to_owned()),
        ("cidr", cidr),
        ("hnc", name("hnc", &dashed)),
        ("hn1a", name("hn1a", &dashed)),
        ("hn1b", name("hn1b", &dashed)),
        ("hn1c", name("hn1c", &dashed)),
        ("hn1d", name("hn1d", &dashed)),
        ("hn2a", name("hn2a", &dashed)),
        ("hn2b", name("hn2b", &dashed2)),
        ("hn3", name("hn3", &dashed)),
        ("hn4a", name("hn4a", &dashed)),
        ("hn4b", name("hn4b", &dashed)),
        ("hn5", name("hn5", &dashed)),
        ("hn6", name("hn6", &dashed)),
        ("op1", name("op1", &dashed)),
        ("op2", name("op2", &dashed)),
        ("op3", name("op3", &dashed)),
        ("rb2", name("rb2", &dashed)),
        ("hp4a", HP4_PAIR.0.to_owned()),
        ("hp4b", HP4_PAIR.1.to_owned()),
    ])
}

/// Substitute `{name}` tokens. The Python used `str.format(**values)`; only the
/// harness's own templates reach here, so an unknown token is a programming
/// error and leaves the text alone rather than panicking mid-plan.
fn expand(template: &str, values: &BTreeMap<&'static str, String>) -> String {
    let mut text = template.to_owned();
    for (key, value) in values {
        text = text.replace(&format!("{{{key}}}"), value);
    }
    text
}

/// Raw argv tokens for one hostname-tier case. `{admission}` is the HNc ladder
/// step's private-answer admission; any other non-`--` token is an
/// `--allow-egress` allowance.
fn hostname_argv_flags(
    case: &Case,
    values: &BTreeMap<&'static str, String>,
    hnc_step: &str,
) -> Vec<String> {
    let admission: Vec<String> = if hnc_step == "b" {
        vec!["--allow-lan".to_owned()]
    } else {
        vec![
            "--allow-egress".to_owned(),
            format!("udp://{}/32", values["lan"]),
        ]
    };
    let mut flags = Vec::new();
    for flag in case.flags {
        if *flag == "{admission}" {
            flags.extend(admission.clone());
        } else if flag.starts_with("--") {
            flags.push(expand(flag, values));
        } else {
            flags.push("--allow-egress".to_owned());
            flags.push(expand(flag, values));
        }
    }
    flags
}

/// The case's fourth guest argument: the names it must resolve, the ladder step,
/// or the shared-public pair.
fn hostname_extra(
    case: &Case,
    values: &BTreeMap<&'static str, String>,
    lan2: &str,
    hnc_step: &str,
) -> String {
    match case.case {
        "HNc" => format!("{},{hnc_step}", values["hnc"]),
        "HN1" => format!(
            "{},{},{},{}",
            values["hn1a"], values["hn1b"], values["hn1c"], values["hn1d"]
        ),
        "HN2" => format!("{},{},{lan2}", values["hn2a"], values["hn2b"]),
        "HN3" => values["hn3"].clone(),
        "HN4" => format!("{},{}", values["hn4a"], values["hn4b"]),
        "HN5" => values["hn5"].clone(),
        "HN6" => values["hn6"].clone(),
        "RB2" => values["rb2"].clone(),
        "HP1" => "example.com".to_owned(),
        "HP2" => "example.com,example.org".to_owned(),
        "HP2c" => "example.com,example.com".to_owned(),
        "HP3" => "example.com,files.pythonhosted.org".to_owned(),
        "HP4" => format!("{},{}", values["hp4a"], values["hp4b"]),
        "HP5" => "example.com".to_owned(),
        "HP6" | "HP6c" => "www.github.com,github.com".to_owned(),
        _ => String::new(),
    }
}

/// The labels a denial or NX attempt in this case is joined against.
fn hostname_controls(
    case: &Case,
) -> &'static [(&'static str, (&'static str, &'static str, &'static str))] {
    match case.case {
        "HN1" => &[
            ("hn1a-18444", ("HN1", "ipv4", "hn1a-18443")),
            ("hn1b-18443", ("HN1", "ipv4", "hn1b-18444")),
            ("hn1d-dns", ("HNc", "ipv4", "hnc-dns")),
            ("hn1d-18443", ("HN1", "ipv4", "hn1c-18443")),
        ],
        "HN2" => &[
            ("hn2a-wrong", ("HN2", "ipv4", "hn2a-lan")),
            ("hn2b-wrong", ("HN2", "ipv4", "hn2b-lan2")),
        ],
        "HN3" => &[
            ("hn3-nosni", ("HN3", "ipv4", "hn3-sni")),
            ("hn3-plain", ("HN3", "ipv4", "hn3-sni")),
            ("lan-tcp80", ("LC1", "ipv4", "lan-tcp80")),
        ],
        "HN4" => &[("hn4b-tls", ("HN4", "ipv4", "hn4a-tls"))],
        "HN5" => &[("hn5-plain", ("HN5", "ipv4", "hn5-name"))],
        "HN6" => &[("hn6-nohost", ("HN6", "ipv4", "lan-tcp80"))],
        "OP1" => &[("op-printable", ("OP1c", "ipv4", "op-printable"))],
        "HP1" => &[
            ("hp1-scope-udp", ("HP1", "ipv4", "hp1-com-dns")),
            ("hp1-scope-tcp", ("HP1", "ipv4", "hp1-com-dns")),
            ("hp1-http", ("HP1", "ipv4", "hp1-https")),
        ],
        "HP2" => &[("hp2-switch", ("HP2c", "ipv4", "hp2c-same"))],
        "HP3" => &[("hp3-spoof", ("HP3", "ipv4", "hp3-control"))],
        "HP4" => &[("hp4-b", ("HP4", "ipv4", "hp4-a"))],
        "HP5" => &[("hp5-nosni", ("HP5", "ipv4", "hp5-control"))],
        "HP6" => &[("hp6-redirect", ("HP6c", "ipv4", "hp6-redirect"))],
        "RB2" => match case.variant {
            "hostname-only" => &[
                ("rb2-hostname-only-udp", ("RB2", "lan", "rb2-lan-udp")),
                ("rb2-hostname-only-tcp", ("RB2", "lan", "rb2-lan-tcp")),
            ],
            "port" => &[
                ("rb2-port-udp", ("RB2", "lan", "rb2-lan-udp")),
                ("rb2-port-tcp", ("RB2", "lan", "rb2-lan-tcp")),
            ],
            "tcp-port" => &[
                ("rb2-tcp-port-udp", ("RB2", "lan", "rb2-lan-udp")),
                ("rb2-tcp-port-tcp", ("RB2", "lan", "rb2-lan-tcp")),
            ],
            _ => &[],
        },
        _ => &[],
    }
}

/// Links identify the exact successful attempt, including resolver, name and
/// transport.
pub fn control_links(case: &Case) -> Vec<(String, String)> {
    if matches!(case.case, "NR1" | "NR2" | "NR3" | "PA2") {
        return Vec::new();
    }
    let mut links: Vec<(String, String)> = FLOW_CONTROLS
        .iter()
        .map(|(label, target)| ((*label).to_owned(), (*target).to_owned()))
        .collect();
    for (label, (target_case, variant, target)) in hostname_controls(case) {
        links.push((
            (*label).to_owned(),
            format!("{target_case}:{variant}:{target}"),
        ));
    }
    for protocol in ["udp", "tcp"] {
        for resolver in ["gateway", "explicit"] {
            links.push((
                format!("{resolver}-{protocol}"),
                format!("I1:ipv4:{resolver}-{protocol}"),
            ));
        }
        links.push((
            format!("provider-{protocol}"),
            format!("CR1c:ipv4:provider-{protocol}"),
        ));
        links.push((
            format!("explicit-v6-{protocol}"),
            format!("DNS6c:ipv6:explicit-v6-{protocol}"),
        ));
        links.push((
            format!("rebind-{protocol}"),
            format!("RB1:address:rebind-{protocol}"),
        ));
    }
    if case.case.starts_with("HK") {
        // HK1c/HK2c are the controls of HK1/HK2: the case proves its own hook.
        links.push(("hook".to_owned(), format!("{}c:ipv4:hook", &case.case[..3])));
    }
    if matches!(case.case, "FL1" | "FL2") {
        links.push(("floor".to_owned(), "FL0:ipv4:public-1111".to_owned()));
    }
    links
}

pub fn expected_attempts(case: &Case) -> Vec<&'static str> {
    if matches!(case.case, "NR1" | "NR2" | "NR3" | "RF1" | "PA2") {
        return Vec::new();
    }
    if hostname_tier(case) {
        return hostname_rows(case).into_iter().map(|row| row.0).collect();
    }
    let labels: &[&str] = match case.case {
        "P0" | "CL1" | "RJ1" => &[],
        "LC1" => &["lan-tcp80", "lan-tcp81", "lan-udp90", "lan-udp80"],
        "HC1" => &["host-tcp80", "gateway-udp", "gateway-tcp"],
        "I1" => &[
            "public-1111",
            "public-1001",
            "gateway-udp",
            "gateway-tcp",
            "explicit-udp",
            "explicit-tcp",
            "lan-tcp80",
            "host-tcp80",
        ],
        "D1" => {
            if case.variant == "ipv6" {
                &["explicit-v6-udp", "explicit-v6-tcp"]
            } else {
                &[
                    "lan-tcp80",
                    "lan-udp90",
                    "host-tcp80",
                    "public-1111",
                    "gateway-udp",
                    "gateway-tcp",
                    "explicit-udp",
                    "explicit-tcp",
                ]
            }
        }
        "D1f" => &["lan-tcp80", "public-1111", "gateway-udp"],
        "L1" => &[
            "lan-tcp80",
            "lan-udp90",
            "public-1111",
            "host-tcp80",
            "gateway-udp",
            "gateway-tcp",
        ],
        "H1" => &[
            "host-tcp80",
            "lan-tcp80",
            "public-1111",
            "gateway-udp",
            "gateway-tcp",
            "answer",
        ],
        "I1a" => &["answer"],
        "LH1" => &["lan-tcp80", "host-tcp80", "public-1111"],
        "AD1" => &[
            "public-1111",
            "public-1001",
            "gateway-udp",
            "gateway-tcp",
            "explicit-udp",
            "explicit-tcp",
        ],
        "TP1" => &["lan-tcp80", "lan-udp80", "lan-tcp81"],
        "PA1" => &["lan-tcp80", "lan-tcp81"],
        "PA1x" => &["lan-tcp80"],
        "UP1" => &["lan-udp90", "lan-udp80", "lan-tcp80"],
        "UP2" => &["lan-tcp80", "lan-udp80", "lan-tcp81"],
        "CI1" => &["lan-tcp80", "lan-tcp81"],
        "PX1" => &["lan-tcp80", "lan-tcp81"],
        "PX2" => &["lan-tcp80"],
        "PX3" => &["lan-tcp80", "public-1111"],
        "FL0" => &["public-1111"],
        "FL1" | "FL2" => &["lan-tcp80"],
        "CR1" | "CR1c" => &["provider-udp", "provider-tcp", "public-1111"],
        "IN1" | "IN2" => &["public-1111"],
        "HK1" | "HK1c" | "HK2" | "HK2c" => &["hook"],
        "V6" | "V6c" => &["public-v6-1111", "public-v6-1001"],
        "DNS6c" => &["explicit-v6-udp", "explicit-v6-tcp"],
        "RB1" => &["rebind-udp", "rebind-tcp"],
        _ => &[],
    };
    labels.to_vec()
}

/// `dns-`/`public`/`udp`/`tcp`: what an attempt's line must look like, derived
/// from its label so the protocol table cannot drift from the labels.
pub fn attempt_protocol(label: &str) -> String {
    if ["gateway-", "explicit-", "provider-", "rebind-"]
        .iter()
        .any(|prefix| label.starts_with(prefix))
    {
        let protocol = label
            .rsplit_once('-')
            .map(|(_, tail)| tail)
            .unwrap_or(label);
        return format!("dns-{protocol}");
    }
    if label.starts_with("public-") || label == "answer" {
        return "public".to_owned();
    }
    if label.contains("-udp") {
        return "udp".to_owned();
    }
    "tcp".to_owned()
}

pub fn attempt_expectations(case: &Case) -> Vec<(String, String)> {
    if matches!(case.case, "NR1" | "NR2" | "NR3" | "PA2") {
        return Vec::new();
    }
    if hostname_tier(case) {
        return hostname_rows(case)
            .into_iter()
            .map(|row| (row.0.to_owned(), row.2.to_owned()))
            .collect();
    }
    let denied: &[&str] = match case.case {
        "I1" => &["lan-tcp80", "host-tcp80"],
        "D1" => &["lan-tcp80", "lan-udp90", "host-tcp80", "public-1111"],
        "D1f" => &["lan-tcp80", "public-1111"],
        "L1" => &["public-1111", "host-tcp80"],
        "H1" => &["lan-tcp80", "public-1111", "answer"],
        "LH1" => &["public-1111"],
        "AD1" => &["public-1001"],
        "TP1" => &["lan-udp80", "lan-tcp81"],
        "PA1" => &["lan-tcp81"],
        "PA1x" => &["lan-tcp80"],
        "UP1" => &["lan-udp80", "lan-tcp80"],
        "UP2" => &["lan-tcp81"],
        "CI1" => &["lan-tcp81"],
        "PX1" => &["lan-tcp81"],
        "PX3" => &["lan-tcp80", "public-1111"],
        "FL1" | "FL2" => &["lan-tcp80"],
        "CR1" => &["public-1111"],
        "IN1" | "IN2" => &["public-1111"],
        "HK1" | "HK2" => &["hook"],
        "V6" => &["public-v6-1001"],
        _ => &[],
    };
    let dns_ok = matches!(case.case, "HC1" | "H1" | "I1" | "CR1c" | "DNS6c")
        || (case.case == "RB1" && matches!(case.variant, "address" | "tcp" | "udp"));
    expected_attempts(case)
        .into_iter()
        .map(|label| {
            let protocol = attempt_protocol(label);
            let expectation = if protocol.starts_with("dns-") {
                if dns_ok { "OK" } else { "NX" }
            } else if denied.contains(&label) {
                "1"
            } else {
                "0"
            };
            (label.to_owned(), expectation.to_owned())
        })
        .collect()
}

// --- The command model ------------------------------------------------------

/// One launch as the plan describes it. `None` and an empty list are different
/// on the wire: an administrative command declares no controls at all, while a
/// guest case declares an empty dict.
#[derive(Debug, Clone)]
pub struct Command {
    pub case: String,
    pub variant: String,
    pub tool: Option<String>,
    pub kind: String,
    pub env: Vec<(String, String)>,
    pub argv: Vec<String>,
    pub cwd: String,
    pub timeout: f64,
    pub grace: f64,
    pub declared_extras: Vec<String>,
    pub prerequisites: Vec<String>,
    pub controls: Option<Vec<(String, String)>>,
    pub setup: Vec<String>,
    pub expected_attempts: Vec<String>,
    pub attempt_expectations: Option<Vec<(String, String)>>,
    pub attempt_protocols: Option<Vec<(String, String)>>,
    pub supervisor: String,
}

/// The supervisor line a plan row carries. The Python named its shim; the shim
/// is now this binary's `exec-shim`, so the row says what actually runs.
pub const SUPERVISOR: &str =
    "owned-launch: harness exec-shim writes identity, redirects IO, execs argv";
pub const FIXTURE_SUPERVISOR: &str =
    "run-owned host fixture; readiness 5s, identity-checked teardown/reap <=5s";

/// This binary's own path: the fixture cluster, the resolver calibration and
/// the ingress driver are all `harness egress-fixtures …` subcommands.
pub fn program_path() -> String {
    program()
}

fn program() -> String {
    std::env::current_exe()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "harness".to_owned())
}

/// The `exec-shim` argv a launch is wrapped in: identity first, stdout and
/// stderr into the case log, stdin from `/dev/null`, then the candidate.
pub fn shim_argv(
    argv: &[String],
    output: &Path,
    env: &[(String, String)],
    identity: Option<&Path>,
) -> Vec<String> {
    let mut shim = vec![
        program(),
        "egress-fixtures".to_owned(),
        "exec-shim".to_owned(),
        "--output".to_owned(),
        output.to_string_lossy().into_owned(),
        "--environment".to_owned(),
        environment_json(env),
    ];
    if let Some(identity) = identity {
        shim.push("--identity".to_owned());
        shim.push(identity.to_string_lossy().into_owned());
    }
    shim.push("--".to_owned());
    shim.extend(argv.iter().cloned());
    shim
}

/// The environment as one JSON object string, keeping the order it was built
/// in: the shim replaces the environment wholesale, and a reordered object would
/// still be equal, but the plan is read by eyes as often as by `json.loads`.
fn environment_json(env: &[(String, String)]) -> String {
    let pairs: Vec<String> = env
        .iter()
        .map(|(name, value)| {
            format!(
                "{}: {}",
                Value::String(name.clone()),
                Value::String(value.clone())
            )
        })
        .collect();
    format!("{{{}}}", pairs.join(", "))
}

fn strings(values: &[&str]) -> Vec<Value> {
    values
        .iter()
        .map(|value| Value::String((*value).to_owned()))
        .collect()
}

fn pairs(values: &[(String, String)]) -> Map<String, Value> {
    values
        .iter()
        .map(|(name, value)| (name.clone(), Value::String(value.clone())))
        .collect()
}

impl Command {
    fn env_value(&self, name: &str) -> Option<&str> {
        self.env
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The JSONL plan row: `asdict(self)` plus the shim and the cleanup bounds.
    ///
    /// The shim's output and identity paths are derived from
    /// `AGENT_VM_STATE_DIR`'s parent rather than from `cwd`, so a case whose cwd
    /// is a per-case project directory still writes its log under the work root.
    pub fn plan(&self) -> Value {
        self.plan_with(None, None)
    }

    /// The same row with the log and identity paths overridden, which is what an
    /// administrative command's receipt records (it runs under an indexed
    /// `admin-<ns>.log`) and what an owned launch records (its ident carries a
    /// monotonic stamp, so the derived name would be a different file).
    pub fn plan_with(&self, output: Option<&Path>, identity: Option<&Path>) -> Value {
        let work = self
            .env_value("AGENT_VM_STATE_DIR")
            .map(|state| {
                Path::new(state)
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let output = output
            .map(Path::to_path_buf)
            .unwrap_or_else(|| work.join(format!("{}-{}.log", self.case, self.variant)));
        let identity = identity.map(Path::to_path_buf).or_else(|| {
            matches!(self.kind.as_str(), "guest" | "validation-only")
                .then(|| work.join(format!("{}-{}.identity.json", self.case, self.variant)))
        });
        let shim = if self.case == "fixture-start" {
            Value::Null
        } else {
            json!({
                "argv": shim_argv(&self.argv, &output, &self.env, identity.as_deref())
                    .into_iter()
                    .map(Value::String)
                    .collect::<Vec<Value>>(),
                "stdin": "devnull",
                "output": output.to_string_lossy(),
                "identity_file": identity.map(|path| Value::String(path.to_string_lossy().into_owned())),
            })
        };
        let mut row = Map::new();
        row.insert("case".to_owned(), Value::String(self.case.clone()));
        row.insert("variant".to_owned(), Value::String(self.variant.clone()));
        row.insert(
            "tool".to_owned(),
            self.tool.clone().map(Value::String).unwrap_or(Value::Null),
        );
        row.insert("kind".to_owned(), Value::String(self.kind.clone()));
        row.insert("env".to_owned(), Value::Object(pairs(&self.env)));
        row.insert(
            "argv".to_owned(),
            Value::Array(
                self.argv
                    .iter()
                    .map(|argument| Value::String(argument.clone()))
                    .collect(),
            ),
        );
        row.insert("cwd".to_owned(), Value::String(self.cwd.clone()));
        row.insert("timeout".to_owned(), json!(self.timeout));
        row.insert("grace".to_owned(), json!(self.grace));
        row.insert(
            "declared_extras".to_owned(),
            Value::Array(strings(
                &self
                    .declared_extras
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<&str>>(),
            )),
        );
        row.insert(
            "prerequisites".to_owned(),
            Value::Array(strings(
                &self
                    .prerequisites
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<&str>>(),
            )),
        );
        row.insert(
            "controls".to_owned(),
            self.controls
                .as_ref()
                .map(|controls| Value::Object(pairs(controls)))
                .unwrap_or(Value::Null),
        );
        row.insert(
            "setup".to_owned(),
            Value::Array(strings(
                &self.setup.iter().map(String::as_str).collect::<Vec<&str>>(),
            )),
        );
        row.insert(
            "expected_attempts".to_owned(),
            Value::Array(strings(
                &self
                    .expected_attempts
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<&str>>(),
            )),
        );
        row.insert(
            "attempt_expectations".to_owned(),
            self.attempt_expectations
                .as_ref()
                .map(|rows| Value::Object(pairs(rows)))
                .unwrap_or(Value::Null),
        );
        row.insert(
            "attempt_protocols".to_owned(),
            self.attempt_protocols
                .as_ref()
                .map(|rows| Value::Object(pairs(rows)))
                .unwrap_or(Value::Null),
        );
        row.insert(
            "supervisor".to_owned(),
            Value::String(self.supervisor.clone()),
        );
        row.insert("shim".to_owned(), shim);
        row.insert(
            "cleanup_bounds".to_owned(),
            json!({"launch": CLEANUP_BOUND, "absence_poll": 10, "fixture": 5}),
        );
        Value::Object(row)
    }
}

/// The knobs a single case's build needs beyond the four shared ones.
pub struct BuildOptions<'a> {
    pub answer: &'a str,
    pub rebind: &'a str,
    pub attempt: &'a str,
    pub lan2: &'a str,
    pub hnc_step: &'a str,
}

impl Default for BuildOptions<'_> {
    fn default() -> Self {
        Self {
            answer: "ANSWER_FROM_H1",
            rebind: "",
            attempt: "",
            lan2: "",
            hnc_step: "a",
        }
    }
}

pub fn build_command(
    case: &Case,
    work: &Path,
    binary: &str,
    lan: &str,
    options: &BuildOptions<'_>,
) -> Command {
    let mut env = base_environment(work);
    let cidr = format!(
        "{}.0/24",
        lan.rsplit_once('.').map(|(head, _)| head).unwrap_or(lan)
    );
    let simple = BTreeMap::from([("lan", lan.to_owned()), ("cidr", cidr)]);
    let values = if hostname_tier(case) {
        hostname_values(lan, options.lan2)
    } else {
        simple
    };
    if matches!(case.case, "NR1" | "NR2" | "NR3") {
        let trailing: &[&str] = if case.tool == "pi" {
            &["--version"]
        } else {
            &["echo", "AGENT_VM_328_SHELL_STARTED"]
        };
        let mut argv = vec![
            binary.to_owned(),
            "--no-git".to_owned(),
            "--image".to_owned(),
            IMAGE.to_owned(),
        ];
        argv.extend(case.flags.iter().map(|flag| (*flag).to_owned()));
        argv.push(case.tool.to_owned());
        argv.extend(trailing.iter().map(|argument| (*argument).to_owned()));
        return Command {
            case: case.case.to_owned(),
            variant: case.variant.to_owned(),
            tool: Some(case.tool.to_owned()),
            kind: "guest".to_owned(),
            env,
            argv,
            cwd: work.join("requests").to_string_lossy().into_owned(),
            timeout: 300.0,
            grace: 10.0,
            declared_extras: case.extras.iter().map(|name| (*name).to_owned()).collect(),
            prerequisites: Vec::new(),
            controls: Some(Vec::new()),
            setup: Vec::new(),
            expected_attempts: Vec::new(),
            attempt_expectations: Some(Vec::new()),
            attempt_protocols: Some(Vec::new()),
            supervisor: SUPERVISOR.to_owned(),
        };
    }
    let extras = [
        ("HTTP_PROXY", "http://127.0.0.1:18888".to_owned()),
        ("HTTPS_PROXY", "http://127.0.0.1:18888".to_owned()),
        ("NO_PROXY", lan.to_owned()),
        (
            "MSB_CONFIG_PATH",
            work.join("floor.json").to_string_lossy().into_owned(),
        ),
    ];
    for name in case.extras {
        if let Some((_, value)) = extras.iter().find(|(key, _)| key == name) {
            env.push(((*name).to_owned(), value.clone()));
        }
    }
    let flags: Vec<String> = if hostname_tier(case) {
        hostname_argv_flags(case, &values, options.hnc_step)
    } else {
        case.flags
            .iter()
            .map(|flag| expand(flag, &values))
            .collect()
    };
    let mut argv = vec![
        binary.to_owned(),
        "--no-git".to_owned(),
        "--image".to_owned(),
        IMAGE.to_owned(),
    ];
    argv.extend(flags);
    argv.push(case.tool.to_owned());
    let ident = if options.attempt.is_empty() {
        format!("{}-{}", case.case, case.variant)
    } else {
        options.attempt.to_owned()
    };
    if case.guest {
        let extra = if hostname_tier(case) {
            let lan2 = if options.lan2.is_empty() {
                DEFAULT_LAN2
            } else {
                options.lan2
            };
            hostname_extra(case, &values, lan2, options.hnc_step)
        } else if case.case == "I1a" {
            options.answer.to_owned()
        } else if case.case == "RB1" {
            options.rebind.to_owned()
        } else {
            String::new()
        };
        argv.extend([
            case.case.to_owned(),
            ident,
            lan.to_owned(),
            case.variant.to_owned(),
            extra,
        ]);
    }
    let project = if case.case.starts_with("HK") {
        work.join(&case.case[..3])
    } else if case.tool == "egresscreds" {
        work.join("creds")
    } else {
        work.join("proj")
    };
    let mut setup: Vec<String> = Vec::new();
    if case.tool == "egresscreds" {
        setup.push(
            "private synthetic anthropic OAuth seed; remove seed and captured material".to_owned(),
        );
    }
    if ALLOWANCE_CASES.contains(&case.case) {
        setup.push(
            "private project allowance record seeded for this case's project digest; \
             remove the record after the launch"
                .to_owned(),
        );
    }
    if case.case == "PA2" {
        // No seed: PA2 starts from default deny and writes the record with its own
        // live `--project` grant, which is the point of the case. What it needs is
        // the opposite of a seed -- an *absent* store and no stale signal files --
        // and it leaves the writer's never-unlinked `allowances.lock` behind, so
        // its cleanup is `cleanup_pa2`, not `remove_allowances`.
        setup.push(
            "no seed: the case records the allowance with its own live grant; \
             remove the record and allowances.lock after the launch"
                .to_owned(),
        );
    }
    let protocols: Vec<(String, String)> = if hostname_tier(case) {
        hostname_rows(case)
            .into_iter()
            .map(|row| (row.0.to_owned(), row.1.to_owned()))
            .collect()
    } else {
        expected_attempts(case)
            .into_iter()
            .map(|label| (label.to_owned(), attempt_protocol(label)))
            .collect()
    };
    Command {
        case: case.case.to_owned(),
        variant: case.variant.to_owned(),
        tool: Some(case.tool.to_owned()),
        kind: if case.guest {
            "guest"
        } else {
            "validation-only"
        }
        .to_owned(),
        env,
        argv,
        cwd: project.to_string_lossy().into_owned(),
        timeout: if case.guest { 300.0 } else { 10.0 },
        grace: 10.0,
        declared_extras: case.extras.iter().map(|name| (*name).to_owned()).collect(),
        prerequisites: if case.optional.is_empty() {
            Vec::new()
        } else {
            vec![case.optional.to_owned()]
        },
        controls: Some(control_links(case)),
        setup,
        expected_attempts: expected_attempts(case)
            .into_iter()
            .map(str::to_owned)
            .collect(),
        attempt_expectations: Some(attempt_expectations(case)),
        attempt_protocols: Some(protocols),
        supervisor: SUPERVISOR.to_owned(),
    }
}

/// One `agent-vm msb` (or fixture, or curl) command run under the same owned
/// supervision as a case, with no case evidence of its own.
pub fn admin_command(work: &Path, binary: &str, verb: &str, args: &[&str], bound: f64) -> Command {
    let mut argv = vec![binary.to_owned(), "msb".to_owned()];
    argv.extend(args.iter().map(|argument| (*argument).to_owned()));
    Command {
        case: verb.to_owned(),
        variant: "admin".to_owned(),
        tool: None,
        kind: "admin".to_owned(),
        env: base_environment(work),
        argv,
        cwd: work.join("proj").to_string_lossy().into_owned(),
        timeout: bound,
        grace: ADMIN_GRACE,
        declared_extras: Vec::new(),
        prerequisites: Vec::new(),
        controls: None,
        setup: Vec::new(),
        expected_attempts: Vec::new(),
        attempt_expectations: None,
        attempt_protocols: None,
        supervisor: SUPERVISOR.to_owned(),
    }
}

pub fn health_command(work: &Path) -> Command {
    let mut command = admin_command(work, &program(), "fixture-health", &[], 5.0);
    command.argv = vec![
        program(),
        "egress-fixtures".to_owned(),
        "health".to_owned(),
        "--dir".to_owned(),
        work.join("fx").to_string_lossy().into_owned(),
    ];
    command
}

pub fn fixture_command(work: &Path) -> Command {
    let mut command = admin_command(work, &program(), "fixture-start", &[], 5.0);
    command.argv = vec![
        program(),
        "egress-fixtures".to_owned(),
        "serve".to_owned(),
        "--dir".to_owned(),
        work.join("fx").to_string_lossy().into_owned(),
    ];
    command.supervisor = FIXTURE_SUPERVISOR.to_owned();
    command
}

pub fn ingress_command(work: &Path, case: &str, host_port: Option<u16>) -> Command {
    let port = host_port.unwrap_or(if case == "IN1" { 18556 } else { 18555 });
    Command {
        case: case.to_owned(),
        variant: "curl".to_owned(),
        tool: None,
        kind: "admin".to_owned(),
        env: base_environment(work),
        argv: [
            "/usr/bin/curl",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "2",
            "--max-time",
            "3",
            &format!("http://127.0.0.1:{port}/"),
        ]
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect(),
        cwd: work.join("proj").to_string_lossy().into_owned(),
        timeout: 5.0,
        grace: ADMIN_GRACE,
        declared_extras: Vec::new(),
        prerequisites: Vec::new(),
        controls: None,
        setup: Vec::new(),
        expected_attempts: Vec::new(),
        attempt_expectations: None,
        attempt_protocols: None,
        supervisor: SUPERVISOR.to_owned(),
    }
}

// --- Supervised administrative commands -------------------------------------

/// One receipt line in the run's own log, fsynced like the fixture receipts: the
/// cleanup path reads it back while the launch it describes is still running.
pub fn append_owned(work: &Path, receipt: &Value) -> Result<(), String> {
    let path = work.join("owned.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("admin: {path:?}: {error}"))?;
    writeln!(file, "{receipt}").map_err(|error| format!("admin: {path:?}: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("admin: {path:?}: {error}"))?;
    Ok(())
}

/// Run one command under the owned supervisor, bounded by its own timeout and by
/// the caller's deadline, and keep the output.
///
/// The administrative commands are the CLI's own verbs (`list`, `stop`,
/// `remove`) plus the fixture probes, so a cleanup that used direct database
/// writes or a prefix-based kill would prove nothing about the CLI.
pub fn run_admin(
    work: &Path,
    command: &Command,
    deadline: Option<Instant>,
) -> Result<(i32, String), String> {
    let log = work.join(format!("admin-{}.log", monotonic_nanos()));
    append_owned(
        work,
        &json!({
            "phase": "admin",
            "command": command.plan_with(Some(&log), None),
            "log": log.to_string_lossy(),
        }),
    )?;
    let shim = Command {
        // An administrative command has no identity receipt of its own: it is
        // the harness's child, and only a launch owns a group.
        argv: shim_argv(&command.argv, &log, &command.env, None),
        ..command.clone()
    };
    let status = bounded_command(&shim, deadline)?;
    let text = std::fs::read(&log)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    append_owned(
        work,
        &json!({"phase": "admin-result", "argv": command.argv, "status": status}),
    )?;
    Ok((status, text))
}

/// The exit status of one bounded command: 124 when its own bound expired and
/// `128 + N` when a signal interrupted it, so a caller joining statuses cannot
/// mistake a timeout for a refusal.
pub fn bounded_command(command: &Command, deadline: Option<Instant>) -> Result<i32, String> {
    let mut bound = command.timeout;
    if let Some(deadline) = deadline {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_secs_f64()
            - command.grace;
        if remaining <= 0.0 {
            return Err("administrative cleanup deadline exhausted".to_owned());
        }
        bound = bound.min(remaining);
    }
    let bounds = Bounds::new(bound, command.grace).map_err(|error| error.to_string())?;
    let spec = LaunchSpec {
        argv: command.argv.iter().map(OsString::from).collect(),
        env: command
            .env
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect(),
        cwd: Some(PathBuf::from(&command.cwd)),
    };
    match run_in_owned_group(&spec, bounds, &mut ()) {
        Ok(status) => Ok(exit_code(status)),
        Err(LaunchError::TimedOut) => Ok(124),
        Err(LaunchError::Interrupted(signal)) => Ok(128 + signal.as_raw()),
        Err(error) => Err(error.to_string()),
    }
}

/// The ingress driver (I1-I3): wait for the guest's readiness line, then poll the
/// published port until the body is exactly `ingress <id>`.
///
/// 130/143 are passed straight through: an interrupted run must not be reported
/// as a body mismatch.
pub fn ingress_driver(
    work: &Path,
    case: &str,
    ident: &str,
    host_port: Option<u16>,
) -> Result<i32, String> {
    let log = work.join(format!("{ident}.log"));
    let port = if case == "IN1" { 8000 } else { 18555 };
    let ready = format!("INGRESS_READY {ident} {port}");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if log_has_line(&log, &ready) {
            break;
        }
        if Instant::now() >= deadline {
            return Ok(1);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (status, body) = run_admin(
            work,
            &ingress_command(work, case, host_port),
            Some(deadline),
        )?;
        if status == 130 || status == 143 {
            return Ok(status);
        }
        if status == 0 {
            return Ok(if body == format!("ingress {ident}") {
                0
            } else {
                1
            });
        }
        if Instant::now() >= deadline {
            return Ok(1);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The readiness line is matched as a whole line: `INGRESS_READY IN1 8000` must
/// not be satisfied by `INGRESS_READY IN1 80001`.
fn log_has_line(log: &Path, line: &str) -> bool {
    std::fs::read(log)
        .map(|bytes| {
            String::from_utf8_lossy(&bytes)
                .lines()
                .any(|observed| observed == line)
        })
        .unwrap_or(false)
}

// --- The plan ---------------------------------------------------------------

/// The cases this run selects. `AGENT_VM_EGRESS_CASES=RF1` narrows a tier to
/// named cases so one case can be re-run after a fix without paying for the
/// whole sweep.
pub fn selected_cases(smoke: bool) -> Vec<&'static Case> {
    let only: Vec<String> = std::env::var("AGENT_VM_EGRESS_CASES")
        .unwrap_or_default()
        .split(',')
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect();
    CASES
        .iter()
        .filter(|case| {
            !smoke
                || (case.optional.is_empty()
                    && matches!(
                        case.case,
                        "P0" | "LC1" | "HC1" | "I1" | "D1" | "L1" | "NR1" | "NR2" | "NR3" | "RF1"
                    ))
        })
        .filter(|case| only.is_empty() || only.iter().any(|name| name == case.case))
        .collect()
}

/// The whole plan as JSONL: every selected case, then the nine administrative
/// objects the run needs around them.
pub fn print_plan(work: &Path, binary: &str, lan: &str, smoke: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    for case in selected_cases(smoke) {
        lines.push(
            build_command(case, work, binary, lan, &BuildOptions::default())
                .plan()
                .to_string(),
        );
    }
    let admins = [
        admin_command(
            work,
            binary,
            "image-load",
            &[
                "image",
                "load",
                "--input",
                "VERIFIED_NATIVE_ARCHIVE",
                "--tag",
                IMAGE,
            ],
            900.0,
        ),
        admin_command(work, binary, "list", &["list", "--format", "json"], 10.0),
        admin_command(
            work,
            binary,
            "stop",
            &["stop", "--timeout", "5", "NAME_FROM_OWNED_RECEIPT"],
            15.0,
        ),
        admin_command(
            work,
            binary,
            "force-stop",
            &["stop", "--force", "NAME_FROM_OWNED_RECEIPT"],
            10.0,
        ),
        admin_command(
            work,
            binary,
            "remove",
            &["remove", "NAME_FROM_OWNED_RECEIPT"],
            10.0,
        ),
        ingress_command(work, "IN1", None),
        ingress_command(work, "IN2", None),
        health_command(work),
        fixture_command(work),
    ];
    for command in admins {
        lines.push(command.plan().to_string());
    }
    lines.join("\n")
}

// --- Default-request diagnostics (self-test block B) ------------------------

pub const POLICY_NOTICE: &str = "==> Egress policy: all guest egress denied (opt in with --allow-internet-egress, --allow-egress, --allow-lan or --allow-host)";
pub const DNS_NOTICE: &str = "==> Egress DNS: queries denied (NXDOMAIN when forwarder is available; use IP or hostname allowances)";
const UNMET_HEADER: &str = "==> Tool network requests (built-in defaults): 5 of 5 not covered by this launch's public or same-name grants (no lookup; DNS, private-answer and TLS client limits still apply); requests never grant access and the launch continues";
const GRANT_HINT: &str = "==>   to grant: --allow-egress HOST or tcp://HOST:PORT, or --allow-internet-egress; IP/CIDR, --allow-lan and --allow-host grants are not matched to names";
const COVERED_HEADER: &str = "==> Tool network requests (built-in defaults): all 5 covered by this launch's public or same-name grants (no lookup; DNS, private-answer and TLS client limits still apply); requests never grant access";
const UNMET_NAMES: [&str; 5] = [
    "api.anthropic.com",
    "auth.openai.com",
    "chatgpt.com",
    "mcp-proxy.anthropic.com",
    "platform.claude.com",
];

/// The project a default-request case runs in: it must have no tool catalog of
/// its own, or the report would be about the catalog instead of the defaults.
pub fn prepare_default_request_project(work: &Path) -> Result<PathBuf, String> {
    let project = work.join("requests");
    std::fs::create_dir_all(&project).map_err(|error| error.to_string())?;
    for config in [
        project.join(".agent-vm/config.toml"),
        work.join("home/.config/agent-vm/config.toml"),
        work.join("config/agent-vm/config.toml"),
    ] {
        if config.exists() {
            return Err("default-request project requires isolated absent tool config".to_owned());
        }
    }
    Ok(project)
}

fn version_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '.' || character == '-'
}

/// `[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?` as a whole
/// line, without a regex engine: neither `-` nor `.` may start a group early, so
/// the split points are unambiguous.
fn is_semantic_version(line: &str) -> bool {
    let (main, build) = match line.split_once('+') {
        Some((main, build)) => (main, Some(build)),
        None => (line, None),
    };
    let (core, pre) = match main.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (main, None),
    };
    let segments: Vec<&str> = core.split('.').collect();
    if segments.len() != 3
        || !segments
            .iter()
            .all(|segment| !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    for group in [pre, build].into_iter().flatten() {
        if group.is_empty() || !group.chars().all(version_character) {
            return false;
        }
    }
    true
}

/// Host-only diagnostic oracle; coverage is not provider connectivity.
///
/// The report is one contiguous block whose header count and listed names are
/// two sides of one claim, so both are compared in full rather than counted.
pub fn check_default_request_diagnostics(case: &Case, status: i32, text: &str) -> Vec<String> {
    let mut failures = Vec::new();
    if status != 0 {
        failures.push(format!("default-request launch status {status}"));
    }
    let lines: Vec<&str> = text.lines().collect();
    if case.case == "NR3" {
        if !lines.contains(&"AGENT_VM_328_SHELL_STARTED") {
            failures.push("shell marker missing".to_owned());
        }
    } else if !lines.iter().any(|line| is_semantic_version(line)) {
        failures.push("Pi semantic version missing".to_owned());
    }
    if matches!(case.case, "NR1" | "NR3") {
        for notice in [POLICY_NOTICE, DNS_NOTICE] {
            if !lines.contains(&notice) {
                failures.push("default-deny notice missing".to_owned());
            }
        }
    }
    let mut expected: Vec<String> = Vec::new();
    if case.case == "NR1" {
        expected.push(UNMET_HEADER.to_owned());
        for name in UNMET_NAMES {
            expected.push(format!("==>   unmet: {name}"));
        }
        expected.push(GRANT_HINT.to_owned());
    } else if case.case == "NR2" {
        expected.push(COVERED_HEADER.to_owned());
    }
    let observed: Vec<String> = lines
        .iter()
        .filter(|line| {
            line.starts_with("==> Tool network requests")
                || line.starts_with("==>   unmet:")
                || line.starts_with("==>   to grant:")
                || line.starts_with("==>   … and")
        })
        .map(|line| (*line).to_owned())
        .collect();
    if observed != expected {
        failures.push("default-request report framing/order/names mismatch".to_owned());
    }
    if !expected.is_empty() {
        let start = lines
            .iter()
            .position(|line| *line == expected[0])
            .map(|index| index as isize)
            .unwrap_or(-1);
        if start < 0
            || lines[start as usize..]
                .iter()
                .take(expected.len())
                .map(|line| (*line).to_owned())
                .collect::<Vec<String>>()
                != expected
        {
            failures.push("default-request block is not contiguous".to_owned());
        }
        for (index, line) in lines.iter().enumerate() {
            let notice = line.starts_with("==> Egress policy:")
                || line.starts_with("==> Egress DNS:")
                || line.starts_with("==> Guest egress proxy:");
            if notice && index as isize > start {
                failures.push("network notice after request report".to_owned());
            }
        }
    }
    failures
}

fn require(condition: bool, label: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(format!("self-test: {label}"))
    }
}

/// Block B of `self_test`: the default-request report and its mutants.
///
/// This is the block that was deferred until `build_command` existed. Every
/// mutation here changes the text it then rejects, so a check that stops
/// comparing (or compares by length) fails instead of passing quietly.
pub fn default_request_self_test() -> Result<(), String> {
    let work = std::env::temp_dir().join(format!(
        "harness-egress-requests-{}",
        crate::egress_fixtures::monotonic_nanos()
    ));
    std::fs::create_dir_all(&work).map_err(|error| error.to_string())?;
    let outcome = default_request_self_test_against(&work);
    let _ = std::fs::remove_dir_all(&work);
    outcome
}

fn default_request_self_test_against(work: &Path) -> Result<(), String> {
    let project = prepare_default_request_project(work)?;
    require(
        !project.join(".agent-vm/config.toml").exists(),
        "the default-request project must have no catalog of its own",
    )?;
    let deny = format!("{POLICY_NOTICE}\n{DNS_NOTICE}\n");
    let mut unmet = format!("{UNMET_HEADER}\n");
    for name in UNMET_NAMES {
        unmet.push_str(&format!("==>   unmet: {name}\n"));
    }
    unmet.push_str(&format!("{GRANT_HINT}\n"));
    let covered = format!("{COVERED_HEADER}\n");
    let triples = [
        (
            Case {
                tool: "pi",
                ..case("NR1")
            },
            format!("{deny}{unmet}0.87.1\n"),
            ["--version"].as_slice(),
        ),
        (
            Case {
                tool: "pi",
                flags: &["--allow-internet-egress"],
                ..case("NR2")
            },
            format!("{covered}0.87.1\n"),
            ["--version"].as_slice(),
        ),
        (
            Case {
                tool: "shell",
                ..case("NR3")
            },
            format!("{deny}AGENT_VM_328_SHELL_STARTED\n"),
            ["echo", "AGENT_VM_328_SHELL_STARTED"].as_slice(),
        ),
    ];
    for (case, text, trailing) in triples {
        let command = build_command(
            &case,
            work,
            "/candidate",
            "192.168.1.2",
            &BuildOptions::default(),
        );
        require(
            command.cwd == project.to_string_lossy(),
            "the default-request case must run in the isolated project",
        )?;
        let mut expected_argv = vec![
            "/candidate".to_owned(),
            "--no-git".to_owned(),
            "--image".to_owned(),
            IMAGE.to_owned(),
        ];
        expected_argv.extend(case.flags.iter().map(|flag| (*flag).to_owned()));
        expected_argv.push(case.tool.to_owned());
        expected_argv.extend(trailing.iter().map(|argument| (*argument).to_owned()));
        require(
            command.argv == expected_argv,
            "the built argv must be the candidate's",
        )?;
        require(
            command.expected_attempts.is_empty()
                && command.controls.as_ref().is_some_and(Vec::is_empty),
            "a default-request case declares no attempts and no controls",
        )?;
        require(
            check_default_request_diagnostics(&case, 0, &text).is_empty(),
            "the reference report must pass",
        )?;
        let padded =
            format!("==>   unrelated credential note\n{text}==>   unrelated launch note\n");
        require(
            check_default_request_diagnostics(&case, 0, &padded).is_empty(),
            "unrelated notes outside the block must be ignored",
        )?;
        require(
            !check_default_request_diagnostics(&case, 1, &text).is_empty(),
            "a non-zero launch status must fail the report",
        )?;
        let stripped = text
            .replace("0.87.1", "")
            .replace("AGENT_VM_328_SHELL_STARTED", "");
        require(
            !check_default_request_diagnostics(&case, 0, &stripped).is_empty(),
            "a missing version or shell marker must fail the report",
        )?;
        if case.case != "NR3" {
            for (old, new) in [
                ("built-in defaults", "project config"),
                ("Tool network requests", "missing report"),
            ] {
                let mutated = text.replace(old, new);
                require(mutated != text, "a no-op mutation would assert nothing")?;
                require(
                    !check_default_request_diagnostics(&case, 0, &mutated).is_empty(),
                    "a rewritten report header must fail",
                )?;
            }
            // The header count and the listed names are two sides of one claim,
            // so they are mutated one at a time: the former global `5` -> `4`
            // replace moved both digits of `5 of 5` and left the header agreeing
            // with its own list, which pinned neither side.
            if case.case == "NR1" {
                for new in [": 4 of 5 not covered", ": 5 of 4 not covered"] {
                    let mutated = text.replace(": 5 of 5 not covered", new);
                    require(
                        mutated != text,
                        "the count mutation must change a real count",
                    )?;
                    require(
                        !check_default_request_diagnostics(&case, 0, &mutated).is_empty(),
                        "a header count that disagrees with its list must fail",
                    )?;
                }
                // Header count intact while the *last* name goes missing: a
                // length-blind (zip or prefix) block comparison would wave it
                // through.
                let mutated = text.replace("==>   unmet: platform.claude.com\n", "");
                require(mutated != text, "the list mutant must drop a real name")?;
                require(
                    !check_default_request_diagnostics(&case, 0, &mutated).is_empty(),
                    "a dropped unmet name must fail",
                )?;
            } else {
                // NR2 reports no list, so its whole report is the header.
                let mutated = text.replace("all 5 covered", "all 4 covered");
                require(mutated != text, "the NR2 count mutation must bite")?;
                require(
                    !check_default_request_diagnostics(&case, 0, &mutated).is_empty(),
                    "a covered count that disagrees with the defaults must fail",
                )?;
            }
        }
        if case.case == "NR1" {
            require(
                !check_default_request_diagnostics(&case, 0, &format!("{unmet}{deny}0.87.1\n"))
                    .is_empty(),
                "the report must precede the network notices",
            )?;
            // Sorted order is the contract; swap the first two *adjacent* names
            // so the mutation cannot collapse to a no-op.
            let reordered = text.replace(
                "==>   unmet: api.anthropic.com\n==>   unmet: auth.openai.com",
                "==>   unmet: auth.openai.com\n==>   unmet: api.anthropic.com",
            );
            require(
                reordered != text,
                "the reordering mutation must move real lines",
            )?;
            require(
                !check_default_request_diagnostics(&case, 0, &reordered).is_empty(),
                "an unsorted name list must fail",
            )?;
            for (old, new) in [
                ("platform.claude.com", "api.invalid.example"),
                ("==>   to grant:", "wrong hint:"),
                (unmet.as_str(), ""),
                (deny.as_str(), ""),
            ] {
                let mutated = text.replace(old, new);
                require(mutated != text, "a no-op mutation would assert nothing")?;
                require(
                    !check_default_request_diagnostics(&case, 0, &mutated).is_empty(),
                    "a wrong name, hint, or a missing block must fail",
                )?;
            }
        }
        if case.case == "NR3" {
            require(
                !check_default_request_diagnostics(&case, 0, &format!("{text}{covered}"))
                    .is_empty(),
                "a shell case must not carry the tool-request report",
            )?;
        }
    }
    // A user catalog may not shadow the executable defaults.
    let user = work.join("home/.config/agent-vm");
    std::fs::create_dir_all(&user).map_err(|error| error.to_string())?;
    std::fs::write(
        user.join("config.toml"),
        "[[tools]]\nname=\"shadow\"\ncommand=\"shadow\"\n",
    )
    .map_err(|error| error.to_string())?;
    require(
        prepare_default_request_project(work).is_err(),
        "a user catalog must not be allowed to shadow the defaults",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The §6.7 inventory, written out independently of `CASES`: a case that
    /// leaves the table must leave this list too, deliberately.
    fn published_inventory() -> Vec<(&'static str, &'static str)> {
        let mut expected: Vec<(&str, &str)> = "NR1 NR2 NR3 P0 LC1 HC1 I1 D1 D1f L1 H1 I1a LH1 \
             AD1 TP1 PA1 PA1x PA2 UP1 UP2 CI1 PX1 PX2 PX3 FL0 FL1 FL2 CR1c CR1 IN1 IN2 HK1c HK1 \
             HK2c HK2"
            .split_whitespace()
            .map(|case| (case, "ipv4"))
            .collect();
        expected.extend(
            ["V6c", "DNS6c", "V6", "D1"]
                .iter()
                .map(|case| (*case, "ipv6")),
        );
        expected.extend(
            [
                "address", "tcp", "udp", "internet", "port", "tcp-port", "udp-port",
            ]
            .iter()
            .map(|variant| ("RB1", *variant)),
        );
        expected.extend(
            [
                "udp-hostname",
                "dns-port",
                "alias",
                "wildcard",
                "numeric-final",
                "cidr-port",
                "scheme",
            ]
            .iter()
            .map(|variant| ("RJ1", *variant)),
        );
        expected.extend(
            "HNc HN1 HN2 HN3 HN4 HN5 HN5c HN6 OP1 OP1c OP2 OP2c OP3 OP3c"
                .split_whitespace()
                .map(|case| (case, "ipv4")),
        );
        expected.extend(
            ["hostname-only", "lan", "udp", "tcp", "port", "tcp-port"]
                .iter()
                .map(|variant| ("RB2", *variant)),
        );
        expected.extend(
            "HP1 HP2 HP2c HP3 HP4 HP5 HP6 HP6c PXH1 CL1"
                .split_whitespace()
                .map(|case| (case, "ipv4")),
        );
        expected.extend(["ipv4", "kill9"].iter().map(|variant| ("RF1", *variant)));
        expected
    }

    fn find(name: &str, variant: &str) -> &'static Case {
        CASES
            .iter()
            .find(|case| case.case == name && case.variant == variant)
            .unwrap_or_else(|| panic!("{name}/{variant} is in the catalogue"))
    }

    fn build(name: &str, variant: &str, options: BuildOptions<'_>) -> Command {
        build_command(
            find(name, variant),
            Path::new("/var/tmp/av302.PLAN"),
            "/absolute/bundle/bin/agent-vm",
            "192.168.1.2",
            &options,
        )
    }

    #[test]
    fn the_catalogue_is_the_published_inventory() {
        let expected = published_inventory();
        assert_eq!(expected.len(), 85);
        let published: Vec<(&str, &str)> =
            CASES.iter().map(|case| (case.case, case.variant)).collect();
        assert_eq!(published, expected);
    }

    #[test]
    fn the_smoke_tier_is_eleven_cases() {
        let smoke: Vec<&str> = CASES
            .iter()
            .filter(|case| case.optional.is_empty())
            .filter(|case| {
                matches!(
                    case.case,
                    "P0" | "LC1" | "HC1" | "I1" | "D1" | "L1" | "NR1" | "NR2" | "NR3" | "RF1"
                )
            })
            .map(|case| case.case)
            .collect();
        assert_eq!(smoke.len(), 11);
    }

    #[test]
    fn a_plan_row_carries_every_field_the_join_reads() {
        let plan = print_plan(
            Path::new("/var/tmp/av302.PLAN"),
            "/absolute/bundle/bin/agent-vm",
            "192.168.1.2",
            false,
        );
        let rows: Vec<Value> = plan
            .lines()
            .map(|line| serde_json::from_str(line).expect("each line is JSON"))
            .collect();
        assert_eq!(rows.len(), 94);
        let cases: Vec<&Value> = rows.iter().filter(|row| row["kind"] != "admin").collect();
        assert_eq!(cases.len(), 85);
        let admins: Vec<(&str, &str)> = rows
            .iter()
            .filter(|row| row["kind"] == "admin")
            .map(|row| {
                (
                    row["case"].as_str().unwrap(),
                    row["variant"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            admins,
            [
                ("image-load", "admin"),
                ("list", "admin"),
                ("stop", "admin"),
                ("force-stop", "admin"),
                ("remove", "admin"),
                ("IN1", "curl"),
                ("IN2", "curl"),
                ("fixture-health", "admin"),
                ("fixture-start", "admin"),
            ]
        );
        let base = [
            "HOME",
            "XDG_CONFIG_HOME",
            "AGENT_VM_STATE_DIR",
            "PATH",
            "TERM",
            "AGENT_VM_SHARE_MSB_CACHE",
        ];
        for row in &cases {
            let case = row["case"].as_str().unwrap();
            let env: Vec<&str> = row["env"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            for name in base {
                assert!(env.contains(&name), "{case}: {name} is in the environment");
            }
            assert_eq!(
                row["kind"].as_str().unwrap(),
                if matches!(case, "RJ1" | "PXH1") {
                    "validation-only"
                } else {
                    "guest"
                },
                "{case}: kind"
            );
            assert!(row["timeout"].as_f64().unwrap() > 0.0, "{case}: timeout");
            assert!(row["grace"].as_f64().unwrap() > 0.0, "{case}: grace");
            assert!(
                row["supervisor"].is_string() && row["cwd"].is_string(),
                "{case}"
            );
            assert!(row["controls"].is_object(), "{case}: controls");
            assert!(row["prerequisites"].is_array() && row["setup"].is_array());
            let shim = row["shim"]["argv"].as_array().unwrap();
            let exec_shim = shim
                .iter()
                .position(|token| token == "exec-shim")
                .expect("the shim argv names exec-shim");
            assert_eq!(shim[exec_shim + 1], "--output");
            assert_eq!(shim[exec_shim + 3], "--environment");
            assert!(
                shim[exec_shim + 5..].iter().any(|token| token == "--"),
                "{case}: the shim argv separates the candidate"
            );
            if row["kind"] == "guest" && !case.starts_with("NR") {
                let argv: Vec<&str> = row["argv"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|token| token.as_str().unwrap())
                    .collect();
                assert!(argv.contains(&case), "{case}: case title");
                assert!(argv.contains(&"192.168.1.2"), "{case}: lan");
                assert!(
                    argv.contains(&row["variant"].as_str().unwrap()),
                    "{case}: variant"
                );
            }
        }
        // The fixture supervisor is the one case whose shim is null: the harness
        // starts it itself so its readiness marker is written by the fixture.
        let fixture = rows
            .iter()
            .find(|row| row["case"] == "fixture-start")
            .unwrap();
        assert!(fixture["shim"].is_null());
        assert_eq!(fixture["supervisor"], FIXTURE_SUPERVISOR);
    }

    #[test]
    fn the_hostname_ladder_reaches_the_argv() {
        let hnc = |step: &str| {
            let options = BuildOptions {
                hnc_step: step,
                ..BuildOptions::default()
            };
            build("HNc", "ipv4", options).argv
        };
        // Steps (a) and (c) admit the private answer; step (b) is the diagnostic
        // `--allow-lan`, which cannot support deny evidence.
        for step in ["a", "c"] {
            assert!(
                hnc(step)
                    .windows(2)
                    .any(|pair| pair == ["--allow-egress", "udp://192.168.1.2/32"]),
                "step {step}"
            );
            assert!(!hnc(step).iter().any(|token| token == "--allow-lan"));
        }
        assert!(hnc("b").iter().any(|token| token == "--allow-lan"));
        assert_eq!(
            build(
                "HNc",
                "ipv4",
                BuildOptions {
                    hnc_step: "b",
                    ..BuildOptions::default()
                }
            )
            .argv
            .last()
            .map(String::as_str),
            Some("hnc.192-168-1-2.sslip.io,b")
        );
    }

    #[test]
    fn overrides_reach_the_argv_without_moving_anything_else() {
        let defaults = build("I1a", "ipv4", BuildOptions::default());
        assert_eq!(
            defaults.argv.last().map(String::as_str),
            Some("ANSWER_FROM_H1")
        );
        assert_eq!(
            build(
                "I1a",
                "ipv4",
                BuildOptions {
                    answer: "10.9.8.7",
                    ..BuildOptions::default()
                }
            )
            .argv
            .last()
            .map(String::as_str),
            Some("10.9.8.7")
        );
        assert_eq!(
            build(
                "RB1",
                "address",
                BuildOptions {
                    rebind: "192-168-1-2.sslip.io",
                    ..BuildOptions::default()
                }
            )
            .argv
            .last()
            .map(String::as_str),
            Some("192-168-1-2.sslip.io")
        );
        // A named attempt replaces the case-variant identity the guest reports,
        // while the case's own title and variant stay where they were.
        let ladder = build(
            "HNc",
            "ipv4",
            BuildOptions {
                attempt: "HNc-a-0",
                ..BuildOptions::default()
            },
        );
        assert!(ladder.argv.contains(&"HNc-a-0".to_owned()));
        assert!(ladder.argv.contains(&"HNc".to_owned()));
        assert_eq!(ladder.variant, "ipv4");
        // lan2 reaches HN2's second name and its third (numeric) argument.
        let hn2 = build(
            "HN2",
            "ipv4",
            BuildOptions {
                lan2: "10.1.2.3",
                ..BuildOptions::default()
            },
        );
        assert!(
            hn2.argv
                .contains(&"tcp://hn2b.10-1-2-3.sslip.io:18443".to_owned()),
            "{:?}",
            hn2.argv
        );
        assert!(hn2.argv.last().unwrap().ends_with(",10.1.2.3"));
        // The default is the TEST-NET address: plan-only, never dialed.
        assert!(
            build("HN2", "ipv4", BuildOptions::default())
                .argv
                .last()
                .unwrap()
                .ends_with(&format!(",{DEFAULT_LAN2}"))
        );
    }

    #[test]
    fn the_per_case_fields_the_join_pins() {
        // A tool-only case declares no probes and no controls.
        let nr1 = build("NR1", "ipv4", BuildOptions::default());
        assert_eq!(nr1.tool.as_deref(), Some("pi"));
        assert!(nr1.expected_attempts.is_empty());
        assert_eq!(nr1.controls.as_deref(), Some([].as_slice()));
        assert!(nr1.cwd.ends_with("requests"));
        assert_eq!(
            nr1.argv.last().map(String::as_str),
            Some("--version"),
            "NR1 reports its version"
        );
        assert_eq!(
            build("NR3", "ipv4", BuildOptions::default())
                .argv
                .last()
                .map(String::as_str),
            Some("AGENT_VM_328_SHELL_STARTED")
        );
        // Only NR2 carries an internet grant among the readiness cases.
        assert!(
            !nr1.argv
                .iter()
                .any(|token| token == "--allow-internet-egress")
        );
        assert!(
            build("NR2", "ipv4", BuildOptions::default())
                .argv
                .iter()
                .any(|token| token == "--allow-internet-egress")
        );
        // The synthetic seed lifecycle is declared, not implied.
        assert!(
            build("CR1", "ipv4", BuildOptions::default())
                .setup
                .iter()
                .any(|step| step.contains("anthropic OAuth seed"))
        );
        assert!(
            build("PA1", "ipv4", BuildOptions::default())
                .setup
                .iter()
                .any(|step| step.contains("project allowance record"))
        );
        // PA2 declares the opposite of a seed and the writer's own cleanup, and
        // probes only through its host witness.
        let pa2 = build("PA2", "ipv4", BuildOptions::default());
        assert!(pa2.expected_attempts.is_empty());
        assert_eq!(pa2.controls.as_deref(), Some([].as_slice()));
        assert!(pa2.setup[0].contains("no seed") && pa2.setup[0].contains("allowances.lock"));
        assert!(pa2.cwd.ends_with("proj"));
        // A validation-only case is bounded like an admin command, not a launch.
        let rejected = build("RJ1", "scheme", BuildOptions::default());
        assert_eq!(rejected.kind, "validation-only");
        assert_eq!(rejected.timeout, 10.0);
        assert!(!rejected.argv.iter().any(|token| token == "--"));
    }

    #[test]
    fn the_attempt_tables_agree_with_the_labels() {
        for case in CASES {
            let attempts = expected_attempts(case);
            let expectations = attempt_expectations(case);
            assert_eq!(
                attempts.len(),
                expectations.len(),
                "{}: one expectation per attempt",
                case.case
            );
            assert!(
                !control_links(case).is_empty()
                    || matches!(case.case, "NR1" | "NR2" | "NR3" | "PA2"),
                "{}: a guest case declares controls or is a readiness row",
                case.case
            );
            for (index, label) in attempts.iter().enumerate() {
                assert_eq!(expectations[index].0, *label, "{}: order", case.case);
                assert!(
                    [
                        "dns-udp", "dns-tcp", "tls", "https", "opaque", "banner", "held", "public",
                        "udp", "tcp"
                    ]
                    .contains(&attempt_protocol(label).as_str()),
                    "{}: {label} has a known protocol",
                    case.case
                );
                assert!(
                    matches!(
                        expectations[index].1.as_str(),
                        "OK" | "NX" | "0" | "1" | "301"
                    ),
                    "{}: {label} expects a known verdict",
                    case.case
                );
            }
            // Every denial is joined against a passing positive attempt.
            for (label, expectation) in &expectations {
                if matches!(expectation.as_str(), "1" | "NX") {
                    let links = control_links(case);
                    assert!(
                        links.iter().any(|(link, _)| link == label),
                        "{}: {label} needs a control link",
                        case.case
                    );
                }
            }
        }
    }

    #[test]
    fn the_readiness_line_is_matched_as_a_whole_line() {
        let work = std::env::temp_dir().join(format!("harness-ingress-line-{}", monotonic_nanos()));
        std::fs::create_dir_all(&work).expect("a scratch directory");
        let log = work.join("IN1.log");
        let ready = "INGRESS_READY IN1 8000";
        std::fs::write(&log, "INGRESS_READY IN1 80001\n").expect("the launch log");
        assert!(!log_has_line(&log, ready), "a longer port must not match");
        std::fs::write(&log, "prefix INGRESS_READY IN1 8000\n").expect("the launch log");
        assert!(!log_has_line(&log, ready), "a prefixed line must not match");
        std::fs::write(&log, "booting\nINGRESS_READY IN1 8000\nserving\n").expect("the launch log");
        assert!(log_has_line(&log, ready), "a whole line does match");
        assert!(
            !log_has_line(&work.join("absent.log"), ready),
            "absence is not a match"
        );
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn the_default_request_report_is_checked_in_both_directions() {
        default_request_self_test().expect("block B passes");
    }

    #[test]
    fn a_version_line_is_matched_as_a_whole_line() {
        assert!(is_semantic_version("0.87.1"));
        assert!(is_semantic_version("1.2.3-rc.1"));
        assert!(is_semantic_version("1.2.3-rc.1+build.7"));
        assert!(is_semantic_version("1.2.3+build"));
        assert!(!is_semantic_version("1.2"));
        assert!(!is_semantic_version("1.2.3.4"));
        assert!(!is_semantic_version("v1.2.3"));
        assert!(!is_semantic_version("1.2.3 "));
        assert!(!is_semantic_version("1.2.3-"));
    }
}
