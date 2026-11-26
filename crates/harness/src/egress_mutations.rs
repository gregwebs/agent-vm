//! Fault-detection controls in disposable source copies; never edit kernels in place.
//!
//! Ported from `script/test/egress-mutations.py` (#695). A row mutates one
//! tracked file in a throwaway copy of the tree, runs the control that is
//! supposed to notice, and requires that control to fail. A compiler error, a
//! timeout, or a missing test is not a killed mutation: each of those is a
//! **harness** failure and says so.
//!
//! # Where a row's verdict comes from
//!
//! Five kinds of control, one ledger:
//!
//! * [`Run::AgentBin`] / [`Run::AgentTest`] build the mutated `agent-vm` crate
//!   and run one `cargo test` target.
//! * [`Run::Proof`] verifies the mutated crate with the pinned Verus gate
//!   (`script/test/verus-verification.sh --repo-gate`).
//! * [`Run::ReadAt`] mutates text that a *prebuilt* `harness` control reads from
//!   disk at run time (`--repo-root .`), so the mutation is the copy's and the
//!   binary is the checkout's.
//! * [`Run::Crate`] (#695) mutates a `crates/harness` source, rebuilds the
//!   harness crate from the copy, and runs that build's own control. This is
//!   the only shape that can grade Rust *behaviour* that moved off Python into
//!   a compiled binary: the seventeen rows #693 and #694 had to drop needed
//!   exactly this.
//!
//! # A verdict must not depend on build history (#327)
//!
//! Rows build in this checkout's `target/egress-mutations/target`, never its
//! `target/`; proof rows keep the documented `target/verus`, which their gate
//! cleans on every run. Cargo's fingerprints ignore the copy's path, so a target
//! dir that is warm from an earlier run can answer with an artifact that was
//! never compiled from *this* mutation. Two rules carry the verdict:
//!
//! * every compiling row removes its package's artifacts (`cargo clean -p …`)
//!   before it builds, and
//! * every compiling row then requires cargo to report that it recompiled that
//!   package from the copy.
//!
//! A row whose mutated source cargo reports as fresh, or as never compiled, is a
//! harness failure -- never a surviving mutant.
//!
//! # Cost
//!
//! Warm-ups (the `agent-vm` test units, the Verus gate, the harness crate's
//! dependencies) run once, outside every per-row bound. Measured on an Apple
//! Silicon host with a warm compiler cache, one row costs 7-21 s for a
//! [`Run::Crate`] rebuild, 7-10 s for a [`Run::Proof`] verification, ~4 s for a
//! [`Run::ReadAt`] control, and 10-50 s for a [`Run::AgentBin`] target, which
//! relinks the whole `agent-vm` binary after `cargo clean -p agent-vm` -- that
//! relink is #327's price and it is why the full ledger is a ~52 minute run while
//! CI runs only `--check-anchors`. Every subprocess wait is bounded
//! ([`CONTROL_BOUND`] per row, [`WARMUP_BOUND`] per warm-up), so a hung control
//! fails a gate instead of hanging it.
//!
//! `--check-anchors` is what CI runs. It resolves *find text only*: it proves
//! each pre-mutation anchor is present the expected number of times and never
//! that a replacement compiles. A row whose injection names an API that has
//! since been renamed therefore passes CI and controls nothing, reporting "the
//! mutant was never compiled" only when someone runs it (#581). The guard is
//! operational: after renaming or moving an API an injection calls, run that row
//! with `--only <row> --evidence <fresh dir>` and require a `PASS` line.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command as Process, Stdio},
    time::{Duration, Instant, SystemTime},
};

use serde_json::{Value, json};

/// Bound on one control, mutated build included. A wedged control is a failure,
/// not a hung gate.
const CONTROL_BOUND: Duration = Duration::from_secs(240);
/// Bound on one warm-up build: a cold dependency graph is a build cost, not a
/// control's verdict, so it gets its own generous bound outside the matrix.
const WARMUP_BOUND: Duration = Duration::from_secs(3600);

/// Where the mutated `agent-vm` rows and the mutated harness rows both build.
/// Sharing one dir means the dependency graph is compiled once for both; the
/// per-row `cargo clean -p <package>` is what keeps a shared dir honest.
const HARNESS_TARGET: &str = "target/egress-mutations/target";
/// The documented Verus target dir, cleaned by its own gate on every run.
const PROOF_TARGET: &str = "target/verus";

const AGENT_PACKAGE: &str = "crates/agent-vm/Cargo.toml";
const HARNESS_PACKAGE: &str = "crates/harness/Cargo.toml";
const LAUNCH_TARGET: &str = "config_launch_driven";

/// Cargo's whole-build failure line, as `--message-format=json-render-diagnostics`
/// renders it: that mode renders diagnostics as *text*, so cargo emits no
/// `compiler-message` records and the signal is the summary line or a typed error.
const BUILD_FAILED: &str = "error: could not compile ";
/// The Verus gate's proof-failure summary. It only exists once the crate
/// compiled, so its presence means the failure is a failed *proof*.
const VERUS_SUMMARY: &str = "verification results::";

/// Which command a row runs, and where it builds.
#[derive(Debug, Clone, Copy)]
enum Run {
    /// `cargo test -p agent-vm --bin agent-vm <filter>`.
    AgentBin(&'static str),
    /// `cargo test -p agent-vm --test <target> <filter>`.
    AgentTest(&'static str, &'static str),
    /// `bash script/test/verus-verification.sh --repo-gate`.
    Proof,
    /// The prebuilt `harness` binary, which reads the mutated file at run time.
    ReadAt(&'static [&'static str]),
    /// The copy's own rebuilt `harness` binary.
    Crate(&'static [&'static str]),
}

impl Run {
    /// The package whose artifacts the row removes and then requires to be
    /// recompiled. `None` for a control this ledger does not build: the Verus
    /// gate cleans `target/verus` itself, and a `ReadAt` control builds nothing.
    fn package(self) -> Option<&'static str> {
        match self {
            Run::AgentBin(_) | Run::AgentTest(..) => Some(AGENT_PACKAGE),
            Run::Crate(_) => Some(HARNESS_PACKAGE),
            Run::Proof | Run::ReadAt(_) => None,
        }
    }

    fn target_dir(self) -> &'static str {
        match self {
            Run::Proof => PROOF_TARGET,
            _ => HARNESS_TARGET,
        }
    }
}

/// One mutation: a find/replace in `path`, and the control that must fail.
#[derive(Debug, Clone, Copy)]
struct Row {
    name: &'static str,
    path: &'static str,
    /// The pre-mutation text. `--check-anchors` proves it is present `anchors`
    /// times and nothing more.
    old: &'static str,
    new: &'static str,
    run: Run,
    /// What the killed control must have said. A non-zero exit alone can be a
    /// usage error, which is not fault detection. More than one shape is listed
    /// where the same fault reaches the caller two ways: an `assert!` panics,
    /// a returned `Err` reaches `main`'s `harness: FAIL:` line.
    markers: &'static [&'static str],
    /// How many times `old` must occur. Two only where the language repeats the
    /// same statement at two sites a single mutation must reach.
    anchors: usize,
}

/// The anchor ledger. One row per property a control is meant to notice; the
/// comment above each group says what its mutation is *for*.
///
/// Rows are the independent oracle of the ported checks: the assertion says what
/// the code must do, the row says that the assertion bites.
fn ledger() -> Vec<Row> {
    vec![
        Row {
            name: r#"lan-dns"#,
            path: r#"crates/agent-vm/src/egress_policy.rs"#,
            old: r#"gateway_dns: grants.internet, public:"#,
            new: r#"gateway_dns: grants.internet || grants.lan, public:"#,
            run: Run::AgentBin(r#"egress_policy"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"profiles"#,
            path: r#"crates/agent-vm/src/egress_policy.rs"#,
            old: r#"let emitted = group_rules(self.groups);"#,
            new: r#"if self.groups.lan || self.groups.host || self.groups.internet {
            use microsandbox_network::policy::NetworkProfile;
            return microsandbox::NetworkPolicy::from_profiles([
                NetworkProfile::Public, NetworkProfile::Private, NetworkProfile::Host]);
        }
        let emitted = group_rules(self.groups);"#,
            run: Run::AgentBin(r#"egress_policy"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"mapped-v6"#,
            path: r#"crates/agent-vm/src/egress_policy.rs"#,
            old: r#"&& v6.prefix() >= 96"#,
            new: r#"&& false && v6.prefix() >= 96"#,
            run: Run::AgentBin(r#"egress_policy"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"leading-zero"#,
            path: r#"crates/agent-vm/src/egress_grammar.rs"#,
            old: r#"if bytes[0] == 0x30 { return None; }"#,
            new: r#"if bytes[0] == 0xff { return None; }"#,
            run: Run::AgentBin(r#"egress_policy"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"leading-zero-proof"#,
            path: r#"crates/agent-vm/src/egress_grammar.rs"#,
            old: r#"if bytes[0] == 0x30 { return None; }"#,
            new: r#"if bytes[0] == 0xff { return None; }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"scheme-any"#,
            path: r#"crates/agent-vm/src/egress_grammar.rs"#,
            old: r#"} else if contains_separator(s, 0) {
        Err(LayoutError::UnsupportedScheme)"#,
            new: r#"} else if contains_separator(s, 0) {
        Ok((SchemeSel::Any, 0))"#,
            run: Run::AgentBin(r#"egress_policy"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"scheme-any-proof"#,
            path: r#"crates/agent-vm/src/egress_grammar.rs"#,
            old: r#"} else if contains_separator(s, 0) {
        Err(LayoutError::UnsupportedScheme)"#,
            new: r#"} else if contains_separator(s, 0) {
        Ok((SchemeSel::Any, 0))"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"port-value"#,
            path: r#"crates/agent-vm/src/egress_grammar.rs"#,
            old: r#"port: Some(port) }"#,
            new: r#"port: Some(if port == 22 { 80 } else { port }) }"#,
            run: Run::AgentBin(r#"egress_policy"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 2,
        },
        Row {
            name: r#"port-value-proof"#,
            path: r#"crates/agent-vm/src/egress_grammar.rs"#,
            old: r#"port: Some(port) }"#,
            new: r#"port: Some(if port == 22 { 80 } else { port }) }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 2,
        },
        Row {
            name: r#"address-substring"#,
            path: r#"crates/agent-vm/src/egress_grammar.rs"#,
            old: r#"addr_start: 0, addr_end: t.len(), port: None"#,
            new: r#"addr_start: 1, addr_end: t.len(), port: None"#,
            run: Run::AgentBin(r#"egress_policy"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"address-substring-proof"#,
            path: r#"crates/agent-vm/src/egress_grammar.rs"#,
            old: r#"addr_start: 0, addr_end: t.len(), port: None"#,
            new: r#"addr_start: 1, addr_end: t.len(), port: None"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"bracket-suffix"#,
            path: r#"crates/agent-vm/src/egress_grammar.rs"#,
            old: r#"if k + 1 != t.len() && t[k+1] != 0x3a { return Err(LayoutError::MalformedAddress); }"#,
            new: r#"if k + 1 != t.len() && t[k+1] != 0x3a { return Ok(TargetLayout { addr_start: 1, addr_end: k, port: None }); }"#,
            run: Run::AgentBin(r#"egress_policy"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"bracket-suffix-proof"#,
            path: r#"crates/agent-vm/src/egress_grammar.rs"#,
            old: r#"if k + 1 != t.len() && t[k+1] != 0x3a { return Err(LayoutError::MalformedAddress); }"#,
            new: r#"if k + 1 != t.len() && t[k+1] != 0x3a { return Ok(TargetLayout { addr_start: 1, addr_end: k, port: None }); }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"request-port-ignored"#,
            path: r#"crates/agent-vm/src/egress_hostname.rs"#,
            old: r#"&self.name == name && self.effective_ports(ports).contains(&port.get())"#,
            new: r#"&self.name == name"#,
            run: Run::AgentBin(r#"network_request_coverage"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"request-internet-ignored"#,
            path: r#"crates/agent-vm/src/egress_policy.rs"#,
            old: r#"let public = group_rules(self.groups).public;"#,
            new: r#"let public = false;"#,
            run: Run::AgentBin(r#"network_request_coverage"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"request-report-unbounded"#,
            path: r#"crates/agent-vm/src/network_requests.rs"#,
            old: r#".take_while(|(shown, _)| report_budget_allows(*shown))"#,
            new: r#".take_while(|_| true)"#,
            run: Run::AgentBin(r#"network_requests::tests::"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"request-limit"#,
            path: r#"crates/agent-vm/src/network_requests.rs"#,
            old: r#"    ensures ok == request_count_within_limit_spec(count),
{
    count <= MAX_NETWORK_REQUESTS
}"#,
            new: r#"    ensures ok == request_count_within_limit_spec(count),
{
    count <= MAX_NETWORK_REQUESTS + 1
}"#,
            run: Run::AgentBin(r#"network_requests::tests::"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"request-limit-proof"#,
            path: r#"crates/agent-vm/src/network_requests.rs"#,
            old: r#"    ensures ok == request_count_within_limit_spec(count),
{
    count <= MAX_NETWORK_REQUESTS
}"#,
            new: r#"    ensures ok == request_count_within_limit_spec(count),
{
    count <= MAX_NETWORK_REQUESTS + 1
}"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"domain-all-ports"#,
            path: r#"crates/agent-vm/src/egress_hostname.rs"#,
            old: r#"ports: effective.into_iter().map(PortRange::single).collect(),"#,
            new: r#"ports: vec![],"#,
            run: Run::AgentBin(r#"hostname_rule_shape"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"domain-any-protocol"#,
            path: r#"crates/agent-vm/src/egress_hostname.rs"#,
            old: r#"protocols: vec![Protocol::Tcp],"#,
            new: r#"protocols: vec![],"#,
            run: Run::AgentBin(r#"hostname_rule_shape"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"domain-first"#,
            path: r#"crates/agent-vm/src/egress_policy.rs"#,
            old: r#"rules.extend(domain_rules(&self.effective.hostnames, &ports));"#,
            new: r#"rules.splice(0..0, domain_rules(&self.effective.hostnames, &ports));"#,
            run: Run::AgentBin(r#"hostname_rule_shape"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"hostname-dns"#,
            path: r#"crates/agent-vm/src/egress_policy.rs"#,
            old: r#"rules.extend(domain_rules(&self.effective.hostnames, &ports));"#,
            new: r#"rules.push(Rule::allow_dns()); rules.extend(domain_rules(&self.effective.hostnames, &ports));"#,
            run: Run::AgentBin(r#"hostname_rule_shape"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"tls-ports-missing"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"Some(ports) => tls.intercepted_ports(ports.clone()),"#,
            new: r#"Some(_) => tls,"#,
            run: Run::AgentBin(r#"hostname_launch_keeps_strict_and_intercepts_every_domain_port"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"tls-off"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"let enable_tls = !publish_ports.is_empty() || hostname_ports.is_some();"#,
            new: r#"let enable_tls = !publish_ports.is_empty();"#,
            run: Run::AgentBin(r#"hostname_launch_keeps_strict_and_intercepts_every_domain_port"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"bare-port-443-only"#,
            path: r#"crates/agent-vm/src/egress_hostname.rs"#,
            old: r#"HostnameScope::InterceptedPorts => ports.to_vec(),"#,
            new: r#"HostnameScope::InterceptedPorts => { let _ = ports; vec![443] },"#,
            run: Run::AgentBin(r#"hostname_rule_shape"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"dns-port-allowed"#,
            path: r#"crates/agent-vm/src/egress_hostname.rs"#,
            old: r#"if p == 53 || p == 853 { Err(HostnameScopeError::DnsPort) }"#,
            new: r#"if false { Err(HostnameScopeError::DnsPort) }"#,
            run: Run::AgentBin(r#"egress_hostname::tests"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"dns-port-allowed-proof"#,
            path: r#"crates/agent-vm/src/egress_hostname.rs"#,
            old: r#"if p == 53 || p == 853 { Err(HostnameScopeError::DnsPort) }"#,
            new: r#"if false { Err(HostnameScopeError::DnsPort) }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"udp-hostname"#,
            path: r#"crates/agent-vm/src/egress_hostname.rs"#,
            old: r#"if scheme == SchemeSel::Udp { return Err(HostnameScopeError::Udp); }"#,
            new: r#"if false { return Err(HostnameScopeError::Udp); }"#,
            run: Run::AgentBin(r#"egress_hostname::tests"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"udp-hostname-proof"#,
            path: r#"crates/agent-vm/src/egress_hostname.rs"#,
            old: r#"if scheme == SchemeSel::Udp { return Err(HostnameScopeError::Udp); }"#,
            new: r#"if false { return Err(HostnameScopeError::Udp); }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"numeric-final-label"#,
            path: r#"crates/agent-vm/src/egress_hostname.rs"#,
            old: r#"!numeric_label_bytes(bytes)"#,
            new: r#"{ let _ = numeric_label_bytes(bytes); true }"#,
            run: Run::AgentBin(r#"egress_hostname::tests"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"numeric-final-label-proof"#,
            path: r#"crates/agent-vm/src/egress_hostname.rs"#,
            old: r#"!numeric_label_bytes(bytes)"#,
            new: r#"{ let _ = numeric_label_bytes(bytes); true }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"single-label-refused"#,
            path: r#"crates/agent-vm/src/egress_hostname.rs"#,
            old: r#"None => {
            proof {"#,
            new: r#"None => { return false;
            proof {"#,
            run: Run::AgentBin(r#"egress_hostname::tests"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"single-label-refused-proof"#,
            path: r#"crates/agent-vm/src/egress_hostname.rs"#,
            old: r#"None => {
            proof {"#,
            new: r#"None => { return false;
            proof {"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"alias-allowed"#,
            path: r#"crates/agent-vm/src/egress_hostname.rs"#,
            old: r#"if host == "host.microsandbox.internal" {"#,
            new: r#"if false {"#,
            run: Run::AgentBin(r#"grammar_error_precedence_table"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"hostname-proxy-unchecked"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"if egress.has_hostnames() && observation.connector_used {"#,
            new: r#"if false && egress.has_hostnames() && observation.connector_used {"#,
            run: Run::AgentBin(r#"hostname_proxy_selection_mirrors_the_host_connector"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"proxy-any-scheme"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => rest,"#,
            new: r#"Some((_, rest)) => rest,"#,
            run: Run::AgentBin(r#"hostname_proxy_selection_mirrors_the_host_connector"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"proxy-first-var-only"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"usable |= connector_would_select(&value);"#,
            new: r#"if notice.is_none() { usable |= connector_would_select(&value); }"#,
            run: Run::AgentBin(r#"hostname_proxy_selection_mirrors_the_host_connector"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"proxy-no-proxy-ignored"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"connector_used: usable && !wildcard,"#,
            new: r#"connector_used: usable && (wildcard || !wildcard),"#,
            run: Run::AgentBin(r#"hostname_proxy_selection_mirrors_the_host_connector"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"early-return"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"let policy = self.egress.policy();"#,
            new: r#"if self.publish_ports.is_empty() && !self.auto_publish { return builder; }
        let policy = self.egress.policy();"#,
            run: Run::AgentBin(
                r#"network::tests::default_plan_denies_all_egress_and_preserves_non_policy_network_config"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"early-return-g1"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"let policy = self.egress.policy();"#,
            new: r#"if self.publish_ports.is_empty() && !self.auto_publish { return builder; }
        let policy = self.egress.policy();"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"default_tools_launch_with_their_declared_provisioning"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"early-return-g2"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"let policy = self.egress.policy();"#,
            new: r#"if self.publish_ports.is_empty() && !self.auto_publish { return builder; }
        let policy = self.egress.policy();"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"a_zero_provisioning_launch_boots_with_no_tls_overlay"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"dense-strict"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"network = network.policy(policy);"#,
            new: r#"network = network.policy(policy);
            network = network.strict(false);"#,
            run: Run::AgentBin(
                r#"network::tests::default_plan_denies_all_egress_and_preserves_non_policy_network_config"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"dense-tls"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"network = network.policy(policy);"#,
            new: r#"network = network.policy(policy);
            network = network.tls(|tls| tls.enabled(true));"#,
            run: Run::AgentBin(
                r#"network::tests::default_plan_denies_all_egress_and_preserves_non_policy_network_config"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"dense-ports"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"network = network.policy(policy);"#,
            new: r#"network = network.policy(policy);
            network = network.tls_overlay(|tls| tls.intercepted_ports(vec![8443]));"#,
            run: Run::AgentBin(
                r#"network::tests::default_plan_denies_all_egress_and_preserves_non_policy_network_config"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"dense-rebind"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"network = network.policy(policy);"#,
            new: r#"network = network.policy(policy);
            network = network.dns(|dns| dns.rebind_protection(false));"#,
            run: Run::AgentBin(
                r#"network::tests::default_plan_denies_all_egress_and_preserves_non_policy_network_config"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"dense-nameservers"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"network = network.policy(policy);"#,
            new: r#"network = network.policy(policy);
            network = network.dns(|dns| dns.nameservers([std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))]));"#,
            run: Run::AgentBin(
                r#"network::tests::default_plan_denies_all_egress_and_preserves_non_policy_network_config"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"dense-intercept-limit"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"network = network.policy(policy);"#,
            new: r#"network = network.policy(policy);
            network = network.intercept(|intercept| intercept.max_request_bytes(1));"#,
            run: Run::AgentBin(
                r#"network::tests::default_plan_denies_all_egress_and_preserves_non_policy_network_config"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"dense-secret"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"network = network.policy(policy);"#,
            new: r#"network = network.policy(policy);
            network = network.secret(|secret| secret.env("MSB_MUTANT").value("synthetic").allow("example.com"));"#,
            run: Run::AgentBin(
                r#"network::tests::default_plan_denies_all_egress_and_preserves_non_policy_network_config"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"dense-connections"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"network = network.policy(policy);"#,
            new: r#"network = network.policy(policy);
            network = network.max_connections(0);"#,
            run: Run::AgentBin(
                r#"network::tests::default_plan_denies_all_egress_and_preserves_non_policy_network_config"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"unknown-key"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"applied.as_object_mut().unwrap().remove("policy");"#,
            new: r#"applied["unknown_mutation"] = serde_json::json!(true);
        applied.as_object_mut().unwrap().remove("policy");"#,
            run: Run::AgentBin(
                r#"network::tests::default_plan_denies_all_egress_and_preserves_non_policy_network_config"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The helper's signature is the anchor, so it has to name the exact parameter
        // list the test file compiles today (it gained `proxy_from_env` when the
        // launcher began opting into ambient proxy discovery).
        Row {
            name: r#"zero-secret"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["secrets"]["secrets"] = serde_json::json!([{ "env_var": "MSB_MUTANT" }]);"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"a_zero_provisioning_launch_boots_with_no_tls_overlay"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"g1-secret"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["secrets"]["secrets"] = serde_json::json!([{ "env_var": "MSB_MUTANT" }]);"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"default_tools_launch_with_their_declared_provisioning"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"zero-header"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["secrets"]["header_credentials"] = serde_json::json!([{ "id": "mutant" }]);"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"a_zero_provisioning_launch_boots_with_no_tls_overlay"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"g1-header"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["secrets"]["header_credentials"] = serde_json::json!([{ "id": "mutant" }]);"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"default_tools_launch_with_their_declared_provisioning"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"zero-route"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["intercept"]["rules"] = serde_json::json!([{ "host": "example.com" }]);"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"a_zero_provisioning_launch_boots_with_no_tls_overlay"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"g1-route"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["intercept"]["rules"] = serde_json::json!([{ "host": "example.com" }]);"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"default_tools_launch_with_their_declared_provisioning"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"zero-hook"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["intercept"]["hook"] = serde_json::json!(["mutant"]);"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"a_zero_provisioning_launch_boots_with_no_tls_overlay"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"g1-hook"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["intercept"]["hook"] = serde_json::json!(["mutant"]);"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"default_tools_launch_with_their_declared_provisioning"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"zero-tls"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["tls"]["enabled"] = serde_json::json!(true);"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"a_zero_provisioning_launch_boots_with_no_tls_overlay"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"g1-tls"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["tls"]["enabled"] = serde_json::json!(true);"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"default_tools_launch_with_their_declared_provisioning"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"zero-policy"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["policy"]["rules"] = serde_json::json!([{ "action": "allow" }]);"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"a_zero_provisioning_launch_boots_with_no_tls_overlay"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"g1-policy"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["policy"]["rules"] = serde_json::json!([{ "action": "allow" }]);"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"default_tools_launch_with_their_declared_provisioning"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"zero-strict"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["strict"] = serde_json::json!(false);"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"a_zero_provisioning_launch_boots_with_no_tls_overlay"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"g1-strict"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["strict"] = serde_json::json!(false);"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"default_tools_launch_with_their_declared_provisioning"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"zero-missing-secrets"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["secrets"].as_object_mut().unwrap().remove("secrets");"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"a_zero_provisioning_launch_boots_with_no_tls_overlay"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"g1-missing-secrets"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["secrets"].as_object_mut().unwrap().remove("secrets");"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"default_tools_launch_with_their_declared_provisioning"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"zero-missing-rules"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["intercept"].as_object_mut().unwrap().remove("rules");"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"a_zero_provisioning_launch_boots_with_no_tls_overlay"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"g1-missing-rules"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {"#,
            new: r#"fn assert_default_deny_zero_provision_network(
    network: &serde_json::Value,
    context: &str,
    proxy_from_env: bool,
) {
    let mut changed = network.clone();
    let network = &mut changed;
    network["intercept"].as_object_mut().unwrap().remove("rules");"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"default_tools_launch_with_their_declared_provisioning"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"overlay-equal-length"#,
            path: r#"crates/agent-vm/src/credential_injection.rs"#,
            old: r#"let base_ports = intercepted_ports_of(&network)?;"#,
            new: r#"let base_ports = intercepted_ports_of(&network)?;
        network = network.policy(serde_json::from_value(serde_json::json!({"default_egress":"deny","default_ingress":"allow","rules": [
{"direction":"egress","destination":{"group":"public"},"protocols":[],"ports":[],"action":"allow"},{"direction":"egress","destination":{"group":"public"},"protocols":[],"ports":[],"action":"allow"},{"direction":"egress","destination":{"group":"public"},"protocols":[],"ports":[],"action":"allow"},{"direction":"egress","destination":{"group":"public"},"protocols":[],"ports":[],"action":"allow"}]})).unwrap());"#,
            run: Run::AgentBin(r#"credential_overlay_preserves_base_network_plan"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The three rows below control one property: a rejected allowance is refused
        // before launch state exists. The injection creates that state just ahead of
        // the parse that rejects, and it goes through the constructor `launch` itself
        // calls, so it names exactly the directories the test asserts are absent
        // instead of restating the hash-to-path rule. #581: an earlier spelling,
        // `ProjectSession::for_cwd()`, named a constructor that did not exist, so all
        // three rows reported "the mutant was never compiled" (E0599) and controlled
        // nothing while `--check-anchors` kept passing it -- that check resolves find
        // text only and never compiles a replacement.
        Row {
            name: r#"preparse-project"#,
            path: r#"crates/agent-vm/src/run.rs"#,
            old: r#"
    let mut network_plan = crate::network::Plan::from_args(
        args.network,
        user_network,
        user_tools,
        grant.authorized_tool_egress(),
    )?;"#,
            new: r#"
    let early = ProjectSession::for_project(&project)?;
    std::fs::create_dir_all(&early.state_dir)?;
    let mut network_plan = crate::network::Plan::from_args(
        args.network,
        user_network,
        user_tools,
        grant.authorized_tool_egress(),
    )?;"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"rejected_allowance_is_refused_before_launch_state_is_created"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"preparse-mounts"#,
            path: r#"crates/agent-vm/src/run.rs"#,
            old: r#"
    let mut network_plan = crate::network::Plan::from_args(
        args.network,
        user_network,
        user_tools,
        grant.authorized_tool_egress(),
    )?;"#,
            new: r#"
    let early = ProjectSession::for_project(&project)?;
    std::fs::create_dir_all(early.state_dir.with_extension("mounts"))?;
    let mut network_plan = crate::network::Plan::from_args(
        args.network,
        user_network,
        user_tools,
        grant.authorized_tool_egress(),
    )?;"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"rejected_allowance_is_refused_before_launch_state_is_created"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"preparse-secrets"#,
            path: r#"crates/agent-vm/src/run.rs"#,
            old: r#"
    let mut network_plan = crate::network::Plan::from_args(
        args.network,
        user_network,
        user_tools,
        grant.authorized_tool_egress(),
    )?;"#,
            new: r#"
    let early = ProjectSession::for_project(&project)?;
    std::fs::create_dir_all(early.state_dir.with_extension("secrets"))?;
    let mut network_plan = crate::network::Plan::from_args(
        args.network,
        user_network,
        user_tools,
        grant.authorized_tool_egress(),
    )?;"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"rejected_allowance_is_refused_before_launch_state_is_created"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"valid-no-fork"#,
            path: r#"crates/agent-vm/tests/config_launch_driven.rs"#,
            old: r#"&["--mount", &mount, "--allow-egress", "api.example.com"],"#,
            new: r#"&["--allow-egress", "api.example.com"],"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"rejected_allowance_is_refused_before_launch_state_is_created"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"valid-no-credential"#,
            path: r#"crates/agent-vm/src/run.rs"#,
            old: r#".context("snapshotting host credentials")?;"#,
            new: r#".context("snapshotting host credentials")?;
    if let Some(file) = &creds.anthropic_token_file { std::fs::remove_file(file)?; }"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"rejected_allowance_is_refused_before_launch_state_is_created"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // #693: the wire and dispatcher controls are harness checks now. Each runs
        // with the disposable copy as its repository root, so the mutation it grades is
        // the copy's own probe library or fixture module, while the harness binary is
        // the checkout's.
        Row {
            name: r#"dns-short-read"#,
            path: r#"script/test/fixtures/egress-probe.sh"#,
            old: r#"dd bs=1 count="$frame""#,
            new: r#"dd bs="$frame" count=1"#,
            run: Run::ReadAt(&[
                r#"egress-probe"#,
                r#"--self-test"#,
                r#"--repo-root"#,
                r#"."#,
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: r#"dns-eof"#,
            path: r#"script/test/fixtures/egress-probe.sh"#,
            old: r#"timeout 3 dd bs=1 count="$frame""#,
            new: r#"timeout 3 cat"#,
            run: Run::ReadAt(&[
                r#"egress-probe"#,
                r#"--self-test"#,
                r#"--repo-root"#,
                r#"."#,
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        // --- Restored crate rows (#695) -----------------------------------------
        // Every row below grades Rust *behaviour* that #693 or #694 had to drop,
        // because its subject moved from a Python file into a crate the harness
        // binary is compiled from: a text mutation of the old copy could never reach
        // a prebuilt binary, so the row could not fail. `Run::Crate` mutates the
        // crate, rebuilds it from the copy, and runs that build's own control, which
        // is the grading path a Python-only runner could not have.
        //
        // #693 dropped the two hook rows: `write_hook` is Rust now. The control that
        // bites is `egress-probe`'s `generated hook status matrix`, which executes
        // the generated hook and asserts both halves these rows name -- nothing says
        // "command not found", and HK2's denial exits 7.
        Row {
            name: "hook-no-library",
            path: "crates/harness/src/egress_run.rs",
            old: r#"        "EGRESS_PROBE_LIB=1 . ./egress-probe.sh\n\
         if http_get {lan} {port} {ident}; then\n    \
         return 0"#,
            new: r#"        "\n\
         if http_get {lan} {port} {ident}; then\n    \
         return 0"#,
            run: Run::Crate(&[
                "egress-probe",
                "--self-test",
                "--only",
                "generated hook status matrix",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: "hook-zero",
            path: "crates/harness/src/egress_run.rs",
            old: r#"    } else {
        "return 7"
    };"#,
            new: r#"    } else {
        "return 0"
    };"#,
            run: Run::Crate(&[
                "egress-probe",
                "--self-test",
                "--only",
                "generated hook status matrix",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        // ADR-0065's per-case allowance lifecycle: each deletion is one way a case runs
        // without its record (PA1x then passes while proving nothing) or leaves one
        // behind.
        Row {
            name: r#"allowance-seed-dropped"#,
            path: r#"crates/harness/src/egress_run.rs"#,
            old: r#"            let mut failures = prepare_allowance(work, case.case, lan);"#,
            new: r#"            let mut failures = Vec::new();"#,
            run: Run::ReadAt(&[
                r#"egress-supervisor"#,
                r#"--self-test"#,
                r#"--repo-root"#,
                r#"."#,
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: r#"allowance-restore-dropped"#,
            path: r#"crates/harness/src/egress_run.rs"#,
            old: r#"    if ALLOWANCE_CASES.contains(&case.case) {
        failures.extend(remove_allowances(work));
    }"#,
            new: r#""#,
            run: Run::ReadAt(&[
                r#"egress-supervisor"#,
                r#"--self-test"#,
                r#"--repo-root"#,
                r#"."#,
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: r#"allowance-final-cleanup-dropped"#,
            path: r#"crates/harness/src/egress_run.rs"#,
            old: r#"    cleanup_errors.extend(final_cleanup(&work));"#,
            new: r#"    cleanup_errors.extend(remove_credentials(&work));"#,
            run: Run::ReadAt(&[
                r#"egress-supervisor"#,
                r#"--self-test"#,
                r#"--repo-root"#,
                r#"."#,
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        // ADR-0066 (PA2): the same shape for the live-allowance case, whose evidence is
        // a *transition*. Dropping any of its three call sites must be caught: without
        // the pre-launch reset a seeded store makes the first, supposed-to-be-refused
        // probe pass; without the verdict the case would pass on the guest's markers
        // alone; without the restore the record and the writer's lock leak.
        Row {
            name: r#"live-allowance-reset-dropped"#,
            path: r#"crates/harness/src/egress_run.rs"#,
            old: r#"            let failures = prepare_live_allowance(work, case.case);"#,
            new: r#"            let failures = Vec::new();"#,
            run: Run::ReadAt(&[
                r#"egress-supervisor"#,
                r#"--self-test"#,
                r#"--repo-root"#,
                r#"."#,
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: r#"live-allowance-verdict-dropped"#,
            path: r#"crates/harness/src/egress_run.rs"#,
            old: r#"        failures.extend(check_live_allowance(work, owned.ident(), &text));"#,
            new: r#""#,
            run: Run::ReadAt(&[
                r#"egress-supervisor"#,
                r#"--self-test"#,
                r#"--repo-root"#,
                r#"."#,
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: r#"live-allowance-cleanup-dropped"#,
            path: r#"crates/harness/src/egress_run.rs"#,
            old: r#"    if case.case == "PA2" {
        failures.extend(cleanup_pa2(work));
    }"#,
            new: r#""#,
            run: Run::ReadAt(&[
                r#"egress-supervisor"#,
                r#"--self-test"#,
                r#"--repo-root"#,
                r#"."#,
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        // #694 dropped fifteen rows whose subjects became Rust behaviour. The eight
        // case-table rows are graded by the independent inventories in the ported
        // controls -- `the plan and the recorder agree` re-derives the argv shape,
        // the tool, the dispatch kind and the environment from its own rules, and
        // `the required calibrations and their links` holds the four calibration
        // lists itself, so deleting one from the table cannot delete its oracle.
        Row {
            name: "shell-argv",
            path: "crates/harness/src/egress_cases.rs",
            old: r#"    if case.guest {
        let extra = if hostname_tier(case) {"#,
            new: r#"    if case.guest {
        argv.push("shell".to_owned());
        argv.push("-c".to_owned());
        let extra = if hostname_tier(case) {"#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "the plan and the recorder agree",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: "credential-tool",
            path: "crates/harness/src/egress_cases.rs",
            old: r#"    argv.push(case.tool.to_owned());
    let ident = if options.attempt.is_empty() {"#,
            new: r#"    argv.push("egressprobe".to_owned());
    let ident = if options.attempt.is_empty() {"#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "the plan and the recorder agree",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: "rejection-guest",
            path: "crates/harness/src/egress_cases.rs",
            old: r#"        kind: if case.guest {
            "guest"
        } else {
            "validation-only"
        }"#,
            new: r#"        kind: if case.guest || case.case == "RJ1" {
            "guest"
        } else {
            "validation-only"
        }"#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "the plan and the recorder agree",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: "extra-env",
            path: "crates/harness/src/egress_cases.rs",
            old: r#"    let mut env = base_environment(work);"#,
            new: r#"    let mut env = base_environment(work);
    env.push(("MUTANT".to_owned(), "1".to_owned()));"#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "the plan and the recorder agree",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        // The four calibrations: each deletion leaves a case that proves only part of
        // its protocol matrix, which is exactly what the ported control's own list
        // is there to notice.
        Row {
            name: "tcp-calibration",
            path: "crates/harness/src/egress_cases.rs",
            old: r#"        "LC1" => &["lan-tcp80", "lan-tcp81", "lan-udp90", "lan-udp80"],"#,
            new: r#"        "LC1" => &["lan-tcp80", "lan-udp90", "lan-udp80"],"#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "the required calibrations and their links",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: "udp-calibration",
            path: "crates/harness/src/egress_cases.rs",
            old: r#"        "LC1" => &["lan-tcp80", "lan-tcp81", "lan-udp90", "lan-udp80"],"#,
            new: r#"        "LC1" => &["lan-tcp80", "lan-tcp81", "lan-udp90"],"#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "the required calibrations and their links",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: "v6-calibration",
            path: "crates/harness/src/egress_cases.rs",
            old: r#"        "V6" | "V6c" => &["public-v6-1111", "public-v6-1001"],"#,
            new: r#"        "V6" | "V6c" => &["public-v6-1111"],"#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "the required calibrations and their links",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: "resolver-calibration",
            path: "crates/harness/src/egress_cases.rs",
            old: r#"        "I1" => &[
            "public-1111",
            "public-1001",
            "gateway-udp","#,
            new: r#"        "I1" => &[
            "public-1111",
            "gateway-udp","#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "the required calibrations and their links",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        // The seven cleanup/catalog rows. `a timeout separates the launch from its
        // cleanup` is the control that owns most of the teardown contract -- the verb
        // sequence, the stale socket, and a cleanup that reports what went wrong -- so
        // one line of `egress_launch::cleanup` per row is what it must notice. The
        // identity signals are graded by `a failed force stop falls back to
        // identities` instead: in the timeout control the fake's runtime is reaped
        // before the identity loop can matter, so that control cannot tell whether
        // the loop ran.
        Row {
            name: "cleanup-no-kill",
            path: "crates/harness/src/egress_launch.rs",
            old: r#"                for identity in live {"#,
            new: r#"                for identity in Vec::<Value>::new() {"#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "a failed force stop falls back to identities",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: "cleanup-no-remove",
            path: "crates/harness/src/egress_launch.rs",
            old: r#"                ("remove", vec!["remove", name.as_str()], 10.0),"#,
            new: r#"                ("list", vec!["list"], 10.0),"#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "a timeout separates the launch from its cleanup",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: "cleanup-no-unlink",
            path: "crates/harness/src/egress_launch.rs",
            old: r#"                    if path.exists() {"#,
            new: r#"                    if false && path.exists() {"#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "a timeout separates the launch from its cleanup",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: "cleanup-suppress",
            path: "crates/harness/src/egress_launch.rs",
            old: r#"        if let Err(error) = self.record("cleanup") {
            failures.push(error);
        }
        failures"#,
            new: r#"        if let Err(error) = self.record("cleanup") {
            failures.push(error);
        }
        Vec::new()"#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "a timeout separates the launch from its cleanup",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        // An ignored deadline cannot be graded by the *unbounded* cleanup row: the
        // fake candidate finishes either way. What notices is the wedged-admin
        // control, which passes a 3 s deadline and requires the cleanup to be back
        // inside 4 s. The mutant honours a fixed 10 s instead, so the row costs one
        // wedged call rather than the 120 s cleanup bound.
        Row {
            name: "cleanup-unbounded",
            path: "crates/harness/src/egress_launch.rs",
            old: r#"        let listed = match list_catalog(&self.work, &binary, Some(limit)) {"#,
            new: r#"        let listed = match list_catalog(&self.work, &binary, Some(Instant::now() + Duration::from_secs(10))) {"#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "a wedged admin call cannot outlive the cleanup deadline",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        // #449's two catalog states: an absent table is "not yet initialized" and
        // keeps polling, a table with the wrong columns is a hard error. Both are
        // graded by `an unmigrated catalog is not yet initialized`, which builds the
        // database itself with `rusqlite` rather than through the code it grades.
        Row {
            name: "catalog-unmigrated-mismatch",
            path: "crates/harness/src/msb_catalog.rs",
            old: r#"            Ok(observed) if observed.is_empty() => return Attempt::NotYetInitialized,"#,
            new: r#"            Ok(observed) if observed.is_empty() && false => return Attempt::NotYetInitialized,"#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "an unmigrated catalog is not yet initialized",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: "catalog-mismatch-silenced",
            path: "crates/harness/src/msb_catalog.rs",
            old: r#"                    if !observed.iter().any(|name| name == column) {"#,
            new: r#"                    if false && !observed.iter().any(|name| name == column) {"#,
            run: Run::Crate(&[
                "egress-supervisor",
                "--self-test",
                "--only",
                "an unmigrated catalog is not yet initialized",
            ]),
            markers: &[r#"panicked at"#, r#"harness: FAIL: "#],
            anchors: 1,
        },
        Row {
            name: r#"prospective-bytewise"#,
            path: r#"crates/agent-vm/src/protected_config_dir.rs"#,
            old: r#"    if !name_is_plain(a) || !name_is_plain(b) { return true; }"#,
            new: r#"    return a == b;"#,
            run: Run::AgentBin(r#"protected_config_dir"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"prospective-bytewise-proof"#,
            path: r#"crates/agent-vm/src/protected_config_dir.rs"#,
            old: r#"    if !name_is_plain(a) || !name_is_plain(b) { return true; }"#,
            new: r#"    return a == b;"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"wildcard-dropped"#,
            path: r#"crates/agent-vm/src/protected_config_dir.rs"#,
            old: r#"    if !name_is_plain(a) || !name_is_plain(b) { return true; }"#,
            new: r#"    if !name_is_plain(a) || !name_is_plain(b) { return false; }"#,
            run: Run::AgentBin(r#"protected_config_dir"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"wildcard-dropped-proof"#,
            path: r#"crates/agent-vm/src/protected_config_dir.rs"#,
            old: r#"    if !name_is_plain(a) || !name_is_plain(b) { return true; }"#,
            new: r#"    if !name_is_plain(a) || !name_is_plain(b) { return false; }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"exposes-no-identity"#,
            path: r#"crates/agent-vm/src/protected_config_dir.rs"#,
            old: r#"(root_id.is_some() && ids[i] == root_id) || config::byte_path_contains"#,
            new: r#"false || config::byte_path_contains"#,
            run: Run::AgentBin(r#"protected_config_dir"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"exposes-no-identity-proof"#,
            path: r#"crates/agent-vm/src/protected_config_dir.rs"#,
            old: r#"(root_id.is_some() && ids[i] == root_id) || config::byte_path_contains"#,
            new: r#"false || config::byte_path_contains"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"prospective-path-only"#,
            path: r#"crates/agent-vm/src/protected_config_dir.rs"#,
            old: r#"src_id == ids[j] || anchor_paths_match"#,
            new: r#"false || anchor_paths_match"#,
            run: Run::AgentBin(r#"protected_config_dir"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"prospective-path-only-proof"#,
            path: r#"crates/agent-vm/src/protected_config_dir.rs"#,
            old: r#"src_id == ids[j] || anchor_paths_match"#,
            new: r#"false || anchor_paths_match"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"launch-nlink-skip"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"    config_dir.check_authority_links()?;"#,
            new: r#"    // mutant: skipped authority link check"#,
            run: Run::AgentBin(r#"mount"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"prospective-skip"#,
            path: r#"crates/agent-vm/src/protected_config_dir.rs"#,
            old: r#"                let (anchor, suffix) = resolve(&root, Walk::ProvisionedSource)?.end;"#,
            new: r#"                return Ok(());
                let (anchor, suffix) = resolve(&root, Walk::ProvisionedSource)?.end;"#,
            run: Run::AgentBin(r#"protected_config_dir"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"guard-skip-core"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"        config_dir.check_core_bind(source)?;"#,
            new: r#"        let _ = source;"#,
            run: Run::AgentBin(r#"mount"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"relative-unanchored"#,
            path: r#"crates/agent-vm/src/protected_config_dir.rs"#,
            old: r#"        cwd.join(path)"#,
            new: r#"        path.to_path_buf()"#,
            run: Run::AgentBin(r#"protected_config_dir"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"guard-ro-too"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"!m.is_readonly() && !m.is_fork()"#,
            new: r#"!m.is_fork()"#,
            run: Run::AgentBin(r#"mount"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"authority-home-from-pi"#,
            path: r#"crates/agent-vm/src/run.rs"#,
            old: r#"    let authority_home = config::host_home_dir().context("locating the authority home")?;"#,
            new: r#"    let authority_home = host_home.clone();"#,
            run: Run::AgentBin(r#"run::tests::raw_authority_home_selected"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"account-home-dropped"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"        .chain(context.account_home.iter())"#,
            new: r#""#,
            run: Run::AgentBin(r#"mount"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"saved-beats-cli"#,
            path: r#"crates/agent-vm/src/egress_policy.rs"#,
            old: r#"    match cli.0 {
        Some(c) => ResolvedGrant { enabled: c, source: GrantSource::Cli },
        None => match saved.0 {
            Some(u) => ResolvedGrant { enabled: u, source: GrantSource::UserConfig },
            None => ResolvedGrant { enabled: false, source: GrantSource::Default },
        },
    }"#,
            new: r#"    match saved.0 {
        Some(u) => ResolvedGrant { enabled: u, source: GrantSource::UserConfig },
        None => match cli.0 {
            Some(c) => ResolvedGrant { enabled: c, source: GrantSource::Cli },
            None => ResolvedGrant { enabled: false, source: GrantSource::Default },
        },
    }"#,
            run: Run::AgentBin(r#"egress_policy"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"saved-beats-cli-proof"#,
            path: r#"crates/agent-vm/src/egress_policy.rs"#,
            old: r#"    match cli.0 {
        Some(c) => ResolvedGrant { enabled: c, source: GrantSource::Cli },
        None => match saved.0 {
            Some(u) => ResolvedGrant { enabled: u, source: GrantSource::UserConfig },
            None => ResolvedGrant { enabled: false, source: GrantSource::Default },
        },
    }"#,
            new: r#"    match saved.0 {
        Some(u) => ResolvedGrant { enabled: u, source: GrantSource::UserConfig },
        None => match cli.0 {
            Some(c) => ResolvedGrant { enabled: c, source: GrantSource::Cli },
            None => ResolvedGrant { enabled: false, source: GrantSource::Default },
        },
    }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"directory-owner-ignored"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"if dir.uid != euid { return Some(AuthorityRefusal::DirOwner); }"#,
            new: r#"if false { return Some(AuthorityRefusal::DirOwner); }"#,
            run: Run::AgentBin(r#"config_authority::tests"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"directory-owner-ignored-proof"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"if dir.uid != euid { return Some(AuthorityRefusal::DirOwner); }"#,
            new: r#"if false { return Some(AuthorityRefusal::DirOwner); }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"directory-writable-ignored"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"if dir.mode & 0o022 != 0 { return Some(AuthorityRefusal::DirWritable); }"#,
            new: r#"if false { return Some(AuthorityRefusal::DirWritable); }"#,
            run: Run::AgentBin(r#"config_authority::tests"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"directory-writable-ignored-proof"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"if dir.mode & 0o022 != 0 { return Some(AuthorityRefusal::DirWritable); }"#,
            new: r#"if false { return Some(AuthorityRefusal::DirWritable); }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"file-owner-ignored"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"if f.uid != euid { Some(AuthorityRefusal::FileOwner) }"#,
            new: r#"if false { Some(AuthorityRefusal::FileOwner) }"#,
            run: Run::AgentBin(r#"config_authority::tests"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"file-owner-ignored-proof"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"if f.uid != euid { Some(AuthorityRefusal::FileOwner) }"#,
            new: r#"if false { Some(AuthorityRefusal::FileOwner) }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"symlink-trusted"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"Reached::ThroughSymlink => Some(AuthorityRefusal::ThroughSymlink)"#,
            new: r#"Reached::ThroughSymlink => None"#,
            run: Run::AgentBin(r#"config_authority::tests"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"symlink-trusted-proof"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"Reached::ThroughSymlink => Some(AuthorityRefusal::ThroughSymlink)"#,
            new: r#"Reached::ThroughSymlink => None"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"links-ignored"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"else if !authority_file_singly_linked(f.nlink) { Some(AuthorityRefusal::FileLinks(f.nlink)) }"#,
            new: r#"else if false { Some(AuthorityRefusal::FileLinks(f.nlink)) }"#,
            run: Run::AgentBin(r#"config_authority::tests"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"links-ignored-proof"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"else if !authority_file_singly_linked(f.nlink) { Some(AuthorityRefusal::FileLinks(f.nlink)) }"#,
            new: r#"else if false { Some(AuthorityRefusal::FileLinks(f.nlink)) }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"mask-other-only"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"else if f.mode & 0o022 != 0"#,
            new: r#"else if f.mode & 0o002 != 0"#,
            run: Run::AgentBin(r#"config_authority::tests"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"mask-other-only-proof"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"else if f.mode & 0o022 != 0"#,
            new: r#"else if f.mode & 0o002 != 0"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // Presence, not contents, is what makes a user file authority-bearing
        // (ADR-0040/0046). The anchor is the kernel body, never its `ensures`
        // clause, so replacing it cannot weaken the contract it is checked against.
        // #397 widened the disjunction from two fields to three, #511 to four and
        // #735 to five, so the anchor and its test both moved again: the body now
        // names `allow_tools`, and the oracle is the thirty-two-row table.
        Row {
            name: r#"config-mounts-authority-or"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"if t.network { true } else { t.mounts || t.mount_sets || t.egress_sets || t.allow_tools }"#,
            new: r#"if t.network { t.mounts || t.mount_sets || t.egress_sets || t.allow_tools } else { false }"#,
            run: Run::AgentBin(r#"authority_required_matches_the_thirty_two_rows"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"config-mounts-authority-or-proof"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"if t.network { true } else { t.mounts || t.mount_sets || t.egress_sets || t.allow_tools }"#,
            new: r#"if t.network { t.mounts || t.mount_sets || t.egress_sets || t.allow_tools } else { false }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // The merge/refuse rule decides whether a declaration is silently dropped
        // (a last-wins override) or refused, now that config and argv claims meet.
        // Both anchors are kernel *bodies*; their `ensures` clauses spell the same
        // rules in a shape the bodies never use, so the `-proof` twins still catch a
        // mutated implementation rather than a weakened contract.
        Row {
            name: r#"config-mounts-claim-conflict-merged"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"else { ClaimDecision::Conflict }"#,
            new: r#"else { ClaimDecision::Merge }"#,
            run: Run::AgentBin(r#"claim_decision_matches_the_oracle_table"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"config-mounts-claim-conflict-merged-proof"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"else { ClaimDecision::Conflict }"#,
            new: r#"else { ClaimDecision::Merge }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // `declarations_equivalent` is the merge half of the same rule, and every one
        // of its six facts is load-bearing. `exclusions` is the fact a reader is
        // least likely to notice: dropping it merges two fork declarations that
        // differ only in what they leave out of the copy, so one declaration
        // disappears and its exclusions silently stop applying. The anchor is the
        // kernel *body*; its `ensures` spells the same conjunction in a shape the
        // body never uses, so the `-proof` twin catches the mutated body rather than
        // a weakened contract.
        Row {
            name: r#"config-mounts-equivalent-exclusions-dropped"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"    if !f.fork { return false; }
    f.exclusions"#,
            new: r#"    if !f.fork { return false; }
    true"#,
            run: Run::AgentBin(r#"declarations_equivalent_matches_the_oracle_table"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"config-mounts-equivalent-exclusions-dropped-proof"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"    if !f.fork { return false; }
    f.exclusions"#,
            new: r#"    if !f.fork { return false; }
    true"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // The launch half of the same rule: a config/argv pair that disagrees must
        // refuse, so the mutant's silent merge is observable as a launch that
        // reaches builder wiring instead of naming both origins.
        Row {
            name: r#"config-mounts-claim-conflict-merged-launch"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"else { ClaimDecision::Conflict }"#,
            new: r#"else { ClaimDecision::Merge }"#,
            run: Run::AgentTest(
                r#"config_mounts"#,
                r#"config_and_cli_conflicts_are_refused_naming_both"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // `~` may expand for config path fields and never for `--mount`: the shell
        // already expanded argv, so a quoted `~/x` must stay "must be absolute".
        Row {
            name: r#"config-mounts-home-expanded-on-cli"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"else if home == HomeExpansion::Enabled && bytes.len() >= 2"#,
            new: r#"else if bytes.len() >= 2"#,
            run: Run::AgentBin(r#"path_spelling_matches_the_oracle_table"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"config-mounts-home-expanded-on-cli-proof"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"else if home == HomeExpansion::Enabled && bytes.len() >= 2"#,
            new: r#"else if bytes.len() >= 2"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // The guest field may expand `~/` only where the host may (#530): argv keeps
        // reading `/a:~/b` as a mode. Kernel body: killed by the oracle and the proof.
        Row {
            name: r#"config-mounts-guest-home-expanded-on-cli"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"|| path_spelling(bytes, home) != PathSpelling::Refused"#,
            new: r#"|| path_spelling(bytes, HomeExpansion::Enabled) != PathSpelling::Refused"#,
            run: Run::AgentBin(r#"segment_is_guest_path_matches_the_oracle_table"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"config-mounts-guest-home-expanded-on-cli-proof"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"|| path_spelling(bytes, home) != PathSpelling::Refused"#,
            new: r#"|| path_spelling(bytes, HomeExpansion::Enabled) != PathSpelling::Refused"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // The adapter: `parse_mount_spec` must pass its own grammar's expansion. With
        // `Enabled`, argv `/x:~/y` becomes a `~/y` guest refused as "must be absolute"
        // instead of an unknown mode, which the unit row observes.
        Row {
            name: r#"config-mounts-guest-classified-with-config-grammar"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#".is_some_and(|s| segment_is_guest_path(s.as_bytes(), expansion));"#,
            new: r#".is_some_and(|s| segment_is_guest_path(s.as_bytes(), HomeExpansion::Enabled));"#,
            run: Run::AgentBin(r#"only_the_config_syntax_may_expand_a_tilde"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // A mount that shadows a declared `persist` link is refused inside
        // `mount::prepare`, ahead of `prepare_forks` (ADR-0046 Decision 6). Skipping
        // the check does not merely move a message: the plan publishes a fork copy of
        // the user's directory for a launch that is then refused. Both rows kill on
        // "a fork store exists after a refusal", the unit one through `prepare`'s
        // absent store path and the launch one through the whole-process snapshot.
        Row {
            name: r#"config-mounts-persist-check-skipped"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"    context.persisted_home.refuse_conflicts(&destinations)?;"#,
            new: r#"    let _ = &destinations;"#,
            run: Run::AgentBin(r#"persist_collision_refuses_before_any_fork_store"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The launch row kills through the config route: the declaration that
        // causes the collision *and* the fork are both in the user file, so this is
        // the path a user actually hits (the two CLI-only rows above stay as the
        // declaration-source-independent red tests they were written as).
        Row {
            name: r#"config-mounts-persist-check-skipped-launch"#,
            path: r#"crates/agent-vm/src/mount.rs"#,
            old: r#"    context.persisted_home.refuse_conflicts(&destinations)?;"#,
            new: r#"    let _ = &destinations;"#,
            run: Run::AgentTest(
                r#"config_mounts"#,
                r#"a_config_fork_shadowing_a_persist_path_is_refused_before_any_fork"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // `--no-config-mounts` withholds the user config's declarations and nothing
        // else (ADR-0046 Decision 5). The anchor is the kernel *body*: its `ensures`
        // spells the same rule as `r == (f.declared && !f.suppressed)`, a shape the
        // body never uses, so the `-proof` twin still catches a mutated body.
        Row {
            name: r#"config-mounts-opt-out-ignored"#,
            path: r#"crates/agent-vm/src/mount_selection.rs"#,
            old: r#"if f.suppressed { false } else { f.declared }"#,
            new: r#"if false { false } else { f.declared }"#,
            run: Run::AgentBin(r#"config_mounts_selected_matches_the_four_rows"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"config-mounts-opt-out-ignored-proof"#,
            path: r#"crates/agent-vm/src/mount_selection.rs"#,
            old: r#"if f.suppressed { false } else { f.declared }"#,
            new: r#"if false { false } else { f.declared }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"config-mounts-opt-out-ignored-launch"#,
            path: r#"crates/agent-vm/src/mount_selection.rs"#,
            old: r#"if f.suppressed { false } else { f.declared }"#,
            new: r#"if false { false } else { f.declared }"#,
            run: Run::AgentTest(
                r#"config_mounts"#,
                r#"opt_out_keeps_cli_core_and_persisted_paths"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The union now iterates the resolved user tier and the resolved CLI entries;
        // dropping the user side is the mutation (#506 moved it behind `ResolvedAllowances`).
        Row {
            name: r#"user-allowances-dropped"#,
            path: r#"crates/agent-vm/src/egress_policy.rs"#,
            old: r#".flat_map(ResolvedAllowances::allowances)"#,
            new: r#".flat_map(ResolvedAllowances::allowances).take(0)"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"user_network_table_reaches_the_sandbox_policy"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // #506's authority path. A reference must expand to real allowances, and a CLI
        // reference must consume the verified read's verdict: dropping either is the
        // kind of regression these two rows exist to kill.
        Row {
            name: r#"reference-expansion-dropped"#,
            path: r#"crates/agent-vm/src/egress_reference.rs"#,
            old: r#"    requests
        .iter()
        .map(|request| {"#,
            new: r#"    requests
        .iter()
        .take(0)
        .map(|request| {"#,
            run: Run::AgentBin(r#"expansion_is_port_pinned"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"reference-trust-unchecked"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            // The whole body, so the mutant still compiles: replacing only the head
            // leaves `map_err`'s closure parameter untyped (E0282), which is a
            // compile failure rather than the surviving-verdict behaviour this row
            // names.
            old: r#"    pub(crate) fn require(&self) -> Result<(), UntrustedConfig> {
        self.measurement
            .map_err(|measurement| measurement.into_untrusted(AuthoritySubject::EgressReference))
    }"#,
            new: r#"    pub(crate) fn require(&self) -> Result<(), UntrustedConfig> {
        Ok(())
    }"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"cli_set_reference_requires_a_verified_user_file"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The user arm now destructures `Verification` instead of yielding the token
        // directly, so the anchor is the assignment of the verified token. Discarding
        // it is the mutation: a present `[network]` then finds no token and load fails
        // with the "authority was not measured" invariant, which is a behaviour change
        // rather than a syntax error.
        Row {
            name: r#"verify-always-skipped"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"            authorized: verification.authorized,"#,
            new: r#"            authorized: None,"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"unsafe_user_network_is_refused_before_launch_state"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // A present `mounts` key makes a user file authority-bearing, empty list
        // included: the trigger reads the *presence* of the field, so both mutants
        // below keep the field but drop its effect, and a symlinked `mounts = []`
        // file then loads through the compatibility path meant for tools-only files.
        // The mount trigger is one aggregate over both sites (#396), so the shared
        // anchor is that expression. Every replacement below keeps the struct shape, so
        // a control cannot pass (or fail) on a missing-field compile error.
        // #511 added the fourth trigger, so the shared anchor grew one line: every
        // derived mutant keeps it, and no row can pass or fail on a missing-field
        // compile error instead of on the behaviour it names.
        Row {
            name: r#"config-mounts-presence-ignored"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"            top_level: allowed && document.contains_key("mounts"),"#,
            new: r#"            top_level: false,"#,
            run: Run::AgentBin(r#"present_empty_mounts_through_a_symlink_is_refused"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"config-mounts-presence-ignored-launch"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"            top_level: allowed && document.contains_key("mounts"),"#,
            new: r#"            top_level: false,"#,
            run: Run::AgentTest(
                r#"config_mounts"#,
                r#"unsafe_user_mounts_are_refused_before_launch_state"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"config-mounts-empty-unverified"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"            top_level: allowed && document.contains_key("mounts"),"#,
            new: r#"            top_level: document.get("mounts").and_then(toml::Value::as_array).is_some_and(|a| !a.is_empty()),"#,
            run: Run::AgentBin(r#"present_empty_mounts_through_a_symlink_is_refused"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"config-mounts-empty-unverified-launch"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"            top_level: allowed && document.contains_key("mounts"),"#,
            new: r#"            top_level: document.get("mounts").and_then(toml::Value::as_array).is_some_and(|a| !a.is_empty()),"#,
            run: Run::AgentTest(
                r#"config_mounts"#,
                r#"empty_mounts_still_requires_a_verified_file"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"config-mounts-verify-skipped-launch"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"            authorized: verification.authorized,"#,
            // #695: this replacement used to be `FileTierKind::User => None,`,
            // which was a compiling arm value when the tier decision was one
            // `match` expression. #506 split the arm into a block so a second
            // verdict could be carried out of the same read, and from then on the
            // replacement was a syntax error: the row reported "the mutant was
            // never compiled" on every run while `--check-anchors` kept passing it,
            // because that check never parses a replacement (#581). Discarding the
            // verdict is the same mutation as `verify-always-skipped`, which is the
            // point: the two rows own two different refusals.
            new: r#"            authorized: None,"#,
            run: Run::AgentTest(
                r#"config_mounts"#,
                r#"unsafe_user_mounts_are_refused_before_launch_state"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The project tier may not declare mounts at all (ADR-0046 is user-scope), so
        // the refusal is a boundary in its own right: without it a project checkout
        // would hand every launch of it a host bind.
        Row {
            name: r#"config-mounts-builtin-mounts-accepted"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"    if raw.mounts.is_some() {
        return Err(mounts_refusal(path, RefusingTier::BuiltIn));
    }"#,
            new: r#"    if false {
        return Err(mounts_refusal(path, RefusingTier::BuiltIn));
    }"#,
            run: Run::AgentBin(r#"builtin_mounts_are_refused"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // -- Named mount sets (#397) -------------------------------------------------
        // Every replacement below keeps all three `AuthorityTriggers` fields, so a
        // control can never pass (or fail) on a missing-struct-field compile error
        // instead of on the behaviour it names.
        Row {
            name: r#"mount-sets-presence-ignored"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"        mount_sets: document.contains_key("mount_sets"),"#,
            new: r#"        mount_sets: false,"#,
            run: Run::AgentBin(r#"mount_sets_presence_requires_a_verified_file"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"mount-sets-presence-ignored-launch"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"        mount_sets: document.contains_key("mount_sets"),"#,
            new: r#"        mount_sets: false,"#,
            run: Run::AgentTest(
                r#"config_mounts"#,
                r#"named_mount_sets_unsafe_file_is_refused_before_launch_state"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // Declaring a set is user-scope only; accepting a project table would let a
        // checkout plant filesystem access for every launch of it.
        Row {
            name: r#"mount-sets-project-accepted"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"    if raw.mount_sets.is_some() {
        return Err(mount_sets_refusal(path, tier));
    }"#,
            new: r#"    if false {
        return Err(mount_sets_refusal(path, tier));
    }"#,
            run: Run::AgentBin(r#"project_mount_sets_are_refused_even_when_empty"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // Every declared closure is validated, unused sets included (decision A2). A
        // cycle edge treated as "already seen" is the smallest way to skip that: the
        // walk completes and nothing is refused.
        Row {
            name: r#"mount-sets-cycle-skipped"#,
            path: r#"crates/agent-vm/src/config_mounts/sets.rs"#,
            old: r#"                VisitDecision::Cycle => {
                    return Err(UserMountsError::Cycle {
                        site: EntrySite::SetEntry {
                            definition: set.0,
                            index,
                        },
                    });
                }"#,
            new: r#"                VisitDecision::Cycle => {}"#,
            run: Run::AgentBin(r#"reference_errors_are_named_by_site"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"mount-sets-cycle-skipped-launch"#,
            path: r#"crates/agent-vm/src/config_mounts/sets.rs"#,
            old: r#"                VisitDecision::Cycle => {
                    return Err(UserMountsError::Cycle {
                        site: EntrySite::SetEntry {
                            definition: set.0,
                            index,
                        },
                    });
                }"#,
            new: r#"                VisitDecision::Cycle => {}"#,
            run: Run::AgentTest(
                r#"config_mounts"#,
                r#"named_mount_sets_reference_errors_refuse_load_under_every_option"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // An unknown reference must be refused at load, in an unused set too.
        Row {
            name: r#"mount-sets-unknown-set-skipped"#,
            path: r#"crates/agent-vm/src/config_mounts/sets.rs"#,
            old: r#"                        None => {
                            return Err(UserMountsError::UnknownSet {
                                site,
                                declaration: text.to_string(),
                            });
                        }
                    },
                    Err(SelectorError::Direct(error)) => {"#,
            new: r#"                        None => Entry::Reference(SetId(0)),
                    },
                    Err(SelectorError::Direct(error)) => {"#,
            run: Run::AgentBin(r#"reference_errors_are_named_by_site"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // `explicit_set` now hands back a shared resolved list (#396), so the mutant
        // returns that type's empty value rather than a `Vec`.
        Row {
            name: r#"mount-sets-opt-out-drops-explicit-names"#,
            path: r#"crates/agent-vm/src/mount_selection.rs"#,
            old: r#"                let selected = explicit_set(user, &name)?;"#,
            new: r#"                let selected = if policy.suppressed() { ResolvedMountList::empty() } else { explicit_set(user, &name)? };"#,
            run: Run::AgentBin(r#"explicit_set_names_survive_the_opt_out"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"mount-sets-opt-out-drops-explicit-names-launch"#,
            path: r#"crates/agent-vm/src/mount_selection.rs"#,
            old: r#"                let selected = explicit_set(user, &name)?;"#,
            new: r#"                let selected = if policy.suppressed() { ResolvedMountList::empty() } else { explicit_set(user, &name)? };"#,
            run: Run::AgentTest(
                r#"config_mounts"#,
                r#"named_mount_sets_opt_out_keeps_an_explicit_selection"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // Each direct leaf's origin holds one *reference* to its set's name: copying
        // the key per leaf multiplies retained provenance by the leaf count, below both
        // the file-size and leaf-visit bounds. The regression observes the allocation
        // itself (`Arc::ptr_eq` across leaves and across a model clone).
        Row {
            name: r#"mount-sets-name-copied-per-leaf"#,
            path: r#"crates/agent-vm/src/config_mounts/sets.rs"#,
            old: r#"                            set: Arc::clone(&shared[definition]),"#,
            new: r#"                            set: Arc::from(names[definition].as_str()),"#,
            run: Run::AgentBin(r#"mount_set_key_is_stored_once_across_leaves_and_clones"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The differential's left-hand side is the real `mount::claim`, so a fact its
        // fixtures never isolate is a fact the indexed adapter can ignore without
        // disagreeing. Each equivalence fact needs one row where that fact alone
        // differs: with only the fork-vs-read-only pair, an adapter that drops `fork`
        // still agrees on every fixture (read-only differs in that pair as well). The
        // anchor is the adapter's call to the shared kernel, replaced by a hand-rolled
        // conjunction that leaves fork out.
        Row {
            name: r#"mount-sets-claim-ignores-fork"#,
            path: r#"crates/agent-vm/src/config_mounts/sets.rs"#,
            old: r#"            equivalent: same_declaration(&first.request.mount, &candidate.request.mount),"#,
            new: r#"            equivalent: { let a = &first.request.mount; let b = &candidate.request.mount; a.source_spelling == b.source_spelling && a.host == b.host && matches!(a.policy, crate::mount::MountPolicy::BindReadOnly { .. }) == matches!(b.policy, crate::mount::MountPolicy::BindReadOnly { .. }) && matches!(a.policy, crate::mount::MountPolicy::BindReadOnly { follow_links: true } | crate::mount::MountPolicy::Fork { follow_links: true }) == matches!(b.policy, crate::mount::MountPolicy::BindReadOnly { follow_links: true } | crate::mount::MountPolicy::Fork { follow_links: true }) && a.exclusions == b.exclusions },"#,
            run: Run::AgentBin(r#"mount_set_indexed_claim_matches_claim"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The selector precedence is what keeps the two grammars apart. The literal
        // "absolute path classified as a name" mutation cannot exist — decision A1
        // excludes `/` and `~`, so no path spelling can parse as a name — so the
        // load-bearing direction is the reverse: a valid name classified as a path.
        Row {
            name: r#"mount-sets-name-classified-as-path"#,
            path: r#"crates/agent-vm/src/config_mounts.rs"#,
            old: r#"    if f.path_spelling {
        SelectorKind::Path"#,
            new: r#"    if f.name_spelling {
        SelectorKind::Path"#,
            run: Run::AgentBin(r#"selector_classification_matches_the_table"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"mount-sets-name-classified-as-path-proof"#,
            path: r#"crates/agent-vm/src/config_mounts.rs"#,
            old: r#"    if f.path_spelling {
        SelectorKind::Path"#,
            new: r#"    if f.name_spelling {
        SelectorKind::Path"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // The expansion budget's polarity: one more leaf admitted past the limit turns
        // a refused file into a hang. The anchor is the kernel *body*; its `ensures`
        // spells `<` in a shape the body never uses, so the `-proof` twin still bites.
        Row {
            name: r#"mount-sets-budget-off-by-one"#,
            path: r#"crates/agent-vm/src/config_mounts/sets.rs"#,
            old: r#"{
    used < MAX_MOUNT_SET_EXPANSION_WORK
}"#,
            new: r#"{
    used <= MAX_MOUNT_SET_EXPANSION_WORK
}"#,
            run: Run::AgentBin(r#"mount_set_expansion_work_boundary"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"mount-sets-budget-off-by-one-proof"#,
            path: r#"crates/agent-vm/src/config_mounts/sets.rs"#,
            old: r#"{
    used < MAX_MOUNT_SET_EXPANSION_WORK
}"#,
            new: r#"{
    used <= MAX_MOUNT_SET_EXPANSION_WORK
}"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // The anchor names the *noting-symlink* reader's checkpoint plus the line it
        // exists for: #557 added a second checkpointed reader, so a bare
        // `after_open();` is no longer one statement.
        Row {
            name: r#"descriptor-reopen"#,
            path: r#"crates/agent-vm/src/host_paths.rs"#,
            old: r#"            after_open();
            read_regular_no_follow_fd(fd, path, max).map(|(bytes, facts)| VerifiedRead {"#,
            new: r#"            after_open(); drop(fd); let fd = rfs::open(path, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())?;
            read_regular_no_follow_fd(fd, path, max).map(|(bytes, facts)| VerifiedRead {"#,
            run: Run::AgentBin(
                r#"noting_symlink_takes_bytes_and_facts_from_the_opened_descriptor"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The built-in tier's refusals moved into the one routine both non-user tiers
        // share (#396), so the anchor is that routine's network arm — still the exact
        // statement that refuses a built-in `[network]` table.
        Row {
            name: r#"builtin-network-accepted"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"        return Err(network_refusal(value, path, RefusingTier::BuiltIn));"#,
            new: r#"        let _ = value;"#,
            run: Run::AgentBin(r#"builtin_network_table_is_refused_naming_setting_and_tier"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // -- Tool-specific config mounts (#396) --------------------------------------
        // A tool's `mounts` field makes the file authority-bearing even when empty and
        // even on a definition no launch verb reaches: ignoring that half of the
        // aggregate lets a symlinked `mounts = []` tool field load unverified.
        Row {
            name: r#"tool-mounts-presence-ignored"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"            tool_field: tool_mounts,"#,
            new: r#"            tool_field: false,"#,
            run: Run::AgentBin(r#"tool_mounts_presence_requires_verified_read_even_empty"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"tool-mounts-presence-ignored-launch"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"            tool_field: tool_mounts,"#,
            new: r#"            tool_field: false,"#,
            run: Run::AgentTest(
                r#"config_mounts"#,
                r#"empty_present_tool_mounts_require_authority_before_any_launch"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"tool-mounts-empty-unverified"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"            tool_field: tool_mounts,"#,
            new: r#"            tool_field: document.get("tools").and_then(toml::Value::as_array).is_some_and(|tools| tools.iter().any(|tool| tool.as_table().and_then(|t| t.get("mounts")).and_then(toml::Value::as_array).is_some_and(|a| !a.is_empty()))),"#,
            run: Run::AgentBin(r#"tool_mounts_presence_requires_verified_read_even_empty"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // Mount authority is no longer project-refused (#735 made a project or
        // sourced tool's `mounts` an inert declaration): the compiled-in defaults
        // are the one tier that may not carry one, because a shipped definition is
        // not something a launch can authorize. Accepting it there is the mutation.
        Row {
            name: r#"tool-mounts-builtin-accepted"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"    if let Some(declaration) = raw.tools.iter().position(|tool| tool.mounts.is_some()) {
        return Err(tool_mounts_refusal(
            path,
            RefusingTier::BuiltIn,
            declaration,
        ));
    }"#,
            new: r#"    if let Some(declaration) = raw.tools.iter().position(|tool| tool.mounts.is_some()) {
        let _ = declaration;
    }"#,
            run: Run::AgentBin(
                r#"project_tool_mounts_are_inert_until_authorized_and_builtin_ones_are_refused"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The fold must cover the whole visited closure, not just the launched tool's
        // own list: an inherited declaration silently dropped is exactly the bug the
        // closure exists to prevent.
        Row {
            name: r#"tool-mounts-facet-dropped"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"            if !tool.mounts().is_empty() {
                lists.push(tool.mounts());
            }"#,
            new: r#"            if tool.declaration_index == definitions[start.0].declaration_index
                && !tool.mounts().is_empty()
            {
                lists.push(tool.mounts());
            }"#,
            run: Run::AgentTest(
                r#"config_mounts"#,
                r#"tool_mount_chain_cycle_and_diamond_bind_each_declaration_once"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The opt-out gates both automatic inputs at one site; appending the entry
        // facet outside that gate leaves a tool's host paths mounted under
        // `--no-config-mounts`.
        Row {
            name: r#"tool-mounts-suppression-ignored"#,
            path: r#"crates/agent-vm/src/mount_selection.rs"#,
            old: r#"    let selected = config_mounts_selected(ConfigSelectionFacts {
        declared,
        suppressed: policy.suppressed(),
    });"#,
            new: r#"    let selected = config_mounts_selected(ConfigSelectionFacts {
        declared,
        suppressed: false,
    });"#,
            run: Run::AgentBin(r#"suppression_drops_both_automatic_inputs_but_not_cli_sets"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"tool-mounts-suppression-ignored-launch"#,
            path: r#"crates/agent-vm/src/mount_selection.rs"#,
            old: r#"    let selected = config_mounts_selected(ConfigSelectionFacts {
        declared,
        suppressed: policy.suppressed(),
    });"#,
            new: r#"    let selected = config_mounts_selected(ConfigSelectionFacts {
        declared,
        suppressed: false,
    });"#,
            run: Run::AgentTest(
                r#"config_mounts"#,
                r#"opt_out_removes_defaults_own_and_inherited_mounts_but_keeps_cli"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // One budget for the whole file, continued into catalog construction: a fresh
        // counter per tool or per launch makes the same leaves free to repeat.
        // One budget for the whole load, carried across tiers and into the catalog
        // build (#735 V23): a fresh counter per tier, per declared tool list or at
        // the hand-off makes the same leaves free to repeat.
        Row {
            name: r#"mount-budget-tier-reset"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"                home,
                work,
            )
            .map_err(|error| anyhow!("config: {}: {error}", crate::one_line::quoted_path(path)))?;"#,
            new: r#"                home,
                &mut config_mounts::MountExpansionWork::fresh(),
            )
            .map_err(|error| anyhow!("config: {}: {error}", crate::one_line::quoted_path(path)))?;"#,
            run: Run::AgentBin(r#"mount_budget_spans_project_source_and_user_tiers"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"mount-budget-declared-reset"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"            config_mounts::parse_declared_tool_mounts(path, &tool_mount_values, home, work)"#,
            new: r#"            config_mounts::parse_declared_tool_mounts(
                path,
                &tool_mount_values,
                home,
                &mut config_mounts::MountExpansionWork::fresh(),
            )"#,
            run: Run::AgentBin(r#"mount_budget_spans_project_source_and_user_tiers"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"tool-mounts-budget-reset-handoff"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"        let mut work = mount_work;"#,
            new: r#"        let mut work = config_mounts::MountExpansionWork::fresh();"#,
            run: Run::AgentBin(r#"mount_budget_continues_from_combined_tiers_into_the_catalog"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // Retained lists share leaf handles; allocating a fresh `Arc` from a cloned
        // payload per occurrence multiplies retained memory by the entry count.
        Row {
            name: r#"tool-mounts-payload-deep-copied"#,
            path: r#"crates/agent-vm/src/config_mounts/sets.rs"#,
            old: r#"    ResolvedMountList::from_leaves(unique.iter().map(|leaf| Arc::clone(leaf)).collect())"#,
            new: r#"    ResolvedMountList::from_leaves(unique.iter().map(|leaf| Arc::new(ConfigMountLeaf { request: leaf.request.clone(), site: leaf.site.clone() })).collect())"#,
            run: Run::AgentBin(r#"tool_closures_share_leaf_payloads_across_catalog_entries"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // -- Named egress sets (#511) ------------------------------------------------
        // Presence, not contents, is again the rule: `[egress_sets]` makes the file
        // authority-bearing even empty, so dropping its effect lets a symlinked
        // sets-only file load through the tools-only compatibility path.
        Row {
            name: r#"egress-sets-presence-ignored"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"        egress_sets: document.contains_key("egress_sets"),"#,
            new: r#"        egress_sets: false,"#,
            run: Run::AgentBin(r#"egress_sets_presence_requires_a_verified_file"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // Declaring sets is user-scope only; accepting a project table would let a
        // checkout name egress for every launch of it.
        Row {
            name: r#"egress-sets-project-accepted"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"    if raw.egress_sets.is_some() {
        return Err(egress_sets_refusal(path, tier));
    }"#,
            new: r#"    if false {
        return Err(egress_sets_refusal(path, tier));
    }"#,
            run: Run::AgentBin(r#"project_egress_sets_are_refused_even_when_empty"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // A cycle edge treated as "already seen" is the smallest way to skip the
        // refusal: the walk completes and the load succeeds.
        Row {
            name: r#"egress-sets-cycle-skipped"#,
            path: r#"crates/agent-vm/src/egress_reference/sets.rs"#,
            old: r#"                VisitDecision::Cycle => {
                    return Err(EgressSetError::Cycle {
                        definition: set.0,
                        index,
                    });
                }"#,
            new: r#"                VisitDecision::Cycle => {}"#,
            run: Run::AgentBin(r#"cycles_are_refused_by_site"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // Every definition is a root: walking only the first leaves an unused set
        // unvalidated, and compile then finds an order that omits it.
        Row {
            name: r#"egress-sets-unused-unvalidated"#,
            path: r#"crates/agent-vm/src/egress_reference/sets.rs"#,
            old: r#"    for root in 0..definitions.len() {"#,
            new: r#"    for root in 0..definitions.len().min(1) {"#,
            run: Run::AgentBin(r#"unused_sets_are_compiled"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // A child's closure is the whole reason a set may nest.
        Row {
            name: r#"egress-sets-nested-closure-dropped"#,
            path: r#"crates/agent-vm/src/egress_reference/sets.rs"#,
            old: r#"                    for allowance in &closures[child.0] {"#,
            new: r#"                    for allowance in closures[child.0].iter().take(0) {"#,
            run: Run::AgentBin(r#"issue_example_closures"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The budget's enforcement, as distinct from its kernel: a `false` here admits
        // every visit a crafted table can produce.
        Row {
            name: r#"egress-sets-budget-unchecked"#,
            path: r#"crates/agent-vm/src/egress_reference/sets.rs"#,
            old: r#"        if !egress_set_expansion_work_allowed(self.used) {"#,
            new: r#"        if false {"#,
            run: Run::AgentBin(r#"egress_set_expansion_work_boundary"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The kernel's polarity: one more visit admitted past the limit is the
        // difference between a refused file and an unbounded expansion. The anchor is
        // the body, so the `-proof` twin still bites on the contract.
        Row {
            name: r#"egress-sets-budget-off-by-one-proof"#,
            path: r#"crates/agent-vm/src/egress_reference/sets.rs"#,
            old: r#"{
    used < MAX_EGRESS_SET_EXPANSION_WORK
}"#,
            new: r#"{
    used <= MAX_EGRESS_SET_EXPANSION_WORK
}"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // A repeated reference re-applies the cached expansion instead of skipping:
        // the grants are identical, so only the insertion counter can see it.
        Row {
            name: r#"egress-sets-repeat-reapplied"#,
            path: r#"crates/agent-vm/src/egress_reference.rs"#,
            old: r#"                if resolved.reference_index(&reference).is_some() {
                    continue;
                }"#,
            new: r#"                if let Some(slot) = resolved.reference_index(&reference) {
                    for allowance in resolved.references[slot].1.clone() {
                        resolved.insert(allowance, false, Some(slot));
                    }
                    continue;
                }"#,
            run: Run::AgentBin(r#"repeated_references_apply_once"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // Case folding is the whole compatibility claim of R5: without it `SET:8443`
        // silently keeps its old meaning while `set:8443` becomes a reference.
        Row {
            name: r#"set-claim-case-sensitive"#,
            path: r#"crates/agent-vm/src/egress_reference.rs"#,
            old: r#"    let prefix = (s[0] == 0x73 || s[0] == 0x53)"#,
            new: r#"    let prefix = (s[0] == 0x73)"#,
            run: Run::AgentBin(r#"set_claim_matches_byte_oracle"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"set-claim-case-sensitive-proof"#,
            path: r#"crates/agent-vm/src/egress_reference.rs"#,
            old: r#"    let prefix = (s[0] == 0x73 || s[0] == 0x53)"#,
            new: r#"    let prefix = (s[0] == 0x73)"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // -- Image-declared network requests (#505, ADR-0060) -----------------------
        // Every anchor below is executable-body text that occurs exactly once: the
        // kernel anchors include the `ensures` line plus the whole body (the
        // `limit_body` precedent), so the spec text can never be what is mutated.
        Row {
            name: r#"image-label-limit"#,
            path: r#"crates/agent-vm/src/image_requests.rs"#,
            old: r#"    ensures ok == request_label_count_within_limit_spec(count),
{
    count <= MAX_REQUEST_LABELS
}"#,
            new: r#"    ensures ok == request_label_count_within_limit_spec(count),
{
    count <= MAX_REQUEST_LABELS + 1
}"#,
            run: Run::AgentBin(r#"image_requests::tests::label_budget_"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"image-label-limit-proof"#,
            path: r#"crates/agent-vm/src/image_requests.rs"#,
            old: r#"    ensures ok == request_label_count_within_limit_spec(count),
{
    count <= MAX_REQUEST_LABELS
}"#,
            new: r#"    ensures ok == request_label_count_within_limit_spec(count),
{
    count <= MAX_REQUEST_LABELS + 1
}"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // The kind precedence: the Agent arm answering Image is one word, and the
        // table notices. `requires !(image_word && agent_word)` keeps the two arms
        // mutually exclusive, so this is the only way to invert the decision.
        Row {
            name: r#"image-label-kind"#,
            path: r#"crates/agent-vm/src/image_requests.rs"#,
            old: r#"    ensures k == request_label_kind_spec(f),
{
    if !f.under_prefix {
        RequestLabelKind::NotRequest
    } else if f.image_word && f.name_safe {
        RequestLabelKind::Image
    } else if f.agent_word && f.name_safe {
        RequestLabelKind::Agent
    } else {
        RequestLabelKind::Unrecognized
    }
}"#,
            new: r#"    ensures k == request_label_kind_spec(f),
{
    if !f.under_prefix {
        RequestLabelKind::NotRequest
    } else if f.image_word && f.name_safe {
        RequestLabelKind::Image
    } else if f.agent_word && f.name_safe {
        RequestLabelKind::Image
    } else {
        RequestLabelKind::Unrecognized
    }
}"#,
            run: Run::AgentBin(r#"image_requests::tests::key_kind_"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"image-label-kind-proof"#,
            path: r#"crates/agent-vm/src/image_requests.rs"#,
            old: r#"    ensures k == request_label_kind_spec(f),
{
    if !f.under_prefix {
        RequestLabelKind::NotRequest
    } else if f.image_word && f.name_safe {
        RequestLabelKind::Image
    } else if f.agent_word && f.name_safe {
        RequestLabelKind::Agent
    } else {
        RequestLabelKind::Unrecognized
    }
}"#,
            new: r#"    ensures k == request_label_kind_spec(f),
{
    if !f.under_prefix {
        RequestLabelKind::NotRequest
    } else if f.image_word && f.name_safe {
        RequestLabelKind::Image
    } else if f.agent_word && f.name_safe {
        RequestLabelKind::Image
    } else {
        RequestLabelKind::Unrecognized
    }
}"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // The one place coverage touches the report. Admitting every addition is the
        // mutant that makes a fully covered group print.
        Row {
            name: r#"image-coverage-ignored"#,
            path: r#"crates/agent-vm/src/image_requests.rs"#,
            old: r#"    added.filter(|request| !covered(request)).collect()"#,
            new: r#"    added.filter(|_| true).collect()"#,
            run: Run::AgentBin(r#"image_requests::tests::compose_covered_"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The store's count bound. There is no pre-truncation to 256 on the write
        // path, so the encode row reaches the predicate at 257 and the decode row
        // hands it a hand-written 257.
        Row {
            name: r#"image-baseline-limit"#,
            path: r#"crates/agent-vm/src/image_requests/baseline.rs"#,
            old: r#"    ensures ok == baseline_store_admits_spec(count, bytes),
{
    count <= MAX_BASELINE_REFERENCES && bytes <= MAX_BASELINE_BYTES
}"#,
            new: r#"    ensures ok == baseline_store_admits_spec(count, bytes),
{
    count <= MAX_BASELINE_REFERENCES + 1 && bytes <= MAX_BASELINE_BYTES
}"#,
            run: Run::AgentBin(r#"image_requests::baseline::tests::admission_"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"image-baseline-limit-proof"#,
            path: r#"crates/agent-vm/src/image_requests/baseline.rs"#,
            old: r#"    ensures ok == baseline_store_admits_spec(count, bytes),
{
    count <= MAX_BASELINE_REFERENCES && bytes <= MAX_BASELINE_BYTES
}"#,
            new: r#"    ensures ok == baseline_store_admits_spec(count, bytes),
{
    count <= MAX_BASELINE_REFERENCES + 1 && bytes <= MAX_BASELINE_BYTES
}"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // --- Automatic Git metadata mounts (#535, ADR-0062) -------------------
        // Every anchor is a kernel *body*; its `ensures` states the same decision in
        // a shape the body never uses, so the `-proof` twins catch a mutated
        // implementation rather than a weakened contract. The launch rows are the
        // only ones that can see the discovery adapter at all.
        Row {
            name: r#"git-mount-off-ignored"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if mode.off {
        MountAccessDecision::Skip"#,
            new: r#"    if mode.off {
        MountAccessDecision::ReadOnly"#,
            run: Run::AgentBin(r#"git_mount_access_matches_the_three_rows"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"git-mount-off-ignored-proof"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if mode.off {
        MountAccessDecision::Skip"#,
            new: r#"    if mode.off {
        MountAccessDecision::ReadOnly"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"git-mount-off-ignored-launch"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if mode.off {
        MountAccessDecision::Skip"#,
            new: r#"    if mode.off {
        MountAccessDecision::ReadOnly"#,
            run: Run::AgentTest(r#"git_metadata_mounts"#, r#"off_bypasses_discovery_only"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // A pointer file is untrusted text: dropping the control-byte test admits a
        // newline (which forges a diagnostic line) and a tab (which breaks the
        // boot-params framing).
        Row {
            name: r#"git-pointer-control-byte-accepted"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"        if is_control_byte(bytes[j]) {"#,
            new: r#"        if false && is_control_byte(bytes[j]) {"#,
            run: Run::AgentBin(r#"pointer_path_span_matches_the_oracle_table"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"git-pointer-control-byte-accepted-proof"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"        if is_control_byte(bytes[j]) {"#,
            new: r#"        if false && is_control_byte(bytes[j]) {"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // The back-pointer is one of the two facts that make the directory *this*
        // worktree's registration rather than any directory Git would open.
        Row {
            name: r#"git-back-pointer-ignored"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if !f.back_pointer_matches {"#,
            new: r#"    if false && !f.back_pointer_matches {"#,
            run: Run::AgentBin(r#"worktree_verdict_matches_the_oracle_on_all_4096_rows"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"git-back-pointer-ignored-proof"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if !f.back_pointer_matches {"#,
            new: r#"    if false && !f.back_pointer_matches {"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"git-back-pointer-ignored-launch"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if !f.back_pointer_matches {"#,
            new: r#"    if false && !f.back_pointer_matches {"#,
            run: Run::AgentTest(
                r#"git_metadata_mounts"#,
                r#"broken_relationships_are_refused_before_launch_state"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // Guest-spelling consistency is what refuses a `..` that crosses a symlink:
        // the guest would resolve a different directory than the host.
        Row {
            name: r#"git-symlink-layout-accepted"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if !f.guest_spelling_consistent {"#,
            new: r#"    if false && !f.guest_spelling_consistent {"#,
            run: Run::AgentBin(r#"worktree_verdict_matches_the_oracle_on_all_4096_rows"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"git-symlink-layout-accepted-proof"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if !f.guest_spelling_consistent {"#,
            new: r#"    if false && !f.guest_spelling_consistent {"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // No launch twin: with the fact forced true, layout D is *still* refused —
        // the coverage rule sees the guest spelling nest while the host path does
        // not — so the two refusals are indistinguishable at the launch boundary and
        // the kernel table plus the proof are what kill this mutation.
        // Binding a metadata directory that is already inside the project would make
        // part of the writable project bind read-only.
        Row {
            name: r#"git-covered-by-project-binds"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if f.inside_project {"#,
            new: r#"    if false && f.inside_project {"#,
            run: Run::AgentBin(r#"metadata_placement_matches_the_exhaustive_table"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"git-covered-by-project-binds-proof"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if f.inside_project {"#,
            new: r#"    if false && f.inside_project {"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // The launch twin: a worktree whose common directory lives inside the project
        // bind, where the mutant binds it read-only inside a writable route.
        Row {
            name: r#"git-covered-by-project-binds-launch"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if f.inside_project {"#,
            new: r#"    if false && f.inside_project {"#,
            run: Run::AgentTest(
                r#"git_metadata_mounts"#,
                r#"metadata_inside_the_project_bind_is_reported_as_reachable"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // A checkout inside the common directory. A bare repository is all metadata and
        // is bound whole, so the `.git`-entry rule cannot keep a *registered* worktree
        // created inside it out: the bind would carry another worktree's source.
        Row {
            name: r#"git-checkout-in-common-bound"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if f.contains_checkout {"#,
            new: r#"    if false && f.contains_checkout {"#,
            run: Run::AgentBin(r#"metadata_placement_matches_the_exhaustive_table"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"git-checkout-in-common-bound-proof"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if f.contains_checkout {"#,
            new: r#"    if false && f.contains_checkout {"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"git-checkout-in-common-bound-launch"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if f.contains_checkout {"#,
            new: r#"    if false && f.contains_checkout {"#,
            run: Run::AgentTest(
                r#"git_metadata_mounts"#,
                r#"a_common_directory_containing_another_checkout_is_refused"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // POSIX clamps `/..` to `/`; this kernel refuses it, because clamping lets a
        // pointer walk out of the directory Git resolved and back into another one.
        // The anchor is the resolver's *executable* escape branch. A spec-body
        // anchor would be invisible to `cargo test` (the spec erases), so the two
        // cargo rows below could not kill it and only the proof would. Mutating the
        // exec branch to clamp — the POSIX rule this kernel deliberately rejects —
        // is observable through both the table and a launch.
        Row {
            name: r#"git-parent-clamped-at-root"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"        } else {
            escaped = true;
            i += 1;
        }"#,
            new: r#"        } else {
            i += 1;
        }"#,
            run: Run::AgentBin(r#"resolve_components_matches_the_stack_oracle"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"git-parent-clamped-at-root-proof"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"        } else {
            escaped = true;
            i += 1;
        }"#,
            new: r#"        } else {
            i += 1;
        }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"git-parent-clamped-at-root-launch"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"        } else {
            escaped = true;
            i += 1;
        }"#,
            new: r#"        } else {
            i += 1;
        }"#,
            run: Run::AgentTest(
                r#"git_metadata_mounts"#,
                r#"broken_relationships_are_refused_before_launch_state"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // A `HEAD`-less directory is not a Git directory, whatever the relationship
        // facts say. The twin sits in the `HEAD` kernel itself.
        Row {
            name: r#"git-head-unchecked"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if !f.worktree_is_git_dir {"#,
            new: r#"    if false && !f.worktree_is_git_dir {"#,
            run: Run::AgentBin(r#"worktree_verdict_matches_the_oracle_on_all_4096_rows"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"git-head-unchecked-proof"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if !f.worktree_is_git_dir {"#,
            new: r#"    if false && !f.worktree_is_git_dir {"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"git-head-unchecked-launch"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    if !f.worktree_is_git_dir {"#,
            new: r#"    if false && !f.worktree_is_git_dir {"#,
            run: Run::AgentTest(
                r#"git_metadata_mounts"#,
                r#"a_fully_cross_linked_forgery_is_refused"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"git-headref-any-ref-prefix"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"        bytes.len() - i >= 5
            && bytes[i] == 0x72u8"#,
            new: r#"        true || bytes.len() - i >= 5
            && bytes[i] == 0x72u8"#,
            run: Run::AgentBin(r#"headref_valid_matches_the_git_table"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"git-headref-any-ref-prefix-proof"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"        bytes.len() - i >= 5
            && bytes[i] == 0x72u8"#,
            new: r#"        true || bytes.len() - i >= 5
            && bytes[i] == 0x72u8"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        // A missing `commondir` with linked-layout evidence is a *damaged* worktree,
        // not a submodule: ignoring the evidence silently disables the feature.
        Row {
            name: r#"git-missing-commondir-not-linked"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"        return if f.linked_evidence {"#,
            new: r#"        return if false && f.linked_evidence {"#,
            run: Run::AgentBin(r#"worktree_verdict_matches_the_oracle_on_all_4096_rows"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"git-missing-commondir-not-linked-proof"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"        return if f.linked_evidence {"#,
            new: r#"        return if false && f.linked_evidence {"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"git-missing-commondir-not-linked-launch"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"        return if f.linked_evidence {"#,
            new: r#"        return if false && f.linked_evidence {"#,
            run: Run::AgentTest(
                r#"git_metadata_mounts"#,
                r#"a_missing_commondir_is_refused_and_other_gitfiles_are_unchanged"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The enclosing-declaration decision (#535 M2). Accepting a declaration that
        // maps the metadata path somewhere else is what makes the automatic child bind
        // outrank the user's route: the kernel, its table and a real refusal all see it.
        Row {
            name: r#"git-enclosing-declaration-shadowed"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    } else {
        Enclosure::Shadowed
    }"#,
            new: r#"    } else {
        Enclosure::Reachable
    }"#,
            run: Run::AgentBin(r#"declaration_enclosure_matches_the_exhaustive_table"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"git-enclosing-declaration-shadowed-proof"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    } else {
        Enclosure::Shadowed
    }"#,
            new: r#"    } else {
        Enclosure::Reachable
    }"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"git-enclosing-declaration-shadowed-launch"#,
            path: r#"crates/agent-vm/src/git_metadata.rs"#,
            old: r#"    } else {
        Enclosure::Shadowed
    }"#,
            new: r#"    } else {
        Enclosure::Reachable
    }"#,
            run: Run::AgentTest(
                r#"git_metadata_mounts"#,
                r#"an_enclosing_declaration_is_never_shadowed"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // #557 slice 2: the seven critical live-allowance controls. Each anchor is
        // 4-5 lines of unique context, so `grant`'s and `revoke`'s `Unsupported` arms
        // can never share one, and each is killed by the test the plan names.
        Row {
            name: r#"live-grant-skips-policy-rederive"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"        let derived_policy = candidate.policy();
        Ok((
            Self {
                egress: candidate,"#,
            new: r#"        let derived_policy = self.egress.policy();
        Ok((
            Self {
                egress: candidate,"#,
            run: Run::AgentBin(
                r#"allowances::tests::live_grant_rederives_through_egress_authority_policy"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"live-grant-ignores-port-change"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"        if !crate::egress_hostname::InterceptedPorts::is_subset(
            candidate.intercepted_ports().as_ref(),
            self.launch_intercepted_ports.as_ref(),
        ) {
            return Err(LivePolicyPrecondition::InterceptedPortsFixedAtLaunch);"#,
            new: r#"        if false && !crate::egress_hostname::InterceptedPorts::is_subset(
            candidate.intercepted_ports().as_ref(),
            self.launch_intercepted_ports.as_ref(),
        ) {
            return Err(LivePolicyPrecondition::InterceptedPortsFixedAtLaunch);"#,
            run: Run::AgentBin(
                r#"allowances::tests::live_grant_refuses_or_defers_when_intercepted_ports_change"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"revoke-unconfirmed-succeeds"#,
            path: r#"crates/agent-vm/src/access_cmd.rs"#,
            old: r#"            )
            .context("writing the unconfirmed revoke")?;
            Ok(1)
        }"#,
            new: r#"            )
            .context("writing the unconfirmed revoke")?;
            Ok(0)
        }"#,
            run: Run::AgentBin(
                r#"access_cmd::tests::revoke_exits_nonzero_and_names_session_when_unconfirmed"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"grant-failed-writes-project-record"#,
            path: r#"crates/agent-vm/src/allowances/apply.rs"#,
            old: r#"                let record_on_runtime_failure = false;
                if record_on_runtime_failure && scope == GrantScope::Project {
                    let _ = record.record(&destination, now_ms).await;
"#,
            new: r#"                let record_on_runtime_failure = true;
                if record_on_runtime_failure && scope == GrantScope::Project {
                    let _ = record.record(&destination, now_ms).await;
"#,
            run: Run::AgentBin(
                r#"access_cmd::tests::project_grant_writes_no_record_when_live_session_cannot_confirm"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"older-runtime-fails-grant"#,
            path: r#"crates/agent-vm/src/allowances/apply.rs"#,
            old: r#"            Err(microsandbox::MicrosandboxError::Unsupported { .. }) => {
                match record.record(&destination, now_ms).await {
                    Ok(outcome) => GrantResult::NextLaunch {"#,
            new: r#"            Err(microsandbox::MicrosandboxError::Unsupported { .. }) if false => {
                match record.record(&destination, now_ms).await {
                    Ok(outcome) => GrantResult::NextLaunch {"#,
            run: Run::AgentBin(
                r#"access_cmd::tests::older_runtime_without_policy_update_yields_next_launch_grant_and_never_fails"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"session-allowance-writes-store"#,
            path: r#"crates/agent-vm/src/allowances/apply.rs"#,
            old: r#"            Ok(revision) => {
                if scope == GrantScope::Project {"#,
            new: r#"            Ok(revision) => {
                if true {"#,
            run: Run::AgentBin(
                r#"access_cmd::tests::session_allowance_never_touches_disk_or_another_project"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"applied-coverage-at-or-before-refusal"#,
            path: r#"crates/agent-vm/src/allowances.rs"#,
            old: r#"                let Some(revision) = item.revision else {
                    continue;
                };
                // M7: only a revision after the refusal confirms it.
                let confirmed_after_refusal = revision > entry.last_revision;"#,
            new: r#"                let Some(revision) = item.revision else {
                    continue;
                };
                // M7: only a revision after the refusal confirms it.
                let confirmed_after_refusal = revision >= entry.last_revision;"#,
            run: Run::AgentBin(
                r#"allowances::tests::applied_coverage_requires_confirmed_revision_after_last_refusal"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The ports a live derivation hands on are the ones the *launch* fixed, never
        // a recomputation from the set now in force (#569). Recomputing makes the
        // last-hostname revoke forget port 443, so the next hostname grant is refused
        // as needing a relaunch the netstack already paid for.
        Row {
            name: r#"live-revoke-recomputes-launch-ports"#,
            path: r#"crates/agent-vm/src/network.rs"#,
            old: r#"        let derived_policy = candidate.policy();
        Ok((
            Self {
                egress: candidate,
                launch_intercepted_ports: self.launch_intercepted_ports.clone(),"#,
            new: r#"        let derived_policy = candidate.policy();
        let recomputed = candidate.intercepted_ports();
        Ok((
            Self {
                egress: candidate,
                launch_intercepted_ports: recomputed,"#,
            run: Run::AgentBin(
                r#"allowances::tests::live_revoke_of_last_hostname_stops_connections_within_launch_ports_and_keeps_state_on_failure"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The four honesty defects the reviews found by hand, now each guarded by the
        // test that was written for it: a surviving mutant is how they shipped.
        Row {
            name: r#"revoke-still-effective-configured"#,
            path: r#"crates/agent-vm/src/allowances/apply.rs"#,
            old: r#"            let still_effective = snapshot.plan.is_configured(destination)
                || next_session
                    .iter()
                    .chain(next_project.iter())
                    .any(|entry| entry.destination() == destination);"#,
            new: r#"            let still_effective = true;"#,
            run: Run::AgentBin(
                r#"allowances::tests::revoke_names_only_what_the_policy_still_allows"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"queued-project-grant-skips-record"#,
            path: r#"crates/agent-vm/src/allowances/apply.rs"#,
            old: r#"                (GrantScope::Project, false) => {
                    self.record_queued_as_project(entry, destination, record)
                        .await
                }"#,
            new: r#"                (GrantScope::Project, false) => GrantResult::QueuedForBoot {
                    destination: destination.to_string(),
                    scope: GrantScope::Project,
                    recorded_ms: entry.allowance.granted_ms(),
                },"#,
            run: Run::AgentBin(
                r#"allowances::tests::project_grant_over_a_queued_session_entry_records_before_claiming_it"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"retry-demotion-forgotten"#,
            path: r#"crates/agent-vm/src/allowances/apply.rs"#,
            old: r#"            if item.destination() == destination {
                item.not_recorded_error = Some(message.to_owned());
            }"#,
            new: r#"            if item.destination() == destination {
                item.not_recorded_error = None;
            }"#,
            run: Run::AgentBin(
                r#"allowances::tests::project_grant_over_a_session_entry_keeps_the_demotion_on_the_entry"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"live-swap-while-boot-queue-pending"#,
            path: r#"crates/agent-vm/src/allowances/apply.rs"#,
            old: r#"        let updater = if queued_for_boot { None } else { updater };"#,
            new: r#"        let updater = { let _ = queued_for_boot; updater };"#,
            run: Run::AgentBin(
                r#"allowances::tests::a_grant_while_the_boot_queue_is_pending_makes_no_swap"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"adoption-skips-queued-rederive"#,
            path: r#"crates/agent-vm/src/allowances/apply.rs"#,
            old: r#"            match post_adoption_plan.derive_for(state.combined()) {"#,
            new: r#"            match post_adoption_plan.derive_for(Vec::new()) {"#,
            run: Run::AgentBin(
                r#"allowances::tests::adopt_boot_allowances_rederives_a_queued_grant_over_the_post_adoption_plan"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"sibling-label-hardcoded"#,
            path: r#"crates/agent-vm/src/access_cmd.rs"#,
            old: r#"        escape(row.snapshot.info.id.as_str()),
        row.state.label()"#,
            new: r#"        escape(row.snapshot.info.id.as_str()),
        "running""#,
            run: Run::AgentBin(
                r#"access_cmd::tests::siblings_are_named_in_every_state_and_offline_revoke_names_them"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"demoted-status-collapsed"#,
            path: r#"crates/agent-vm/src/access_cmd.rs"#,
            old: r#"        (Some(revision), Some(error)) => format!(
            "applied to this session only (rev {revision}), not recorded for the project: {}",
            escape(error)
        ),"#,
            new: r#"        (Some(revision), Some(_error)) => format!("applied (rev {revision})"),"#,
            run: Run::AgentBin(
                r#"access_cmd::tests::allowances_keeps_a_demoted_live_project_entry_demoted"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // The two defects the independent verifier found, and the lock wording that
        // told a user to wait for a permission error. Each is the exact sentence or
        // filter that was wrong, so the probe that found it is the control's kill.
        Row {
            name: r#"allowances-silence-not-per-session"#,
            path: r#"crates/agent-vm/src/access_cmd.rs"#,
            old: r#"    silent.retain(|(id, _)| wanted.is_none_or(|wanted| wanted == id));"#,
            new: r#"    silent.retain(|(_, _)| { let _ = wanted; true });"#,
            run: Run::AgentBin(
                r#"access_cmd::tests::allowances_session_filter_lists_only_the_named_session"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"offline-session-only-claims-the-record"#,
            path: r#"crates/agent-vm/src/access_cmd.rs"#,
            old: r#"        match scope {
            RevokeScope::Session => writeln!(
                out,
                "no session is active, so {spelled} was not revoked from any session; \
                 the project record for this project is unchanged"
            )
            .context("writing the offline session-only revoke")?,
"#,
            new: r#"        match scope {
            RevokeScope::Session => writeln!(
                out,
                "{} {} for this project; no session is active, so the next launch starts without it",
                if removed { "deleted" } else { "no record for" },
                spelled
            )
            .context("writing the offline revoke")?,
"#,
            run: Run::AgentBin(
                r#"access_cmd::verifier_probes::verifier_revoke_session_only_never_claims_the_record_is_gone"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"lock-unopenable-reported-as-busy"#,
            path: r#"crates/agent-vm/src/allowances/store.rs"#,
            old: r#"            Self::LockUnopenable(error) => format!(
                "the project allowance store's lock file {LOCK_FILE} could not be opened ({error}); nothing was written — waiting will not help, so check that directory's permissions and that {LOCK_FILE} is a regular file this user owns"
            ),"#,
            new: r#"            Self::LockUnopenable(error) => {
                format!("the project allowance store is busy ({error}); nothing was written")
            }"#,
            run: Run::AgentBin(
                r#"allowances::store::tests::a_lock_the_host_refuses_to_open_is_not_reported_as_busy"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"launch-entry-arena-paired"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"            let tool = slots.get_mut(id.0).and_then(Option::take).ok_or_else(|| {"#,
            new: r#"            let tool = slots.iter_mut().find_map(Option::take).ok_or_else(|| {"#,
            run: Run::AgentBin(r#"authorized_entries_keep_their_own_definition_and_facets"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"inert-source-references-skipped"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"            ResolvedTools::from_defaults_retaining(default_tools()?, sourced),"#,
            new: r#"            ResolvedTools::from_defaults_retaining(default_tools()?, Vec::new()),"#,
            run: Run::AgentBin(r#"defaults_path_still_validates_inert_source_references"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"allow-tools-authority-operand-dropped"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"if t.network { true } else { t.mounts || t.mount_sets || t.egress_sets || t.allow_tools }"#,
            new: r#"if t.network { true } else { t.mounts || t.mount_sets || t.egress_sets }"#,
            run: Run::AgentBin(r#"allow_tools_presence_requires_the_verified_read"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"allow-tools-authority-operand-dropped-proof"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"    ensures r == (t.network || t.mounts || t.mount_sets || t.egress_sets || t.allow_tools),"#,
            new: r#"    ensures r == (t.network || t.mounts || t.mount_sets || t.egress_sets),"#,
            run: Run::Proof,
            markers: &[r#"verification results::"#],
            anchors: 1,
        },
        Row {
            name: r#"allow-tools-authority-operand-dropped-launch"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"if t.network { true } else { t.mounts || t.mount_sets || t.egress_sets || t.allow_tools }"#,
            new: r#"if t.network { true } else { t.mounts || t.mount_sets || t.egress_sets }"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"a_symlinked_config_authorizing_tools_is_refused"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"allow-tools-presence-ignored"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"        allow_tools: raw.allow_tools.is_some(),"#,
            new: r#"        allow_tools: false,"#,
            run: Run::AgentBin(r#"allow_tools_presence_requires_the_verified_read"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"allow-tools-trusted-verdict-bypassed"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"                references.require_for_trusted_tool().map_err(|refusal| {"#,
            new: r#"                Ok::<(), crate::config_authority::UntrustedConfig>(()).map_err(|refusal| {"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"a_project_authorization_of_a_trusted_tool_needs_the_trusted_verdict"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"allow-tools-source-accepted"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"    if raw.egress_sets.is_some() {
        return Err(egress_sets_refusal(path, tier));
    }"#,
            new: r#"    if raw.egress_sets.is_some() {
        return Err(egress_sets_refusal(path, tier));
    }
    if raw.allow_tools.is_some() {
        return Ok(());
    }"#,
            run: Run::AgentBin(r#"v10_an_untrusted_source_cannot_grant_authority"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"allow-tools-closure-unchecked"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"        enforce_closure_authorization(
            &definitions,
            &visited,
            *start,
            &authorized,
            &untrusted_origins,
        )?;"#,
            new: r#"        let _ = (
            &definitions,
            &visited,
            *start,
            &authorized,
            &untrusted_origins,
        );"#,
            run: Run::AgentBin(r#"tool_closure_authorization_is_explicit"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"authorized-tool-egress-dropped"#,
            path: r#"crates/agent-vm/src/launch_target.rs"#,
            old: r#"                    tool_egress: Some(if entry.is_authorized_egress() {"#,
            new: r#"                    tool_egress: Some(if false {"#,
            run: Run::AgentTest(
                r#"config_launch_driven"#,
                r#"an_authorized_tool_grants_its_exact_hostnames"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"authorized-tool-port-widened"#,
            path: r#"crates/agent-vm/src/egress_reference.rs"#,
            old: r#"            let text = format!("tcp://{}:{}", request.name().as_str(), request.port());"#,
            new: r#"            let text = format!("tcp://{}", request.name().as_str());"#,
            run: Run::AgentBin(r#"expansion_is_port_pinned"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"authorized-tool-facets-dropped"#,
            path: r#"crates/agent-vm/src/launch_target.rs"#,
            old: r#"                    mounts: entry.mounts().clone(),"#,
            new: r#"                    mounts: crate::config_mounts::ResolvedMountList::empty(),"#,
            run: Run::AgentBin(r#"authorized_source_entry_lowers_every_own_and_closure_facet"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // -- #748: [[sources]] trust/allow adoption boundaries -----------------
        // Every row below keeps its replacement compiling: an `allow = false`
        // trusted source already holds the adoption token, so a leaked mount or
        // egress table reaches the launch plan instead of failing on "authority
        // was not measured".
        Row {
            name: r#"allow-false-mounts-adopted"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"    raw.mounts = None;
    raw.network = None;"#,
            new: r#"    raw.network = None;"#,
            run: Run::AgentBin(r#"allow_false_trusted_source_mounts_stay_inert"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"allow-false-network-adopted"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"    raw.mounts = None;
    raw.network = None;"#,
            new: r#"    raw.mounts = None;"#,
            run: Run::AgentBin(r#"allow_false_trusted_source_network_stays_inert"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"trusted-source-inside-checkout-accepted"#,
            path: r#"crates/agent-vm/src/project_config.rs"#,
            old: r#"        self.boundary_ids.contains(&dir_id)
            || self
                .boundary_roots
                .iter()
                .any(|boundary| cursor.starts_with(boundary))"#,
            new: r#"        let _ = (dir_id, cursor);
        false"#,
            run: Run::AgentBin(r#"trusted_source_inside_checkout_is_refused"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"trusted-source-symlink-target-route-skipped"#,
            path: r#"crates/agent-vm/src/project_config.rs"#,
            old: r#"            check_trusted_symlink_target_against_boundary(path, boundary.as_ref())?;"#,
            new: r#"            let _ = (path, boundary.as_ref());"#,
            run: Run::AgentBin(r#"trusted_source_symlink_into_checkout_reports_route_refusal"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"trusted-source-verify-skipped"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"    match authority_refusal(reached, parent_dir, crate::host_paths::current_euid()) {"#,
            new: r#"    match {
        let _ = (reached, parent_dir, crate::host_paths::current_euid());
        None::<AuthorityRefusal>
    } {"#,
            run: Run::AgentBin(r#"trusted_source_group_writable_regular_file_is_refused"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"untrusted-step-stat-open-disagreement-accepted"#,
            path: r#"crates/agent-vm/src/project_config.rs"#,
            old: r#"    if seen.identity != opened {
        return Err(UntrustedReadError::RootReplaced);
    }"#,
            new: r#"    let _ = (seen, opened);"#,
            run: Run::AgentBin(
                r#"a_double_swap_inside_one_step_is_refused_by_the_stat_then_open_agreement"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"untrusted-root-parent-rename-accepted"#,
            path: r#"crates/agent-vm/src/project_config.rs"#,
            old: r#"    if dir_change_stamp(fd)? != stamp {
        return Err(UntrustedReadError::RootReplaced);
    }"#,
            new: r#"    if false && dir_change_stamp(fd)? != stamp {
        return Err(UntrustedReadError::RootReplaced);
    }"#,
            run: Run::AgentBin(
                r#"a_swap_before_the_captured_root_step_is_refused_by_the_parent_change_stamp"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"pin-unapproved-allow-true-adopted"#,
            path: r#"crates/agent-vm/src/config_pins.rs"#,
            old: r#"        let pins = self.pins.as_ref().expect("the pin state was just loaded");
        #[cfg(test)]"#,
            new: r#"        let pins = self.pins.as_mut().expect("the pin state was just loaded");
        pins.current.sources.insert(
            key.clone(),
            KeyState {
                active: hash,
                approved: vec![Approval {
                    hash,
                    approved_ms: 0,
                    active_ms: 0,
                }],
            },
        );
        let pins = &*pins;
        #[cfg(test)]"#,
            run: Run::AgentBin(r#"approved_untrusted_bytes_adopt_and_changed_bytes_do_not"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"pin-checkout-confinement-bypassed"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"    let read = crate::project_config::read_untrusted_source_route(
        entry,
        route,
        boundary,
        MAX_CONFIG_FILE_BYTES,
    )
    .map_err(|error| untrusted_read_error(project, entry, route, error))?;
    budget.charge(entry.path(), read.bytes.len())?;
    check_not_self_source(Some(project), read.identity, entry)?;
    Ok(read)"#,
            new: r#"    let _ = (route, boundary);
    let read = crate::host_paths::read_bounded_regular_file_noting_symlink(
        entry.path(),
        MAX_CONFIG_FILE_BYTES,
    )
    .map_err(|error| {
        anyhow!(
            "config: {}: {error}",
            crate::one_line::quoted_path(entry.path())
        )
    })?;
    budget.charge(entry.path(), read.bytes().len())?;
    check_not_self_source(Some(project), read.identity(), entry)?;
    Ok(crate::project_config::UntrustedSourceRead {
        scope: crate::config_sources::SourceScope::Checkout,
        bytes: read.bytes().to_vec(),
        identity: read.identity(),
    })"#,
            run: Run::AgentBin(
                r#"an_untrusted_checkout_escape_discloses_nothing_and_creates_no_store"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"pin-unapproved-allow-false-recorded"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"    let read = read_untrusted_bytes(entry, project, route, boundary, budget)?;
    let path = entry.path();
    match approval.check_untrusted_source(project, entry, read.scope, &read.bytes)? {"#,
            new: r#"    let read = read_untrusted_bytes(entry, project, route, boundary, budget)?;
    let path = entry.path();
    if !entry.is_allowed() {
        let (text, _document) = parse_toml_table(path, &read.bytes)?;
        let mut raw = decode_raw_config(path, text)?;
        let inert = record_inert(&mut raw);
        let (report, contents) = build_tier(
            path,
            raw,
            TierAuthority::Source(None),
            FileTierKind::Source(entry.alias()),
            home,
            work,
        )?;
        return Ok(SourceReadOutcome::Approved {
            tier: report,
            contents,
            inert,
            pin: None,
            scope: Some(read.scope),
        });
    }
    match approval.check_untrusted_source(project, entry, read.scope, &read.bytes)? {"#,
            run: Run::AgentBin(r#"the_four_trust_allow_combinations_are_independent"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // The observation's lock identity is the fence fix (1) added. A
            // mutant that drops the acquired-vs-observed comparison lets a
            // replaced `pins.lock` accept a review.
            name: r#"pin-lock-identity-unchecked"#,
            path: r#"crates/agent-vm/src/config_pins/store.rs"#,
            old: r#"        if !observed_lock_matches(expected.state, Some(lock.identity)) {
            return Err(WriteError::IncarnationChanged);
        }"#,
            new: r#"        let _ = observed_lock_matches(expected.state, Some(lock.identity));"#,
            run: Run::AgentBin(r#"a_replaced_lock_inode_is_not_the_observed_lock"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"project-config-verify-skipped"#,
            path: r#"crates/agent-vm/src/config_authority.rs"#,
            old: r#"    measure_facts(path, final_component, false)
        .map_err(|measurement| measurement.into_untrusted(AuthoritySubject::ProjectConfig))?;"#,
            new: r#"    let _ = measure_facts(path, final_component, false);"#,
            run: Run::AgentBin(r#"unsafe_project_config_mounts_and_network_are_refused"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"sources-count-bound-removed"#,
            path: r#"crates/agent-vm/src/config_sources.rs"#,
            old: r#"        if items.len() > MAX_DECLARED_SOURCES {"#,
            new: r#"        if false {"#,
            run: Run::AgentBin(r#"more_sources_than_the_bound_refuse_the_load"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"sources-duplicate-lookup-ignored"#,
            path: r#"crates/agent-vm/src/config_sources.rs"#,
            old: r#"        if let Some(first) = self.aliases.get(&entry.alias) {"#,
            new: r#"        if let Some(first) = None::<&usize> {"#,
            run: Run::AgentBin(r#"a_duplicate_at_the_end_of_a_maximal_list_is_refused"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"sources-byte-budget-ignored"#,
            path: r#"crates/agent-vm/src/config.rs"#,
            old: r#"        let Some(remaining) = self.remaining.checked_sub(bytes as u64) else {
            return Err(anyhow!(
                "config: {}: the declared sources read more than {MAX_SOURCE_BYTES_TOTAL} bytes in \
                 total; remove the sources agent-vm does not use, or the parts of them no launch \
                 needs",
                crate::one_line::quoted_path(path)
            ));
        };"#,
            new: r#"        let remaining = self.remaining.saturating_sub(bytes as u64);
        let _ = path;"#,
            run: Run::AgentBin(r#"the_declared_sources_share_one_byte_budget"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            name: r#"cross-project-trusted-source-symlink-skipped"#,
            path: r#"crates/agent-vm/src/protected_config_dir.rs"#,
            old: r#"    let mut dir = match resolve(&parent, Walk::Authority) {"#,
            new: r#"    let mut dir = match Err::<Resolution, anyhow::Error>(anyhow::anyhow!("mutant")) {"#,
            run: Run::AgentBin(
                r#"a_writable_bind_over_another_projects_symlinked_trusted_source_is_refused"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // #737's project config writer, graded on the writer's own API: every
        // property below is observable there without a registry, a clock or the
        // CLI, and a CLI control would let a loader refusal mask the mutation.
        Row {
            // A descriptor keeps naming the inode it was opened on after that name
            // moves, so the canonical-spelling tie is the only thing that notices a
            // route directory replaced between opening and use.
            name: r#"project-writer-route-identity-skipped"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"    if (measured.dev(), measured.ino()) != level.facts.identity() {"#,
            new: r#"    if false && (measured.dev(), measured.ino()) != level.facts.identity() {"#,
            run: Run::AgentBin(r#"a_route_directory_replaced_after_it_was_opened_is_refused"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // ADR-0073: `projects/` and `projects/<id>/` are opened O_NOFOLLOW. A
            // mutant that follows the store link reads and writes through it.
            name: r#"project-writer-store-link-followed"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"        flags |= OFlags::NOFOLLOW;"#,
            new: r#"        flags |= OFlags::empty();"#,
            run: Run::AgentBin(r#"a_symlinked_store_directory_is_refused"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // ADR-0040 keeps a stable dotfile alias outside the checkout and refuses
            // one inside it. Without the route check the walk creates the store in
            // the checkout through its own `.config`.
            name: r#"project-writer-checkout-alias-accepted"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"    if crate::project_config::resolves_inside_project(&canonical, Some(&level.path), root) {"#,
            new: r#"    if false && crate::project_config::resolves_inside_project(&canonical, Some(&level.path), root) {"#,
            run: Run::AgentBin(r#"a_checkout_alias_route_is_refused_before_anything_is_created"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // A rename into a writable directory would succeed over a `0400` file,
            // which is why the owner-write refusal exists: without it the user's own
            // read-only bytes are replaced.
            name: r#"project-writer-readonly-config-written"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"        if crate::config_authority::raw_mode_u32(facts.mode) & 0o200 == 0 {"#,
            new: r#"        if false && crate::config_authority::raw_mode_u32(facts.mode) & 0o200 == 0 {"#,
            run: Run::AgentBin(r#"a_read_only_config_is_refused_on_probe_and_at_publish"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // ADR-0040 on the writer's descriptor: a group-writable, multi-link or
            // foreign-owned file is never read as ours. `measure_facts`-only
            // mutations leave this check in place, so the row targets the writer's
            // own call to the shared kernel, on a `0620` file in a `0700` directory.
            name: r#"project-writer-verify-skipped"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"        crate::config_authority::verify_project_file_at(
            store.dir_facts(),
            &FinalComponent::Regular(facts),
        )
        .map_err(|refusal| crate::config::project_tier_error(config, &refusal))?;"#,
            new: r#"        let _ = crate::config_authority::verify_project_file_at(
            store.dir_facts(),
            &FinalComponent::Regular(facts),
        );"#,
            run: Run::AgentBin(r#"an_untrusted_config_is_refused_without_being_read_or_replaced"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // ADR-0078 D4 rejects `DocumentMut`'s round trip because it normalises
            // EOLs. The mutation clobbers the delivery of an already correct splice
            // (the root image is still the new reference), so the semantic check
            // passes and only the exact-byte assertion can notice.
            name: r#"project-writer-crlf-normalised"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"    check_rendered(&bytes, reference)?;"#,
            new: r#"    let bytes = String::from_utf8_lossy(&bytes).replace("\r\n", "\n").into_bytes();
    check_rendered(&bytes, reference)?;"#,
            run: Run::AgentBin(r#"crlf_and_mixed_line_endings_are_never_normalised"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // The inserted assignment must stay in the root prelude, above the
            // comment block that introduces the next table (D4). A scan that goes
            // straight to the header line publishes the note inside the wrong place:
            // still a root key, so only the expected bytes refuse it.
            name: r#"project-writer-table-note-clobbered"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"            return if block_start == header_line {
                header_line
            } else {
                previous
            };"#,
            new: r#"            return header_line;"#,
            run: Run::AgentBin(r#"a_file_heading_and_a_table_note_keep_their_places"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // The no-op is decided here, at the writer, because the planner's
            // `Unchanged` alone does not stop a rename: handed the live bytes, a
            // save that publishes them replaces the inode, mode and mtime anyway.
            name: r#"project-writer-unchanged-renames"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"        if let ConfigFileState::Present { bytes, .. } = &live
            && bytes.as_bytes() == new_bytes
        {"#,
            new: r#"        if let ConfigFileState::Present { bytes, .. } = &live
            && false
            && bytes.as_bytes() == new_bytes
        {"#,
            run: Run::AgentBin(r#"a_save_of_the_live_bytes_publishes_nothing"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // ADR-0078 D1: a stale base is refused on its identity *or* its bytes.
            // Weakening the comparison to a conjunction publishes over a file a peer
            // changed in place.
            name: r#"project-writer-stale-save-accepted"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"            ) => identity != live_identity || bytes != live_bytes,"#,
            new: r#"            ) => identity != live_identity && bytes != live_bytes,"#,
            run: Run::AgentBin(r#"a_stale_save_is_refused_when_the_bytes_changed"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // The last check before the rename. Both halves are removed together: a
            // displaced store also fails the destination-name comparison, so removing
            // only one leaves the save refused as `Stale` and nothing is published.
            name: r#"project-writer-pre-rename-check-skipped"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"            let parent = match verify_anchored(&walk, &steps, &locked, euid) {
                Ok(parent) => parent,
                Err(conflict) => {
                    veto.set(Some(conflict));
                    return Err(anyhow!(
                        "config: {}: {}",
                        quoted_path(config),
                        conflict.reason(),
                    ));
                }
            };
            match final_name_matches(parent, store, &live, config)? {
                true => Ok(()),
                false => {
                    veto.set(Some(ConfigConflict::Stale));
                    Err(anyhow!(
                        "config: {}: {}",
                        quoted_path(config),
                        ConfigConflict::Stale.reason(),
                    ))
                }
            }"#,
            new: r#"            Ok(())"#,
            run: Run::AgentBin(r#"a_pre_rename_veto_from_a_displaced_store_leaves_the_old_bytes"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // A descriptor keeps naming the inode it was opened on after that name
            // moves, so a `projects/` replaced after the walk leaves every held
            // relationship true inside a detached tree. Only stating each admitted
            // name again from the descriptor above it can notice the move.
            name: r#"project-writer-ancestor-fence-skipped"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"            || entry_identity(&entry) != identity"#,
            new: r#"            || false && entry_identity(&entry) != identity"#,
            run: Run::AgentBin(
                r#"a_moved_projects_directory_before_the_rename_is_a_displaced_refusal"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // D8's boundary must be re-applied, not remembered: a `chmod` between
            // the under-lock read and the rename keeps identity, link count and
            // size, so only measuring owner and mode again refuses the replacement.
            name: r#"project-writer-late-authority-accepted"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"    if crate::config_authority::verify_project_file_at(parent, &FinalComponent::Regular(facts))
        .is_err()
    {"#,
            new: r#"    if false
        && crate::config_authority::verify_project_file_at(
            parent,
            &FinalComponent::Regular(facts),
        )
        .is_err()
    {"#,
            run: Run::AgentBin(
                r#"a_config_made_group_writable_before_the_rename_is_a_stale_refusal"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // D2: an `ENOENT` from a link-following open is a missing *name* or a
            // missing *target*. Only the first is a slot a save may create; the second
            // is a dangling alias, and the `mkdirat` that follows the old reading
            // reports it as `EEXIST` after acquisition instead.
            name: r#"project-writer-dangling-route-name-created"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"        Err(Errno::NOENT) => classify_missing_child(parent, step, config),"#,
            new: r#"        Err(Errno::NOENT) => Ok(None),"#,
            run: Run::AgentBin(r#"a_dangling_dotfile_alias_is_refused_rather_than_created_over"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // D2: an admitted alias is only as good as the directories above it. A
            // leaf this user owns under a parent others may write is a route another
            // process can replace, which is the reader's own refusal.
            name: r#"project-writer-alias-ancestry-unchecked"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"    if canonical != level.path {"#,
            new: r#"    if false && canonical != level.path {"#,
            run: Run::AgentBin(
                r#"a_dotfile_alias_inside_an_ancestry_another_user_controls_is_refused"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // D2: "inside the active project" is the identity this command captured,
            // not a spelling. A root replaced after the capture makes every route
            // answer below it describe a directory nothing measured.
            name: r#"project-writer-captured-root-identity-unchecked"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"    if !crate::project_config::captured_root_is_live(root, root_id) {"#,
            new: r#"    if false && !crate::project_config::captured_root_is_live(root, root_id) {"#,
            run: Run::AgentBin(r#"a_project_root_replaced_after_the_capture_is_refused"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // D2: a umask that masks the owner's own read or search bit is repaired on
            // the name through the parent descriptor, before the entry is opened. A
            // repair that re-applies the masked mode repairs nothing.
            name: r#"project-writer-masked-creation-mode-kept"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"    rustix::fs::chmodat(&parent.fd, &step.name, DIR_MODE, AtFlags::empty())"#,
            new: r#"    rustix::fs::chmodat(&parent.fd, &step.name, create_mode, AtFlags::empty())"#,
            run: Run::AgentBin(
                r#"an_unopenable_creation_mode_is_repaired_before_the_entry_is_opened"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // D4: the backward comment scan is bounded by the end of the last root
            // value. Unbounded, a `#` that *begins a line inside* a multiline string is
            // read as a comment and the assignment is spliced into the value.
            name: r#"project-writer-root-value-scan-unbounded"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"        if previous < root_values_end {"#,
            new: r#"        if false && previous < root_values_end {"#,
            run: Run::AgentBin(
                r#"a_multiline_root_value_ending_on_a_comment_looking_line_is_not_a_note"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // D4: an existing zero-byte file keeps its missing final newline. The
            // absent-file seed is the only case that adds one.
            name: r#"project-writer-empty-file-gains-newline"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"        let bytes = assignment.into_bytes();"#,
            new: r#"        let bytes = format!("{assignment}\n").into_bytes();"#,
            run: Run::AgentBin(r#"an_empty_file_gets_only_the_assignment_and_no_final_newline"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // D8/B6: growth below the reader's ceiling is still a change. The read
            // length must equal the size the descriptor had when it was opened and the
            // size it has now, not merely stay under the cap.
            name: r#"project-writer-growth-below-cap-accepted"#,
            path: r#"crates/agent-vm/src/project_config_writer.rs"#,
            old: r#"        if size_now != Some(measured_size) || bytes.len() as u64 != measured_size {"#,
            new: r#"        if size_now.is_some()
            && false
            && (size_now != Some(measured_size) || bytes.len() as u64 != measured_size)
        {"#,
            run: Run::AgentBin(r#"a_config_that_grows_below_the_cap_is_refused"#),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        // `image set-default` itself: two properties that only the command can show
        // -- the post-acquisition approval conflict (D3) and the `<alias>:image`
        // argument refusal (D8). Both run against the fixture registry on loopback
        // with an isolated `$HOME`; neither reaches the network or a live registry.
        Row {
            // D3 and D7: the approval lookup happens after acquisition and before
            // the write, and it writes no approval. Without it the command saves a
            // reference whose next launch would consume the approved content.
            name: r#"set-default-post-acquire-pin-recheck-skipped"#,
            path: r#"crates/agent-vm/src/image_pin/project_default.rs"#,
            old: r#"    if let Some(existing) = super::lookup(&key)?
        && existing.digest != *prepared.image().acquired_digest()
    {"#,
            new: r#"    if let Some(existing) = super::lookup(&key)?
        && false
        && existing.digest != *prepared.image().acquired_digest()
    {"#,
            run: Run::AgentTest(
                r#"default_image_upgrade"#,
                r#"a_tag_approved_at_another_digest_refuses_and_writes_nothing"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // D1: the no-op takes the same compare-and-publish as an edit, so
            // `Unchanged` means the snapshot was found live under the lock. Letting
            // the planner's `Unchanged` answer the command directly prints success
            // over a file a peer already replaced.
            name: r#"set-default-unchanged-path-skips-cas"#,
            path: r#"crates/agent-vm/src/boot_image/upgrade.rs"#,
            old: r#"    store.save(snapshot, bytes)
}"#,
            new: r#"    if plan.bytes().is_none() {
        return Ok(ConfigSave::Unchanged);
    }
    store.save(snapshot, bytes)
}"#,
            run: Run::AgentBin(
                r#"an_unchanged_plan_still_compares_and_publishes_against_a_live_snapshot"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
        Row {
            // D8: `<alias>:image` is a source delegation in a project config, so this
            // command refuses it with its own value-free advice instead of the OCI
            // grammar's. A generic refusal keeps the exit status and loses the reason.
            name: r#"set-default-source-delegation-generic-refusal"#,
            path: r#"crates/agent-vm/src/boot_image/upgrade.rs"#,
            old: r#"        if is_source_delegation(raw) {
            return Err(SOURCE_DELEGATION_REASON);
        }"#,
            new: r#"        if is_source_delegation(raw) {
            return Err(INVALID_REFERENCE_REASON);
        }"#,
            run: Run::AgentTest(
                r#"default_image_upgrade"#,
                r#"an_alias_shaped_image_argument_is_a_usage_error_with_advice"#,
            ),
            markers: &[r#"test result: FAILED"#],
            anchors: 1,
        },
    ]
}

pub fn run(args: EgressMutationsArgs) -> Result<crate::Outcome, String> {
    let rows = ledger();
    if args.check_anchors {
        return check_anchors(&rows).map(crate::Outcome::Report);
    }
    let Some(evidence) = args.evidence else {
        return Err("usage: --evidence is required unless --check-anchors is used".to_owned());
    };
    let selected: Vec<Row> = rows
        .into_iter()
        .filter(|row| {
            args.only
                .as_ref()
                .is_none_or(|only| row.name.contains(only.as_str()))
        })
        .collect();
    if selected.is_empty() {
        return Err(format!(
            "usage: --only {:?} matched no mutation",
            args.only.unwrap_or_default()
        ));
    }
    // Fail closed before spending the matrix: the `-proof` rows need the pinned
    // Verus release, and a missing toolchain would otherwise land as a bare FAIL
    // that is indistinguishable from a surviving mutant.
    if selected.iter().any(|row| matches!(row.run, Run::Proof)) && !on_path("cargo-verus") {
        return Err(
            "egress mutations: cargo-verus is not on PATH; the selected -proof rows need the \
             pinned Verus release on PATH"
                .to_owned(),
        );
    }
    matrix(&selected, &absolute(&evidence)?).map(crate::Outcome::Exit)
}

/// Prove every pre-mutation anchor is still there, and report the count CI
/// prints. A replacement is never compiled here: the contracts job builds
/// nothing, so this cannot say "every mutant builds".
fn check_anchors(rows: &[Row]) -> Result<String, String> {
    let root = repo_root();
    let mut sources: BTreeMap<&str, String> = BTreeMap::new();
    for row in rows {
        let text = match sources.get(row.path) {
            Some(text) => text,
            None => {
                let path = root.join(row.path);
                let text = fs::read_to_string(&path)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                sources.entry(row.path).or_insert(text)
            }
        };
        let matches = text.matches(row.old).count();
        if matches != row.anchors {
            return Err(format!(
                "FAIL: stale or ambiguous mutation anchor: {}: {matches}, expected {}",
                row.name, row.anchors
            ));
        }
    }
    Ok(format!(
        "PASS: {} mutation anchors (find text only; a real run compiles each replacement)",
        rows.len()
    ))
}

#[derive(Debug, clap::Args)]
pub struct EgressMutationsArgs {
    /// Verify every anchor still names text that exists, then report the count.
    #[arg(long)]
    check_anchors: bool,
    /// Directory for the per-row logs and `results.json`; it must be fresh.
    #[arg(long, value_name = "DIR")]
    evidence: Option<PathBuf>,
    /// Run only the rows whose name contains this string.
    #[arg(long, value_name = "NAME")]
    only: Option<String>,
}

/// The repository this binary was built in: the checkout whose sources the
/// anchors name, and whose `target/` holds the mutation builds.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn absolute(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
    Ok(cwd.join(path))
}

/// `shutil.which`, without a dependency: an executable regular file named
/// `name` on `PATH`.
fn on_path(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|directory| {
        let candidate = directory.join(name);
        fs::metadata(&candidate)
            .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    })
}

// --- The matrix -------------------------------------------------------------

/// Run every selected row over one disposable copy, and report the exit status
/// the caller exits with.
fn matrix(rows: &[Row], evidence: &Path) -> Result<i32, String> {
    // Refuse to mix runs: a reused directory would overwrite per-row logs and
    // leave stale rows beside the fresh `results.json`.
    if let Ok(mut entries) = fs::read_dir(evidence)
        && entries.next().is_some()
    {
        return Err(format!(
            "usage: --evidence {} is not empty; use a fresh directory so runs cannot be mixed",
            evidence.display()
        ));
    }
    let root = repo_root();
    // Canonicalize once: the anchors and the `manifest_path` comparison are path
    // comparisons, and `CARGO_MANIFEST_DIR/../..` is spelled with a `..`.
    let root = fs::canonicalize(&root).unwrap_or(root);
    let started = Instant::now();
    let copy = Disposable::create(&root)?;
    // Cargo holds no lock while a test binary runs, so two runs sharing a target
    // dir could rebuild or delete the binary the other is executing -- a false
    // result of exactly the kind this ledger rejects.
    let _lock = Lock::acquire(&root)?;
    let harness_target = root.join(HARNESS_TARGET);
    let proof_target = root.join(PROOF_TARGET);
    fs::create_dir_all(evidence).map_err(|error| format!("{}: {error}", evidence.display()))?;
    for (label, argv, target) in warmups(rows) {
        let target = if target == PROOF_TARGET {
            proof_target.clone()
        } else {
            harness_target.clone()
        };
        let log = evidence.join(format!("warmup-{label}.log"));
        let warm_started = Instant::now();
        let mut command = Process::new(argv[0]);
        command
            .args(&argv[1..])
            .current_dir(&copy.path)
            .env("CARGO_TARGET_DIR", &target);
        let captured = bounded(&mut command, &log, WARMUP_BOUND)?;
        println!(
            "{}",
            json!({
                "warmup": label,
                "command": argv,
                "CARGO_TARGET_DIR": target.to_string_lossy(),
                "exit": captured.status,
                "seconds": seconds(warm_started),
            })
        );
        if captured.status != 0 {
            return Err(format!(
                "egress mutations: the disposable copy's {label} warm-up failed; see {}",
                log.display()
            ));
        }
    }
    let mut results: Vec<Value> = Vec::new();
    for row in rows {
        results.push(run_row(row, &copy.path, &root, &harness_target, evidence));
        write_results(evidence, &results)?;
    }
    let passed = results
        .iter()
        .filter(|result| result["status"] == json!("PASS"))
        .count();
    println!(
        "total: {passed}/{} controls PASS in {}s",
        results.len(),
        seconds(started)
    );
    Ok(if results.is_empty() || passed != results.len() {
        1
    } else {
        0
    })
}

/// `(label, argv, target)` per warm-up the selected rows need. Cold dependencies
/// are a build cost, not a control's verdict, so they compile once here, outside
/// every per-row bound.
fn warmups(rows: &[Row]) -> Vec<(&'static str, Vec<&'static str>, &'static str)> {
    let mut warmups = Vec::new();
    if rows
        .iter()
        .any(|row| matches!(row.run, Run::AgentBin(_) | Run::AgentTest(..)))
    {
        // The units the matrix runs, so each row's build is incremental.
        warmups.push((
            "cargo",
            vec![
                "cargo",
                "test",
                "--locked",
                "-p",
                "agent-vm",
                "--no-run",
                "--bin",
                "agent-vm",
                "--test",
                LAUNCH_TARGET,
                "--test",
                "config_mounts",
                "--test",
                "git_metadata_mounts",
            ],
            HARNESS_TARGET,
        ));
    }
    if rows.iter().any(|row| matches!(row.run, Run::Proof)) {
        warmups.push((
            "verus",
            vec!["cargo", "verus", "verify", "--locked", "-p", "agent-vm"],
            PROOF_TARGET,
        ));
    }
    if rows.iter().any(|row| matches!(row.run, Run::Crate(_))) {
        warmups.push((
            "harness",
            vec![
                "cargo",
                "build",
                "--locked",
                "-p",
                "agent-vm-harness",
                "--bins",
            ],
            HARNESS_TARGET,
        ));
    }
    warmups
}

/// Mutate one file, run the control that must notice, restore the file whatever
/// happened, and report the row.
fn run_row(row: &Row, copy: &Path, root: &Path, harness_target: &Path, evidence: &Path) -> Value {
    let file = copy.join(row.path);
    let log = evidence.join(format!("{}.log", row.name));
    let started = Instant::now();
    let mut result = json!({
        "mutation": row.name,
        "command": control_argv(row),
        "status": "FAIL",
        "exit": Value::Null,
        "seconds": 0.0,
        "evidence": log.to_string_lossy(),
    });
    let original = match fs::read_to_string(&file) {
        Ok(original) => original,
        Err(error) => {
            result["reason"] = json!(format!("{}: {error}", file.display()));
            return result;
        }
    };
    // The same rule `--check-anchors` applied to the checkout, applied to the
    // copy: a file that changed under the run is not mutated blindly.
    let (status, reason, exit) = if original.matches(row.old).count() != row.anchors {
        (
            "FAIL".to_owned(),
            Some(format!("stale or ambiguous mutation anchor: {}", row.name)),
            Value::Null,
        )
    } else {
        let verdict = mutate_and_run(row, &file, &original, copy, root, harness_target, &log);
        // Restoring the copy is not optional: every later row reads the same tree.
        let restored = fs::write(&file, &original);
        match (verdict, restored) {
            (Ok(verdict), Ok(())) => verdict,
            (Ok(_), Err(error)) => (
                "FAIL".to_owned(),
                Some(format!(
                    "restoring {} after the row: {error}",
                    file.display()
                )),
                Value::Null,
            ),
            (Err(failure), _) => ("FAIL".to_owned(), Some(failure), Value::Null),
        }
    };
    result["status"] = json!(status);
    result["exit"] = exit;
    result["seconds"] = json!(seconds(started));
    if let Some(reason) = reason {
        result["reason"] = json!(reason);
    }
    println!("{result}");
    result
}

/// The mutation itself: write the replacement, run the control bounded, and
/// judge what it said.
fn mutate_and_run(
    row: &Row,
    file: &Path,
    original: &str,
    copy: &Path,
    root: &Path,
    harness_target: &Path,
    log: &Path,
) -> Result<(String, Option<String>, Value), String> {
    fs::write(file, original.replace(row.old, row.new))
        .map_err(|error| format!("{}: {error}", file.display()))?;
    let target = root.join(row.run.target_dir());
    let mut header = json!({
        "cwd": copy.to_string_lossy(),
        "command": control_argv(row),
        "CARGO_TARGET_DIR": target.to_string_lossy(),
    });
    if matches!(row.run, Run::Crate(_)) {
        header["build"] = json!(build_argv(row));
    }
    fs::write(log, format!("{header}\n")).map_err(|error| format!("{}: {error}", log.display()))?;
    // The mutated package must be rebuilt from these sources: never trust a
    // fingerprint this run did not produce (#327).
    if let Some(package) = row.run.package() {
        let name = package_name(package);
        let mut clean = Process::new("cargo");
        clean
            .args(["clean", "-p", name])
            .current_dir(copy)
            .env("CARGO_TARGET_DIR", &target);
        let cleaned = bounded(&mut clean, log, CONTROL_BOUND)?;
        append_log(
            log,
            &format!("# cargo clean -p {name}: exit {}\n", cleaned.status),
        )?;
        if cleaned.status != 0 {
            return Err("cargo clean -p failed; the mutation might not be rebuilt".to_owned());
        }
    }
    let (mut status, mut timed_out) = (0, false);
    if matches!(row.run, Run::Crate(_)) {
        // A crate row rebuilds first; the control is then the copy's new binary.
        let argv = build_argv(row);
        let mut build = Process::new(&argv[0]);
        build
            .args(&argv[1..])
            .current_dir(copy)
            .env("CARGO_TARGET_DIR", &target);
        let built = bounded(&mut build, log, CONTROL_BOUND)?;
        append_log(
            log,
            &format!("# {}: exit {}\n", argv.join(" "), built.status),
        )?;
        status = built.status;
        timed_out = built.timed_out;
        if status != 0 || timed_out {
            // A build failure is judged below, as a harness failure, never as a
            // surviving mutant.
            let text = fs::read_to_string(log).unwrap_or_default();
            return Ok(judge(row, status, timed_out, &text, copy));
        }
    }
    let mut command = control_command(row, copy, harness_target)?;
    // The control inherits the row's build directory: the proof gate falls back to
    // a `CARGO_TARGET_DIR` of its own under the copy, and a cold one rebuilds
    // vstd's 2059 proofs for every row.
    command.env("CARGO_TARGET_DIR", &target);
    let run = bounded(&mut command, log, CONTROL_BOUND)?;
    if !timed_out {
        status = run.status;
        timed_out = run.timed_out;
    }
    let text = fs::read_to_string(log).unwrap_or_default();
    Ok(judge(row, status, timed_out, &text, copy))
}

fn judge(
    row: &Row,
    status: i32,
    timed_out: bool,
    text: &str,
    copy: &Path,
) -> (String, Option<String>, Value) {
    let exit = json!(status);
    if timed_out {
        return (
            "FAIL".to_owned(),
            Some("timeout is not fault detection".to_owned()),
            exit,
        );
    }
    if let Some(failure) = compile_failure(text) {
        return (
            "FAIL".to_owned(),
            Some(format!("the mutant was never compiled: {failure}")),
            exit,
        );
    }
    let mut killed = status != 0 && row.markers.iter().any(|marker| text.contains(marker));
    if matches!(row.run, Run::Proof) {
        // The gate's own rule: the region from cargo's last `Checking agent-vm …`
        // or `Compiling agent-vm …` line to the end of the log.
        let Some(region) = verus_region(text) else {
            return (
                "FAIL".to_owned(),
                Some(
                    "the gate never checked the agent-vm crate; the mutation was never verified"
                        .to_owned(),
                ),
                exit,
            );
        };
        // "10 errors" also contains "0 errors".
        killed = killed && !zero_errors(region) && region.contains("error:");
    }
    if let Some(package) = row.run.package() {
        let target = match row.run {
            // The harness package holds only the crate this row mutates, so the
            // package scope is the target.
            Run::Crate(_) => None,
            _ => Some(mutation_target(row.path)),
        };
        let artifacts = package_artifacts(text, &copy.join(package), target);
        let name = target.unwrap_or_else(|| package_name(package));
        if artifacts.iter().any(fresh) {
            return (
                "FAIL".to_owned(),
                Some(format!(
                    "cargo reused a fresh {name} artifact; the mutation was never compiled"
                )),
                exit,
            );
        }
        if !artifacts.iter().any(|message| !fresh(message)) {
            return (
                "FAIL".to_owned(),
                Some(format!(
                    "cargo reported no {name} compilation; the mutation was never compiled"
                )),
                exit,
            );
        }
        if status == 0
            && matches!(row.run, Run::AgentBin(_) | Run::AgentTest(..))
            && !ran_tests(text)
        {
            // A filter that matches nothing exits 0 with a green "test result: ok"
            // line, which is indistinguishable from a surviving mutant unless it
            // is named. A typo'd filter must never read as "the test did not
            // detect the mutation".
            return (
                "FAIL".to_owned(),
                Some("the killing filter matched no test (harness failure)".to_owned()),
                exit,
            );
        }
    }
    if killed {
        ("PASS".to_owned(), None, exit)
    } else {
        ("FAIL".to_owned(), None, exit)
    }
}

/// Why the mutated target did not build, if it did not.
///
/// A mutant that cannot compile is a harness defect, never a surviving mutant
/// and never a test's failure: a row naming a field that has since been renamed
/// "fails" every time without exercising anything. Syntax, type and name errors
/// all end at cargo's `error: could not compile` line; a typed error catches a
/// message whose summary was elided. The Verus gate is the exception that shapes
/// the second rule: a *failed proof* also makes cargo fail, and it reports
/// `verification results:: … N errors`, a line that only exists after the crate
/// compiled.
fn compile_failure(text: &str) -> Option<String> {
    if let Some(start) = text.find("error[E")
        && let Some(end) = text[start..].find(']')
    {
        return Some(text[start..start + end + 1].to_owned());
    }
    if text.contains(BUILD_FAILED) && !text.contains(VERUS_SUMMARY) {
        return Some("cargo could not compile the mutated target".to_owned());
    }
    None
}

/// One `cargo verus verify` report: from cargo's last `Checking agent-vm …` or
/// `Compiling agent-vm …` status line to the end of the log. The trailing space
/// is what keeps `agent-vm-harness` (a dev-dependency the verifier also builds)
/// out of the region, and with it a `0 errors` line that belongs to vstd.
fn verus_region(text: &str) -> Option<&str> {
    let mut offset = None;
    let mut cursor = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with("Checking agent-vm ") || trimmed.starts_with("Compiling agent-vm ") {
            offset = Some(cursor);
        }
        cursor += line.len();
    }
    offset.map(|offset| &text[offset..])
}

/// `\b0 errors\b`, spelled out: `10 errors` must not read as zero.
fn zero_errors(tail: &str) -> bool {
    let bytes = tail.as_bytes();
    let mut index = 0;
    while let Some(found) = tail[index..].find("0 errors") {
        let at = index + found;
        let before = at == 0 || !bytes[at - 1].is_ascii_alphanumeric() && bytes[at - 1] != b'_';
        let after = at + "0 errors".len();
        let following =
            after >= bytes.len() || !bytes[after].is_ascii_alphanumeric() && bytes[after] != b'_';
        if before && following {
            return true;
        }
        index = at + 1;
    }
    false
}

/// Whether cargo reported actually running tests, so a green exit is a real
/// result rather than an unmatched filter.
fn ran_tests(text: &str) -> bool {
    text.lines().any(|line| {
        let Some(rest) = line.trim().strip_prefix("running ") else {
            return false;
        };
        let Some(count) = rest
            .strip_suffix(" tests")
            .or_else(|| rest.strip_suffix(" test"))
        else {
            return false;
        };
        count.parse::<u32>().is_ok_and(|count| count > 0)
    })
}

fn fresh(message: &Value) -> bool {
    message
        .get("fresh")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// The compilation events cargo reported for one package, optionally narrowed to
/// one target. The target is named explicitly rather than inferred, so a row
/// cannot pass by compiling a test of the same name in a different binary.
fn package_artifacts(text: &str, package: &Path, target: Option<&str>) -> Vec<Value> {
    text.lines()
        .map(str::trim)
        .filter(|line| line.starts_with('{'))
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|message| {
            message.get("reason").and_then(Value::as_str) == Some("compiler-artifact")
        })
        .filter(|message| {
            message
                .get("manifest_path")
                .and_then(Value::as_str)
                .is_some_and(|path| same_file(path, package))
        })
        .filter(|message| {
            target.is_none_or(|target| {
                message
                    .pointer("/target/name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name == target)
            })
        })
        .collect()
}

fn same_file(path: &str, package: &Path) -> bool {
    let path = Path::new(path);
    match (fs::canonicalize(path), fs::canonicalize(package)) {
        (Ok(a), Ok(b)) => a == b,
        _ => path == package,
    }
}

/// The cargo target whose compilation carries a mutation in this file.
fn mutation_target(path: &str) -> &str {
    match path.strip_prefix("crates/agent-vm/tests/") {
        Some(stem) => stem.trim_end_matches(".rs"),
        None => "agent-vm",
    }
}

fn package_name(package: &str) -> &'static str {
    if package == HARNESS_PACKAGE {
        "agent-vm-harness"
    } else {
        "agent-vm"
    }
}

/// The argv that decides the row, `argv[0]` first, as it is logged.
fn control_argv(row: &Row) -> Vec<String> {
    match row.run {
        Run::AgentBin(filter) => agent_argv(None, filter),
        Run::AgentTest(target, filter) => agent_argv(Some(target), filter),
        Run::Proof => vec![
            "bash".to_owned(),
            "script/test/verus-verification.sh".to_owned(),
            "--repo-gate".to_owned(),
        ],
        Run::ReadAt(argv) | Run::Crate(argv) => argv.iter().map(|arg| (*arg).to_owned()).collect(),
    }
}

/// `cargo build` for a crate row: the mutated harness package, with cargo's own
/// JSON so the verdict can ask whether *this* mutation was compiled. Only a
/// [`Run::Crate`] row builds, and the harness package is the only one it mutates.
fn build_argv(row: &Row) -> Vec<String> {
    debug_assert!(matches!(row.run, Run::Crate(_)));
    vec![
        "cargo".to_owned(),
        "build".to_owned(),
        "--locked".to_owned(),
        "-p".to_owned(),
        package_name(HARNESS_PACKAGE).to_owned(),
        "--bins".to_owned(),
        "--message-format=json-render-diagnostics".to_owned(),
    ]
}

fn agent_argv(target: Option<&str>, filter: &str) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        "cargo".to_owned(),
        "test".to_owned(),
        "--locked".to_owned(),
        "-p".to_owned(),
        "agent-vm".to_owned(),
        "--message-format=json-render-diagnostics".to_owned(),
    ];
    match target {
        Some(target) => argv.extend(["--test".to_owned(), target.to_owned()]),
        None => argv.extend(["--bin".to_owned(), "agent-vm".to_owned()]),
    }
    argv.push(filter.to_owned());
    argv
}

/// The command that decides the row, run in the copy. Every row runs in the copy:
/// `cargo` resolves the workspace from the working directory, and the proof gate
/// resolves its repository root from the script's own relative path, so a row
/// started anywhere else would grade the checkout instead of the mutation.
fn control_command(row: &Row, copy: &Path, harness_target: &Path) -> Result<Process, String> {
    let (program, argv): (PathBuf, Vec<String>) = match row.run {
        // The checkout's own binary: it reads the copy's mutated source from disk.
        Run::ReadAt(argv) => (
            crate::egress_cases::harness_binary(),
            argv.iter().map(|arg| (*arg).to_owned()).collect(),
        ),
        // The copy's rebuilt binary: what it does *is* the mutation.
        Run::Crate(argv) => (
            harness_target.join("debug/harness"),
            argv.iter().map(|arg| (*arg).to_owned()).collect(),
        ),
        // `cargo test` and the Verus gate: `argv[0]` is the program, not an
        // argument.
        _ => {
            let argv = control_argv(row);
            let program = PathBuf::from(&argv[0]);
            (program, argv[1..].to_vec())
        }
    };
    let mut command = Process::new(program);
    command.args(argv).current_dir(copy);
    Ok(command)
}

fn write_results(evidence: &Path, results: &[Value]) -> Result<(), String> {
    let path = evidence.join("results.json");
    let text = serde_json::to_string_pretty(results).map_err(|error| error.to_string())?;
    fs::write(&path, text + "\n").map_err(|error| format!("{}: {error}", path.display()))
}

fn seconds(started: Instant) -> f64 {
    (started.elapsed().as_secs_f64() * 10.0).round() / 10.0
}

fn append_log(log: &Path, text: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .map_err(|error| format!("{}: {error}", log.display()))?;
    file.write_all(text.as_bytes())
        .map_err(|error| format!("{}: {error}", log.display()))
}

// --- Bounded subprocesses ---------------------------------------------------

struct Captured {
    status: i32,
    timed_out: bool,
}

/// Run `command` with its output appended to `log`, and never wait longer than
/// `bound`. A control that hangs fails the row instead of hanging the gate.
fn bounded(command: &mut Process, log: &Path, bound: Duration) -> Result<Captured, String> {
    let out = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .map_err(|error| format!("{}: {error}", log.display()))?;
    let err = out
        .try_clone()
        .map_err(|error| format!("{}: {error}", log.display()))?;
    command.stdout(Stdio::from(out)).stderr(Stdio::from(err));
    let program = command.get_program().to_string_lossy().into_owned();
    let mut child = command
        .spawn()
        .map_err(|error| format!("{program}: {error}"))?;
    let deadline = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(Captured {
                    status: status.code().unwrap_or(-1),
                    timed_out: false,
                });
            }
            Ok(None) => {}
            Err(error) => return Err(format!("{program}: {error}")),
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(Captured {
                status: -1,
                timed_out: true,
            });
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

// --- The disposable copy ----------------------------------------------------

/// A throwaway copy of the tracked tree, removed when the run ends.
struct Disposable {
    path: PathBuf,
}

impl Disposable {
    /// Copy every tracked file except `vendor/`, which is symlinked instead: it
    /// is upstream's submodules, hundreds of megabytes the controls only read.
    fn create(root: &Path) -> Result<Self, String> {
        let base = root.join("target");
        fs::create_dir_all(&base).map_err(|error| format!("{}: {error}", base.display()))?;
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let path = base.join(format!("egress-mutations-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let copy = Disposable { path };
        // `git ls-files -z` writes to a file, never through a pipe: the listing is
        // larger than a pipe buffer, so a bounded wait that did not drain it
        // would deadlock. `--others --exclude-standard` adds the files a port has
        // written but not yet committed: the copy is the *working* tree, and a
        // mutation run must be able to grade the module it is porting before the
        // coordinator commits it.
        let listing = base.join(format!("ls-files-{nanos}.tmp"));
        let mut git = Process::new("git");
        git.args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(root);
        let captured = bounded(&mut git, &listing, CONTROL_BOUND)?;
        if captured.status != 0 {
            let _ = fs::remove_file(&listing);
            return Err("git ls-files failed; the disposable copy was not made".to_owned());
        }
        let tracked = fs::read(&listing).map_err(|error| error.to_string())?;
        let _ = fs::remove_file(&listing);
        for name in tracked.split(|byte| *byte == 0) {
            let name = String::from_utf8_lossy(name);
            if name.is_empty() || name.starts_with("vendor/") {
                continue;
            }
            let source = root.join(name.as_ref());
            if !source.is_file() {
                continue;
            }
            let destination = copy.path.join(name.as_ref());
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("{}: {error}", parent.display()))?;
            }
            fs::copy(&source, &destination).map_err(|error| {
                format!("{} -> {}: {error}", source.display(), destination.display())
            })?;
        }
        let vendor = copy.path.join("vendor");
        std::os::unix::fs::symlink(root.join("vendor"), &vendor)
            .map_err(|error| format!("{}: {error}", vendor.display()))?;
        Ok(copy)
    }
}

impl Drop for Disposable {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// The exclusive lock that keeps two runs out of one target dir. Cargo does not
/// hold its own lock while a test binary runs, so a second run could delete the
/// binary the first is executing.
struct Lock {
    file: fs::File,
}

impl Lock {
    fn acquire(root: &Path) -> Result<Self, String> {
        let directory = root.join("target/egress-mutations");
        fs::create_dir_all(&directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
        let path = directory.join("run.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        use std::os::fd::AsRawFd;
        // SAFETY: `flock` takes a descriptor this process owns for as long as
        // `file` lives, and the call neither reads nor writes memory.
        let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if status != 0 {
            return Err(format!(
                "egress mutations: another egress mutation run holds {}",
                path.display()
            ));
        }
        Ok(Lock { file })
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: as in `acquire`; unlocking a descriptor this process holds is
        // the documented inverse of the lock.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// The exit status a failed command asks for, when it asks for one of its own:
/// an inconclusive refusal (another run, a missing toolchain) is not the same
/// answer as a surviving mutant.
pub fn failure_status(error: &str) -> Option<i32> {
    error.starts_with("egress mutations: ").then_some(2)
}
