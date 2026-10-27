#!/usr/bin/env python3
"""Fault-detection controls in disposable source copies; never edit kernels in place.

Run from any cwd. Logs and the exact command ledger go under --evidence.
A compiler error, timeout, or missing test is not a killed mutation.

A control's verdict must not depend on build history (#327). Two properties
carry that:

* Cargo rows build in the harness's own `CARGO_TARGET_DIR`
  (`target/egress-mutations/target`), never the checkout's `target/`; proof rows
  keep the documented `target/verus`, which their gate cleans on every run.
  Fingerprints ignore the copy's path, so a target dir shared with the checkout
  answers with artifacts that were never compiled from the copy (#327).
* Every compiling control removes the package's artifacts (`cargo clean -p
  agent-vm`) and then requires cargo to report that it recompiled the target the
  mutation lives in. A mutation that was never compiled is a harness failure,
  never a surviving mutant.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "target"
# Cargo rows share one target dir so dependencies compile once. Fingerprints
# ignore the copy's path, so what keeps a verdict honest is the per-control
# `cargo clean -p agent-vm` plus the recompile assertion -- never this dir. A
# lock serializes runs, since cargo holds no lock while a test binary runs.
HARNESS_TARGET = TARGET / "egress-mutations" / "target"
# Proof rows keep the documented Verus target dir; `verus-verification.sh
# --repo-gate` already removes this package's artifacts before it verifies.
VERUS_TARGET = TARGET / "verus"
VERUS_WARMUP = ["cargo", "verus", "verify", "--locked", "-p", "agent-vm"]
CLEAN_PACKAGE = ["cargo", "clean", "-p", "agent-vm"]
# Build the units the matrix runs, so its cold dependency build happens once,
# outside every per-control timeout.
WARMUP = ["cargo", "test", "--locked", "-p", "agent-vm", "--no-run",
          "--bin", "agent-vm", "--test", "config_launch_driven",
          "--test", "config_mounts"]
WARMUP_TIMEOUT = 3600
CONTROL_TIMEOUT = 240
SRC = "crates/agent-vm/src/"
TEST = "crates/agent-vm/tests/config_launch_driven.rs"
EGRESS = SRC + "egress_policy.rs"
GRAMMAR = SRC + "egress_grammar.rs"
NETWORK = SRC + "network.rs"
FIXTURE = "script/test/lib/egress-fixtures.py"
PROBE = "script/test/fixtures/egress-probe.sh"
LAUNCH = "config_launch_driven"
MOUNTS = "config_mounts"


def rust(pattern, test=None):
    """A unit row (`--bin agent-vm`) or an integration row in one named target.

    The target is named explicitly rather than inferred, so a row cannot pass by
    running a test of the same name in a different binary.
    """
    # JSON messages are how the harness learns whether cargo recompiled the
    # package or answered from an artifact it did not compile from the mutation.
    return [
        "cargo", "test", "--locked", "-p", "agent-vm", "--message-format=json-render-diagnostics",
        *(["--test", test] if test else ["--bin", "agent-vm"]), pattern,
    ]


def package_artifacts(text, package):
    """The compilation events cargo reported for the copy's agent-vm package."""
    artifacts = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict) or message.get("reason") != "compiler-artifact":
            continue
        if Path(message.get("manifest_path", "")).resolve() == package:
            artifacts.append(message)
    return artifacts


def mutation_target(path):
    """The cargo target whose compilation carries a mutation in this file."""
    if path.startswith("crates/agent-vm/tests/"):
        return Path(path).stem
    return "agent-vm"


def outcome(name, command, marker, exit_code, text, package, target):
    """PASS only for a mutation that this run compiled (or verified) and killed."""
    killed = exit_code != 0 and marker in text
    if name.endswith("-proof"):
        verified = "Checking agent-vm v" in text or "Compiling agent-vm v" in text
        if not verified:
            return "FAIL", "the gate never checked the agent-vm crate; the mutation was never verified"
        # "10 errors" also contains "0 errors".
        killed = killed and not re.search(r"\b0 errors\b", text.split("Checking agent-vm")[-1]) and "error:" in text
    if command[0] == "cargo":
        artifacts = [message for message in package_artifacts(text, package)
                     if message["target"]["name"] == target]
        if any(message.get("fresh") for message in artifacts):
            return "FAIL", f"cargo reused a fresh {target} artifact; the mutation was never compiled"
        if not any(not message.get("fresh") for message in artifacts):
            return "FAIL", f"cargo reported no {target} compilation; the mutation was never compiled"
        if exit_code == 0 and not re.search(r"^running [1-9]\d* tests?$", text, re.MULTILINE):
            # A filter that matches nothing exits 0 with a green "test result: ok"
            # line, which is indistinguishable from a surviving mutant unless it
            # is named. A typo'd filter must never read as "the test did not
            # detect the mutation".
            return "FAIL", "the killing filter matched no test (harness failure)"
    return ("PASS", None) if killed else ("FAIL", None)


def matrix():
    controls = []

    def add(name, path, old, new, command, marker="test result: FAILED"):
        controls.append((name, path, old, new, command, marker))

    egress = rust("egress_policy")
    gate = ["bash", "script/test/verus-verification.sh", "--repo-gate"]
    add("lan-dns", EGRESS, "gateway_dns: grants.internet, public:", "gateway_dns: grants.internet || grants.lan, public:", egress)
    add("profiles", EGRESS, "let emitted = group_rules(self.groups);", """if self.groups.lan || self.groups.host || self.groups.internet {
            use microsandbox_network::policy::NetworkProfile;
            return microsandbox::NetworkPolicy::from_profiles([
                NetworkProfile::Public, NetworkProfile::Private, NetworkProfile::Host]);
        }
        let emitted = group_rules(self.groups);""", egress)
    add("mapped-v6", EGRESS, "&& v6.prefix() >= 96", "&& false && v6.prefix() >= 96", egress)
    kernel_mutations = [
        ("leading-zero", "if bytes[0] == 0x30 { return None; }", "if bytes[0] == 0xff { return None; }"),
        ("scheme-any", "} else if contains_separator(s, 0) {\n        Err(LayoutError::UnsupportedScheme)", "} else if contains_separator(s, 0) {\n        Ok((SchemeSel::Any, 0))"),
        ("port-value", "port: Some(port) }", "port: Some(if port == 22 { 80 } else { port }) }"),
        ("address-substring", "addr_start: 0, addr_end: t.len(), port: None", "addr_start: 1, addr_end: t.len(), port: None"),
        ("bracket-suffix", "if k + 1 != t.len() && t[k+1] != 0x3a { return Err(LayoutError::MalformedAddress); }", "if k + 1 != t.len() && t[k+1] != 0x3a { return Ok(TargetLayout { addr_start: 1, addr_end: k, port: None }); }"),
    ]
    for name, old, new in kernel_mutations:
        add(name, GRAMMAR, old, new, egress)
        add(name + "-proof", GRAMMAR, old, new, gate, "verification results::")
    hostname = SRC + "egress_hostname.rs"
    requests = SRC + "network_requests.rs"
    coverage = rust("network_request_coverage")
    request_units = rust("network_requests::tests::")
    add("request-port-ignored", hostname,
        "&self.name == name && self.effective_ports(ports).contains(&port.get())",
        "&self.name == name", coverage)
    add("request-internet-ignored", EGRESS,
        "let public = group_rules(self.groups).public;",
        "let public = false;", coverage)
    add("request-report-unbounded", requests,
        ".take_while(|(shown, _)| report_budget_allows(*shown))",
        ".take_while(|_| true)", request_units)
    limit_body = "    ensures ok == request_count_within_limit_spec(count),\n{\n    count <= MAX_NETWORK_REQUESTS\n}"
    limit_mutant = "    ensures ok == request_count_within_limit_spec(count),\n{\n    count <= MAX_NETWORK_REQUESTS + 1\n}"
    add("request-limit", requests, limit_body, limit_mutant, request_units)
    add("request-limit-proof", requests, limit_body, limit_mutant, gate, "verification results::")
    shape = rust("hostname_rule_shape")
    host_kernel = rust("egress_hostname::tests")
    proxy = rust("hostname_proxy_selection_mirrors_the_host_connector")
    add("domain-all-ports", hostname, "ports: effective.into_iter().map(PortRange::single).collect(),", "ports: vec![],", shape)
    add("domain-any-protocol", hostname, "protocols: vec![Protocol::Tcp],", "protocols: vec![],", shape)
    add("domain-first", EGRESS, "rules.extend(domain_rules(&self.hostnames, &ports));", "rules.splice(0..0, domain_rules(&self.hostnames, &ports));", shape)
    add("hostname-dns", EGRESS, "rules.extend(domain_rules(&self.hostnames, &ports));", "rules.push(Rule::allow_dns()); rules.extend(domain_rules(&self.hostnames, &ports));", shape)
    add("tls-ports-missing", NETWORK, "Some(ports) => tls.intercepted_ports(ports.clone()),", "Some(_) => tls,", rust("hostname_launch_keeps_strict_and_intercepts_every_domain_port"))
    add("tls-off", NETWORK, "let enable_tls = !publish_ports.is_empty() || hostname_ports.is_some();", "let enable_tls = !publish_ports.is_empty();", rust("hostname_launch_keeps_strict_and_intercepts_every_domain_port"))
    add("bare-port-443-only", hostname, "HostnameScope::InterceptedPorts => ports.to_vec(),", "HostnameScope::InterceptedPorts => { let _ = ports; vec![443] },", shape)
    for name, old, new in (
        ("dns-port-allowed", "if p == 53 || p == 853 { Err(HostnameScopeError::DnsPort) }", "if false { Err(HostnameScopeError::DnsPort) }"),
        ("udp-hostname", "if scheme == SchemeSel::Udp { return Err(HostnameScopeError::Udp); }", "if false { return Err(HostnameScopeError::Udp); }"),
        ("numeric-final-label", "!numeric_label_bytes(bytes)", "{ let _ = numeric_label_bytes(bytes); true }"),
        ("single-label-refused", "None => {\n            proof {", "None => { return false;\n            proof {"),
    ):
        add(name, hostname, old, new, host_kernel)
        add(name + "-proof", hostname, old, new, gate, "verification results::")
    add("alias-allowed", hostname, 'if host == "host.microsandbox.internal" {', 'if false {', rust("grammar_error_precedence_table"))
    add("hostname-proxy-unchecked", NETWORK, "if egress.has_hostnames() && observation.connector_used {", "if false && egress.has_hostnames() && observation.connector_used {", proxy)
    add("proxy-any-scheme", NETWORK, 'Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => rest,', 'Some((_, rest)) => rest,', proxy)
    add("proxy-first-var-only", NETWORK, "usable |= connector_would_select(&value);", "if notice.is_none() { usable |= connector_would_select(&value); }", proxy)
    add("proxy-no-proxy-ignored", NETWORK, "connector_used: usable && !wildcard,", "connector_used: usable && (wildcard || !wildcard),", proxy)
    dense = rust("network::tests::default_plan_denies_all_egress_and_preserves_non_policy_network_config")
    early = "if self.publish_ports.is_empty() && !self.auto_publish { return builder; }\n        let policy = self.egress.policy();"
    add("early-return", NETWORK, "let policy = self.egress.policy();", early, dense)
    add("early-return-g1", NETWORK, "let policy = self.egress.policy();", early, rust("default_tools_launch_with_their_declared_provisioning", LAUNCH))
    add("early-return-g2", NETWORK, "let policy = self.egress.policy();", early, rust("a_zero_provisioning_launch_boots_with_no_tls_overlay", LAUNCH))
    for name, expression in (
        ("strict", "network.strict(false)"),
        ("tls", "network.tls(|tls| tls.enabled(true))"),
        ("ports", "network.tls_overlay(|tls| tls.intercepted_ports(vec![8443]))"),
        ("rebind", "network.dns(|dns| dns.rebind_protection(false))"),
        ("nameservers", 'network.dns(|dns| dns.nameservers([std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))]))'),
        ("intercept-limit", "network.intercept(|intercept| intercept.max_request_bytes(1))"),
        ("secret", 'network.secret(|secret| secret.env("MSB_MUTANT").value("synthetic").allow("example.com"))'),
        ("connections", "network.max_connections(0)"),
    ):
        add("dense-" + name, NETWORK, "network = network.policy(policy);", "network = network.policy(policy);\n            network = " + expression + ";", dense)
    add("unknown-key", NETWORK, 'applied.as_object_mut().unwrap().remove("policy");', 'applied["unknown_mutation"] = serde_json::json!(true);\n        applied.as_object_mut().unwrap().remove("policy");', dense)
    # Inject into the applied object, never expected defaults or launch goldens.
    # The shared G1/G2 helper is faulted through both actual launch callers.
    zero = rust("a_zero_provisioning_launch_boots_with_no_tls_overlay", LAUNCH)
    for name, injection in (
        ("secret", 'network["secrets"]["secrets"] = serde_json::json!([{ "env_var": "MSB_MUTANT" }]);'),
        ("header", 'network["secrets"]["header_credentials"] = serde_json::json!([{ "id": "mutant" }]);'),
        ("route", 'network["intercept"]["rules"] = serde_json::json!([{ "host": "example.com" }]);'),
        ("hook", 'network["intercept"]["hook"] = serde_json::json!(["mutant"]);'),
        ("tls", 'network["tls"]["enabled"] = serde_json::json!(true);'),
        ("policy", 'network["policy"]["rules"] = serde_json::json!([{ "action": "allow" }]);'),
        ("strict", 'network["strict"] = serde_json::json!(false);'),
        ("missing-secrets", 'network["secrets"].as_object_mut().unwrap().remove("secrets");'),
        ("missing-rules", 'network["intercept"].as_object_mut().unwrap().remove("rules");'),
    ):
        for prefix, command in (("zero-", zero), ("g1-", rust("default_tools_launch_with_their_declared_provisioning", LAUNCH))):
            add(prefix + name, TEST,
                'fn assert_default_deny_zero_provision_network(network: &serde_json::Value, context: &str) {',
                'fn assert_default_deny_zero_provision_network(network: &serde_json::Value, context: &str) {\n    let mut changed = network.clone();\n    let network = &mut changed;\n    ' + injection, command)
    add("overlay-equal-length", SRC + "credential_injection.rs",
        "let base_ports = intercepted_ports_of(&network)?;",
        'let base_ports = intercepted_ports_of(&network)?;\n        network = network.policy(serde_json::from_value(serde_json::json!({"default_egress":"deny","default_ingress":"allow","rules": [\n' +
        ','.join(['{"direction":"egress","destination":{"group":"public"},"protocols":[],"ports":[],"action":"allow"}'] * 4) +
        ']})).unwrap());', rust("credential_overlay_preserves_base_network_plan"))
    g4 = rust("rejected_allowance_is_refused_before_launch_state_is_created", LAUNCH)
    for name, suffix in (("project", ""), ("mounts", ".mounts"), ("secrets", ".secrets")):
        add("preparse-" + name, SRC + "run.rs",
            "\n    let network_plan = crate::network::Plan::from_args(args.network, user_network)?;",
            '\n    let early = ProjectSession::for_cwd()?;\n    std::fs::create_dir_all(' +
            ('&early.state_dir' if not suffix else 'early.state_dir.with_extension("' + suffix[1:] + '")') +
            ')?;\n    let network_plan = crate::network::Plan::from_args(args.network, user_network)?;', g4)
    add("valid-no-fork", TEST,
        '&["--mount", &mount, "--allow-egress", "api.example.com"],',
        '&["--allow-egress", "api.example.com"],', g4)
    add("valid-no-credential", SRC + "run.rs", '.context("snapshotting host credentials")?;', '.context("snapshotting host credentials")?;\n    if let Some(file) = &creds.anthropic_token_file { std::fs::remove_file(file)?; }', g4)
    host = ["python3", "script/test/lib/egress-supervisor-contract.py"]
    for name, old, new in (
        ("shell-argv",
         '    if case.guest:\n        extra = hostname_extra(case, values, lan2 or DEFAULT_LAN2, hnc_step) if hostname_tier(case.case) else (\n            answer if case.case == "I1a" else rebind if case.case == "RB1" else "")\n        argv.extend((case.case, ident, lan, case.variant, extra))',
         '    if case.guest:\n        argv[len(flags) + 4] = "shell"\n        extra = hostname_extra(case, values, lan2 or DEFAULT_LAN2, hnc_step) if hostname_tier(case.case) else (\n            answer if case.case == "I1a" else rebind if case.case == "RB1" else "")\n        argv.extend(("-c", case.case, ident, lan, case.variant, extra))'),
        ("credential-tool", 'argv = [binary, "--no-git", "--image", IMAGE, *flags, case.tool]', 'argv = [binary, "--no-git", "--image", IMAGE, *flags, "egressprobe"]'),
        ("rejection-guest", 'if case.guest:\n        extra = hostname_extra', 'if case.guest or case.case == "RJ1":\n        extra = hostname_extra'),
        ("extra-env", 'env = base_environment(work)\n    extras', 'env = base_environment(work)\n    env["MUTANT"] = "1"\n    extras'),
        ("tcp-calibration", '"LC1": ("lan-tcp80", "lan-tcp81", "lan-udp90", "lan-udp80"),', '"LC1": ("lan-tcp80", "lan-udp90", "lan-udp80"),'),
        ("udp-calibration", '"LC1": ("lan-tcp80", "lan-tcp81", "lan-udp90", "lan-udp80"),', '"LC1": ("lan-tcp80", "lan-tcp81", "lan-udp90"),'),
        ("v6-calibration", '"V6c": ("public-v6-1111", "public-v6-1001"),', '"V6c": ("public-v6-1111",),'),
        ("resolver-calibration", '"HC1": ("host-tcp80", *gateway),\n        "I1": ("public-1111", "public-1001", *gateway, *explicit, "lan-tcp80", "host-tcp80"),', '"HC1": ("host-tcp80", *gateway),\n        "I1": ("public-1111", "public-1001", *gateway, "lan-tcp80", "host-tcp80"),'),
    ):
        add(name, FIXTURE, old, new, host, "FAILED (")
    wire = ["python3", "script/test/lib/egress-wire-contract.py"]
    add("dns-short-read", PROBE, 'dd bs=1 count="$frame"', 'dd bs="$frame" count=1', wire, "FAILED (")
    add("dns-eof", PROBE, 'timeout 3 dd bs=1 count="$frame"', 'timeout 3 cat', wire, "FAILED (")
    hooks = ["python3", "script/test/lib/egress-probe-contract.py"]
    add("hook-no-library", FIXTURE, 'EGRESS_PROBE_LIB=1 . ./egress-probe.sh\\n', ':\\n', hooks, "FAILED (")
    add("hook-zero", FIXTURE, 'else "return 7"', 'else "return 0"', hooks, "FAILED (")
    # Real timeout/catalog/socket contracts exercise these independent omissions.
    for name, old, new in (
        ("cleanup-no-kill", 'for identity in launch.alive():', 'for identity in []:'),
        ("cleanup-no-unlink", '                            path.unlink()', '                            pass'),
        ("cleanup-no-remove", '("remove", ("remove", name), 10)):', '("list", ("list",), 10)):'),
        ("cleanup-suppress", '    return errors\n\n\ndef cleanup_run', '    return []\n\n\ndef cleanup_run'),
        ("cleanup-unbounded", 'if deadline is not None:', 'if False and deadline is not None:'),
    ):
        add(name, FIXTURE, old, new, host, "FAILED (")
    guard = SRC + "protected_config_dir.rs"
    guard_tests = rust("protected_config_dir")
    for name, old, new in (
        ("prospective-bytewise", "    if !name_is_plain(a) || !name_is_plain(b) { return true; }", "    return a == b;"),
        ("wildcard-dropped", "    if !name_is_plain(a) || !name_is_plain(b) { return true; }", "    if !name_is_plain(a) || !name_is_plain(b) { return false; }"),
        ("exposes-no-identity", "(root_id.is_some() && ids[i] == root_id) || config::byte_path_contains", "false || config::byte_path_contains"),
        ("prospective-path-only", "src_id == ids[j] || anchor_paths_match", "false || anchor_paths_match"),
    ):
        add(name, guard, old, new, guard_tests)
        add(name + "-proof", guard, old, new, gate, "verification results::")
    add("launch-nlink-skip", SRC + "mount.rs", "    config_dir.check_authority_links()?;", "    // mutant: skipped authority link check", rust("mount"))
    add("prospective-skip", guard,
        "                let (anchor, suffix) = resolve(&root, Walk::ProvisionedSource)?.end;",
        "                return Ok(());\n                let (anchor, suffix) = resolve(&root, Walk::ProvisionedSource)?.end;", guard_tests)
    add("guard-skip-core", SRC + "mount.rs", "        config_dir.check_core_bind(source)?;", "        let _ = source;", rust("mount"))
    add("relative-unanchored", guard, "        cwd.join(path)", "        path.to_path_buf()", guard_tests)
    add("guard-ro-too", SRC + "mount.rs", "!m.is_readonly() && !m.is_fork()", "!m.is_fork()", rust("mount"))
    add("authority-home-from-pi", SRC + "run.rs",
        '    let authority_home = config::host_home_dir().context("locating the authority home")?;',
        "    let authority_home = host_home.clone();", rust("run::tests::raw_authority_home_selected"))
    add("account-home-dropped", SRC + "mount.rs",
        "        .chain(context.account_home.iter())",
        "", rust("mount"))
    persisted = SRC + "config_authority.rs"
    grant_old = """    match cli.0 {
        Some(c) => ResolvedGrant { enabled: c, source: GrantSource::Cli },
        None => match saved.0 {
            Some(u) => ResolvedGrant { enabled: u, source: GrantSource::UserConfig },
            None => ResolvedGrant { enabled: false, source: GrantSource::Default },
        },
    }"""
    grant_new = """    match saved.0 {
        Some(u) => ResolvedGrant { enabled: u, source: GrantSource::UserConfig },
        None => match cli.0 {
            Some(c) => ResolvedGrant { enabled: c, source: GrantSource::Cli },
            None => ResolvedGrant { enabled: false, source: GrantSource::Default },
        },
    }"""
    for name, path, old, new, tests in (
        ("saved-beats-cli", EGRESS, grant_old, grant_new, egress),
        ("directory-owner-ignored", persisted, "if dir.uid != euid { return Some(AuthorityRefusal::DirOwner); }", "if false { return Some(AuthorityRefusal::DirOwner); }", rust("config_authority::tests")),
        ("directory-writable-ignored", persisted, "if dir.mode & 0o022 != 0 { return Some(AuthorityRefusal::DirWritable); }", "if false { return Some(AuthorityRefusal::DirWritable); }", rust("config_authority::tests")),
        ("file-owner-ignored", persisted, "if f.uid != euid { Some(AuthorityRefusal::FileOwner) }", "if false { Some(AuthorityRefusal::FileOwner) }", rust("config_authority::tests")),
        ("symlink-trusted", persisted, "Reached::ThroughSymlink => Some(AuthorityRefusal::ThroughSymlink)", "Reached::ThroughSymlink => None", rust("config_authority::tests")),
        ("links-ignored", persisted, "else if !authority_file_singly_linked(f.nlink) { Some(AuthorityRefusal::FileLinks(f.nlink)) }", "else if false { Some(AuthorityRefusal::FileLinks(f.nlink)) }", rust("config_authority::tests")),
        ("mask-other-only", persisted, "else if f.mode & 0o022 != 0", "else if f.mode & 0o002 != 0", rust("config_authority::tests")),
    ):
        add(name, path, old, new, tests)
        add(name + "-proof", path, old, new, gate, "verification results::")
    # Presence, not contents, is what makes a user file authority-bearing
    # (ADR-0040/0046). The anchor is the kernel body, never its `ensures`
    # clause, so replacing it cannot weaken the contract it is checked against.
    # #397 widened the disjunction from two fields to three, so the anchor and its
    # test both moved: the body now names `mount_sets` too.
    authority_or = "if t.network { true } else { t.mounts || t.mount_sets }"
    authority_or_mutant = "if t.network { t.mounts || t.mount_sets } else { false }"
    add("config-mounts-authority-or", persisted, authority_or, authority_or_mutant,
        rust("authority_required_matches_the_eight_rows"))
    add("config-mounts-authority-or-proof", persisted, authority_or, authority_or_mutant,
        gate, "verification results::")
    # The merge/refuse rule decides whether a declaration is silently dropped
    # (a last-wins override) or refused, now that config and argv claims meet.
    # Both anchors are kernel *bodies*; their `ensures` clauses spell the same
    # rules in a shape the bodies never use, so the `-proof` twins still catch a
    # mutated implementation rather than a weakened contract.
    mounts = SRC + "mount.rs"
    conflict_merged = "else { ClaimDecision::Conflict }"
    conflict_merged_mutant = "else { ClaimDecision::Merge }"
    add("config-mounts-claim-conflict-merged", mounts, conflict_merged, conflict_merged_mutant,
        rust("claim_decision_matches_the_oracle_table"))
    add("config-mounts-claim-conflict-merged-proof", mounts, conflict_merged, conflict_merged_mutant,
        gate, "verification results::")
    # `declarations_equivalent` is the merge half of the same rule, and every one
    # of its six facts is load-bearing. `exclusions` is the fact a reader is
    # least likely to notice: dropping it merges two fork declarations that
    # differ only in what they leave out of the copy, so one declaration
    # disappears and its exclusions silently stop applying. The anchor is the
    # kernel *body*; its `ensures` spells the same conjunction in a shape the
    # body never uses, so the `-proof` twin catches the mutated body rather than
    # a weakened contract.
    equivalent_exclusions = "    if !f.fork { return false; }\n    f.exclusions"
    equivalent_exclusions_mutant = "    if !f.fork { return false; }\n    true"
    add("config-mounts-equivalent-exclusions-dropped", mounts, equivalent_exclusions,
        equivalent_exclusions_mutant, rust("declarations_equivalent_matches_the_oracle_table"))
    add("config-mounts-equivalent-exclusions-dropped-proof", mounts, equivalent_exclusions,
        equivalent_exclusions_mutant, gate, "verification results::")
    # The launch half of the same rule: a config/argv pair that disagrees must
    # refuse, so the mutant's silent merge is observable as a launch that
    # reaches builder wiring instead of naming both origins.
    add("config-mounts-claim-conflict-merged-launch", mounts, conflict_merged,
        conflict_merged_mutant,
        rust("config_and_cli_conflicts_are_refused_naming_both", MOUNTS))
    # `~` may expand for user `mounts` and never for `--mount`: the shell already
    # expanded argv, so a quoted `~/x` must stay "must be absolute".
    home_on_cli = "else if home == HomeExpansion::Enabled && bytes.len() >= 2"
    home_on_cli_mutant = "else if bytes.len() >= 2"
    add("config-mounts-home-expanded-on-cli", mounts, home_on_cli, home_on_cli_mutant,
        rust("host_spelling_matches_the_oracle_table"))
    add("config-mounts-home-expanded-on-cli-proof", mounts, home_on_cli, home_on_cli_mutant,
        gate, "verification results::")
    # A mount that shadows a declared `persist` link is refused inside
    # `mount::prepare`, ahead of `prepare_forks` (ADR-0046 Decision 6). Skipping
    # the check does not merely move a message: the plan publishes a fork copy of
    # the user's directory for a launch that is then refused. Both rows kill on
    # "a fork store exists after a refusal", the unit one through `prepare`'s
    # absent store path and the launch one through the whole-process snapshot.
    persist_skipped = "    context.persisted_home.refuse_conflicts(&destinations)?;"
    persist_skipped_mutant = "    let _ = &destinations;"
    add("config-mounts-persist-check-skipped", mounts, persist_skipped, persist_skipped_mutant,
        rust("persist_collision_refuses_before_any_fork_store"))
    # The launch row kills through the config route: the declaration that
    # causes the collision *and* the fork are both in the user file, so this is
    # the path a user actually hits (the two CLI-only rows above stay as the
    # declaration-source-independent red tests they were written as).
    add("config-mounts-persist-check-skipped-launch", mounts, persist_skipped,
        persist_skipped_mutant,
        rust("a_config_fork_shadowing_a_persist_path_is_refused_before_any_fork", MOUNTS))
    # `--no-config-mounts` withholds the user config's declarations and nothing
    # else (ADR-0046 Decision 5). The anchor is the kernel *body*: its `ensures`
    # spells the same rule as `r == (f.declared && !f.suppressed)`, a shape the
    # body never uses, so the `-proof` twin still catches a mutated body.
    selection = SRC + "mount_selection.rs"
    opt_out = "if f.suppressed { false } else { f.declared }"
    opt_out_mutant = "if false { false } else { f.declared }"
    add("config-mounts-opt-out-ignored", selection, opt_out, opt_out_mutant,
        rust("config_mounts_selected_matches_the_four_rows"))
    add("config-mounts-opt-out-ignored-proof", selection, opt_out, opt_out_mutant,
        gate, "verification results::")
    add("config-mounts-opt-out-ignored-launch", selection, opt_out, opt_out_mutant,
        rust("opt_out_keeps_cli_core_and_persisted_paths", MOUNTS))
    add("user-allowances-dropped", EGRESS,
        "for entry in user_entries.iter().chain(&cli_entries) {",
        "for entry in cli_entries.iter() {", rust("user_network_table_reaches_the_sandbox_policy", LAUNCH))
    verify_arm = ('FileTierKind::User => config_authority::verify(&read, triggers)\n'
                  '            .map_err(|error| anyhow!("config: {}: {error}", '
                  'crate::one_line::quoted_path(path)))?,')
    add("verify-always-skipped", SRC + "config.rs", verify_arm,
        'FileTierKind::User => None,', rust("unsafe_user_network_is_refused_before_launch_state", LAUNCH))
    # A present `mounts` key makes a user file authority-bearing, empty list
    # included: the trigger reads the *presence* of the field, so both mutants
    # below keep the field but drop its effect, and a symlinked `mounts = []`
    # file then loads through the compatibility path meant for tools-only files.
    mounts_present = "        mounts: raw.mounts.is_some(),\n        mount_sets: raw.mount_sets.is_some(),\n    };"
    mounts_absent_mutant = "        mounts: false,\n        mount_sets: raw.mount_sets.is_some(),\n    };"
    mounts_nonempty_mutant = (
        "        mounts: raw.mounts.as_ref().and_then(toml::Value::as_array).is_some_and(|a| !a.is_empty()),\n        mount_sets: raw.mount_sets.is_some(),\n    };")
    add("config-mounts-presence-ignored", SRC + "config.rs", mounts_present,
        mounts_absent_mutant, rust("present_empty_mounts_through_a_symlink_is_refused"))
    add("config-mounts-presence-ignored-launch", SRC + "config.rs", mounts_present,
        mounts_absent_mutant, rust("unsafe_user_mounts_are_refused_before_launch_state", MOUNTS))
    add("config-mounts-empty-unverified", SRC + "config.rs", mounts_present,
        mounts_nonempty_mutant, rust("present_empty_mounts_through_a_symlink_is_refused"))
    add("config-mounts-empty-unverified-launch", SRC + "config.rs", mounts_present,
        mounts_nonempty_mutant, rust("empty_mounts_still_requires_a_verified_file", MOUNTS))
    add("config-mounts-verify-skipped-launch", SRC + "config.rs", verify_arm,
        'FileTierKind::User => None,', rust("unsafe_user_mounts_are_refused_before_launch_state", MOUNTS))
    # The project tier may not declare mounts at all (ADR-0046 is user-scope), so
    # the refusal is a boundary in its own right: without it a project checkout
    # would hand every launch of it a host bind.
    add("config-mounts-project-mounts-accepted", SRC + "config.rs",
        "    if raw.mounts.is_some() {\n        return Err(mounts_refusal(path, RefusingTier::Project));\n    }",
        "    if false {\n        return Err(mounts_refusal(path, RefusingTier::Project));\n    }",
        rust("project_mounts_are_refused_even_when_empty"))
    # -- Named mount sets (#397) -------------------------------------------------
    # Every replacement below keeps all three `AuthorityTriggers` fields, so a
    # control can never pass (or fail) on a missing-struct-field compile error
    # instead of on the behaviour it names.
    sets_source = SRC + "config_mounts/sets.rs"
    sets_module = SRC + "config_mounts.rs"
    presence_sets_absent = "        mounts: raw.mounts.is_some(),\n        mount_sets: false,\n    };"
    add("mount-sets-presence-ignored", SRC + "config.rs", mounts_present,
        presence_sets_absent, rust("mount_sets_presence_requires_a_verified_file"))
    add("mount-sets-presence-ignored-launch", SRC + "config.rs", mounts_present,
        presence_sets_absent,
        rust("named_mount_sets_unsafe_file_is_refused_before_launch_state", MOUNTS))
    # Declaring a set is user-scope only; accepting a project table would let a
    # checkout plant filesystem access for every launch of it.
    project_sets = ('    if raw.mount_sets.is_some() {\n'
                    '        return Err(mount_sets_refusal(path, RefusingTier::Project));\n'
                    '    }')
    add("mount-sets-project-accepted", SRC + "config.rs", project_sets,
        project_sets.replace("if raw.mount_sets.is_some()", "if false"),
        rust("project_mount_sets_are_refused_even_when_empty"))
    # Every declared closure is validated, unused sets included (decision A2). A
    # cycle edge treated as "already seen" is the smallest way to skip that: the
    # walk completes and nothing is refused.
    cycle_arm = ('                VisitDecision::Cycle => {\n'
                 '                    return Err(UserMountsError::Cycle {\n'
                 '                        site: EntrySite::SetEntry {\n'
                 '                            definition: set.0,\n'
                 '                            index,\n'
                 '                        },\n'
                 '                    });\n'
                 '                }')
    add("mount-sets-cycle-skipped", sets_source, cycle_arm, "                VisitDecision::Cycle => {}", rust("reference_errors_are_named_by_site"))
    add("mount-sets-cycle-skipped-launch", sets_source, cycle_arm,
        "                VisitDecision::Cycle => {}",
        rust("named_mount_sets_reference_errors_refuse_load_under_every_option", MOUNTS))
    # An unknown reference must be refused at load, in an unused set too.
    unknown_set = ('                        None => return Err(UserMountsError::UnknownSet { site }),\n'
                   '                    },\n'
                   '                    Err(SelectorError::Direct(error)) => {')
    add("mount-sets-unknown-set-skipped", sets_source, unknown_set,
        ('                        None => Entry::Reference(SetId(0)),\n'
         '                    },\n'
         '                    Err(SelectorError::Direct(error)) => {'),
        rust("reference_errors_are_named_by_site"))
    # `--no-config-mounts` removes the defaults, never an explicit name.
    explicit = "                let selected = explicit_set(user, &name)?;"
    explicit_mutant = ("                let selected = if policy.suppressed() { Vec::new() } else { "
                       "explicit_set(user, &name)? };")
    add("mount-sets-opt-out-drops-explicit-names", selection, explicit, explicit_mutant,
        rust("explicit_set_names_survive_the_opt_out"))
    add("mount-sets-opt-out-drops-explicit-names-launch", selection, explicit, explicit_mutant,
        rust("named_mount_sets_opt_out_keeps_an_explicit_selection", MOUNTS))
    # Each direct leaf's origin holds one *reference* to its set's name: copying
    # the key per leaf multiplies retained provenance by the leaf count, below both
    # the file-size and leaf-visit bounds. The regression observes the allocation
    # itself (`Arc::ptr_eq` across leaves and across a model clone).
    shared_name = "                            set: Arc::clone(&shared[definition]),"
    add("mount-sets-name-copied-per-leaf", sets_source, shared_name,
        "                            set: Arc::from(names[definition].as_str()),",
        rust("mount_set_key_is_stored_once_across_leaves_and_clones"))
    # The differential's left-hand side is the real `mount::claim`, so a fact its
    # fixtures never isolate is a fact the indexed adapter can ignore without
    # disagreeing. Each equivalence fact needs one row where that fact alone
    # differs: with only the fork-vs-read-only pair, an adapter that drops `fork`
    # still agrees on every fixture (read-only differs in that pair as well). The
    # anchor is the adapter's call to the shared kernel, replaced by a hand-rolled
    # conjunction that leaves fork out.
    equivalent_call = ("            equivalent: same_declaration(&leaves[first.0].mount, "
                       "&leaves[candidate.0].mount),")
    equivalent_ignores_fork = (
        "            equivalent: { let a = &leaves[first.0].mount; "
        "let b = &leaves[candidate.0].mount; "
        "a.source_spelling == b.source_spelling && a.host == b.host "
        "&& matches!(a.policy, crate::mount::MountPolicy::BindReadOnly { .. }) "
        "== matches!(b.policy, crate::mount::MountPolicy::BindReadOnly { .. }) "
        "&& matches!(a.policy, crate::mount::MountPolicy::BindReadOnly { follow_links: true } "
        "| crate::mount::MountPolicy::Fork { follow_links: true }) "
        "== matches!(b.policy, crate::mount::MountPolicy::BindReadOnly { follow_links: true } "
        "| crate::mount::MountPolicy::Fork { follow_links: true }) "
        "&& a.exclusions == b.exclusions },")
    add("mount-sets-claim-ignores-fork", sets_source, equivalent_call,
        equivalent_ignores_fork, rust("mount_set_indexed_claim_matches_claim"))
    # The selector precedence is what keeps the two grammars apart. The literal
    # "absolute path classified as a name" mutation cannot exist — decision A1
    # excludes `/` and `~`, so no path spelling can parse as a name — so the
    # load-bearing direction is the reverse: a valid name classified as a path.
    selector_body = "    if f.path_spelling {\n        SelectorKind::Path"
    selector_mutant = "    if f.name_spelling {\n        SelectorKind::Path"
    add("mount-sets-name-classified-as-path", sets_module, selector_body, selector_mutant,
        rust("selector_classification_matches_the_table"))
    add("mount-sets-name-classified-as-path-proof", sets_module, selector_body,
        selector_mutant, gate, "verification results::")
    # The expansion budget's polarity: one more leaf admitted past the limit turns
    # a refused file into a hang. The anchor is the kernel *body*; its `ensures`
    # spells `<` in a shape the body never uses, so the `-proof` twin still bites.
    budget_body = "{\n    used < MAX_MOUNT_SET_EXPANSION_WORK\n}"
    budget_mutant = "{\n    used <= MAX_MOUNT_SET_EXPANSION_WORK\n}"
    add("mount-sets-budget-off-by-one", sets_source, budget_body, budget_mutant,
        rust("mount_set_expansion_work_boundary"))
    add("mount-sets-budget-off-by-one-proof", sets_source, budget_body, budget_mutant,
        gate, "verification results::")
    add("descriptor-reopen", SRC + "host_paths.rs", "            after_open();",
        "            after_open(); drop(fd); let fd = rfs::open(path, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())?;",
        rust("noting_symlink_takes_bytes_and_facts_from_the_opened_descriptor"))
    add("builtin-network-accepted", SRC + "config.rs",
        "return Err(network_refusal(table, path, RefusingTier::BuiltIn));", "let _ = table;",
        rust("builtin_network_table_is_refused_naming_setting_and_tier"))
    return controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--check-anchors", action="store_true")
    parser.add_argument("--only", help="substring of mutation name")
    args = parser.parse_args()
    controls = matrix()
    if args.check_anchors:
        for name, path, old, _, _, _ in controls:
            expected = 2 if name in ("port-value", "port-value-proof") else 1
            matches = (ROOT / path).read_text().count(old)
            if matches != expected:
                raise RuntimeError(f"stale or ambiguous mutation anchor: {name}: {matches}, expected {expected}")
        print(f"PASS: {len(controls)} mutation anchors")
        return 0
    if args.evidence is None:
        parser.error("--evidence is required unless --check-anchors is used")
    evidence = args.evidence.resolve()
    # Refuse to reuse a non-empty directory: it would overwrite per-row logs and
    # leave stale rows beside the fresh results.json.
    if evidence.exists() and any(evidence.iterdir()):
        parser.error(
            f"--evidence {evidence} is not empty; use a fresh directory so runs cannot be mixed"
        )
    selected = [row for row in controls if not args.only or args.only in row[0]]
    if not selected:
        parser.error(f"--only {args.only!r} matched no mutation")
    # Fail closed before spending ~40 minutes: the -proof rows need the pinned
    # Verus release, and a missing toolchain would otherwise land as a bare FAIL
    # indistinguishable from a surviving mutant.
    if any(name.endswith("-proof") for name, *_ in selected) and shutil.which("cargo-verus") is None:
        print(
            "FAIL: cargo-verus is not on PATH; the selected -proof rows need the "
            "pinned Verus release on PATH",
            file=sys.stderr,
        )
        return 2
    # Cargo does not hold its target lock while a test binary runs, so two runs
    # sharing a target dir could rebuild or delete the binary the other is
    # executing -- a false result of exactly the kind this harness rejects.
    lock_dir = HARNESS_TARGET.parent
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / "run.lock"
    with lock_path.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"FAIL: another egress mutation run holds {lock_path}", file=sys.stderr)
            return 2
        return run_matrix(selected, evidence)


def run_matrix(selected, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    env["CARGO_TARGET_DIR"] = str(HARNESS_TARGET)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="egress-mutations-", dir=TARGET) as temp:
        copy = Path(temp)
        package = (copy / "crates/agent-vm/Cargo.toml").resolve()
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
        for name in tracked:
            if not name or name.startswith("vendor/"):
                continue
            source, dest = ROOT / name, copy / name
            if source.is_file():
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, dest)
        (copy / "vendor").symlink_to(ROOT / "vendor", target_is_directory=True)
        # Cold dependencies are a build cost, not a control's verdict: warm each
        # target dir once, outside every per-control timeout.
        warmups = []
        if any(command[0] == "cargo" for _, _, _, _, command, _ in selected):
            warmups.append(("cargo", WARMUP, HARNESS_TARGET))
        if any(name.endswith("-proof") for name, *_ in selected):
            warmups.append(("verus", VERUS_WARMUP, VERUS_TARGET))
        for label, command, target_dir in warmups:
            env["CARGO_TARGET_DIR"] = str(target_dir)
            warm_started = time.monotonic()
            warmup = subprocess.run(command, cwd=copy, env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=WARMUP_TIMEOUT)
            (evidence / f"warmup-{label}.log").write_bytes(warmup.stdout)
            print(json.dumps({"warmup": label, "command": command, "CARGO_TARGET_DIR": env["CARGO_TARGET_DIR"],
                              "exit": warmup.returncode, "seconds": round(time.monotonic() - warm_started, 1)}), flush=True)
            if warmup.returncode != 0:
                print(
                    f"FAIL: the disposable copy's {label} warm-up failed; see {evidence / f'warmup-{label}.log'}",
                    file=sys.stderr,
                )
                return 1
        env["CARGO_TARGET_DIR"] = str(HARNESS_TARGET)
        results = []
        for name, path, old, new, command, marker in selected:
            file = copy / path
            original = file.read_text()
            matches = 2 if name in ("port-value", "port-value-proof") else 1
            if original.count(old) != matches:
                raise RuntimeError(f"stale or ambiguous mutation anchor: {name}")
            # The port-value mutation intentionally changes bracket/bare paths.
            file.write_text(original.replace(old, new))
            log = evidence / (name + ".log")
            env["CARGO_TARGET_DIR"] = str(VERUS_TARGET) if name.endswith("-proof") else str(HARNESS_TARGET)
            row_started = time.monotonic()
            status, reason, exit_code = None, None, None
            try:
                with log.open("w") as out:
                    out.write(json.dumps({"cwd": str(copy), "command": command, "CARGO_TARGET_DIR": env["CARGO_TARGET_DIR"]}) + "\n")
                    out.flush()
                    if command[0] == "cargo":
                        # The mutated package must be rebuilt from these sources.
                        # Never trust a fingerprint this run did not produce.
                        clean = subprocess.run(CLEAN_PACKAGE, cwd=copy, env=env, timeout=CONTROL_TIMEOUT,
                                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        out.write(clean.stdout.decode(errors="replace"))
                        out.write(f"# {CLEAN_PACKAGE[0]} {CLEAN_PACKAGE[1]} {CLEAN_PACKAGE[2]} {CLEAN_PACKAGE[3]}: exit {clean.returncode}\n")
                        out.flush()
                        if clean.returncode != 0:
                            raise RuntimeError("cargo clean -p agent-vm failed; the mutation might not be rebuilt")
                    run = subprocess.run(command, cwd=copy, env=env, stdout=out, stderr=subprocess.STDOUT, timeout=CONTROL_TIMEOUT)
                exit_code = run.returncode
                status, reason = outcome(name, command, marker, exit_code, log.read_text(), package,
                                         mutation_target(path))
            except subprocess.TimeoutExpired:
                status, reason = "FAIL", "timeout is not fault detection"
            except RuntimeError as failure:
                status, reason = "FAIL", str(failure)
            finally:
                file.write_text(original)
            result = {"mutation": name, "command": command, "status": status, "exit": exit_code,
                      "seconds": round(time.monotonic() - row_started, 1), "evidence": str(log)}
            if reason:
                result["reason"] = reason
            results.append(result)
            print(json.dumps(result), flush=True)
            (evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        passed = sum(1 for result in results if result["status"] == "PASS")
        print(f"total: {passed}/{len(results)} controls PASS in {round(time.monotonic() - started, 1)}s", flush=True)
        return 0 if results and passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
