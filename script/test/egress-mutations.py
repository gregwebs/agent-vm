#!/usr/bin/env python3
"""Fault-detection controls in disposable source copies; never edit kernels in place.

Run from any cwd. Logs and the exact command ledger go under --evidence.
A compiler error, timeout, or missing test is not a killed mutation.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SRC = "crates/agent-vm/src/"
TEST = "crates/agent-vm/tests/config_launch_driven.rs"
EGRESS = SRC + "egress_policy.rs"
NETWORK = SRC + "network.rs"
FIXTURE = "script/test/lib/egress-fixtures.py"
PROBE = "script/test/fixtures/egress-probe.sh"


def rust(pattern, integration=False):
    return ["cargo", "test", "--locked", "-p", "agent-vm", *(["--test", "config_launch_driven"] if integration else ["--bin", "agent-vm"]), pattern]


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
        add(name, EGRESS, old, new, egress)
        add(name + "-proof", EGRESS, old, new, gate, "verification results::")
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
    add("early-return-g1", NETWORK, "let policy = self.egress.policy();", early, rust("default_tools_launch_with_their_declared_provisioning", True))
    add("early-return-g2", NETWORK, "let policy = self.egress.policy();", early, rust("a_zero_provisioning_launch_boots_with_no_tls_overlay", True))
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
    zero = rust("a_zero_provisioning_launch_boots_with_no_tls_overlay", True)
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
        for prefix, command in (("zero-", zero), ("g1-", rust("default_tools_launch_with_their_declared_provisioning", True))):
            add(prefix + name, TEST,
                'fn assert_default_deny_zero_provision_network(network: &serde_json::Value, context: &str) {',
                'fn assert_default_deny_zero_provision_network(network: &serde_json::Value, context: &str) {\n    let mut changed = network.clone();\n    let network = &mut changed;\n    ' + injection, command)
    add("overlay-equal-length", SRC + "credential_injection.rs",
        "let base_ports = intercepted_ports_of(&network)?;",
        'let base_ports = intercepted_ports_of(&network)?;\n        network = network.policy(serde_json::from_value(serde_json::json!({"default_egress":"deny","default_ingress":"allow","rules": [\n' +
        ','.join(['{"direction":"egress","destination":{"group":"public"},"protocols":[],"ports":[],"action":"allow"}'] * 4) +
        ']})).unwrap());', rust("credential_overlay_preserves_base_network_plan"))
    g4 = rust("rejected_allowance_is_refused_before_launch_state_is_created", True)
    for name, suffix in (("project", ""), ("mounts", ".mounts"), ("secrets", ".secrets")):
        add("preparse-" + name, SRC + "run.rs",
            "\n    let network_plan = crate::network::Plan::from_args(args.network)?;",
            '\n    let early = ProjectSession::for_cwd()?;\n    std::fs::create_dir_all(' +
            ('&early.state_dir' if not suffix else 'early.state_dir.with_extension("' + suffix[1:] + '")') +
            ')?;\n    let network_plan = crate::network::Plan::from_args(args.network)?;', g4)
    add("valid-no-fork", TEST,
        '&["--mount", &mount, "--allow-egress", "api.example.com"],',
        '&["--allow-egress", "api.example.com"],', g4)
    add("valid-no-credential", SRC + "run.rs", '.context("snapshotting host credentials")?;', '.context("snapshotting host credentials")?;\n    if let Some(file) = &creds.anthropic_token_file { std::fs::remove_file(file)?; }', g4)
    host = ["python3", "script/test/lib/egress-supervisor-contract.py"]
    for name, old, new in (
        ("shell-argv",
         '    if case.guest:\n        extra = hostname_extra(case, values, lan2 or DEFAULT_LAN2, hnc_step) if hostname_tier(case.case) else (\n            answer if case.case == "I1a" else rebind if case.case == "RB1" else "")\n        argv.extend(("--", case.case, ident, lan, case.variant, extra))',
         '    if case.guest:\n        argv[1] = "shell"\n        extra = hostname_extra(case, values, lan2 or DEFAULT_LAN2, hnc_step) if hostname_tier(case.case) else (\n            answer if case.case == "I1a" else rebind if case.case == "RB1" else "")\n        argv.extend(("--", "-c", case.case, ident, lan, case.variant, extra))'),
        ("credential-tool", 'argv = [binary, case.tool,', 'argv = [binary, "egressprobe",'),
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
    return controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--only", help="substring of mutation name")
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    # Reuse compiled dependencies without ever sharing live source files.
    env["CARGO_TARGET_DIR"] = str(ROOT / "target")
    with tempfile.TemporaryDirectory(prefix="egress-mutations-", dir=ROOT / "target") as temp:
        copy = Path(temp)
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
        for name in tracked:
            if not name or name.startswith("vendor/"):
                continue
            source, dest = ROOT / name, copy / name
            if source.is_file():
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, dest)
        (copy / "vendor").symlink_to(ROOT / "vendor", target_is_directory=True)
        results = []
        for name, path, old, new, command, marker in matrix():
            if args.only and args.only not in name:
                continue
            file = copy / path
            original = file.read_text()
            matches = 2 if name in ("port-value", "port-value-proof") else 1
            if original.count(old) != matches:
                raise RuntimeError(f"stale or ambiguous mutation anchor: {name}")
            # The port-value mutation intentionally changes bracket/bare paths.
            file.write_text(original.replace(old, new))
            log = evidence / (name + ".log")
            env["CARGO_TARGET_DIR"] = str(ROOT / "target" / "verus") if name.endswith("-proof") else str(ROOT / "target")
            try:
                with log.open("w") as out:
                    out.write(json.dumps({"cwd": str(copy), "command": command, "CARGO_TARGET_DIR": env["CARGO_TARGET_DIR"]}) + "\n")
                    out.flush()
                    run = subprocess.run(command, cwd=copy, env=env, stdout=out, stderr=subprocess.STDOUT, timeout=240)
                text = log.read_text()
                killed = run.returncode != 0 and marker in text
                if name.endswith("-proof"):
                    killed = killed and "0 errors" not in text.split("Checking agent-vm")[-1] and "error:" in text
                result = {"mutation": name, "command": command, "status": "PASS" if killed else "FAIL", "exit": run.returncode, "evidence": str(log)}
            except subprocess.TimeoutExpired:
                result = {"mutation": name, "command": command, "status": "FAIL", "reason": "timeout is not fault detection", "evidence": str(log)}
            finally:
                file.write_text(original)
            results.append(result)
            print(json.dumps(result), flush=True)
            (evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        return 0 if results and all(r["status"] == "PASS" for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
