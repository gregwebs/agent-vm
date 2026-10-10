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
    g4 = rust("hostname_allowance_is_refused_before_launch_state_is_created", True)
    for name, suffix in (("project", ""), ("mounts", ".mounts"), ("secrets", ".secrets")):
        add("preparse-" + name, SRC + "run.rs",
            "\n    let network_plan = crate::network::Plan::from_args(args.network)?;",
            '\n    let early = ProjectSession::for_cwd()?;\n    std::fs::create_dir_all(' +
            ('&early.state_dir' if not suffix else 'early.state_dir.with_extension("' + suffix[1:] + '")') +
            ')?;\n    let network_plan = crate::network::Plan::from_args(args.network)?;', g4)
    add("valid-no-fork", TEST,
        '&["--mount", &mount, "--allow-egress", "10.0.0.0/8"],',
        '&["--allow-egress", "10.0.0.0/8"],', g4)
    add("valid-no-credential", SRC + "run.rs", '.context("snapshotting host credentials")?;', '.context("snapshotting host credentials")?;\n    if let Some(file) = &creds.anthropic_token_file { std::fs::remove_file(file)?; }', g4)
    host = ["python3", "script/test/lib/egress-supervisor-contract.py"]
    for name, old, new in (
        ("shell-argv", 'if case.guest:\n        argv.extend(("--", case.case, ident, lan, case.variant,', 'if case.guest:\n        argv[1] = "shell"\n        argv.extend(("--", "-c", case.case, ident, lan, case.variant,'),
        ("credential-tool", 'argv = [binary, case.tool,', 'argv = [binary, "egressprobe",'),
        ("rejection-guest", 'if case.guest:\n        argv.extend', 'if case.guest or case.case == "RJ1":\n        argv.extend'),
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
