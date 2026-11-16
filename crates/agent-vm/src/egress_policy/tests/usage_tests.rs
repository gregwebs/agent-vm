//! The launch-notice examples in `USAGE.md`, pinned byte for byte, a submodule
//! of `egress_policy::tests` so the shared helpers (`resolve_saved_with_tools`,
//! `reference_tools`, `empty_cli`, `REFERENCE_USER_FILE`) are in scope.
//!
//! Each block below is one stated launch's notice. The `==> Egress authority:`
//! header is elided in USAGE (it only names the reader's own config path); every
//! other line, in order, is the build's own bytes.

use super::*;

/// The notice as USAGE prints it: every line except the authority header.
fn notice(text: &str) -> String {
    text.lines()
        .filter(|line| !line.starts_with("==> Egress authority: "))
        .map(|line| format!("{line}\n"))
        .collect()
}

fn notice_of(authority: &EgressAuthority) -> String {
    let mut out = Vec::new();
    authority.write_notices(&mut out).unwrap();
    notice(&String::from_utf8(out).unwrap())
}

/// USAGE § Egress references: one reference, three tiers.
#[test]
fn usage_reference_examples_print_these_bytes() {
    let tools = reference_tools(&[("fetcher", &["api.example.com:443", "git.example.com:8443"])]);

    // (i) `[network] allow_egress = ["tool:fetcher"]`: persisted only, so no tag.
    let persisted =
        resolve_saved_with_tools(Default::default(), &["tool:fetcher"], empty_cli(), &tools);
    assert_eq!(
        notice_of(&persisted),
        "==> Egress policy: allowing TLS to tool:fetcher (1) on ports 443\n\
==> Egress policy: allowing TLS to tool:fetcher (1) on ports 8443\n\
==> list: agent-vm access egress\n"
    );

    // (ii) the same reference in both tiers: one line per port set, each tagged
    // with both tiers.
    let both = resolve_saved_with_tools(
        Default::default(),
        &["tool:fetcher"],
        CliEgress {
            allowances: &["tool:fetcher".into()],
            ..empty_cli()
        },
        &tools,
    );
    assert_eq!(
        notice_of(&both),
        "==> Egress policy: allowing TLS to tool:fetcher (1) on ports 443 (persisted grants and --allow-egress)\n\
==> Egress policy: allowing TLS to tool:fetcher (1) on ports 8443 (persisted grants and --allow-egress)\n\
==> list: agent-vm access egress\n"
    );

    // (iii) a CLI reference beside a bare literal: the literal keeps its own
    // name, and it widens to every intercepted port, so it gets its own line.
    let cli = resolve_saved_with_tools(
        Default::default(),
        &[],
        CliEgress {
            allowances: &["tool:fetcher".into(), "bare.example.com".into()],
            ..empty_cli()
        },
        &tools,
    );
    assert_eq!(
        notice_of(&cli),
        "==> Egress policy: allowing TLS to tool:fetcher (1) on ports 443 (--allow-egress)\n\
==> Egress policy: allowing TLS to tool:fetcher (1) on ports 8443 (--allow-egress)\n\
==> Egress policy: allowing TLS to bare.example.com on ports 443, 8443 (--allow-egress)\n\
==> list: agent-vm access egress\n"
    );
}

/// USAGE § Egress sets: the `[egress_sets]` fixture declared there.
fn usage_set_namespace() -> crate::egress_reference::EgressNamespace {
    crate::egress_reference::test_support::user_namespace(
        std::path::Path::new(REFERENCE_USER_FILE),
        &[
            ("codex", &["api.openai.com"]),
            ("claude", &["api.anthropic.com"]),
        ],
        Some(
            "corp = [\"git.corp.example\", \"tcp://registry.corp.example:8443\", \"10.0.0.5\"]\n\
             agents = [\"tool:codex\", \"tool:claude\", \"set:corp\"]\n",
        ),
    )
}

/// USAGE § Egress sets, notices: `[network] allow_egress = ["set:agents"]`, and
/// the same key naming a tool and the set that nests it.
#[test]
fn usage_set_examples_print_these_bytes() {
    let namespace = usage_set_namespace();

    // `[network] allow_egress = ["set:agents"]`: every hostname the set granted
    // is counted under the set's own name, per port set.
    let persisted =
        resolve_saved_with_tools(Default::default(), &["set:agents"], empty_cli(), &namespace);
    assert_eq!(
        notice_of(&persisted),
        "==> Egress policy: allowing 10.0.0.5/32 (persisted grants via set:agents)\n\
==> Egress policy: allowing TLS to agents (2) on ports 443\n\
==> Egress policy: allowing TLS to agents (1) on ports 443, 8443\n\
==> Egress policy: allowing TLS to agents (1) on ports 8443\n\
==> list: agent-vm access egress\n"
    );

    // `[network] allow_egress = ["tool:codex", "set:agents"]`: the name both
    // granted counts toward each, in written order.
    let cli = resolve_saved_with_tools(
        Default::default(),
        &["tool:codex", "set:agents"],
        empty_cli(),
        &namespace,
    );
    assert_eq!(
        notice_of(&cli),
        "==> Egress policy: allowing 10.0.0.5/32 (persisted grants via set:agents)\n\
==> Egress policy: allowing TLS to tool:codex (1), agents (2) on ports 443\n\
==> Egress policy: allowing TLS to agents (1) on ports 443, 8443\n\
==> Egress policy: allowing TLS to agents (1) on ports 8443\n\
==> list: agent-vm access egress\n"
    );
}
