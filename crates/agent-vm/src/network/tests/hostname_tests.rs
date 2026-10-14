//! Hostname-launch unit tests, a submodule of `network::tests` so the
//! surrounding helpers (`args`, `configured_network`, `notice_output`) are in
//! scope.

use super::*;

#[tokio::test]
async fn hostname_launch_keeps_strict_and_intercepts_every_domain_port() {
    let mut input = args();
    input.allow_egress = vec![
        "api.example.com".into(),
        "tcp://git.example.com:8443".into(),
        "10.0.0.5".into(),
    ];
    let network = configured_network(input, "hostname-ports").await;
    assert_eq!(network["tls"]["enabled"], true);
    assert_eq!(network["strict"], true);
    assert_eq!(
        network["tls"]["intercepted_ports"],
        serde_json::json!([443, 8443])
    );
    assert_eq!(
        network["policy"]["rules"],
        serde_json::json!([
            {"direction":"egress","destination":{"cidr":"10.0.0.5/32"},"protocols":[],"ports":[],"action":"allow"},
            {"direction":"egress","destination":{"domain":"api.example.com"},"protocols":["tcp"],"ports":[{"start":443,"end":443},{"start":8443,"end":8443}],"action":"allow"},
            {"direction":"egress","destination":{"domain":"git.example.com"},"protocols":["tcp"],"ports":[{"start":8443,"end":8443}],"action":"allow"}
        ])
    );
    let mut input = args();
    input.allow_egress = vec!["build".into()];
    let network = configured_network(input, "hostname-single").await;
    assert_eq!(network["tls"]["enabled"], true);
    assert_eq!(
        network["tls"]["intercepted_ports"],
        serde_json::json!([443])
    );
    assert!(policy_groups(&network).is_empty());
}
#[test]
fn hostname_proxy_selection_mirrors_the_host_connector() {
    let cases: &[(&[(&str, &str)], bool)] = &[
        (&[("http_proxy", "http://user:pw@proxy.example:3128")], true),
        (&[("HTTPS_PROXY", "proxy.example:3128")], true),
        (&[("ALL_PROXY", "http://[::1]:3128")], true),
        (
            &[
                ("HTTPS_PROXY", "socks5://p:1080"),
                ("ALL_PROXY", "http://p:3128"),
            ],
            true,
        ),
        (
            &[
                ("HTTP_PROXY", "http://p:3128"),
                ("NO_PROXY", "api.example.com"),
            ],
            true,
        ),
        (
            &[
                ("https_proxy", "socks5://p:1080"),
                ("HTTPS_PROXY", "http://p:3128"),
            ],
            false,
        ),
        (&[("HTTPS_PROXY", "socks5://p:1080")], false),
        (&[("HTTP_PROXY", "http://p:0")], false),
        (&[("HTTP_PROXY", "http://p q:1")], false),
        (&[("HTTP_PROXY", "https://p:3128")], false),
        (&[("HTTP_PROXY", "http://p:3128"), ("NO_PROXY", "*")], false),
        (
            &[("HTTP_PROXY", "HTTP://p:3128"), ("no_proxy", "p, * other")],
            false,
        ),
        (&[], false),
    ];
    for (values, refused) in cases {
        let lookup = |var: &str| {
            values
                .iter()
                .find_map(|(key, value)| (*key == var).then(|| (*value).to_owned()))
        };
        let mut input = args();
        input.allow_egress = vec!["api.example.com".into()];
        let result = Plan::from_args_with_proxy_lookup(input, None, lookup);
        if *refused {
            let error = result.err().unwrap().to_string();
            assert_eq!(error, HOSTNAME_PROXY_REFUSAL);
            for secret in ["user", "pw", "proxy.example", "api.example.com"] {
                assert!(!error.contains(secret));
            }
        } else {
            assert!(result.is_ok(), "{values:?}");
        }
    }
}
#[test]
fn proxy_refusal_applies_only_to_hostname_launches() {
    for mut input in [
        args(),
        Args {
            allow_internet_egress: Some(true),
            ..args()
        },
        Args {
            allow_egress: vec!["1.1.1.1".into()],
            ..args()
        },
    ] {
        assert!(
            Plan::from_args_with_proxy_lookup(input, None, |v| (v == "http_proxy")
                .then(|| "http://p:3128".into()))
            .is_ok()
        );
        input = args();
        input.allow_egress = vec!["udp://h.example".into()];
        let error = Plan::from_args_with_proxy_lookup(input, None, |v| {
            (v == "http_proxy").then(|| "http://p:3128".into())
        })
        .err()
        .unwrap()
        .to_string();
        assert_eq!(
            error,
            format!(
                "--allow-egress #1: {}",
                crate::egress_grammar::AllowanceError::UdpHostname
            )
        );
    }
}
#[test]
fn allowance_grammar_errors_precede_the_proxy_refusal() {
    let mut input = args();
    input.allow_egress = vec!["udp://h.example".into()];
    let error = Plan::from_args_with_proxy_lookup(input, None, |v| {
        (v == "http_proxy").then(|| "http://p:3128".into())
    })
    .unwrap_err()
    .to_string();
    assert_eq!(
        error,
        format!(
            "--allow-egress #1: {}",
            crate::egress_grammar::AllowanceError::UdpHostname
        )
    );
}
#[test]
fn hostname_notice_variants_preserve_launch_order() {
    for (internet, host) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut input = args();
        input.allow_egress = vec!["build".into()];
        input.allow_internet_egress = Some(internet);
        input.allow_host = Some(host);
        let output = notice_output(input, |_| None);
        let hostname = output.find("allowing TLS to build on ports 443").unwrap();
        let intercept = output.find("==> TLS interception:").unwrap();
        let dns = output.find("==> Egress DNS:").unwrap();
        assert!(hostname < intercept && intercept < dns);
        assert_eq!(
            output.contains("only allowed hostnames resolve"),
            !internet && !host
        );
        assert_eq!(
            output.contains("arbitrary-name DNS queries authorized"),
            internet || host
        );
    }
}
