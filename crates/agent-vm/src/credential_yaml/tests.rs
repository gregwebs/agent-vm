//! Unit tests for the credential authorization loader.
//!
//! No keychain, no launch: every case here is the file → validated set (or
//! refusal) decision. `tests/config_launch_driven.rs` covers the subprocess
//! side; the resolver decision lives in `credential_resolver.rs`.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::*;

/// A `$HOME` with a `0700` `.config/agent-vm` holding `credentials.yaml`.
struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join(USER_CONFIG_DIR_RELATIVE);
        fs::create_dir_all(&config).expect("config dir");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("chmod");
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn file(&self) -> PathBuf {
        path_under_home(self.path())
    }

    fn write(&self, body: &str) -> &Self {
        fs::write(self.file(), body).expect("write credentials.yaml");
        fs::set_permissions(self.file(), fs::Permissions::from_mode(0o600)).expect("chmod");
        self
    }

    fn write_bytes(&self, body: &[u8]) -> &Self {
        fs::write(self.file(), body).expect("write credentials.yaml");
        fs::set_permissions(self.file(), fs::Permissions::from_mode(0o600)).expect("chmod");
        self
    }

    fn load(&self) -> Result<AuthorizationSet> {
        load(self.path())
    }

    /// Write `body` and return the rendered refusal, asserting it is one.
    fn refuses(&self, body: &str) -> String {
        self.write(body);
        match self.load() {
            Ok(_) => panic!("expected a refusal, got a valid authorization set"),
            Err(error) => format!("{error}"),
        }
    }

    fn accepts(&self, body: &str) -> AuthorizationSet {
        self.write(body);
        match self.load() {
            Ok(set) => set,
            Err(error) => panic!("expected acceptance, got: {error}"),
        }
    }
}

/// A minimal valid entry for `service`, with a matching `apiKey.name`.
fn entry(service: &str) -> String {
    let env = service.replace(['-', '.'], "_").to_ascii_uppercase();
    format!(
        "  - service: {service}\n    apiKey:\n      name: {env}_KEY\n      inject:\n        - domain: api.example.com\n          header: x-api-key\n          format: \"%s\"\n"
    )
}

/// A whole one-entry file.
fn minimal(service: &str) -> String {
    format!("credentials:\n{}", entry(service))
}

fn rule(set: &AuthorizationSet, service: &str) -> InjectionRule {
    let name = ServiceName::parse(service).expect("valid service");
    let credential = set.get(&name).expect("authorized");
    credential.inject()[0].clone()
}

// ---------------------------------------------------------------------------
// AC1 / AC3: the accepted subset
// ---------------------------------------------------------------------------

#[test]
fn accepts_the_documented_api_key_subset() {
    // Every accepted shape in one file: bearer desugaring, explicit
    // header+format, explicit port, a literal `%`, multiple rules, multiple
    // entries, `required`, `proxyManaged` alone, and the alias agreeing with
    // `sentinelEnv` in both directions.
    let home = Home::new();
    let set = home.accepts(
        "\
credentials:
  - service: alpha
    description: \"a human label: never rendered\"
    required: true
    apiKey:
      name: ALPHA_KEY
      sentinelEnv: true
      inject:
        - domain: api.alpha.example
          scheme: bearer
        - domain: api2.alpha.example:8443
          header: x-api-key
          format: \"Token %s; v=100%\"
  - service: beta
    apiKey:
      name: BETA_KEY
      proxyManaged: true
      inject:
        - domain: beta.example
          header: x-beta
          format: \"%s\"
  - service: gamma
    apiKey:
      name: GAMMA_KEY
      sentinelEnv: false
      proxyManaged: false
      inject:
        - domain: gamma.example:1
          header: x-gamma
          format: \"%s\"
  - service: delta
    apiKey:
      name: DELTA_KEY
      inject:
        - domain: delta.example.
          header: x-delta
          format: \"%s\"
",
    );

    assert_eq!(set.len(), 4);
    assert_eq!(set.rules(), 5);
    assert_eq!(set.warnings().len(), 1, "only beta used the alias");

    let alpha = ServiceName::parse("alpha").unwrap();
    let alpha = set.get(&alpha).expect("alpha");
    assert!(alpha.required());
    assert!(alpha.sentinel_env());
    assert_eq!(alpha.env_name().as_str(), "ALPHA_KEY");
    // `scheme: bearer` desugars to one representation (AC1).
    assert_eq!(rule(&set, "alpha").header(), "authorization");
    assert_eq!(rule(&set, "alpha").format(), "Bearer %s");
    // An explicit port is exact; the second rule keeps its own.
    assert_eq!(alpha.inject()[1].port(), 8443);
    assert_eq!(alpha.inject()[1].format(), "Token %s; v=100%");

    let beta = set.get(&ServiceName::parse("beta").unwrap()).unwrap();
    assert!(beta.sentinel_env(), "proxyManaged means the sentinel too");
    assert!(!beta.required(), "required defaults to false");
    // `proxyManaged` alone is accepted, with a nudge toward the preferred name.
    assert_eq!(set.warnings().len(), 1);
    assert!(set.warnings()[0].contains("proxyManaged"));

    let gamma = set.get(&ServiceName::parse("gamma").unwrap()).unwrap();
    assert!(!gamma.sentinel_env());
    assert_eq!(gamma.inject()[0].port(), 1);

    // One optional trailing dot is normalized away (the runtime builder strips
    // one too, so the canonical form is idempotent under it).
    let delta = set.get(&ServiceName::parse("delta").unwrap()).unwrap();
    assert_eq!(delta.inject()[0].host(), "delta.example");
    assert_eq!(delta.inject()[0].port(), DEFAULT_HTTPS_PORT);
}

/// The spec's own canonical block (`docs/specs/credential-shielding.md:57-71`)
/// must parse. #162 stages same-*named* resolution, not parsing: an
/// `anthropic` entry has to load so the diagnostic can be about resolution.
#[test]
fn parent_spec_canonical_anthropic_block_parses_unchanged() {
    let home = Home::new();
    let set = home.accepts(
        "\
credentials:
  - service: anthropic
    required: true
    apiKey:
      name: ANTHROPIC_API_KEY
      sentinelEnv: true
      inject:
        - domain: api.anthropic.com
          header: x-api-key
          format: \"%s\"
",
    );
    let credential = set.get(&ServiceName::parse("anthropic").unwrap()).unwrap();
    assert!(credential.required());
    assert!(credential.sentinel_env());
    assert_eq!(rule(&set, "anthropic").host(), "api.anthropic.com");
    assert_eq!(rule(&set, "anthropic").port(), 443);
}

#[test]
fn empty_inputs_are_an_empty_set() {
    let home = Home::new();
    // Absent file, absent directory, empty file, and a null/empty list all mean
    // "nothing is authorized", not an error.
    let empty = load(home.path()).expect("absent file");
    assert!(empty.is_empty());

    let missing_dir = tempfile::tempdir().unwrap();
    assert!(load(missing_dir.path()).unwrap().is_empty());

    for body in [
        "",
        "   \n# only a comment\n",
        "credentials:\n",
        "credentials: []\n",
    ] {
        assert!(home.accepts(body).is_empty(), "body: {body:?}");
    }
}

/// The null/empty/absent `credentials` list must not shortcut validation of the
/// **rest** of the root mapping. `serde_json`'s `preserve_order` makes key order
/// observable, so an unsupported or unknown root key placed *before* or *after*
/// `credentials` must be refused identically (agent-vm #161 review, M2).
#[test]
fn null_or_empty_credentials_do_not_bypass_root_validation() {
    let home = Home::new();
    let credential_forms = ["credentials: null\n", "credentials: []\n", ""];
    // Every recognized-but-unsupported *entry* category can also appear as a
    // root key, and every root key other than `credentials` is unknown here.
    let root_fields = [
        "permissions: {network: ['*']}\n",
        "source: env\n",
        "oauth: {}\n",
        "unknown_field: 1\n",
    ];
    for credential_form in credential_forms {
        for field in root_fields {
            for body in [
                format!("{field}{credential_form}"),
                format!("{credential_form}{field}"),
            ] {
                let error = home.refuses(&body);
                assert!(
                    error.contains("top-level key other than `credentials`"),
                    "{body:?}: {error}"
                );
                // The offending key is never echoed.
                assert!(!error.contains("permissions"), "{body:?}: {error}");
                assert!(!error.contains("source"), "{body:?}: {error}");
                assert!(!error.contains("unknown_field"), "{body:?}: {error}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AC4: rejection by name, never a silent ignore
// ---------------------------------------------------------------------------

#[test]
fn rejects_each_unsupported_field_by_name() {
    let home = Home::new();
    // Each case adds one recognized-but-unsupported key to an otherwise valid
    // entry; the refusal must name the constant category, not fall through.
    let cases: &[(&str, &str, &str)] = &[
        ("source", "    source: env\n", "source"),
        (
            "permissions.network",
            "    permissions:\n      network: [\"api.example.com\"]\n",
            "permissions",
        ),
        ("oauth", "    oauth:\n      scopes: [x]\n", "OAuth"),
        ("basic", "    basic:\n      realm: x\n", "basic auth"),
        ("username", "    username: alice\n", "username"),
        (
            "signing",
            "    signing:\n      algorithm: hmac\n",
            "signing",
        ),
        ("query", "    query: token\n", "query string"),
        ("body", "    body: token\n", "body"),
        ("kit", "    kit: [x]\n", "kit"),
        ("hooks", "    hooks: [x]\n", "hooks"),
        ("images", "    images: [x]\n", "images"),
        ("mounts", "    mounts: [x]\n", "mounts"),
        ("ports", "    ports: [8080]\n", "ports"),
        ("composition", "    composition: {}\n", "compose"),
        ("apiKey.value", "      value: literal\n", "value"),
        ("apiKey.source", "      source: env\n", "apiKey.source"),
        ("inject.query", "          query: token\n", "query string"),
        ("inject.cookies", "          cookies: [x]\n", "cookies"),
    ];
    for (label, extra, expected) in cases {
        let body = if label.starts_with("apiKey.") {
            minimal("alpha").replace("      inject:", &format!("{extra}      inject:"))
        } else if label.starts_with("inject.") {
            minimal("alpha").replace("          format:", &format!("{extra}          format:"))
        } else {
            minimal("alpha").replace("    apiKey:", &format!("{extra}    apiKey:"))
        };
        let error = home.refuses(&body);
        assert!(
            error.contains(expected),
            "{label}: expected the refusal to name {expected:?}, got: {error}"
        );
    }

    // A field this release has never heard of is still a refusal, and its name
    // is not echoed (it could be anything, including a pasted value).
    let error =
        home.refuses(&minimal("alpha").replace("    apiKey:", "    who_knows: 1\n    apiKey:"));
    assert!(error.contains("unknown field"), "{error}");
    assert!(!error.contains("who_knows"), "{error}");
}

#[test]
fn rejects_malformed_destinations() {
    let home = Home::new();
    let cases: &[(&str, &str, &str)] = &[
        ("*.example.com", "wildcard", "wildcard"),
        ("api.example.com/path", "path", "path"),
        ("http://api.example.com", "scheme", "scheme"),
        ("user@api.example.com", "userinfo", "userinfo"),
        ("127.0.0.1", "v4 literal", "IP literal"),
        ("[::1]:443", "v6 literal", "IP literal"),
        ("ex\u{e4}mple.com", "non-ascii", "A-label"),
        ("api.example.com:0", "port zero", "between 1 and 65535"),
        ("api.example.com:70000", "port range", "between 1 and 65535"),
        (
            "api.example.com:https",
            "port not decimal",
            "decimal digits",
        ),
        ("api..example.com", "empty label", "well-formed"),
        ("-api.example.com", "leading hyphen", "well-formed"),
        (
            "api.example.com\\x7f",
            "DEL byte (YAML escape)",
            "whitespace",
        ),
        ("api.example.com?x=1", "query", "query"),
    ];
    for (domain, label, expected) in cases {
        // Quoted so YAML's own syntax (an alias `*`, a flow indicator) cannot
        // pre-empt the grammar check; the grammar is what is under test.
        let body =
            minimal("alpha").replace("domain: api.example.com", &format!("domain: \"{domain}\""));
        let error = home.refuses(&body);
        assert!(
            error.contains(expected),
            "{label} ({domain:?}): expected {expected:?}, got: {error}"
        );
    }
}

#[test]
fn rejects_malformed_headers_and_formats() {
    let home = Home::new();
    for (header, expected) in [
        ("X-Api-Key", "lowercase RFC 9110 token"),
        ("bad header", "lowercase RFC 9110 token"),
        ("x:y", "lowercase RFC 9110 token"),
        ("host", "framing or hop-by-hop"),
        ("content-length", "framing or hop-by-hop"),
    ] {
        let body = minimal("alpha").replace("header: x-api-key", &format!("header: {header}"));
        let error = home.refuses(&body);
        assert!(error.contains(expected), "{header}: {error}");
    }
    for (format, label) in [
        ("Token", "no placeholder"),
        ("%s %s", "two placeholders"),
        ("\\x7f%s", "DEL escape"),
    ] {
        let body = minimal("alpha").replace("format: \"%s\"", &format!("format: \"{format}\""));
        let error = home.refuses(&body);
        assert!(
            error.contains("exactly one `%s`") || error.contains("printable ASCII"),
            "{label}: {error}"
        );
    }
    // A raw CR inside a quoted format is refused at the file layer, so it can
    // never reach the header.
    let error = home.refuses(&minimal("alpha").replace("%s\"", "%s\r\""));
    assert!(error.contains("carriage return"), "{error}");
}

#[test]
fn bare_hostname_means_port_443_and_explicit_ports_are_exact() {
    let home = Home::new();
    let set = home.accepts(&minimal("alpha"));
    assert_eq!(rule(&set, "alpha").port(), 443);
    let set =
        home.accepts(&minimal("alpha").replace("api.example.com\n", "api.example.com:8443\n"));
    assert_eq!(rule(&set, "alpha").port(), 8443);
    // Explicit 443 is indistinguishable from the default, which is the point.
    let set = home.accepts(&minimal("alpha").replace("api.example.com\n", "api.example.com:443\n"));
    assert_eq!(rule(&set, "alpha").port(), 443);
}

#[test]
fn rejects_conflicting_sentinel_env_and_proxy_managed() {
    let home = Home::new();
    for (sentinel, proxy) in [("true", "false"), ("false", "true")] {
        let body = minimal("alpha").replace(
            "      inject:",
            &format!("      sentinelEnv: {sentinel}\n      proxyManaged: {proxy}\n      inject:"),
        );
        let error = home.refuses(&body);
        assert!(error.contains("disagree"), "{error}");
        assert!(error.contains("sentinelEnv"), "{error}");
    }
    // Agreeing values are accepted.
    for (sentinel, proxy) in [("true", "true"), ("false", "false")] {
        let body = minimal("alpha").replace(
            "      inject:",
            &format!("      sentinelEnv: {sentinel}\n      proxyManaged: {proxy}\n      inject:"),
        );
        let set = home.accepts(&body);
        let credential = set.get(&ServiceName::parse("alpha").unwrap()).unwrap();
        assert_eq!(credential.sentinel_env(), sentinel == "true");
        assert!(set.warnings().is_empty(), "the alias was not used alone");
    }
    // Strict booleans (AC3): a quoted or null boolean is a type error, not a
    // coercion.
    for value in ["\"true\"", "null", "1"] {
        let body = minimal("alpha").replace(
            "      inject:",
            &format!("      sentinelEnv: {value}\n      inject:"),
        );
        let error = home.refuses(&body);
        assert!(
            error.contains("must be `true` or `false`"),
            "sentinelEnv: {value}: {error}"
        );
    }
    let body = minimal("alpha").replace("    apiKey:", "    required: \"yes\"\n    apiKey:");
    let error = home.refuses(&body);
    assert!(
        error.contains("must be `true` or `false`"),
        "required: {error}"
    );
}

#[test]
fn rejects_duplicate_services_names_and_targets() {
    let home = Home::new();
    // Duplicate service, including a case variant (names are folded).
    let error = home.refuses(&format!(
        "credentials:\n{}{}",
        entry("alpha"),
        entry("Alpha").replace("ALPHA_KEY", "OTHER_KEY")
    ));
    assert!(error.contains("duplicates an earlier entry"), "{error}");

    // Duplicate apiKey.name across two services.
    let error = home.refuses(&format!(
        "credentials:\n{}{}",
        entry("alpha"),
        entry("beta").replace("BETA_KEY", "ALPHA_KEY")
    ));
    assert!(error.contains("guest environment variable"), "{error}");

    // Two rules on one (origin, header).
    let body = minimal("alpha").replace(
        "          format: \"%s\"\n",
        "          format: \"%s\"\n        - domain: API.example.com\n          header: x-api-key\n          format: \"Token %s\"\n",
    );
    let error = home.refuses(&body);
    assert!(error.contains("same (origin, header)"), "{error}");

    // 33 entries exceeds the runtime's cap, so it is refused here.
    let mut body = String::from("credentials:\n");
    for index in 0..MAX_AUTHORIZATIONS + 1 {
        body.push_str(&format!(
            "  - service: svc{index}\n    apiKey:\n      name: SVC{index}_KEY\n      inject:\n        - domain: api{index}.example\n          header: x-api-key\n          format: \"%s\"\n"
        ));
    }
    let error = home.refuses(&body);
    assert!(error.contains("more than 32 services"), "{error}");

    // 33 rules across entries exceeds the rule cap too.
    let mut body = String::from("credentials:\n");
    for index in 0..MAX_INJECTION_RULES / 2 + 1 {
        body.push_str(&format!(
            "  - service: svc{index}\n    apiKey:\n      name: SVC{index}_KEY\n      inject:\n        - domain: svc{index}.example\n          header: x-api-key\n          format: \"%s\"\n        - domain: svc{index}-b.example\n          header: x-api-key\n          format: \"%s\"\n"
        ));
    }
    // 17 entries × 2 rules = 34 rules, still within the 32-service cap.
    let error = home.refuses(&body);
    assert!(error.contains("more than 32 injection rules"), "{error}");

    // A missing `service`, `apiKey`, `name` or `inject` is a refusal with a
    // fix, not a default.
    for (body, expected) in [
        (
            "credentials:\n  - apiKey:\n      name: A_KEY\n      inject: [{domain: a.example, header: x-a, format: \"%s\"}]\n",
            "must set `service`",
        ),
        (
            "credentials:\n  - service: alpha\n    required: true\n",
            "must set `apiKey`",
        ),
        (
            "credentials:\n  - service: alpha\n    apiKey:\n      inject: [{domain: a.example, header: x-a, format: \"%s\"}]\n",
            "must set `name`",
        ),
        (
            "credentials:\n  - service: alpha\n    apiKey:\n      name: A_KEY\n",
            "must set `inject`",
        ),
        (
            "credentials:\n  - service: alpha\n    apiKey:\n      name: A_KEY\n      inject: []\n",
            "must not be empty",
        ),
        (
            "credentials:\n  - service: alpha\n    apiKey:\n      name: A_KEY\n      inject:\n        - domain: a.example\n          header: x-a\n",
            "`scheme: bearer` or both `header` and `format`",
        ),
        (
            "credentials:\n  - service: alpha\n    apiKey:\n      name: A_KEY\n      inject:\n        - domain: a.example\n          scheme: bearer\n          header: x-a\n          format: \"%s\"\n",
            "not both",
        ),
        (
            "credentials:\n  - service: alpha\n    apiKey:\n      name: A_KEY\n      inject:\n        - domain: a.example\n          scheme: basic\n",
            "must be `bearer`",
        ),
    ] {
        let error = home.refuses(body);
        assert!(error.contains(expected), "{body}\n→ {error}");
    }
}

#[test]
fn rejects_an_invalid_env_name() {
    let home = Home::new();
    for name in ["1KEY", "KEY-E", "", "KEY E", "MSB_X", "HOME"] {
        let body = minimal("alpha").replace("ALPHA_KEY", &format!("\"{name}\""));
        let error = home.refuses(&body);
        assert!(error.contains("apiKey.name"), "name {name:?}: {error}");
        if !name.is_empty() {
            assert!(!error.contains(name), "name {name:?} echoed: {error}");
        }
    }
}

// ---------------------------------------------------------------------------
// AC9: adversarial YAML
// ---------------------------------------------------------------------------

#[test]
fn hostile_yaml_is_rejected() {
    let home = Home::new();

    // Alias expansion (billion laughs), anchors, aliases and merge keys are all
    // refused at the guard; a merge key cannot smuggle in an unknown field.
    let billion_laughs = "\
credentials:
  - service: alpha
    apiKey: &k
      name: ALPHA_KEY
      inject:
        - domain: a.example
          header: x-a
          format: \"%s\"
  - service: beta
    apiKey:
      <<: *k
";
    let error = home.refuses(billion_laughs);
    assert!(
        error.contains("alias") || error.contains("anchor"),
        "{error}"
    );

    // A merge key with no alias is still a refusal (the merge-key policy): it
    // is the one YAML feature that could add a field the schema never saw.
    let merge_key = minimal("alpha").replace("    apiKey:", "    <<: {x: 1}\n    apiKey:");
    assert!(!home.refuses(&merge_key).is_empty());

    let anchor = minimal("alpha").replace("  - service: alpha", "  - service: &a alpha");
    assert!(home.refuses(&anchor).contains("anchor"));

    // An alias to an undefined anchor is refused by the parser itself, before
    // any event reaches the guard; either way it is a refusal.
    let alias_only = minimal("alpha").replace("api.example.com", "*missing");
    let error = home.refuses(&alias_only);
    assert!(
        error.contains("alias") || error.contains("not valid YAML"),
        "{error}"
    );

    // Directives and a second document.
    for body in [
        "%YAML 1.1\n---\ncredentials: []\n",
        "%TAG !e! tag:example.com,2000:\n---\ncredentials: []\n",
    ] {
        assert!(home.refuses(body).contains("directive"), "{body}");
    }
    let two_docs = format!("{}---\ncredentials: []\n", minimal("alpha"));
    assert!(
        home.refuses(&two_docs)
            .contains("more than one YAML document")
    );

    // Explicit tags, in every position that could carry one.
    for body in [
        minimal("alpha").replace("  - service: alpha", "  - service: !!str alpha"),
        minimal("alpha").replace("    apiKey:", "    apiKey: !custom"),
        minimal("alpha").replace("credentials:", "credentials: !!seq"),
    ] {
        assert!(home.refuses(&body).contains("tag"), "{body}");
    }

    // Nesting depth: a deeply nested document whose *only* schema-independent
    // problem is depth. The guard refuses it before the schema walk, so
    // asserting the depth-specific message proves the guard's own check is
    // load-bearing - remove it and the serde budget or the schema walk rejects
    // with a different message (agent-vm #161 review, M4).
    let deep = format!(
        "credentials:\n  - value: {}x{}\n",
        "[".repeat(40),
        "]".repeat(40)
    );
    let error = home.refuses(&deep);
    assert!(
        error.contains("nests more than 16 levels deep"),
        "100-deep nesting: {error}"
    );
    let duplicate = "credentials:\n  - service: alpha\n    service: beta\n    apiKey:\n      name: ALPHA_KEY\n      inject:\n        - domain: a.example\n          header: x-a\n          format: \"%s\"\n";
    assert!(home.refuses(duplicate).contains("not valid YAML"));

    // Encoding: too large, CRLF, BOM, NUL, invalid UTF-8.
    let oversized = format!(
        "{}# {}\n",
        minimal("alpha"),
        "x".repeat(MAX_CREDENTIALS_FILE_BYTES as usize)
    );
    let error = home.refuses(&oversized);
    assert!(error.contains("size limit"), "{error}");

    let crlf = minimal("alpha").replace('\n', "\r\n");
    assert!(home.refuses(&crlf).contains("carriage return"));

    let bom = format!("\u{feff}{}", minimal("alpha"));
    assert!(home.refuses(&bom).contains("byte-order mark"));

    let nul = minimal("alpha").replace("alpha", "al\u{0}pha");
    assert!(home.refuses(&nul).contains("NUL"));

    home.write_bytes(&[0xff, 0xfe, b'x']);
    let error = format!("{}", load(home.path()).unwrap_err());
    assert!(error.contains("not valid UTF-8"), "{error}");
}

/// The redaction rule: a diagnostic names an index and a constant schema
/// label, never file content. The canary is placed in every field, each case
/// paired with something that genuinely makes the file invalid.
#[test]
fn diagnostics_never_echo_file_content() {
    let canary = "sk-CANARY-9f3a2b7c1d4e5f60718293a4b5c6d7e8";
    let home = Home::new();
    let cases: Vec<(&str, String)> = vec![
        (
            "unknown key",
            minimal("alpha").replace("    apiKey:", &format!("    {canary}: 1\n    apiKey:")),
        ),
        (
            "service",
            minimal("alpha").replace("service: alpha", &format!("service: {canary}/x")),
        ),
        (
            "apiKey.name",
            minimal("alpha").replace("ALPHA_KEY", &format!("\"{canary}\"")),
        ),
        (
            "description",
            minimal("alpha").replace(
                "    apiKey:",
                &format!("    description: \"{canary}\"\n    required: 7\n    apiKey:"),
            ),
        ),
        (
            "required",
            minimal("alpha").replace(
                "    apiKey:",
                &format!("    required: \"{canary}\"\n    apiKey:"),
            ),
        ),
        (
            "domain",
            minimal("alpha").replace("api.example.com", &format!("{canary} host")),
        ),
        ("header", minimal("alpha").replace("x-api-key", canary)),
        (
            "format",
            minimal("alpha").replace("\"%s\"", &format!("\"{canary}\"")),
        ),
        (
            "unsupported value",
            minimal("alpha").replace("    apiKey:", &format!("    source: {canary}\n    apiKey:")),
        ),
        (
            "apiKey.value",
            minimal("alpha").replace(
                "      inject:",
                &format!("      value: {canary}\n      inject:"),
            ),
        ),
        ("syntax", format!("credentials: [{canary}\n")),
        (
            "second document",
            format!("{}---\n# {canary}\n", minimal("alpha")),
        ),
        (
            "tag",
            minimal("alpha").replace(
                "  - service: alpha",
                &format!("  - service: !{canary} alpha"),
            ),
        ),
        (
            "anchor",
            minimal("alpha").replace(
                "  - service: alpha",
                &format!("  - service: &{canary} alpha"),
            ),
        ),
        (
            "alias",
            minimal("alpha").replace("api.example.com", &format!("*{canary}")),
        ),
    ];
    for (label, body) in cases {
        let error = home.refuses(&body);
        assert!(
            !error.contains(canary),
            "{label}: the diagnostic echoed file content: {error}"
        );
        // And the whole-error `Debug` path must not either.
        let debugged = {
            home.write(&body);
            format!("{:?}", load(home.path()).unwrap_err())
        };
        assert!(!debugged.contains(canary), "{label}: Debug echoed content");
    }
}

// ---------------------------------------------------------------------------
// Integrity of the file itself
// ---------------------------------------------------------------------------

#[test]
fn integrity_failures_are_refused() {
    let home = Home::new();
    home.write(&minimal("alpha"));

    // Group/other write on the file.
    fs::set_permissions(home.file(), fs::Permissions::from_mode(0o666)).unwrap();
    let error = format!("{}", home.load().unwrap_err());
    assert!(error.contains("group- or other-writable"), "{error}");
    fs::set_permissions(home.file(), fs::Permissions::from_mode(0o600)).unwrap();

    // Group/other write on the directory.
    let config = home.file().parent().unwrap().to_path_buf();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o777)).unwrap();
    let error = format!("{}", home.load().unwrap_err());
    assert!(
        error.contains("directory is group- or other-writable"),
        "{error}"
    );
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();

    // A symlink at the final component is never followed.
    let real_file = home.file().with_extension("real");
    fs::write(&real_file, minimal("alpha")).unwrap();
    fs::remove_file(home.file()).unwrap();
    std::os::unix::fs::symlink(&real_file, home.file()).unwrap();
    let error = format!("{}", home.load().unwrap_err());
    assert!(error.contains("symbolic link"), "{error}");
    fs::remove_file(home.file()).unwrap();

    // A directory where the file belongs is not a regular file.
    fs::create_dir(home.file()).unwrap();
    let error = format!("{}", home.load().unwrap_err());
    assert!(error.contains("not a regular file"), "{error}");
    fs::remove_dir(home.file()).unwrap();

    // Group/other *read* is a warning, not a refusal: the file holds no values.
    home.write(&minimal("alpha"));
    fs::set_permissions(home.file(), fs::Permissions::from_mode(0o644)).unwrap();
    let set = home.load().expect("0644 is accepted");
    assert_eq!(set.warnings().len(), 1);
    assert!(set.warnings()[0].contains("group- or other-readable"));

    // A foreign owner is refused; only testable when the suite runs as root.
    if current_euid() == 0 {
        let other = 65534;
        let c = std::ffi::CString::new(home.file().as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `chown` with a valid NUL-terminated path.
        assert_eq!(unsafe { libc::chown(c.as_ptr(), other, u32::MAX) }, 0);
        let error = format!("{}", home.load().unwrap_err());
        assert!(error.contains("owned by another user"), "{error}");
    }
}

// ---------------------------------------------------------------------------
// D6: the two grammars cannot drift
// ---------------------------------------------------------------------------

/// Consume the runtime's own accept/reject vectors.
///
/// This couples an agent-vm test to the vendored submodule's layout on purpose:
/// the fixture exists so an embedding application can share the grammar, and
/// the point here is that agent-vm's acceptance cannot drift from the durable
/// grammar the runtime enforces on the values agent-vm builds.
///
/// Two fixture `reject` cases are *normalization* cases for agent-vm rather
/// than rejections — `domain` is lowercased and one trailing dot is stripped,
/// exactly as the runtime's builder does — and two are about `id`/`reference`,
/// which agent-vm derives from its own validated `service`. Both sets are
/// listed explicitly so a new fixture case cannot join them silently.
#[test]
fn grammar_matches_the_runtime_fixture() {
    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/microsandbox/packages/microsandbox-types/rust/lib/fixtures/",
        "header_credential_grammar.json"
    );
    let text = fs::read_to_string(FIXTURE).expect("the vendored grammar fixture");
    let fixture: serde_json::Value = serde_json::from_str(&text).expect("fixture is JSON");

    let accepts = |host: &str, port: u16, header: &str, format: &str| -> bool {
        let Some(domain) = origin_from_parts(host, port) else {
            return false;
        };
        parse_domain(&domain).is_ok()
            && header_name_is_valid_bytes(header.as_bytes())
            && !forbidden_header(header)
            && format_placeholder_count_is_one(format.as_bytes())
    };

    for entry in fixture["accept"].as_array().expect("accept list") {
        let host = entry["origin"]["host"].as_str().unwrap();
        let port = entry["origin"]["port"].as_u64().unwrap() as u16;
        let header = entry["header"].as_str().unwrap();
        let format = entry["format"].as_str().unwrap();
        assert!(
            accepts(host, port, header, format),
            "runtime accepts {host}:{port} {header} {format:?} but agent-vm refuses it"
        );
    }

    let normalization: &[&str] = &["uppercase host", "trailing dot host"];
    let reference_only: &[&str] = &["empty id", "empty reference"];
    for entry in fixture["reject"].as_array().expect("reject list") {
        let why = entry["_why"].as_str().unwrap();
        let host = entry["origin"]["host"].as_str().unwrap();
        let port = entry["origin"]["port"].as_u64().unwrap() as u16;
        let header = entry["header"].as_str().unwrap();
        let format = entry["format"].as_str().unwrap();
        let rejected = !accepts(host, port, header, format);
        let documented = normalization.contains(&why) || reference_only.contains(&why);
        assert!(
            rejected || documented,
            "runtime rejects {why:?} ({host}:{port} {header} {format:?}) but agent-vm accepts it, \
             and it is not a documented normalization/reference case"
        );
        assert!(
            !(documented && rejected),
            "{why:?} is listed as a normalization/reference case but agent-vm does reject it; \
             remove it from the exception list"
        );
    }

    // Agent-vm's own normalization output is always acceptable to the runtime:
    // this is the direction that matters, because the canonical form is what
    // the builder receives.
    for (raw, expected) in [
        ("API.example.com", "api.example.com"),
        ("a.example.", "a.example"),
    ] {
        let (canonical, _) = parse_domain(raw).expect("normalized");
        assert_eq!(canonical, expected);
    }
}

/// Render `(host, port)` the way a user writes a `domain`.
fn origin_from_parts(host: &str, port: u16) -> Option<String> {
    if host.is_empty() {
        return None;
    }
    Some(if port == DEFAULT_HTTPS_PORT {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    })
}

// ---------------------------------------------------------------------------
// Predicate tables (the executable form of Step 3's contracts)
// ---------------------------------------------------------------------------

/// Every contracted predicate's **executable** form, pinned against a
/// plain-Rust oracle written out independently of the spec body. The spec
/// linkage itself is each function's `ensures` clause (checked by
/// `script/test/verus-verification.sh`), so this is the other half: that the
/// decision a reader expects is the decision the executable makes. Spec
/// functions erase under a plain build, so the oracle is the only way a unit
/// test can reach this.
#[test]
fn contracted_predicates_match_an_independent_oracle() {
    let header_oracle = |bytes: &[u8]| -> bool {
        !bytes.is_empty()
            && bytes.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || b"!#$%&'*+-.^_`|~".contains(byte)
            })
    };
    let env_oracle = |bytes: &[u8]| -> bool {
        !bytes.is_empty()
            && bytes.len() <= MAX_ENV_NAME_BYTES
            && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
            && bytes[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    };
    for byte in 0u8..=255 {
        for candidate in [
            vec![byte],
            vec![b'a', byte],
            vec![byte, b'a'],
            vec![b'1', byte, b'A'],
        ] {
            assert_eq!(
                header_name_is_valid_bytes(&candidate),
                header_oracle(&candidate),
                "header {candidate:?}"
            );
            assert_eq!(
                guest_env_name_is_valid_bytes(&candidate),
                env_oracle(&candidate),
                "env {candidate:?}"
            );
        }
    }
    for (candidate, expected) in [
        (&b"x-api-key"[..], true),
        (&b"authorization"[..], true),
        (&b"X-Api-Key"[..], false),
        (&b"x api"[..], false),
        (&b""[..], false),
        (&b"x	key"[..], false),
    ] {
        assert_eq!(
            header_name_is_valid_bytes(candidate),
            expected,
            "{candidate:?}"
        );
        assert_eq!(header_oracle(candidate), expected, "{candidate:?}");
    }
    for (candidate, expected) in [
        (&b"OPENAI_API_KEY"[..], true),
        (&b"_x"[..], true),
        (&b"1KEY"[..], false),
        (&b"KEY-2"[..], false),
        (&b"KEY 2"[..], false),
    ] {
        assert_eq!(
            guest_env_name_is_valid_bytes(candidate),
            expected,
            "{candidate:?}"
        );
        assert_eq!(env_oracle(candidate), expected, "{candidate:?}");
    }
    // The limits are exactly the constants they name.
    assert!(authorization_count_within_limit(MAX_AUTHORIZATIONS));
    assert!(!authorization_count_within_limit(MAX_AUTHORIZATIONS + 1));
    assert!(injection_rule_count_within_limit(MAX_INJECTION_RULES));
    assert!(!injection_rule_count_within_limit(MAX_INJECTION_RULES + 1));
    assert!(structural_depth_within_limit(MAX_STRUCTURAL_DEPTH));
    assert!(!structural_depth_within_limit(MAX_STRUCTURAL_DEPTH + 1));
}

#[test]
fn predicates_agree_with_their_rejection_labels() {
    // A header that is a token and lowercase is accepted, and nothing else is;
    // the label function is exercised through the loader elsewhere.
    assert!(header_name_is_valid_bytes(b"x-api-key"));
    assert!(!header_name_is_valid_bytes(b""));
    assert!(!header_name_is_valid_bytes(b"X-Api-Key"));
    assert!(!header_name_is_valid_bytes(b"x api"));
    assert!(!header_name_is_valid_bytes(b":authority"));
    assert!(!header_name_is_valid_bytes(b"x\nkey"));

    assert!(format_placeholder_count_is_one(b"%s"));
    assert!(format_placeholder_count_is_one(b"Token %s; v=100%"));
    assert!(format_placeholder_count_is_one(b"%%s"));
    assert!(!format_placeholder_count_is_one(b"Token"));
    assert!(!format_placeholder_count_is_one(b"%s %s"));
    assert!(!format_placeholder_count_is_one(b"\ns"));
    let many = "%s".repeat(128);
    assert!(
        !format_placeholder_count_is_one(many.as_bytes()),
        "128 placeholders"
    );
    // An over-limit format that is otherwise *valid* (printable ASCII, exactly
    // one `%s`): if the length check were removed, only this would slip
    // through, so the assertion pins the length rule rather than the
    // placeholder rule (agent-vm #161 review, M4).
    let just_under = format!("{}%s", "x".repeat(MAX_FORMAT_BYTES - 2));
    assert_eq!(just_under.len(), MAX_FORMAT_BYTES);
    assert!(format_placeholder_count_is_one(just_under.as_bytes()));
    let over_limit = format!("{}%s", "x".repeat(MAX_FORMAT_BYTES - 1));
    assert_eq!(over_limit.len(), MAX_FORMAT_BYTES + 1);
    assert!(!format_placeholder_count_is_one(over_limit.as_bytes()));

    assert!(origin_host_is_exact_bytes(b"api.example.com"));
    assert!(origin_host_is_exact_bytes(b"a1-b2.example.co.uk"));
    assert!(
        origin_host_is_exact_bytes(b"127.0.0.1"),
        "an IP literal passes the *byte* shape; the IP policy is a separate check"
    );
    assert!(!origin_host_is_exact_bytes(b""));
    assert!(!origin_host_is_exact_bytes(b"api.example.com."));
    assert!(!origin_host_is_exact_bytes(b"API.example.com"));
    assert!(!origin_host_is_exact_bytes(b"api..example.com"));
    assert!(!origin_host_is_exact_bytes(b"-api.example.com"));
    assert!(!origin_host_is_exact_bytes(b"api-.example.com"));
    assert!(!origin_host_is_exact_bytes(b"api.example.com/path"));
    assert!(!origin_host_is_exact_bytes(&[b'a'; MAX_HOST_BYTES + 1]));

    assert!(guest_env_name_is_valid_bytes(b"A_1"));
    assert!(guest_env_name_is_valid_bytes(b"_x"));
    assert!(!guest_env_name_is_valid_bytes(b""));
    assert!(!guest_env_name_is_valid_bytes(b"1A"));
    assert!(!guest_env_name_is_valid_bytes(b"A-B"));
    assert!(!guest_env_name_is_valid_bytes(
        &[b'A'; MAX_ENV_NAME_BYTES + 1]
    ));

    assert!(authorization_count_within_limit(MAX_AUTHORIZATIONS));
    assert!(!authorization_count_within_limit(MAX_AUTHORIZATIONS + 1));
    assert!(injection_rule_count_within_limit(MAX_INJECTION_RULES));
    assert!(!injection_rule_count_within_limit(MAX_INJECTION_RULES + 1));
    assert!(structural_depth_within_limit(MAX_STRUCTURAL_DEPTH));
    assert!(!structural_depth_within_limit(MAX_STRUCTURAL_DEPTH + 1));
}
