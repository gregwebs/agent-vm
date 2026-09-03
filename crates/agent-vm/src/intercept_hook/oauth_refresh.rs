use std::{
    path::Path,
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use serde::{
    Deserialize,
    de::{self, MapAccess, Visitor},
};

use super::http;
use crate::{
    host_paths::{
        MAX_HOST_CREDENTIAL_FILE_BYTES, host_claude_creds_path, host_codex_auth_path,
        read_bounded_regular_file,
    },
    secrets,
};

pub(super) fn handle(
    raw_request: &[u8],
    provider_sni: &str,
    state_dir: &Path,
) -> Result<http::Response> {
    handle_with(raw_request, provider_sni, |validated| {
        refresh(state_dir, validated)
    })
}

fn handle_with<A>(raw_request: &[u8], provider_sni: &str, action: A) -> Result<http::Response>
where
    A: FnOnce(ValidatedRefresh) -> PublicReply,
{
    let validated = match validate(raw_request, provider_sni) {
        Ok(validated) => validated,
        Err(rejection) => return http::Response::error(rejection.status, &rejection.message),
    };
    response(action(validated))
}

fn response(reply: PublicReply) -> Result<http::Response> {
    match reply {
        PublicReply::AnthropicSuccess { expires_in, scope } => http::Response::json(
            200,
            "OK",
            &serde_json::json!({
                "access_token": secrets::ANTHROPIC_ACCESS_PLACEHOLDER,
                "refresh_token": secrets::ANTHROPIC_REFRESH_PLACEHOLDER,
                "expires_in": expires_in.0,
                "token_type": "Bearer", "scope": scope.0,
            }),
        ),
        PublicReply::OpenAiSuccess { expires_in } => http::Response::json(
            200,
            "OK",
            &serde_json::json!({
                "access_token": secrets::OPENAI_ACCESS_PLACEHOLDER,
                "refresh_token": secrets::OPENAI_REFRESH_PLACEHOLDER,
                "id_token": secrets::OPENAI_ID_PLACEHOLDER,
                "expires_in": expires_in.0, "token_type": "Bearer",
            }),
        ),
        PublicReply::TemporarilyUnavailable { provider, reason } => {
            tracing::debug!(provider = ?provider, reason = ?reason, "OAuth refresh temporarily unavailable");
            let command = match provider {
                Provider::Anthropic => "claude login",
                Provider::OpenAi => "codex login",
            };
            http::Response::json(
                503,
                "Service Unavailable",
                &serde_json::json!({
                    "error": "temporarily_unavailable",
                    "error_description": "host credential is temporarily unavailable",
                    "message": format!("retry later or run `{command}` on the host"),
                }),
            )
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    Anthropic,
    OpenAi,
}

struct ValidatedRefresh {
    provider: Provider,
}

struct ExpiresIn(i64);
impl ExpiresIn {
    fn from_expiry_ms(expiry_ms: i64, now_ms: i64, floor: i64) -> Option<Self> {
        let remaining = expiry_ms.checked_sub(now_ms)?.checked_div(1000)?;
        (remaining > floor).then_some(Self(remaining))
    }
    #[cfg(test)]
    fn from_remaining_seconds(remaining: i64, floor: i64) -> Option<Self> {
        (remaining > floor).then_some(Self(remaining))
    }
    fn openai_unknown() -> Self {
        Self(OPENAI_UNKNOWN_EXPIRY_SECS)
    }
}

struct OAuthScope(String);
impl OAuthScope {
    fn from_host(value: Option<&serde_json::Value>) -> Self {
        const MAX_SCOPE_TOKENS: usize = 64;
        const MAX_SCOPE_BYTES: usize = 4096;
        let mut words = Vec::new();
        let mut append = |text: &str| {
            for word in text.split_whitespace() {
                if words.len() >= MAX_SCOPE_TOKENS
                    || !word.bytes().all(is_scope_token_byte)
                    || words.iter().any(|seen: &String| seen == word)
                {
                    continue;
                }
                let prospective =
                    words.iter().map(String::len).sum::<usize>() + words.len() + word.len();
                if prospective <= MAX_SCOPE_BYTES {
                    words.push(word.to_owned());
                }
            }
        };
        match value {
            Some(serde_json::Value::String(text)) => append(text),
            Some(serde_json::Value::Array(values)) => {
                for value in values {
                    if let Some(text) = value.as_str() {
                        append(text);
                    }
                }
            }
            _ => {}
        }
        if !words.iter().any(|word| word == "user:inference") {
            words = vec!["user:inference".into(), "user:profile".into()];
        }
        Self(words.join(" "))
    }
}
fn is_scope_token_byte(byte: u8) -> bool {
    byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnusableReason {
    HostPathUnavailable,
    HostCredentialUnreadable,
    HostCredentialMalformed,
    MissingBearer,
    InvalidExpiry,
    ExpiredOrExpiring,
    RefreshLockUnavailable,
    RotationDidNotProduceUsableCredential,
    TokenInstallFailed,
}

enum PublicReply {
    AnthropicSuccess {
        expires_in: ExpiresIn,
        scope: OAuthScope,
    },
    OpenAiSuccess {
        expires_in: ExpiresIn,
    },
    TemporarilyUnavailable {
        provider: Provider,
        reason: UnusableReason,
    },
}

struct Bearer(String);
impl Bearer {
    fn install(self, path: &Path) -> std::result::Result<(), UnusableReason> {
        secrets::ensure_host_secret_dir(path).map_err(|_| UnusableReason::TokenInstallFailed)?;
        crate::host_paths::atomic_write(path, self.0.as_bytes(), 0o600)
            .map_err(|_| UnusableReason::TokenInstallFailed)
    }
}

struct OAuthRejection {
    status: u16,
    message: String,
}
impl OAuthRejection {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: 400,
            message: message.into(),
        }
    }
    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: 403,
            message: message.into(),
        }
    }
}

fn validate(
    raw_request: &[u8],
    provider_sni: &str,
) -> std::result::Result<ValidatedRefresh, OAuthRejection> {
    let provider = provider_for_sni(provider_sni)?;
    let request = http::Request::parse(raw_request)
        .map_err(|_| OAuthRejection::bad_request("malformed OAuth refresh request"))?;
    let host = exactly_one_header(&request, "host")?;
    if !host.eq_ignore_ascii_case(provider_sni) {
        return Err(OAuthRejection::forbidden(
            "OAuth refresh Host does not match SNI",
        ));
    }
    if request.method() != "POST" {
        return Err(OAuthRejection::forbidden("OAuth refresh requires POST"));
    }
    let expected_path = match provider {
        Provider::Anthropic => secrets::ANTHROPIC_OAUTH_TOKEN_PATH,
        Provider::OpenAi => secrets::OPENAI_OAUTH_TOKEN_PATH,
    };
    if validated_target(request.target(), provider_sni)? != expected_path {
        return Err(OAuthRejection::forbidden(
            "OAuth refresh path is not allowed",
        ));
    }
    let content_types: Vec<_> = request.header_values("content-type").collect();
    if content_types.len() != 1
        || request.headers().iter().any(|(name, value)| {
            (name.eq_ignore_ascii_case("transfer-encoding")
                || name.eq_ignore_ascii_case("content-encoding"))
                && !value.eq_ignore_ascii_case("identity")
        })
    {
        return Err(OAuthRejection::bad_request(
            "OAuth refresh has unsupported HTTP encoding",
        ));
    }
    let lengths: Vec<_> = request.header_values("content-length").collect();
    if lengths.len() != 1 || lengths[0].parse::<usize>().ok() != Some(request.body().len()) {
        return Err(OAuthRejection::bad_request(
            "OAuth refresh has invalid content length",
        ));
    }
    let content_type = content_types[0].split(';').next().unwrap_or("").trim();
    let (grant_ok, token_ok) = if content_type.eq_ignore_ascii_case("application/json") {
        let body: JsonRefresh = serde_json::from_slice(request.body())
            .map_err(|_| OAuthRejection::bad_request("OAuth refresh JSON body is invalid"))?;
        (
            body.grant_type == "refresh_token",
            refresh_placeholder_matches(provider, &body.refresh_token),
        )
    } else if content_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        let values = parse_form(request.body())
            .ok_or_else(|| OAuthRejection::bad_request("OAuth refresh form body is invalid"))?;
        let grants: Vec<_> = values
            .iter()
            .filter(|(key, _)| key == "grant_type")
            .collect();
        let tokens: Vec<_> = values
            .iter()
            .filter(|(key, _)| key == "refresh_token")
            .collect();
        (
            grants.len() == 1 && grants[0].1 == "refresh_token",
            tokens.len() == 1 && refresh_placeholder_matches(provider, &tokens[0].1),
        )
    } else {
        return Err(OAuthRejection::bad_request(
            "OAuth refresh content type is not supported",
        ));
    };
    if !grant_ok || !token_ok {
        return Err(OAuthRejection::forbidden(
            "OAuth refresh grant or refresh token is not allowed",
        ));
    }
    Ok(ValidatedRefresh { provider })
}

fn provider_for_sni(sni: &str) -> std::result::Result<Provider, OAuthRejection> {
    if sni.eq_ignore_ascii_case(secrets::ANTHROPIC_OAUTH_HOST) {
        Ok(Provider::Anthropic)
    } else if sni.eq_ignore_ascii_case(secrets::OPENAI_OAUTH_HOST) {
        Ok(Provider::OpenAi)
    } else {
        Err(OAuthRejection::forbidden(
            "OAuth refresh SNI is not allowed",
        ))
    }
}

fn exactly_one_header<'a>(
    request: &'a http::Request,
    name: &str,
) -> std::result::Result<&'a str, OAuthRejection> {
    let values: Vec<_> = request.header_values(name).collect();
    if values.len() != 1 || values[0].is_empty() {
        return Err(OAuthRejection::bad_request(format!(
            "OAuth refresh requires exactly one {name} header"
        )));
    }
    Ok(values[0])
}

fn validated_target(target: &str, sni: &str) -> std::result::Result<String, OAuthRejection> {
    if target.starts_with('/') {
        if target.contains(['?', '#', '\\']) || http::contains_escaped_path_escape(target) {
            return Err(OAuthRejection::forbidden(
                "OAuth refresh target is not exact",
            ));
        }
        return Ok(target.to_string());
    }
    let url = url::Url::parse(target)
        .map_err(|_| OAuthRejection::bad_request("OAuth refresh target is invalid"))?;
    if !url.scheme().eq_ignore_ascii_case("https")
        || !url
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case(sni))
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(OAuthRejection::forbidden(
            "OAuth refresh authority does not match SNI",
        ));
    }
    if http::contains_escaped_path_escape(url.path()) || url.path().contains('\\') {
        return Err(OAuthRejection::forbidden(
            "OAuth refresh target is not exact",
        ));
    }
    Ok(url.path().to_string())
}

fn parse_form(body: &[u8]) -> Option<Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>> {
    std::str::from_utf8(body).ok()?;
    for (index, byte) in body.iter().enumerate() {
        if *byte == b'%'
            && !body
                .get(index + 1..index + 3)
                .is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit))
        {
            return None;
        }
    }
    Some(url::form_urlencoded::parse(body).collect())
}

struct JsonRefresh {
    grant_type: String,
    refresh_token: String,
}

impl<'de> Deserialize<'de> for JsonRefresh {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct JsonRefreshVisitor;
        impl<'de> Visitor<'de> for JsonRefreshVisitor {
            type Value = JsonRefresh;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an OAuth refresh object")
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut grant_type = None;
                let mut refresh_token = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "grant_type" if grant_type.is_none() => {
                            grant_type = Some(map.next_value()?)
                        }
                        "refresh_token" if refresh_token.is_none() => {
                            refresh_token = Some(map.next_value()?)
                        }
                        "grant_type" | "refresh_token" => {
                            return Err(de::Error::custom(format!("duplicate {key}")));
                        }
                        _ => {
                            let _: de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(JsonRefresh {
                    grant_type: grant_type.ok_or_else(|| de::Error::missing_field("grant_type"))?,
                    refresh_token: refresh_token
                        .ok_or_else(|| de::Error::missing_field("refresh_token"))?,
                })
            }
        }
        deserializer.deserialize_map(JsonRefreshVisitor)
    }
}

fn refresh_placeholder_matches(provider: Provider, token: &str) -> bool {
    match provider {
        Provider::Anthropic => token == secrets::ANTHROPIC_REFRESH_PLACEHOLDER,
        Provider::OpenAi => {
            token == secrets::OPENAI_REFRESH_PLACEHOLDER
                || token == secrets::OPENCODE_OPENAI_REFRESH_PLACEHOLDER
        }
    }
}

const SERVING_FLOOR_SECS: i64 = 300;
const ROTATION_MARGIN_SECS: i64 = 600;
const OPENAI_UNKNOWN_EXPIRY_SECS: i64 = 3600;
const LOCK_CEILING: Duration = Duration::from_secs(20);
const ANTHROPIC_CLI_TIMEOUT: Duration = Duration::from_secs(45);
const OPENAI_CLI_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_OVERSHOOT: Duration = Duration::from_millis(50);
const REAP_CEILING: Duration = Duration::from_secs(2);
const STDERR_GRACE: Duration = Duration::from_millis(100);
const ATTEMPT_STAMP_SECS: Duration = Duration::from_secs(30);

fn refresh(state_dir: &Path, validated: ValidatedRefresh) -> PublicReply {
    let now = match now_ms() {
        Ok(now) => now,
        Err(_) => return unavailable(validated.provider, UnusableReason::InvalidExpiry),
    };
    match validated.provider {
        Provider::Anthropic => anthropic_refresh(state_dir, now, |cmd, args, cwd, timeout| {
            run_host_cli(cmd, args, cwd, timeout)
        }),
        Provider::OpenAi => openai_refresh(state_dir, now, |cmd, args, cwd, timeout| {
            run_host_cli(cmd, args, cwd, timeout)
        }),
    }
}
fn unavailable(provider: Provider, reason: UnusableReason) -> PublicReply {
    PublicReply::TemporarilyUnavailable { provider, reason }
}
fn now_ms() -> Result<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("clock before epoch")?
        .as_millis()
        .try_into()
        .context("clock out of range")
}

enum AnthropicInspection {
    Serve {
        bearer: Bearer,
        expires_in: ExpiresIn,
        scope: OAuthScope,
        above_margin: bool,
    },
    Rotate,
    Unavailable(UnusableReason),
}
fn inspect_anthropic(path: Option<&Path>, now: i64, floor: i64) -> AnthropicInspection {
    let Some(path) = path else {
        return AnthropicInspection::Unavailable(UnusableReason::HostPathUnavailable);
    };
    let raw = match read_bounded_regular_file(path, MAX_HOST_CREDENTIAL_FILE_BYTES) {
        Ok(raw) => raw,
        Err(_) => {
            return AnthropicInspection::Unavailable(UnusableReason::HostCredentialUnreadable);
        }
    };
    let value: serde_json::Value = match serde_json::from_slice(&raw) {
        Ok(value) => value,
        Err(_) => return AnthropicInspection::Unavailable(UnusableReason::HostCredentialMalformed),
    };
    let Some(oauth) = value.get("claudeAiOauth") else {
        return AnthropicInspection::Unavailable(UnusableReason::HostCredentialMalformed);
    };
    let Some(access) = oauth
        .get("accessToken")
        .and_then(serde_json::Value::as_str)
        .filter(|v| !v.is_empty())
    else {
        return AnthropicInspection::Unavailable(UnusableReason::MissingBearer);
    };
    let Some(expiry) = expires_at_ms(oauth.get("expiresAt")) else {
        return AnthropicInspection::Rotate;
    };
    let Some(expires_in) = ExpiresIn::from_expiry_ms(expiry, now, floor) else {
        return AnthropicInspection::Rotate;
    };
    AnthropicInspection::Serve {
        bearer: Bearer(access.into()),
        expires_in,
        scope: OAuthScope::from_host(oauth.get("scopes")),
        above_margin: expiry.saturating_sub(now) / 1000 > ROTATION_MARGIN_SECS,
    }
}
fn expires_at_ms(value: Option<&serde_json::Value>) -> Option<i64> {
    match value? {
        serde_json::Value::Number(value) => value
            .as_i64()
            .filter(|n| *n > 0)
            .or_else(|| {
                value
                    .as_u64()
                    .and_then(|n| i64::try_from(n).ok())
                    .filter(|n| *n > 0)
            })
            .or_else(|| {
                value
                    .as_f64()
                    .filter(|n| n.is_finite() && *n > 0.0 && *n <= i64::MAX as f64)
                    .map(|n| n as i64)
            }),
        _ => None,
    }
}
fn anth_reply(state_dir: &Path, state: AnthropicInspection) -> PublicReply {
    match state {
        AnthropicInspection::Serve {
            bearer,
            expires_in,
            scope,
            ..
        } => match bearer.install(&secrets::anthropic_token_path(state_dir)) {
            Ok(()) => PublicReply::AnthropicSuccess { expires_in, scope },
            Err(reason) => unavailable(Provider::Anthropic, reason),
        },
        AnthropicInspection::Unavailable(reason) => unavailable(Provider::Anthropic, reason),
        AnthropicInspection::Rotate => {
            unavailable(Provider::Anthropic, UnusableReason::ExpiredOrExpiring)
        }
    }
}
fn anthropic_refresh<F>(state_dir: &Path, now: i64, runner: F) -> PublicReply
where
    F: Fn(&str, &[&str], &Path, Duration) -> Result<()>,
{
    let path = host_claude_creds_path();
    let initial = inspect_anthropic(path.as_deref(), now, SERVING_FLOOR_SECS);
    if matches!(
        &initial,
        AnthropicInspection::Serve {
            above_margin: true,
            ..
        }
    ) {
        return anth_reply(state_dir, initial);
    }
    if matches!(&initial, AnthropicInspection::Unavailable(_)) {
        return anth_reply(state_dir, initial);
    }
    let lock = match RefreshLock::acquire(state_dir, secrets::REFRESH_LOCK_ANTHROPIC, LOCK_CEILING)
    {
        Ok(lock) => lock,
        Err(_) => {
            let Ok(now) = now_ms() else {
                return unavailable(Provider::Anthropic, UnusableReason::InvalidExpiry);
            };
            return match inspect_anthropic(path.as_deref(), now, SERVING_FLOOR_SECS) {
                ready @ AnthropicInspection::Serve { .. } => anth_reply(state_dir, ready),
                _ => unavailable(Provider::Anthropic, UnusableReason::RefreshLockUnavailable),
            };
        }
    };
    let Ok(now) = now_ms() else {
        return unavailable(Provider::Anthropic, UnusableReason::InvalidExpiry);
    };
    let reread = inspect_anthropic(path.as_deref(), now, SERVING_FLOOR_SECS);
    if matches!(
        &reread,
        AnthropicInspection::Serve {
            above_margin: true,
            ..
        }
    ) {
        return anth_reply(state_dir, reread);
    }
    if matches!(&reread, AnthropicInspection::Unavailable(_)) {
        return anth_reply(state_dir, reread);
    }
    if !stamp_is_fresh(
        &secrets::attempt_stamp_path_for(state_dir, "anthropic"),
        now,
    ) {
        let _ = write_stamp(state_dir, "anthropic", now);
        let cwd = match isolated_work_dir(state_dir) {
            Ok(dir) => dir,
            Err(_) => return unavailable(Provider::Anthropic, UnusableReason::TokenInstallFailed),
        };
        let _ = runner(
            "claude",
            &["-p", "hi", "--model", "sonnet"],
            cwd.path(),
            ANTHROPIC_CLI_TIMEOUT,
        );
    }
    let Ok(now) = now_ms() else {
        return unavailable(Provider::Anthropic, UnusableReason::InvalidExpiry);
    };
    // Keep the provider lock through installation so a launcher cannot
    // overwrite a just-rotated credential with an older host snapshot.
    let _lock = lock;
    anth_reply(
        state_dir,
        inspect_anthropic(path.as_deref(), now, SERVING_FLOOR_SECS),
    )
}

enum AccessTokenKind {
    Jwt { exp_ms: i64 },
    Opaque,
    MalformedJwt,
}
fn classify_access_token(token: &str) -> AccessTokenKind {
    if !token.contains('.') {
        return AccessTokenKind::Opaque;
    }
    let segments: Vec<_> = token.split('.').collect();
    if segments.len() != 3 {
        return AccessTokenKind::MalformedJwt;
    }
    use base64::Engine as _;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segments[1])
        .or_else(|_| {
            let translated = segments[1].replace('-', "+").replace('_', "/");
            let padded = format!(
                "{}{}",
                translated,
                "=".repeat((4 - translated.len() % 4) % 4)
            );
            base64::engine::general_purpose::STANDARD.decode(padded)
        });
    let Ok(payload) = payload else {
        return AccessTokenKind::MalformedJwt;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        return AccessTokenKind::MalformedJwt;
    };
    let Some(exp) = expires_at_ms(value.get("exp")) else {
        return AccessTokenKind::MalformedJwt;
    };
    AccessTokenKind::Jwt {
        // JWT `exp` is seconds. Saturation preserves a valid far-future
        // timestamp instead of misclassifying it as malformed.
        exp_ms: exp.saturating_mul(1000),
    }
}
enum OpenAiInspection {
    Serve {
        bearer: Bearer,
        expires_in: ExpiresIn,
        above_margin: bool,
    },
    Rotate,
    Unavailable(UnusableReason),
}
fn inspect_openai(path: Option<&Path>, now: i64) -> OpenAiInspection {
    let Some(path) = path else {
        return OpenAiInspection::Unavailable(UnusableReason::HostPathUnavailable);
    };
    let raw = match read_bounded_regular_file(path, MAX_HOST_CREDENTIAL_FILE_BYTES) {
        Ok(raw) => raw,
        Err(_) => return OpenAiInspection::Unavailable(UnusableReason::HostCredentialUnreadable),
    };
    let value: serde_json::Value = match serde_json::from_slice(&raw) {
        Ok(value) => value,
        Err(_) => return OpenAiInspection::Unavailable(UnusableReason::HostCredentialMalformed),
    };
    let api = value
        .get("OPENAI_API_KEY")
        .and_then(serde_json::Value::as_str)
        .filter(|v| !v.is_empty());
    match value
        .pointer("/tokens/access_token")
        .and_then(serde_json::Value::as_str)
        .filter(|v| !v.is_empty())
    {
        Some(token) => match classify_access_token(token) {
            AccessTokenKind::Opaque => OpenAiInspection::Serve {
                bearer: Bearer(token.into()),
                expires_in: ExpiresIn::openai_unknown(),
                above_margin: true,
            },
            AccessTokenKind::Jwt { exp_ms } => {
                match ExpiresIn::from_expiry_ms(exp_ms, now, SERVING_FLOOR_SECS) {
                    Some(expires_in) => OpenAiInspection::Serve {
                        above_margin: exp_ms.saturating_sub(now) / 1000 > ROTATION_MARGIN_SECS,
                        bearer: Bearer(token.into()),
                        expires_in,
                    },
                    None if api.is_some() => OpenAiInspection::Serve {
                        bearer: Bearer(api.unwrap().into()),
                        expires_in: ExpiresIn::openai_unknown(),
                        above_margin: true,
                    },
                    None => OpenAiInspection::Rotate,
                }
            }
            AccessTokenKind::MalformedJwt => api
                .map(|token| OpenAiInspection::Serve {
                    bearer: Bearer(token.into()),
                    expires_in: ExpiresIn::openai_unknown(),
                    above_margin: true,
                })
                .unwrap_or(OpenAiInspection::Rotate),
        },
        None => api
            .map(|token| OpenAiInspection::Serve {
                bearer: Bearer(token.into()),
                expires_in: ExpiresIn::openai_unknown(),
                above_margin: true,
            })
            .unwrap_or(OpenAiInspection::Unavailable(UnusableReason::MissingBearer)),
    }
}
fn openai_reply(state_dir: &Path, state: OpenAiInspection) -> PublicReply {
    match state {
        OpenAiInspection::Serve {
            bearer, expires_in, ..
        } => match bearer.install(&secrets::openai_token_path(state_dir)) {
            Ok(()) => PublicReply::OpenAiSuccess { expires_in },
            Err(reason) => unavailable(Provider::OpenAi, reason),
        },
        OpenAiInspection::Unavailable(reason) => unavailable(Provider::OpenAi, reason),
        OpenAiInspection::Rotate => unavailable(
            Provider::OpenAi,
            UnusableReason::RotationDidNotProduceUsableCredential,
        ),
    }
}
fn openai_refresh<F>(state_dir: &Path, now: i64, runner: F) -> PublicReply
where
    F: Fn(&str, &[&str], &Path, Duration) -> Result<()>,
{
    let path = host_codex_auth_path();
    let initial = inspect_openai(path.as_deref(), now);
    if matches!(
        &initial,
        OpenAiInspection::Serve {
            above_margin: true,
            ..
        }
    ) || matches!(&initial, OpenAiInspection::Unavailable(_))
    {
        return openai_reply(state_dir, initial);
    }
    let lock = match RefreshLock::acquire(state_dir, secrets::REFRESH_LOCK_OPENAI, LOCK_CEILING) {
        Ok(lock) => lock,
        Err(_) => {
            let Ok(now) = now_ms() else {
                return unavailable(Provider::OpenAi, UnusableReason::InvalidExpiry);
            };
            return match inspect_openai(path.as_deref(), now) {
                ready @ OpenAiInspection::Serve { .. } => openai_reply(state_dir, ready),
                _ => unavailable(Provider::OpenAi, UnusableReason::RefreshLockUnavailable),
            };
        }
    };
    let Ok(now) = now_ms() else {
        return unavailable(Provider::OpenAi, UnusableReason::InvalidExpiry);
    };
    let reread = inspect_openai(path.as_deref(), now);
    if matches!(
        &reread,
        OpenAiInspection::Serve {
            above_margin: true,
            ..
        }
    ) {
        return openai_reply(state_dir, reread);
    }
    if matches!(&reread, OpenAiInspection::Unavailable(_)) {
        return openai_reply(state_dir, reread);
    }
    if !stamp_is_fresh(&secrets::attempt_stamp_path_for(state_dir, "openai"), now) {
        let _ = write_stamp(state_dir, "openai", now);
        let cwd = match isolated_work_dir(state_dir) {
            Ok(dir) => dir,
            Err(_) => return unavailable(Provider::OpenAi, UnusableReason::TokenInstallFailed),
        };
        let _ = runner(
            "codex",
            &["exec", "--skip-git-repo-check", "Reply with OK"],
            cwd.path(),
            OPENAI_CLI_TIMEOUT,
        );
    }
    let Ok(now) = now_ms() else {
        return unavailable(Provider::OpenAi, UnusableReason::InvalidExpiry);
    };
    // Hold the same provider lock until the re-read credential is installed.
    let _lock = lock;
    openai_reply(state_dir, inspect_openai(path.as_deref(), now))
}

struct RefreshLock(std::fs::File);
impl RefreshLock {
    fn acquire(state_dir: &Path, name: &str, ceiling: Duration) -> Result<Self> {
        let path = secrets::refresh_lock_path_for(state_dir, name);
        secrets::ensure_host_secret_dir(&path)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        use std::os::fd::AsRawFd;
        let start = Instant::now();
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self(file));
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK)
                || start.elapsed() >= ceiling
            {
                anyhow::bail!("refresh lock unavailable");
            }
            std::thread::sleep(POLL_OVERSHOOT);
        }
    }
}
impl Drop for RefreshLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
fn write_stamp(state_dir: &Path, provider: &str, now: i64) -> Result<()> {
    let path = secrets::attempt_stamp_path_for(state_dir, provider);
    secrets::ensure_host_secret_dir(&path)?;
    crate::host_paths::atomic_write(&path, now.to_string().as_bytes(), 0o600)
}
fn stamp_is_fresh(path: &Path, now: i64) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .is_some_and(|stamp| {
            now.saturating_sub(stamp) >= 0
                && now.saturating_sub(stamp) < ATTEMPT_STAMP_SECS.as_millis() as i64
        })
}
fn isolated_work_dir(state_dir: &Path) -> Result<tempfile::TempDir> {
    let directory = secrets::host_secret_dir_path(state_dir);
    std::fs::create_dir_all(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    }
    tempfile::Builder::new()
        .prefix("oauth-")
        .tempdir_in(directory)
        .context("creating isolated OAuth work directory")
}
fn run_host_cli(cmd: &str, args: &[&str], cwd: &Path, timeout: Duration) -> Result<()> {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for name in [
        "HOME",
        "PATH",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("spawning host {cmd}"))?;
    let pid = child.id() as libc::pid_t;
    let stderr = child.stderr.take().expect("piped");
    let (sent, received) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut std::io::BufReader::new(stderr), &mut std::io::sink());
        let _ = sent.send(());
    });
    let start = Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => {
                let _ = received.recv_timeout(STDERR_GRACE);
                if status.success() {
                    return Ok(());
                }
                anyhow::bail!("host {cmd} failed")
            }
            None if start.elapsed() >= timeout => {
                unsafe {
                    if libc::kill(-pid, libc::SIGKILL) == -1
                        && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
                    {
                        let _ = child.kill();
                    }
                }
                let reap_start = Instant::now();
                while child.try_wait()?.is_none() && reap_start.elapsed() < REAP_CEILING {
                    std::thread::sleep(POLL_OVERSHOOT);
                }
                let _ = received.recv_timeout(STDERR_GRACE);
                anyhow::bail!("host {cmd} timed out")
            }
            None => std::thread::sleep(POLL_OVERSHOOT),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(sni: &str, path: &str, ct: &str, body: &str) -> Vec<u8> {
        format!("POST {path} HTTP/1.1\r\nHost: {sni}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n\r\n{body}",body.len()).into_bytes()
    }
    fn openai_request() -> Vec<u8> {
        let b = format!(
            "grant_type=refresh_token&refresh_token={}",
            secrets::OPENAI_REFRESH_PLACEHOLDER
        );
        request(
            secrets::OPENAI_OAUTH_HOST,
            secrets::OPENAI_OAUTH_TOKEN_PATH,
            "application/x-www-form-urlencoded",
            &b,
        )
    }
    #[test]
    fn validation_precedes_action_and_valid_action_is_framed() {
        let calls = std::cell::Cell::new(0);
        let invalid = handle_with(b"bad", secrets::OPENAI_OAUTH_HOST, |_| {
            calls.set(1);
            unavailable(Provider::OpenAi, UnusableReason::MissingBearer)
        })
        .unwrap();
        assert_eq!(calls.get(), 0);
        assert!(
            std::str::from_utf8(invalid.as_bytes())
                .unwrap()
                .starts_with("HTTP/1.1 400")
        );
        let valid = handle_with(&openai_request(), secrets::OPENAI_OAUTH_HOST, |_| {
            calls.set(2);
            PublicReply::OpenAiSuccess {
                expires_in: ExpiresIn::openai_unknown(),
            }
        })
        .unwrap();
        assert_eq!(calls.get(), 2);
        assert!(
            std::str::from_utf8(valid.as_bytes())
                .unwrap()
                .contains(secrets::OPENAI_ACCESS_PLACEHOLDER)
        );
    }
    #[test]
    fn scope_is_bounded_and_always_has_inference() {
        let scope =
            OAuthScope::from_host(Some(&serde_json::json!(["foo  foo", "bad space", "bar"])));
        assert_eq!(scope.0, "user:inference user:profile");
        let scope = OAuthScope::from_host(Some(&serde_json::json!("user:inference foo foo")));
        assert_eq!(scope.0, "user:inference foo");
    }
    #[test]
    fn expiry_and_jwt_classifier_are_strict() {
        assert!(ExpiresIn::from_expiry_ms(301_000, 0, 300).is_some());
        assert!(ExpiresIn::from_remaining_seconds(301, 300).is_some());
        assert!(ExpiresIn::from_expiry_ms(300_000, 0, 300).is_none());
        assert!(matches!(
            classify_access_token("opaque"),
            AccessTokenKind::Opaque
        ));
        assert!(matches!(
            classify_access_token("a.b"),
            AccessTokenKind::MalformedJwt
        ));
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"exp":{}}}"#, i64::MAX));
        assert!(matches!(
            classify_access_token(&format!("header.{payload}.signature")),
            AccessTokenKind::Jwt { exp_ms } if exp_ms == i64::MAX
        ));
        assert!(expires_at_ms(Some(&serde_json::json!(f64::INFINITY))).is_none());
    }
    #[test]
    fn failed_valid_operation_is_credential_free_503() {
        let response = handle_with(&openai_request(), secrets::OPENAI_OAUTH_HOST, |_| {
            unavailable(Provider::OpenAi, UnusableReason::HostCredentialMalformed)
        })
        .unwrap();
        let text = std::str::from_utf8(response.as_bytes()).unwrap();
        assert!(text.starts_with("HTTP/1.1 503"));
        assert!(!text.contains("CANARY"));
    }
    // ── run_host_cli fake-executable contract ──────────────────────

    fn write_executable_script(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn run_host_cli_captures_argv_isolates_cwd_and_excludes_non_allowlisted_env() {
        let dir = tempfile::tempdir().unwrap();
        let capture = dir.path().join("capture.txt");
        let script = dir.path().join("fake-cli");
        write_executable_script(
            &script,
            &format!(
                "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > '{cap}'\nprintf 'CWD:%s\\n' \"$(pwd)\" >> '{cap}'\nenv | sort >> '{cap}'\nexit 0\n",
                cap = capture.display(),
            ),
        );
        let cwd = dir.path().join("work");
        std::fs::create_dir(&cwd).unwrap();
        let mut env = crate::test_env::guard();
        env.set_var("AGENT_VM_TEST_OAUTH_CANARY", "must-not-be-inherited");
        run_host_cli(
            script.to_str().unwrap(),
            &["exec", "--skip-git-repo-check", "Reply with OK"],
            &cwd,
            Duration::from_secs(5),
        )
        .unwrap();
        let captured = std::fs::read_to_string(&capture).unwrap();
        assert!(
            captured.starts_with("exec\n--skip-git-repo-check\nReply with OK\n"),
            "got: {captured}"
        );
        assert!(!captured.contains("--dangerously-bypass-approvals-and-sandbox"));
        let cwd_line = format!("CWD:{}\n", cwd.canonicalize().unwrap().display());
        assert!(captured.contains(&cwd_line), "got: {captured}");
        assert!(
            !captured.contains("AGENT_VM_TEST_OAUTH_CANARY"),
            "non-allow-listed host env vars must not reach the CLI: {captured}"
        );
        assert!(captured.contains("HOME="), "HOME must be on the allow-list");
    }

    #[test]
    fn run_host_cli_kills_the_process_group_on_timeout_within_reap_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("finished");
        let script = dir.path().join("slow-cli");
        // The grandchild touches its marker after a short, real sleep (not
        // the parent's 30s stall) so this test can actually distinguish a
        // working group-kill from a broken one: we kill well before 1s and
        // then wait past it. If SIGKILL only reached the parent (leaving the
        // detached grandchild alive), the marker would still appear once
        // that 1s elapses; if the whole process group was killed, it never
        // will.
        write_executable_script(
            &script,
            &format!(
                "#!/bin/sh\n(sleep 1; touch '{marker}') &\nsleep 30\n",
                marker = marker.display(),
            ),
        );
        let start = Instant::now();
        let err = run_host_cli(
            script.to_str().unwrap(),
            &[],
            dir.path(),
            Duration::from_millis(200),
        )
        .unwrap_err();
        let elapsed = start.elapsed();
        assert!(err.to_string().contains("timed out"));
        assert!(
            elapsed < Duration::from_secs(5),
            "kill/reap must complete well within the hook timeout budget, took {elapsed:?}"
        );
        // Sleep past the grandchild's 1s mark (accounting for the ~200ms
        // already elapsed above) before checking it never ran.
        std::thread::sleep(
            Duration::from_secs(1).saturating_sub(elapsed) + Duration::from_millis(500),
        );
        assert!(
            !marker.exists(),
            "SIGKILL to the whole process group must also reach the backgrounded grandchild"
        );
    }

    #[test]
    fn run_host_cli_drains_noisy_stderr_without_leaking_it_into_errors() {
        let dir = tempfile::tempdir().unwrap();
        let noisy = dir.path().join("noisy-cli");
        write_executable_script(
            &noisy,
            "#!/bin/sh\nfor i in $(seq 1 5000); do echo \"line $i noisy-stderr-canary\" >&2; done\nexit 0\n",
        );
        run_host_cli(
            noisy.to_str().unwrap(),
            &[],
            dir.path(),
            Duration::from_secs(5),
        )
        .expect("noisy stderr must not block success or the drain thread");

        let failing = dir.path().join("failing-cli");
        write_executable_script(
            &failing,
            "#!/bin/sh\necho 'SECRET-STDERR-CONTENT' >&2\nexit 1\n",
        );
        let err = run_host_cli(
            failing.to_str().unwrap(),
            &[],
            dir.path(),
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(
            !format!("{err:?}").contains("SECRET-STDERR-CONTENT"),
            "operational errors must never include child stderr"
        );
    }

    // ── shared provider-lock coordination ───────────────────────────

    #[test]
    fn refresh_lock_shares_exclusion_with_a_launcher_style_holder() {
        // `secrets::with_provider_lock` (launch capture) and
        // `RefreshLock` (this hook) must lock the exact same path so a
        // launcher cannot race a hook-driven rotation and overwrite a
        // just-installed token with a stale re-read. Model the
        // launcher side directly with `flock` (its actual
        // implementation) rather than depending on `secrets`'s private
        // helper.
        use std::os::fd::AsRawFd as _;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let dir = tempfile::tempdir().unwrap();
        let path = secrets::refresh_lock_path_for(dir.path(), secrets::REFRESH_LOCK_ANTHROPIC);
        secrets::ensure_host_secret_dir(&path).unwrap();
        let launcher_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(launcher_file.as_raw_fd(), libc::LOCK_EX) },
            0,
            "launcher-style holder acquires the lock first"
        );

        let acquired = Arc::new(AtomicBool::new(false));
        let acquired_writer = Arc::clone(&acquired);
        let state_dir = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || {
            let lock = RefreshLock::acquire(
                &state_dir,
                secrets::REFRESH_LOCK_ANTHROPIC,
                Duration::from_secs(2),
            )
            .expect("hook lock eventually acquires once the launcher-style holder releases");
            acquired_writer.store(true, Ordering::SeqCst);
            drop(lock);
        });
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            !acquired.load(Ordering::SeqCst),
            "hook lock must block while the launcher-style holder is alive"
        );
        unsafe {
            libc::flock(launcher_file.as_raw_fd(), libc::LOCK_UN);
        }
        handle.join().unwrap();
        assert!(acquired.load(Ordering::SeqCst));
    }

    #[test]
    fn hook_timeout_contract_has_headroom() {
        let handler =
            include_str!("../../../../vendor/microsandbox/crates/network/lib/intercept/handler.rs");
        assert!(handler.contains("Duration::from_secs(90)"));
        assert!(
            LOCK_CEILING
                + OPENAI_CLI_TIMEOUT
                + POLL_OVERSHOOT
                + REAP_CEILING
                + STDERR_GRACE
                + Duration::from_secs(5)
                < Duration::from_secs(90)
        );
    }
}
