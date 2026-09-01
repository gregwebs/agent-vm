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
use sha2::{Digest, Sha256};

use super::http;
use crate::{
    host_paths::{host_claude_creds_path, host_codex_auth_path},
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
    A: FnOnce(ValidatedRefresh) -> Result<PublicReply>,
{
    let validated = match validate(raw_request, provider_sni) {
        Ok(validated) => validated,
        Err(rejection) => return http::Response::error(rejection.status, &rejection.message),
    };
    response(action(validated)?)
}

fn response(reply: PublicReply) -> Result<http::Response> {
    match reply {
        PublicReply::Anthropic { expires_in, scopes } => http::Response::json(
            200,
            "OK",
            &serde_json::json!({
                "access_token": secrets::ANTHROPIC_ACCESS_PLACEHOLDER,
                "refresh_token": secrets::ANTHROPIC_REFRESH_PLACEHOLDER,
                "expires_in": expires_in,
                "token_type": "Bearer",
                "scope": scopes,
            }),
        ),
        PublicReply::OpenAi => http::Response::json(
            200,
            "OK",
            &serde_json::json!({
                "access_token": secrets::OPENAI_ACCESS_PLACEHOLDER,
                "refresh_token": secrets::OPENAI_REFRESH_PLACEHOLDER,
                "id_token": secrets::OPENAI_ID_PLACEHOLDER,
                "expires_in": 3600,
                "token_type": "Bearer",
            }),
        ),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Provider {
    Anthropic,
    OpenAi,
}

struct ValidatedRefresh {
    provider: Provider,
}

enum PublicReply {
    Anthropic {
        expires_in: i64,
        scopes: Vec<String>,
    },
    OpenAi,
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

fn refresh(state_dir: &Path, validated: ValidatedRefresh) -> Result<PublicReply> {
    match validated.provider {
        Provider::Anthropic => refresh_anthropic(state_dir),
        Provider::OpenAi => refresh_openai(state_dir),
    }
}

fn refresh_anthropic(state_dir: &Path) -> Result<PublicReply> {
    let token_path = secrets::anthropic_token_path(state_dir);
    let before = token_fingerprint(&token_path);
    let (_lock, acquisition) = RefreshLock::acquire(state_dir, secrets::REFRESH_LOCK_ANTHROPIC)?;
    if should_rotate(before, token_fingerprint(&token_path), acquisition) {
        trigger_host_refresh("claude", &["-p", "hi", "--model", "sonnet"])?;
    }
    let path = host_claude_creds_path().context("HOME not set")?;
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    host_credentials::install_anthropic(state_dir, &raw)
        .with_context(|| format!("rotating Anthropic token from {}", path.display()))
}

fn refresh_openai(state_dir: &Path) -> Result<PublicReply> {
    let token_path = secrets::openai_token_path(state_dir);
    let before = token_fingerprint(&token_path);
    let (_lock, acquisition) = RefreshLock::acquire(state_dir, secrets::REFRESH_LOCK_OPENAI)?;
    if should_rotate(before, token_fingerprint(&token_path), acquisition) {
        trigger_host_refresh(
            "codex",
            &[
                "exec",
                "--skip-git-repo-check",
                "--dangerously-bypass-approvals-and-sandbox",
                "Reply with OK",
            ],
        )?;
    }
    let path = host_codex_auth_path().context("HOME not set")?;
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    host_credentials::install_openai(state_dir, &raw)
        .with_context(|| format!("rotating OpenAI token from {}", path.display()))
}

mod host_credentials {
    use super::*;
    use crate::host_paths::atomic_write;

    struct Bearer(String);
    impl Bearer {
        fn consume_into(self, path: &Path) -> Result<()> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            atomic_write(path, self.0.as_bytes(), 0o600)
        }
    }

    pub(super) fn install_anthropic(state_dir: &Path, raw: &str) -> Result<PublicReply> {
        let value: serde_json::Value =
            serde_json::from_str(raw).context("parsing rotated host .credentials.json")?;
        let oauth = value
            .get("claudeAiOauth")
            .context("rotated host .credentials.json missing claudeAiOauth")?;
        let bearer = Bearer(
            oauth
                .get("accessToken")
                .and_then(|value| value.as_str())
                .context("rotated host claudeAiOauth missing accessToken")?
                .to_owned(),
        );
        let expires_in =
            derive_expires_in(oauth.get("expiresAt").unwrap_or(&serde_json::Value::Null));
        let scopes = oauth
            .get("scopes")
            .and_then(|value| value.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        bearer.consume_into(&secrets::anthropic_token_path(state_dir))?;
        Ok(PublicReply::Anthropic { expires_in, scopes })
    }

    pub(super) fn install_openai(state_dir: &Path, raw: &str) -> Result<PublicReply> {
        let value: serde_json::Value =
            serde_json::from_str(raw).context("parsing rotated host codex auth.json")?;
        let bearer = Bearer(
            value
                .pointer("/tokens/access_token")
                .and_then(|value| value.as_str())
                .or_else(|| value.get("OPENAI_API_KEY").and_then(|value| value.as_str()))
                .context("rotated host codex auth missing tokens.access_token or OPENAI_API_KEY")?
                .to_owned(),
        );
        bearer.consume_into(&secrets::openai_token_path(state_dir))?;
        Ok(PublicReply::OpenAi)
    }
}

fn derive_expires_in(expires_at: &serde_json::Value) -> i64 {
    let expires_at_ms = expires_at.as_i64().unwrap_or(0);
    if expires_at_ms == 0 {
        return 3600;
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0);
    let expires_in = (expires_at_ms - now_ms) / 1000;
    if expires_in <= 0 { 3600 } else { expires_in }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenFingerprint {
    Missing,
    Unreadable,
    Sha256([u8; 32]),
}
fn token_fingerprint(path: &Path) -> TokenFingerprint {
    match std::fs::read(path) {
        Ok(bytes) => TokenFingerprint::Sha256(Sha256::digest(bytes).into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => TokenFingerprint::Missing,
        Err(_) => TokenFingerprint::Unreadable,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefreshAcquisition {
    Acquired { contended: bool },
    Degraded,
}
fn should_rotate(
    before: TokenFingerprint,
    after: TokenFingerprint,
    acquisition: RefreshAcquisition,
) -> bool {
    !matches!((before, after, acquisition), (TokenFingerprint::Sha256(before), TokenFingerprint::Sha256(after), RefreshAcquisition::Acquired { contended: true }) if before != after)
}

struct RefreshLock {
    file: Option<std::fs::File>,
}
impl RefreshLock {
    fn acquire(state_dir: &Path, lock_name: &str) -> Result<(Self, RefreshAcquisition)> {
        Self::acquire_with_ceiling(state_dir, lock_name, HOST_REFRESH_TIMEOUT)
    }
    fn acquire_with_ceiling(
        state_dir: &Path,
        lock_name: &str,
        ceiling: Duration,
    ) -> Result<(Self, RefreshAcquisition)> {
        let path = secrets::refresh_lock_path_for(state_dir, lock_name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating secrets dir {}", parent.display()))?;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("opening refresh lock {}", path.display()))?;
        use std::os::unix::io::AsRawFd as _;
        let fd = file.as_raw_fd();
        let start = Instant::now();
        let mut contended = false;
        loop {
            if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok((
                    Self { file: Some(file) },
                    RefreshAcquisition::Acquired { contended },
                ));
            }
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EWOULDBLOCK) => {
                    contended = true;
                    if start.elapsed() >= ceiling {
                        tracing::warn!(lock = %path.display(), "refresh lock contended past {}s; proceeding without single-flight", ceiling.as_secs());
                        return Ok((Self { file: None }, RefreshAcquisition::Degraded));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => {
                    return Err(anyhow::Error::new(std::io::Error::last_os_error())
                        .context(format!("flock(LOCK_EX|LOCK_NB) on {}", path.display())));
                }
            }
        }
    }
}
impl Drop for RefreshLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd as _;
        if let Some(file) = &self.file {
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}
const HOST_REFRESH_TIMEOUT: Duration = Duration::from_secs(90);
fn trigger_host_refresh(cmd: &str, args: &[&str]) -> Result<()> {
    trigger_host_refresh_with_timeout(cmd, args, HOST_REFRESH_TIMEOUT)
}
fn trigger_host_refresh_with_timeout(cmd: &str, args: &[&str], timeout: Duration) -> Result<()> {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("spawning host {cmd}"))?;
    let pid = child.id() as libc::pid_t;
    let stderr = child.stderr.take().expect("stderr was piped");
    let (drained, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut stderr = stderr;
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
        let _ = drained.send(());
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if start.elapsed() >= timeout => {
                #[cfg(unix)]
                unsafe {
                    if libc::kill(-pid, libc::SIGKILL) == -1 {
                        return Err(anyhow::Error::new(std::io::Error::last_os_error())
                            .context(format!("terminating host {cmd} process group")));
                    }
                }
                child
                    .wait()
                    .with_context(|| format!("reaping timed-out host {cmd}"))?;
                let _ = receiver.recv_timeout(Duration::from_millis(100));
                anyhow::bail!(
                    "host {cmd} did not return within {} s; terminated",
                    timeout.as_secs()
                );
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let _ = receiver.recv_timeout(Duration::from_millis(100));
    if !status.success() {
        anyhow::bail!("host {cmd} failed (status {status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };

    fn request(sni: &str, target: &str, content_type: &str, body: &str) -> Vec<u8> {
        format!("POST {target} HTTP/1.1\r\nHost: {sni}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
    }

    fn openai_request() -> Vec<u8> {
        let body = format!(
            "grant_type=refresh_token&refresh_token={}",
            secrets::OPENAI_REFRESH_PLACEHOLDER
        );
        request(
            secrets::OPENAI_OAUTH_HOST,
            secrets::OPENAI_OAUTH_TOKEN_PATH,
            "application/x-www-form-urlencoded",
            &body,
        )
    }

    fn anthropic_request() -> Vec<u8> {
        let body = format!(
            r#"{{"grant_type":"refresh_token","refresh_token":"{}"}}"#,
            secrets::ANTHROPIC_REFRESH_PLACEHOLDER
        );
        request(
            secrets::ANTHROPIC_OAUTH_HOST,
            secrets::ANTHROPIC_OAUTH_TOKEN_PATH,
            "application/json",
            &body,
        )
    }

    fn assert_rejected_without_effects(name: &str, raw: &[u8], sni: &str) {
        let calls = Cell::new(0);
        let response = handle_with(raw, sni, |_| {
            calls.set(calls.get() + 1);
            Ok(PublicReply::OpenAi)
        })
        .unwrap();
        assert_eq!(calls.get(), 0, "{name}");
        let text = std::str::from_utf8(response.as_bytes()).unwrap();
        assert!(
            text.starts_with("HTTP/1.1 400") || text.starts_with("HTTP/1.1 403"),
            "{name}: {text}"
        );
        assert!(!text.contains("VALIDATION_CANARY"), "{name}");
    }

    #[test]
    fn every_invalid_oauth_request_stops_before_the_effect_action() {
        let openai = String::from_utf8(openai_request()).unwrap();
        let anthropic = String::from_utf8(anthropic_request()).unwrap();
        let openai_length = format!(
            "Content-Length: {}",
            openai.split("\r\n\r\n").nth(1).unwrap().len()
        );
        let anthropic_length = format!(
            "Content-Length: {}",
            anthropic.split("\r\n\r\n").nth(1).unwrap().len()
        );
        let cases = vec![
            ("unsupported SNI", openai.clone(), "invalid.test"),
            ("wrong method", openai.replacen("POST ", "GET ", 1), secrets::OPENAI_OAUTH_HOST),
            ("near path", openai.replacen("/oauth/token", "/oauth/token/near", 1), secrets::OPENAI_OAUTH_HOST),
            ("query", openai.replacen("/oauth/token", "/oauth/token?x=1", 1), secrets::OPENAI_OAUTH_HOST),
            ("fragment", openai.replacen("/oauth/token", "/oauth/token#x", 1), secrets::OPENAI_OAUTH_HOST),
            ("backslash", openai.replacen("/oauth/token", "/oauth\\token", 1), secrets::OPENAI_OAUTH_HOST),
            ("HTTP/1.0", openai.replacen("HTTP/1.1", "HTTP/1.0", 1), secrets::OPENAI_OAUTH_HOST),
            ("request-line extra field", openai.replacen("HTTP/1.1", "HTTP/1.1 extra", 1), secrets::OPENAI_OAUTH_HOST),
            ("malformed request line", openai.replacen("POST ", "PO(ST ", 1), secrets::OPENAI_OAUTH_HOST),
            ("malformed header", openai.replacen("Host:", "Broken Header\r\nHost:", 1), secrets::OPENAI_OAUTH_HOST),
            ("missing Host", openai.replacen("Host: auth.openai.com\r\n", "", 1), secrets::OPENAI_OAUTH_HOST),
            ("duplicate Host", openai.replacen("Host: auth.openai.com", "Host: auth.openai.com\r\nHost: auth.openai.com", 1), secrets::OPENAI_OAUTH_HOST),
            ("wrong Host", openai.replacen("Host: auth.openai.com", "Host: attacker.invalid", 1), secrets::OPENAI_OAUTH_HOST),
            ("absolute wrong scheme", openai.replacen("/oauth/token", "http://auth.openai.com/oauth/token", 1), secrets::OPENAI_OAUTH_HOST),
            ("absolute wrong authority", openai.replacen("/oauth/token", "https://attacker.invalid/oauth/token", 1), secrets::OPENAI_OAUTH_HOST),
            ("absolute userinfo", openai.replacen("/oauth/token", "https://attacker@auth.openai.com/oauth/token", 1), secrets::OPENAI_OAUTH_HOST),
            ("absolute port", openai.replacen("/oauth/token", "https://auth.openai.com:444/oauth/token", 1), secrets::OPENAI_OAUTH_HOST),
            ("encoded slash separator", openai.replacen("/oauth/token", "/oauth%2ftoken", 1), secrets::OPENAI_OAUTH_HOST),
            ("encoded dot separator", openai.replacen("/oauth/token", "/oauth%2etoken", 1), secrets::OPENAI_OAUTH_HOST),
            ("encoded backslash separator", openai.replacen("/oauth/token", "/oauth%5ctoken", 1), secrets::OPENAI_OAUTH_HOST),
            ("missing content type", openai.replacen("Content-Type: application/x-www-form-urlencoded\r\n", "", 1), secrets::OPENAI_OAUTH_HOST),
            ("unsupported content type", openai.replacen("application/x-www-form-urlencoded", "text/plain", 1), secrets::OPENAI_OAUTH_HOST),
            ("duplicate content type", openai.replacen("Content-Type: application/x-www-form-urlencoded", "Content-Type: application/x-www-form-urlencoded\r\nContent-Type: application/x-www-form-urlencoded", 1), secrets::OPENAI_OAUTH_HOST),
            ("missing content length", openai.replacen(&format!("{openai_length}\r\n"), "", 1), secrets::OPENAI_OAUTH_HOST),
            ("duplicate content length", openai.replacen(&openai_length, &format!("{openai_length}\r\n{openai_length}"), 1), secrets::OPENAI_OAUTH_HOST),
            ("invalid content length", openai.replacen(&openai_length, "Content-Length: nope", 1), secrets::OPENAI_OAUTH_HOST),
            ("incomplete body", openai.replacen(&openai_length, "Content-Length: 999", 1), secrets::OPENAI_OAUTH_HOST),
            ("transfer encoding", openai.replacen("Content-Length:", "Transfer-Encoding: chunked\r\nContent-Length:", 1), secrets::OPENAI_OAUTH_HOST),
            ("content encoding", openai.replacen("Content-Length:", "Content-Encoding: gzip\r\nContent-Length:", 1), secrets::OPENAI_OAUTH_HOST),
            ("malformed form", openai.replacen("refresh_token=", "refresh_token=%ZZ", 1), secrets::OPENAI_OAUTH_HOST),
            ("duplicate form grant", openai.replacen("grant_type=refresh_token", "grant_type=refresh_token&grant_type=refresh_token", 1), secrets::OPENAI_OAUTH_HOST),
            ("duplicate form token", openai.replacen("refresh_token=", "refresh_token=wrong&refresh_token=", 1), secrets::OPENAI_OAUTH_HOST),
            ("wrong form grant", openai.replacen("grant_type=refresh_token", "grant_type=wrong", 1), secrets::OPENAI_OAUTH_HOST),
            ("wrong OpenAI placeholder", openai.replacen(secrets::OPENAI_REFRESH_PLACEHOLDER, "VALIDATION_CANARY", 1), secrets::OPENAI_OAUTH_HOST),
            ("Anthropic placeholder at OpenAI endpoint", openai.replacen(secrets::OPENAI_REFRESH_PLACEHOLDER, secrets::ANTHROPIC_REFRESH_PLACEHOLDER, 1), secrets::OPENAI_OAUTH_HOST),
            ("malformed JSON", anthropic.replacen("{\"grant", "{not-json\",\"grant", 1), secrets::ANTHROPIC_OAUTH_HOST),
            ("duplicate JSON grant", anthropic.replacen("\"grant_type\":\"refresh_token\"", "\"grant_type\":\"refresh_token\",\"grant_type\":\"refresh_token\"", 1), secrets::ANTHROPIC_OAUTH_HOST),
            ("duplicate JSON token", anthropic.replacen("\"refresh_token\":", "\"refresh_token\":\"wrong\",\"refresh_token\":", 1), secrets::ANTHROPIC_OAUTH_HOST),
            ("wrong JSON grant", anthropic.replacen("\"grant_type\":\"refresh_token\"", "\"grant_type\":\"wrong\"", 1), secrets::ANTHROPIC_OAUTH_HOST),
            ("wrong Anthropic placeholder", anthropic.replacen(secrets::ANTHROPIC_REFRESH_PLACEHOLDER, "VALIDATION_CANARY", 1), secrets::ANTHROPIC_OAUTH_HOST),
            ("OpenAI placeholder at Anthropic endpoint", anthropic.replacen(secrets::ANTHROPIC_REFRESH_PLACEHOLDER, secrets::OPENAI_REFRESH_PLACEHOLDER, 1), secrets::ANTHROPIC_OAUTH_HOST),
            ("OpenCode placeholder at Anthropic endpoint", anthropic.replacen(secrets::ANTHROPIC_REFRESH_PLACEHOLDER, secrets::OPENCODE_OPENAI_REFRESH_PLACEHOLDER, 1), secrets::ANTHROPIC_OAUTH_HOST),
            ("Anthropic missing length", anthropic.replacen(&format!("{anthropic_length}\r\n"), "", 1), secrets::ANTHROPIC_OAUTH_HOST),
        ];
        for (name, raw, sni) in cases {
            assert_rejected_without_effects(name, raw.as_bytes(), sni);
        }
    }

    #[test]
    fn complete_validation_precedes_exactly_one_safe_action() {
        let calls = Cell::new(0);
        let response = handle_with(&openai_request(), secrets::OPENAI_OAUTH_HOST, |_| {
            calls.set(calls.get() + 1);
            Ok(PublicReply::OpenAi)
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        let text = std::str::from_utf8(response.as_bytes()).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains(secrets::OPENAI_ACCESS_PLACEHOLDER));
    }

    #[test]
    fn host_bearers_are_atomically_consumed_into_0600_files_and_exact_safe_replies() {
        for (provider, raw, bearer, path, install, expected) in [
            (
                "anthropic",
                r#"{"claudeAiOauth":{"accessToken":"ANTHROPIC_CANARY","expiresAt":9999999999000,"scopes":["user:inference","user:profile"]}}"#,
                "ANTHROPIC_CANARY",
                secrets::anthropic_token_path as fn(&Path) -> std::path::PathBuf,
                host_credentials::install_anthropic as fn(&Path, &str) -> Result<PublicReply>,
                serde_json::json!({"access_token": secrets::ANTHROPIC_ACCESS_PLACEHOLDER, "refresh_token": secrets::ANTHROPIC_REFRESH_PLACEHOLDER, "token_type": "Bearer", "scope": ["user:inference", "user:profile"]}),
            ),
            (
                "openai",
                r#"{"tokens":{"access_token":"OPENAI_CANARY"}}"#,
                "OPENAI_CANARY",
                secrets::openai_token_path as fn(&Path) -> std::path::PathBuf,
                host_credentials::install_openai as fn(&Path, &str) -> Result<PublicReply>,
                serde_json::json!({"access_token": secrets::OPENAI_ACCESS_PLACEHOLDER, "refresh_token": secrets::OPENAI_REFRESH_PLACEHOLDER, "id_token": secrets::OPENAI_ID_PLACEHOLDER, "expires_in": 3600, "token_type": "Bearer"}),
            ),
        ] {
            let state = tempfile::tempdir().unwrap();
            let token_path = path(state.path());
            std::fs::create_dir_all(token_path.parent().unwrap()).unwrap();
            std::fs::write(&token_path, "old-token").unwrap();
            let old_inode = std::fs::metadata(&token_path).unwrap().ino();
            let framed = response(install(state.path(), raw).unwrap()).unwrap();
            assert_eq!(
                std::fs::read_to_string(&token_path).unwrap(),
                bearer,
                "{provider}"
            );
            assert!(!token_path.starts_with(state.path()));
            let metadata = std::fs::metadata(&token_path).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_ne!(metadata.ino(), old_inode, "{provider} atomic replacement");
            let text = std::str::from_utf8(framed.as_bytes()).unwrap();
            assert!(!text.contains(bearer), "{provider}");
            let body = text.split("\r\n\r\n").nth(1).unwrap();
            let actual: serde_json::Value = serde_json::from_str(body).unwrap();
            for (key, value) in expected.as_object().unwrap() {
                assert_eq!(actual.get(key), Some(value), "{provider} {key}");
            }
            let expected_fields = expected.as_object().unwrap().len();
            if provider == "anthropic" {
                assert_eq!(actual.as_object().unwrap().len(), expected_fields + 1);
                assert!(actual["expires_in"].as_i64().is_some_and(|value| value > 0));
            } else {
                assert_eq!(actual.as_object().unwrap().len(), expected_fields);
            }
        }
    }

    #[test]
    fn credential_failures_and_flat_openai_shape_do_not_leak_host_contents() {
        let state = tempfile::tempdir().unwrap();
        for (name, result) in [
            (
                "invalid Anthropic JSON",
                host_credentials::install_anthropic(state.path(), "ANTHROPIC_ERROR_CANARY"),
            ),
            (
                "missing Anthropic bearer",
                host_credentials::install_anthropic(state.path(), r#"{"claudeAiOauth":{}}"#),
            ),
            (
                "invalid OpenAI JSON",
                host_credentials::install_openai(state.path(), "OPENAI_ERROR_CANARY"),
            ),
            (
                "missing OpenAI bearer",
                host_credentials::install_openai(state.path(), r#"{"tokens":{}}"#),
            ),
        ] {
            let error = match result {
                Ok(_) => panic!("{name} unexpectedly succeeded"),
                Err(error) => error,
            };
            assert!(!error.to_string().contains("CANARY"), "{name}");
        }
        let reply = host_credentials::install_openai(
            state.path(),
            r#"{"OPENAI_API_KEY":"OPENAI_FLAT_CANARY"}"#,
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(secrets::openai_token_path(state.path())).unwrap(),
            "OPENAI_FLAT_CANARY"
        );
        assert!(
            !std::str::from_utf8(response(reply).unwrap().as_bytes())
                .unwrap()
                .contains("OPENAI_FLAT_CANARY")
        );
    }

    #[test]
    fn expires_in_preserves_missing_invalid_expired_and_future_behavior() {
        assert_eq!(derive_expires_in(&serde_json::Value::Null), 3600);
        assert_eq!(
            derive_expires_in(&serde_json::json!("not-a-timestamp")),
            3600
        );
        assert_eq!(derive_expires_in(&serde_json::json!(0)), 3600);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        assert_eq!(derive_expires_in(&serde_json::json!(now_ms - 2_000)), 3600);
        let future = derive_expires_in(&serde_json::json!(now_ms + 300_900));
        assert!((299..=300).contains(&future), "future expiry was {future}");
    }

    #[test]
    fn rotation_decision_matrix_only_skips_contended_changed_token() {
        let before = TokenFingerprint::Sha256([1; 32]);
        let changed = TokenFingerprint::Sha256([2; 32]);
        assert!(!should_rotate(
            before,
            changed,
            RefreshAcquisition::Acquired { contended: true }
        ));
        assert!(should_rotate(
            before,
            changed,
            RefreshAcquisition::Acquired { contended: false }
        ));
        assert!(should_rotate(
            before,
            before,
            RefreshAcquisition::Acquired { contended: true }
        ));
        assert!(should_rotate(
            TokenFingerprint::Missing,
            changed,
            RefreshAcquisition::Acquired { contended: true }
        ));
        assert!(should_rotate(
            TokenFingerprint::Unreadable,
            TokenFingerprint::Unreadable,
            RefreshAcquisition::Degraded
        ));
    }

    #[test]
    fn actual_lock_contention_degrades_only_after_its_ceiling() {
        let state = tempfile::tempdir().unwrap();
        let (_lock, _) = RefreshLock::acquire(state.path(), secrets::REFRESH_LOCK_OPENAI).unwrap();
        let start = Instant::now();
        let (_contender, acquisition) = RefreshLock::acquire_with_ceiling(
            state.path(),
            secrets::REFRESH_LOCK_OPENAI,
            Duration::from_millis(60),
        )
        .unwrap();
        assert_eq!(acquisition, RefreshAcquisition::Degraded);
        assert!(start.elapsed() >= Duration::from_millis(50));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn runner_success_failure_timeout_and_stderr_lifecycle_are_bounded_and_sanitized() {
        trigger_host_refresh_with_timeout("sh", &["-c", "exit 0"], Duration::from_secs(1)).unwrap();
        let error = trigger_host_refresh_with_timeout(
            "sh",
            &["-c", "echo CHILD_CANARY >&2; exit 9"],
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(!error.to_string().contains("CHILD_CANARY"));
        let start = Instant::now();
        let error = trigger_host_refresh_with_timeout(
            "sh",
            &["-c", "while :; do echo NOISY_CANARY >&2; done"],
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(!error.to_string().contains("NOISY_CANARY"));
        let start = Instant::now();
        trigger_host_refresh_with_timeout(
            "sh",
            &["-c", "(sleep 1 >&2) & exit 0"],
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(start.elapsed() < Duration::from_millis(500));
    }
}
