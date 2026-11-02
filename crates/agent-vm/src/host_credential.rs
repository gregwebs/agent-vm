//! Where the Anthropic host credential is, and what it says (#492, ADR-0056).
//!
//! Anthropic has two **host credential locations**: the file
//! `~/.claude/.credentials.json`, and — on macOS — the generic-password item
//! Claude Code keeps its login under. Both are read, the later `expiresAt`
//! wins, and an exact tie keeps the file, so a host whose Claude Code writes
//! only the file observes no change at all. agent-vm never writes either
//! location: the login path it depends on stays the vendor CLI's to own.
//!
//! Selection is a *freshness* heuristic, not a validity check. A later
//! `expiresAt` does not prove a bearer is still accepted, nor that it belongs
//! to the account the user meant. It is the only ordering two opaque blobs
//! offer, and it is right in the case that matters: the location the host CLI
//! refreshed most recently.
//!
//! This module is also the one parser for the credential shape, so a shape
//! change is one edit and one test. Its callers keep their own policy: what to
//! install ([`crate::secrets`]), what to serve
//! ([`crate::intercept_hook::oauth_refresh`]), what to render
//! ([`crate::doctor`]).

use std::path::{Path, PathBuf};
// Only the keychain deadlines below need it, and those are compiled out off
// macOS.
#[cfg(any(target_os = "macos", test))]
use std::time::Duration;

use crate::{
    credential_provider::CredentialProvider,
    host_paths::{MAX_HOST_CREDENTIAL_FILE_BYTES, read_bounded_regular_file},
};

/// The generic-password service Claude Code keeps its login under. Claude Code
/// appends a config-dir hash and an environment suffix to this when
/// `CLAUDE_CONFIG_DIR` (or a non-production environment) is in play; agent-vm
/// reads the default item only, the same limitation its hard-coded
/// `~/.claude/.credentials.json` already has.
pub(crate) const CLAUDE_KEYCHAIN_SERVICE: &str = "Claude Code-credentials";

#[cfg(any(target_os = "macos", test))]
mod mac_keychain;
#[cfg(any(target_os = "macos", test))]
pub(crate) use mac_keychain::KeychainFailure;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Location {
    File(PathBuf),
    /// `account` is the `-a` that matched; `None` when only the bare query did.
    #[cfg(any(target_os = "macos", test))]
    MacKeychain {
        service: &'static str,
        account: Option<String>,
    },
}

impl Location {
    pub(crate) fn is_file(&self) -> bool {
        matches!(self, Location::File(_))
    }

    /// The file location when `$HOME` is unset: the attempt names no path at
    /// all. Nothing renders a loser's path (`doctor` knows the only optional
    /// location is the keychain), and a credential is never built from an
    /// `Err`, so this empty path cannot reach output.
    fn unresolved_file() -> Self {
        Location::File(PathBuf::new())
    }
}

/// How long a keychain read may take: a launch can wait, a proxied request
/// cannot.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ReadBudget {
    Launch,
    Hook,
}

#[cfg(any(target_os = "macos", test))]
pub(crate) const LAUNCH_KEYCHAIN_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(any(target_os = "macos", test))]
pub(crate) const HOOK_KEYCHAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// What one hook keychain read nominally spends: the polling deadline plus the
/// kill/reap and collector grace that follow it.
///
/// It is a *polling/wait budget*, not an absolute wall-clock maximum, and the
/// difference is deliberate. Spawn and OS scheduling are outside it, the runner
/// polls at `POLL_OVERSHOOT` granularity, and it checks for a successful exit
/// before it consults the elapsed time — so a read that answers late but
/// answers is kept rather than discarded to defend a boundary. Two attempts on
/// one request share one deadline, and each attempt still pays its own cleanup:
/// the collectors get one `STDERR_GRACE` each in `finalize`, and the success
/// branch spends one more waiting for stdout before it. Worst case over the two
/// attempts is therefore the deadline, one reap ceiling, four graces (two per
/// attempt) and two poll overshoots (the last poll before the outcome, and the
/// reap loop's own overshoot past `REAP_CEILING`).
/// Test-only because the *budget* is what a caller needs, not this derivation.
#[cfg(test)]
pub(crate) const HOOK_KEYCHAIN_NOMINAL_COST: Duration = HOOK_KEYCHAIN_TIMEOUT
    .saturating_add(crate::host_cli::REAP_CEILING)
    .saturating_add(crate::host_cli::STDERR_GRACE.saturating_mul(4))
    .saturating_add(crate::host_cli::POLL_OVERSHOOT.saturating_mul(2));

/// Why one location yielded no eligible credential.
///
/// `Display` **is** the wording `agent-vm doctor` prints after `UNUSABLE - `,
/// byte-identical to the pre-#492 strings, except for the keychain clause which
/// doctor prefixes itself. No variant can hold a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unusable {
    /// `$HOME` is unset, so the file location does not exist.
    HostPathUnavailable,
    Absent,
    HostCredentialUnreadable {
        why: String,
    },
    HostCredentialMalformed {
        why: String,
    },
    MissingBearer,
    #[cfg(any(target_os = "macos", test))]
    KeychainUnreadable(KeychainFailure),
}

impl std::fmt::Display for Unusable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unusable::HostPathUnavailable => formatter.write_str("no $HOME"),
            Unusable::Absent => formatter.write_str("absent"),
            Unusable::HostCredentialUnreadable { why }
            | Unusable::HostCredentialMalformed { why } => formatter.write_str(why),
            Unusable::MissingBearer => formatter.write_str("claudeAiOauth has no accessToken"),
            #[cfg(any(target_os = "macos", test))]
            Unusable::KeychainUnreadable(failure) => failure.fmt(formatter),
        }
    }
}

impl std::error::Error for Unusable {}

/// What one location's bytes say, before it becomes a credential with a
/// provenance. Both locations share this shape, and this is its only parser.
pub(crate) struct Parsed {
    pub(crate) access_token: String,
    pub(crate) expires_at_ms: Option<i64>,
    /// The `claudeAiOauth` object, for `scopes` and the other passthrough
    /// fields. It also holds the refresh token, hence the redacting `Debug`
    /// below.
    pub(crate) oauth: serde_json::Value,
}

impl Parsed {
    fn into_credential(self, location: Location) -> AnthropicHostCredential {
        AnthropicHostCredential {
            access_token: self.access_token,
            expires_at_ms: self.expires_at_ms,
            oauth: self.oauth,
            location,
        }
    }
}

pub(crate) struct AnthropicHostCredential {
    pub(crate) access_token: String,
    pub(crate) expires_at_ms: Option<i64>,
    pub(crate) oauth: serde_json::Value,
    pub(crate) location: Location,
}

// Hand-written: `oauth` carries a refresh token and `access_token` a bearer,
// and neither may reach a log. `location` and the expiry are what a diagnostic
// needs.
impl std::fmt::Debug for AnthropicHostCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AnthropicHostCredential")
            .field("location", &self.location)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

/// What capture, rotation and doctor all consume. Built only by [`select`], so
/// the impossible "chosen failed but the loser parsed" cannot be constructed.
pub(crate) struct AnthropicHostRead {
    chosen: Result<AnthropicHostCredential, Unusable>,
    file: Result<Option<i64>, Unusable>,
    loser: Option<(Location, Result<Option<i64>, Unusable>)>,
}

impl AnthropicHostRead {
    pub(crate) fn chosen(&self) -> Result<&AnthropicHostCredential, &Unusable> {
        self.chosen.as_ref()
    }

    pub(crate) fn into_chosen(self) -> Result<AnthropicHostCredential, Unusable> {
        self.chosen
    }

    /// The **file** location's own outcome, whichever location won. `doctor`
    /// renders its row from this so one report can never name a winner it also
    /// calls older: both come from one read.
    pub(crate) fn file_outcome(&self) -> &Result<Option<i64>, Unusable> {
        &self.file
    }

    /// The other location's outcome. `Some` exactly when a keychain item exists
    /// — which is also `doctor`'s trigger for appending a source clause.
    pub(crate) fn loser(&self) -> Option<(&Location, &Result<Option<i64>, Unusable>)> {
        self.loser
            .as_ref()
            .map(|(location, outcome)| (location, outcome))
    }
}

/// One location's attempt.
struct Candidate {
    location: Location,
    outcome: Result<Parsed, Unusable>,
}

impl Candidate {
    fn summary(&self) -> Result<Option<i64>, Unusable> {
        self.outcome
            .as_ref()
            .map(|parsed| parsed.expires_at_ms)
            .map_err(Clone::clone)
    }

    fn into_credential(self) -> Result<AnthropicHostCredential, Unusable> {
        self.outcome
            .map(|parsed| parsed.into_credential(self.location))
    }
}

/// Both locations, freshest wins. The only Anthropic host-credential reader;
/// there is deliberately no file-only variant, because a caller that read the
/// file alone would answer with a credential the fresher location contradicts.
pub(crate) fn read_anthropic(budget: ReadBudget) -> AnthropicHostRead {
    let provider = CredentialProvider::Anthropic;
    let keychain = provider
        .host_keychain_service()
        .and_then(|service| keychain_candidate(service, budget));
    select(file_candidate(provider.host_credential_path()), keychain)
}

#[cfg(target_os = "macos")]
fn keychain_candidate(service: &'static str, budget: ReadBudget) -> Option<Candidate> {
    mac_keychain::read(service, budget)
}

/// Off macOS the keychain location does not exist, so [`read_anthropic`]
/// degenerates to the file read.
#[cfg(not(target_os = "macos"))]
fn keychain_candidate(_service: &'static str, _budget: ReadBudget) -> Option<Candidate> {
    None
}

fn file_candidate(path: Option<PathBuf>) -> Candidate {
    let Some(path) = path else {
        return Candidate {
            location: Location::unresolved_file(),
            outcome: Err(Unusable::HostPathUnavailable),
        };
    };
    let outcome = read_file(&path).and_then(|bytes| parse_anthropic(&bytes));
    Candidate {
        location: Location::File(path),
        outcome,
    }
}

fn select(file: Candidate, keychain: Option<Candidate>) -> AnthropicHostRead {
    let file_outcome = file.summary();
    let Some(keychain) = keychain else {
        return AnthropicHostRead {
            chosen: file.into_credential(),
            file: file_outcome,
            loser: None,
        };
    };
    let keychain_outcome = keychain.summary();
    let (chosen, loser) = if keychain_beats(&file_outcome, &keychain_outcome) {
        (
            keychain.into_credential(),
            (file.location.clone(), file_outcome.clone()),
        )
    } else {
        (
            file.into_credential(),
            (keychain.location.clone(), keychain_outcome),
        )
    };
    AnthropicHostRead {
        chosen,
        file: file_outcome,
        loser: Some(loser),
    }
}

/// Eligibility first, then freshness. A failed keychain never displaces a file
/// that parsed, and when neither parses the file's reason is the one reported —
/// that keeps the hook's 503 vocabulary exactly today's on a macOS host whose
/// keychain merely fails.
fn keychain_beats(
    file: &Result<Option<i64>, Unusable>,
    keychain: &Result<Option<i64>, Unusable>,
) -> bool {
    match (file, keychain) {
        (_, Err(_)) => false,
        (Err(_), Ok(_)) => true,
        // Strict: an exact tie keeps the file, so a host that parses both today
        // and gains nothing from the keychain keeps today's answer.
        (Ok(file), Ok(keychain)) => freshness(*keychain) > freshness(*file),
    }
}

/// An absent — or unparsable — expiry is the oldest possible credential.
fn freshness(expires_at_ms: Option<i64>) -> i64 {
    expires_at_ms.unwrap_or(i64::MIN)
}

/// `symlink_metadata` first so "absent" stays distinct from "unreadable":
/// `doctor` has always rendered those two differently.
pub(crate) fn read_file(path: &Path) -> Result<Vec<u8>, Unusable> {
    if std::fs::symlink_metadata(path).is_err() {
        return Err(Unusable::Absent);
    }
    read_bounded_regular_file(path, MAX_HOST_CREDENTIAL_FILE_BYTES).map_err(|error| {
        Unusable::HostCredentialUnreadable {
            why: format!("{error:#}"),
        }
    })
}

/// A candidate is eligible when its bytes parse **and**
/// `claudeAiOauth.accessToken` is a non-empty string. An expired token is still
/// eligible: expiry only orders candidates, and the hook decides serve, rotate
/// or fail from the chosen one, as it always has.
pub(crate) fn parse_anthropic(bytes: &[u8]) -> Result<Parsed, Unusable> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| Unusable::HostCredentialMalformed {
            why: format!("not valid JSON: {error}"),
        })?;
    let Some(oauth) = value.get("claudeAiOauth") else {
        return Err(Unusable::HostCredentialMalformed {
            why: "missing claudeAiOauth (API-key-only login?)".into(),
        });
    };
    let Some(access_token) = oauth
        .get("accessToken")
        .and_then(serde_json::Value::as_str)
        .filter(|token| !token.is_empty())
    else {
        return Err(Unusable::MissingBearer);
    };
    Ok(Parsed {
        access_token: access_token.to_string(),
        expires_at_ms: expires_at_ms(oauth.get("expiresAt")),
        oauth: oauth.clone(),
    })
}

/// Epoch milliseconds from a JSON number, if it is a positive one.
///
/// Shared with OpenAI's JWT `exp`, so it must accept the shapes a hand-written
/// producer emits: an unsigned integer above `i64::MAX` (which serde cannot
/// report through `as_i64`), a float, a far-future value. Anything unusable — a
/// string, an array, zero, a negative, NaN/infinity, an overflow — is "no
/// expiry" rather than an error, because every caller already has a policy for a
/// missing one and none of them can do better with a reason.
pub(crate) fn expires_at_ms(value: Option<&serde_json::Value>) -> Option<i64> {
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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn file_location() -> Location {
        Location::File(PathBuf::from("/h/.claude/.credentials.json"))
    }

    fn keychain_location() -> Location {
        Location::MacKeychain {
            service: CLAUDE_KEYCHAIN_SERVICE,
            account: Some("claude".into()),
        }
    }

    fn candidate(location: Location, access_token: &str, expires_at_ms: Option<i64>) -> Candidate {
        Candidate {
            location,
            outcome: Ok(Parsed {
                access_token: access_token.to_string(),
                expires_at_ms,
                oauth: serde_json::json!({}),
            }),
        }
    }

    /// `Result::unwrap_err` would need `Debug` on [`Parsed`], which holds a
    /// bearer and deliberately has none.
    fn parse_error(bytes: &[u8]) -> Unusable {
        parse_anthropic(bytes)
            .err()
            .expect("the fixture is not a usable credential")
    }

    fn failed(location: Location, reason: Unusable) -> Candidate {
        Candidate {
            location,
            outcome: Err(reason),
        }
    }

    fn chosen_token(read: &AnthropicHostRead) -> String {
        read.chosen()
            .expect("the fixture chose an eligible credential")
            .access_token
            .clone()
    }

    /// T1: the §3 selection table. Freshness orders candidates, a tie keeps the
    /// file, and a failed keychain never displaces a file that parsed.
    #[test]
    fn freshest_wins_and_a_tie_keeps_the_file() {
        // No keychain item: the file, and no loser to render.
        let read = select(candidate(file_location(), "FILE", Some(10)), None);
        assert_eq!(read.chosen().unwrap().location, file_location());
        assert_eq!(chosen_token(&read), "FILE");
        assert!(read.loser().is_none());

        // Keychain later: keychain wins, file (with its expiry) is the loser.
        let read = select(
            candidate(file_location(), "FILE", Some(10)),
            Some(candidate(keychain_location(), "KEYCHAIN", Some(20))),
        );
        assert_eq!(chosen_token(&read), "KEYCHAIN");
        assert_eq!(read.chosen().unwrap().location, keychain_location());
        assert_eq!(read.file_outcome(), &Ok(Some(10)));
        assert_eq!(read.loser().unwrap().1, &Ok(Some(10)));

        // File later: file wins. Guards the "keychain always wins" mistake.
        let read = select(
            candidate(file_location(), "FILE", Some(20)),
            Some(candidate(keychain_location(), "KEYCHAIN", Some(10))),
        );
        assert_eq!(chosen_token(&read), "FILE");
        assert_eq!(read.loser().unwrap().1, &Ok(Some(10)));

        // Exact tie keeps the file.
        let read = select(
            candidate(file_location(), "FILE", Some(10)),
            Some(candidate(keychain_location(), "KEYCHAIN", Some(10))),
        );
        assert_eq!(chosen_token(&read), "FILE");

        // An unparsable expiry sorts as `i64::MIN`, both ways.
        let read = select(
            candidate(file_location(), "FILE", None),
            Some(candidate(keychain_location(), "KEYCHAIN", Some(1))),
        );
        assert_eq!(chosen_token(&read), "KEYCHAIN");
        assert_eq!(read.file_outcome(), &Ok(None));
        let read = select(
            candidate(file_location(), "FILE", Some(1)),
            Some(candidate(keychain_location(), "KEYCHAIN", None)),
        );
        assert_eq!(chosen_token(&read), "FILE");

        // An expired-but-parseable file is still eligible, so it loses only on
        // freshness — never on expiry.
        let read = select(
            candidate(file_location(), "FILE", Some(1)),
            Some(candidate(keychain_location(), "KEYCHAIN", Some(2))),
        );
        assert_eq!(chosen_token(&read), "KEYCHAIN");

        // A readable keychain beats an unusable file.
        let read = select(
            failed(file_location(), Unusable::Absent),
            Some(candidate(keychain_location(), "KEYCHAIN", Some(5))),
        );
        assert_eq!(chosen_token(&read), "KEYCHAIN");
        assert_eq!(read.file_outcome(), &Err(Unusable::Absent));

        // A failed keychain leaves the file alone, and the failure is rendered
        // rather than swallowed.
        let read = select(
            candidate(file_location(), "FILE", Some(5)),
            Some(failed(
                keychain_location(),
                Unusable::KeychainUnreadable(KeychainFailure::TimedOut(HOOK_KEYCHAIN_TIMEOUT)),
            )),
        );
        assert_eq!(chosen_token(&read), "FILE");
        assert!(matches!(
            read.loser().unwrap().1,
            Err(Unusable::KeychainUnreadable(_))
        ));

        // Neither usable: the file's reason is the one reported.
        let read = select(
            failed(file_location(), Unusable::Absent),
            Some(failed(
                keychain_location(),
                Unusable::KeychainUnreadable(KeychainFailure::Oversized),
            )),
        );
        assert_eq!(read.chosen().unwrap_err(), &Unusable::Absent);
        assert_eq!(read.file_outcome(), &Err(Unusable::Absent));
    }

    /// The selection rule restated in the test's own terms, deliberately without
    /// calling the production `freshness` helper: a shared wrong mapping (say,
    /// ranking `None` below `Some(i64::MIN)`) would otherwise pass on both sides
    /// and prove nothing. `None` ranks *equal* to `Some(i64::MIN)`, and a strict
    /// `>` keeps the file on any tie.
    fn expected_token(file: Option<i64>, keychain: Option<i64>) -> &'static str {
        match (file, keychain) {
            (Some(file), Some(keychain)) if keychain > file => "KEYCHAIN",
            (None, Some(keychain)) if keychain > i64::MIN => "KEYCHAIN",
            _ => "FILE",
        }
    }

    /// `None` and `Some(i64::MIN)` must be indistinguishable to the ordering, in
    /// every combination, including the extreme values and both tie directions.
    #[test]
    fn an_unknown_expiry_ranks_with_i64_min_and_ties_keep_the_file() {
        let cases: [(Option<i64>, Option<i64>, &str); 10] = [
            (None, None, "FILE"),
            (None, Some(i64::MIN), "FILE"),
            (Some(i64::MIN), None, "FILE"),
            (Some(i64::MIN), Some(i64::MIN), "FILE"),
            (None, Some(i64::MIN + 1), "KEYCHAIN"),
            (Some(i64::MIN), Some(i64::MIN + 1), "KEYCHAIN"),
            (Some(i64::MAX), None, "FILE"),
            (None, Some(i64::MAX), "KEYCHAIN"),
            (Some(i64::MAX), Some(i64::MAX), "FILE"),
            (Some(i64::MAX - 1), Some(i64::MAX), "KEYCHAIN"),
        ];
        for (file, keychain, expected) in cases {
            let read = select(
                candidate(file_location(), "FILE", file),
                Some(candidate(keychain_location(), "KEYCHAIN", keychain)),
            );
            assert_eq!(chosen_token(&read), expected, "{file:?} vs {keychain:?}");
            // The file's own outcome is the file's, whichever location won.
            assert_eq!(read.file_outcome(), &Ok(file));
            let (loser_location, loser) = read.loser().unwrap();
            let loser = *loser.as_ref().expect("both candidates parsed");
            assert_eq!(loser, if expected == "FILE" { keychain } else { file });
            let expected_loser = if expected == "FILE" {
                keychain_location()
            } else {
                file_location()
            };
            assert_eq!(loser_location, &expected_loser);
            // The rule from the other side: swapping which expiry sits in which
            // location swaps the winner too, so the outcome follows the expiry
            // rather than the location. On a tie the file wins both ways, which
            // is the tie rule itself.
            let swapped = select(
                candidate(file_location(), "FILE", keychain),
                Some(candidate(keychain_location(), "KEYCHAIN", file)),
            );
            assert_eq!(
                chosen_token(&swapped),
                expected_token(keychain, file),
                "swapped {file:?} vs {keychain:?}"
            );
        }
    }

    // T2 (11a): over arbitrary expiries — including the unknown one — the chosen
    // identity matches the rule restated above, the chosen credential is never
    // older than the loser, and the loss is exactly the other candidate.
    proptest! {
        #[test]
        fn the_chosen_credential_is_never_older_than_the_loser(
            file_expiry in prop_oneof![Just(None), any::<i64>().prop_map(Some)],
            keychain_expiry in prop_oneof![Just(None), any::<i64>().prop_map(Some)],
        ) {
            let read = select(
                candidate(file_location(), "FILE", file_expiry),
                Some(candidate(keychain_location(), "KEYCHAIN", keychain_expiry)),
            );
            let expected = expected_token(file_expiry, keychain_expiry);
            prop_assert_eq!(chosen_token(&read), expected);
            let (_, loser) = read.loser().unwrap();
            let loser = *loser.as_ref().expect("both candidates parsed");
            prop_assert_eq!(loser, if expected == "FILE" { keychain_expiry } else { file_expiry });
            prop_assert_eq!(read.chosen().unwrap().expires_at_ms, if expected == "FILE" { file_expiry } else { keychain_expiry });
            prop_assert_eq!(read.file_outcome(), &Ok(file_expiry));
            // "Never older", stated without the production ranking helper.
            match (read.chosen().unwrap().expires_at_ms, loser) {
                (Some(chosen), Some(loser)) => prop_assert!(chosen >= loser),
                (Some(_), None) => prop_assert!(true),
                // An unknown chosen expiry can only be "not older" than a loser
                // that is itself the minimum.
                (None, Some(loser)) => prop_assert_eq!(loser, i64::MIN),
                (None, None) => prop_assert!(true),
            }
        }
    }

    /// T3: each rejected shape carries the exact wording doctor prints, which is
    /// why `Display` is the doctor string and not a paraphrase.
    #[test]
    fn parse_rejects_each_shape_with_the_doctor_wording() {
        let malformed = parse_error(b"not valid json {{{");
        assert!(
            matches!(&malformed, Unusable::HostCredentialMalformed { why } if why.starts_with("not valid JSON: ")),
            "{malformed:?}"
        );
        assert_eq!(
            parse_error(br#"{"other":1}"#).to_string(),
            "missing claudeAiOauth (API-key-only login?)"
        );
        for bytes in [
            br#"{"claudeAiOauth":{}}"#.as_slice(),
            br#"{"claudeAiOauth":{"accessToken":""}}"#.as_slice(),
            br#"{"claudeAiOauth":{"accessToken":42}}"#.as_slice(),
        ] {
            assert_eq!(
                parse_error(bytes),
                Unusable::MissingBearer,
                "{}",
                String::from_utf8_lossy(bytes)
            );
        }
        assert_eq!(
            Unusable::MissingBearer.to_string(),
            "claudeAiOauth has no accessToken"
        );
        assert_eq!(Unusable::Absent.to_string(), "absent");
        assert_eq!(Unusable::HostPathUnavailable.to_string(), "no $HOME");

        let parsed = parse_anthropic(
            br#"{"claudeAiOauth":{"accessToken":"TOKEN","expiresAt":99,"scopes":["user:inference"]}}"#,
        )
        .unwrap();
        assert_eq!(parsed.access_token, "TOKEN");
        assert_eq!(parsed.expires_at_ms, Some(99));
        assert_eq!(parsed.oauth.get("scopes").unwrap()[0], "user:inference");
    }

    /// T4: the expiry reader, moved here unchanged from the hook.
    #[test]
    fn expiry_parse_is_unchanged() {
        // Unsigned above `i64::MAX` arrives as a float or `as_u64`.
        assert_eq!(
            expires_at_ms(Some(&serde_json::json!(1_700_000_000_000u64))),
            Some(1_700_000_000_000)
        );
        assert_eq!(expires_at_ms(Some(&serde_json::json!(1.9))), Some(1));
        assert_eq!(expires_at_ms(Some(&serde_json::json!(0))), None);
        assert_eq!(expires_at_ms(Some(&serde_json::json!(-5))), None);
        assert_eq!(expires_at_ms(Some(&serde_json::json!(f64::INFINITY))), None);
        assert_eq!(expires_at_ms(Some(&serde_json::json!("99"))), None);
        assert_eq!(expires_at_ms(None), None);
        assert_eq!(expires_at_ms(Some(&serde_json::json!(u64::MAX))), None);
    }

    /// T8: neither a bearer nor a refresh token may reach a log.
    #[test]
    fn credential_debug_redacts_tokens() {
        let parsed = parse_anthropic(
            br#"{"claudeAiOauth":{"accessToken":"ACCESS-CANARY","refreshToken":"REFRESH-CANARY","expiresAt":7}}"#,
        )
        .unwrap();
        let printed = format!("{:?}", parsed.into_credential(file_location()));
        assert!(!printed.contains("ACCESS-CANARY"), "{printed}");
        assert!(!printed.contains("REFRESH-CANARY"), "{printed}");
        assert!(printed.contains("expires_at_ms: Some(7)"), "{printed}");
    }

    /// The file location's three readable outcomes, and the unreadable one,
    /// against a real filesystem.
    #[test]
    fn the_file_location_distinguishes_absent_from_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent");
        assert_eq!(read_file(&missing).unwrap_err(), Unusable::Absent);
        // A directory is present but not a regular file: `unreadable`, which is
        // the distinction `doctor` renders.
        assert!(matches!(
            read_file(dir.path()).unwrap_err(),
            Unusable::HostCredentialUnreadable { .. }
        ));
        let present = dir.path().join("present");
        std::fs::write(&present, b"{}").unwrap();
        assert_eq!(read_file(&present).unwrap(), b"{}");
    }

    /// T9/R10: off macOS the keychain is never consulted, whatever `PATH` says.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn the_keychain_is_never_consulted_off_macos() {
        let mut env = crate::test_env::guard();
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("security-was-run");
        let fake = dir.path().join("security");
        std::fs::write(
            &fake,
            format!("#!/bin/sh\ntouch '{}'\nexit 44\n", marker.display()),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        env.set_var("HOME", dir.path());
        env.set_var("AGENT_VM_TEST_SECURITY", &fake);
        env.set_var("USER", "agentvm-test-user");
        let read = read_anthropic(ReadBudget::Launch);
        assert!(read.chosen().is_err(), "no credential file exists here");
        assert!(read.loser().is_none(), "no keychain location off macOS");
        assert!(!marker.exists(), "the keychain must never be consulted");
    }
}
