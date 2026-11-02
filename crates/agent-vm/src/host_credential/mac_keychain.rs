//! The macOS keychain item Claude Code keeps its login in (#492, ADR-0056).
//!
//! Read by spawning `security`, not through the Security framework or the
//! `keyring` crate: the item's ACL trusts the binary that created it,
//! `/usr/bin/security`, because Claude Code spawns that binary for every read
//! and write. A read from any other binary blocks on a consent dialog — the
//! reporter measured 25 s through `keyring` — and a proxy hook must never do
//! that. `security`'s own latency is bounded by the deadline below.

use std::{
    io::ErrorKind,
    path::Path,
    time::{Duration, Instant},
};

use super::{
    Candidate, HOOK_KEYCHAIN_TIMEOUT, LAUNCH_KEYCHAIN_TIMEOUT, Location, ReadBudget, Unusable,
};
use crate::host_cli::{self, Failure};
use crate::host_paths::MAX_HOST_CREDENTIAL_FILE_BYTES;

/// Resolved on `PATH`: the same seam OAuth rotation uses for `claude`/`codex`.
const SECURITY: &str = "security";

/// `errSecItemNotFound` as the `security` CLI reports it.
const ITEM_NOT_FOUND_STATUS: i32 = 44;

/// Why one keychain read produced nothing. Never carries child output: stderr
/// is drained unread and stdout is either a parsed credential or discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeychainFailure {
    /// Reports the budget, not the elapsed time: the budget is what the reader
    /// asked for and what the operator can look up.
    TimedOut(Duration),
    Exit(Option<i32>),
    Oversized,
    Unreadable,
}

impl std::fmt::Display for KeychainFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeychainFailure::TimedOut(budget) => write!(
                formatter,
                "timed out after {}s (is the login keychain locked?)",
                budget.as_secs()
            ),
            KeychainFailure::Exit(Some(status)) => {
                write!(formatter, "`{SECURITY}` exited with status {status}")
            }
            KeychainFailure::Exit(None) => {
                write!(formatter, "`{SECURITY}` was killed by a signal")
            }
            KeychainFailure::Oversized => {
                write!(
                    formatter,
                    "item exceeds {MAX_HOST_CREDENTIAL_FILE_BYTES} bytes"
                )
            }
            KeychainFailure::Unreadable => {
                write!(formatter, "`{SECURITY}` output was not readable")
            }
        }
    }
}

enum Lookup {
    Found(Vec<u8>),
    /// No item for this query. Not a failure: `doctor` must stay byte-identical
    /// on a host without the item.
    Absent,
    Failed(KeychainFailure),
}

pub(super) fn read(service: &'static str, budget: ReadBudget) -> Option<Candidate> {
    // A unit build must never reach a developer's real login item, so `cfg(test)`
    // names the program explicitly and has *no* candidate when the variable is
    // unset: `PATH` cannot supply one. Integration tests are not `cfg(test)` and
    // keep the `PATH` seam; their fake `HOME` already hides the real item,
    // because `security` resolves `$HOME/Library/Keychains/login.keychain-db`.
    #[cfg(test)]
    let program = std::env::var("AGENT_VM_TEST_SECURITY").ok()?;
    // Owned in both builds so one binding serves both `cfg`s.
    #[cfg(not(test))]
    let program = SECURITY.to_owned();
    let timeout = match budget {
        ReadBudget::Launch => LAUNCH_KEYCHAIN_TIMEOUT,
        ReadBudget::Hook => HOOK_KEYCHAIN_TIMEOUT,
    };
    // One deadline across both attempts: a locked keychain must not cost two
    // full timeouts on a single proxied request.
    let deadline = Instant::now() + timeout;
    let account = crate::user::host_account_name();
    // Account-qualified first, because `security` matches any account when `-a`
    // is omitted; the bare query is only the fallback for a miss.
    let (account, found) = match lookup(&program, service, Some(&account), deadline, timeout) {
        Lookup::Absent => (None, lookup(&program, service, None, deadline, timeout)),
        other => (Some(account), other),
    };
    let outcome = match found {
        Lookup::Found(bytes) => super::parse_anthropic(&bytes),
        Lookup::Absent => return None,
        Lookup::Failed(failure) => Err(Unusable::KeychainUnreadable(failure)),
    };
    Some(Candidate {
        location: Location::MacKeychain { service, account },
        outcome,
    })
}

fn lookup(
    program: &str,
    service: &str,
    account: Option<&str>,
    deadline: Instant,
    budget: Duration,
) -> Lookup {
    let Some(remaining) = remaining_budget(deadline, Instant::now()) else {
        return Lookup::Failed(KeychainFailure::TimedOut(budget));
    };
    let mut args = vec!["find-generic-password"];
    if let Some(account) = account {
        args.extend(["-a", account]);
    }
    args.extend(["-w", "-s", service]);
    match host_cli::run_capturing_stdout(
        program,
        &args,
        // `security` reads no relative path, and the hook's cwd is not ours to
        // rely on.
        Path::new("/"),
        remaining,
        // The cap is on the *item*. `-w` adds one newline of presentation, so
        // collecting one byte past the item cap is what keeps an item of exactly
        // the cap size from being rejected, while the nominal cap is still
        // enforced on what the item actually holds.
        MAX_HOST_CREDENTIAL_FILE_BYTES.saturating_add(1),
    ) {
        Ok(bytes) => {
            let item = without_presentation_newline(bytes);
            if item.len() as u64 <= MAX_HOST_CREDENTIAL_FILE_BYTES {
                Lookup::Found(item)
            } else {
                Lookup::Failed(KeychainFailure::Oversized)
            }
        }
        // "No item" and "no `security`" are the same answer to the caller: both
        // leave the file location to decide, and both keep `doctor`
        // byte-identical on a host that has neither.
        Err(Failure::Exit(Some(ITEM_NOT_FOUND_STATUS)) | Failure::Spawn(ErrorKind::NotFound)) => {
            Lookup::Absent
        }
        Err(Failure::TimedOut) => Lookup::Failed(KeychainFailure::TimedOut(budget)),
        Err(Failure::Oversized) => Lookup::Failed(KeychainFailure::Oversized),
        Err(Failure::Exit(status)) => Lookup::Failed(KeychainFailure::Exit(status)),
        Err(_) => Lookup::Failed(KeychainFailure::Unreadable),
    }
}

/// What one lookup may spend: the remainder of the deadline both attempts share,
/// or nothing when it is already spent. Split out so the sharing rule is pinned
/// without measuring anything.
fn remaining_budget(deadline: Instant, now: Instant) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(now);
    (!remaining.is_zero()).then_some(remaining)
}

/// `security -w` appends exactly one newline to the item's own data. At most one
/// is removed, so item data that itself ends in a newline keeps it — two on the
/// wire, one retained.
fn without_presentation_newline(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_credential::{HOOK_KEYCHAIN_NOMINAL_COST, Parsed};

    /// A fake `security`: logs its argv to `<dir>/security.log`, then runs
    /// `body`.
    ///
    /// Each argument is logged wrapped in `<>` so the log keeps the argument
    /// boundaries. `"$*"` joins with spaces, which makes `-s Claude
    /// Code-credentials` (one argument) indistinguishable from the same text sent
    /// as two — and the service name's space is precisely what a wrong query
    /// would get wrong.
    fn fake_security(dir: &Path, body: &str) -> std::path::PathBuf {
        let log = dir.join("security.log");
        let script = dir.join("security");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nfor a in \"$@\"; do printf '<%s>' \"$a\"; done >> '{log}'\n\
                 printf '\\n' >> '{log}'\n{body}\n",
                log = log.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    fn calls(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("security.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn blob(token: &str, expires_at_ms: Option<i64>) -> String {
        match expires_at_ms {
            Some(expiry) => {
                format!(r#"{{"claudeAiOauth":{{"accessToken":"{token}","expiresAt":{expiry}}}}}"#)
            }
            None => format!(r#"{{"claudeAiOauth":{{"accessToken":"{token}"}}}}"#),
        }
    }

    fn credential(candidate: Option<Candidate>) -> Result<Parsed, Unusable> {
        candidate.expect("an item exists").outcome
    }

    /// `Result::unwrap_err` would need `Debug` on `Parsed`, which holds a bearer
    /// and must not have one.
    fn failure(candidate: Option<Candidate>) -> Unusable {
        credential(candidate).err().expect("the item is unusable")
    }

    /// T5: the account-qualified query comes first, and a miss falls through to
    /// the bare one — with both inside a single deadline, and with the complete
    /// argv both times.
    ///
    /// The comparison is element-by-element, not by substring: the service name
    /// contains a space, so a reader that split it into two arguments would send
    /// `-s Claude Code-credentials` — the same text, one argument fewer — and a
    /// substring or `"$*"` check could not tell the two apart.
    #[test]
    fn read_uses_the_account_then_retries_bare() {
        let mut env = crate::test_env::guard();
        let dir = tempfile::tempdir().unwrap();
        let json = blob("KEYCHAIN_TOKEN", Some(1_700_000_000_000));
        let script = fake_security(
            dir.path(),
            // Miss for the account-qualified form only, decided on the delimited
            // arguments rather than on `"$*"`.
            &format!(
                "line=\nfor a in \"$@\"; do line=\"$line<$a>\"; done\n\
                 case \"$line\" in *'<-a><agentvm-test-user><-w>'*) exit 44 ;; esac\n\
                 printf '%s\\n' '{json}'\n"
            ),
        );
        env.set_var("AGENT_VM_TEST_SECURITY", &script);
        env.set_var("USER", "agentvm-test-user");

        let candidate = read("Claude Code-credentials", ReadBudget::Launch)
            .expect("the bare query finds the item");
        assert_eq!(
            candidate.location,
            Location::MacKeychain {
                service: "Claude Code-credentials",
                account: None,
            }
        );
        assert_eq!(
            credential(Some(candidate)).unwrap().access_token,
            "KEYCHAIN_TOKEN"
        );

        assert_eq!(
            calls(dir.path()),
            [
                "<find-generic-password><-a><agentvm-test-user><-w><-s><Claude Code-credentials>",
                "<find-generic-password><-w><-s><Claude Code-credentials>",
            ],
            "the qualified query, then the bare one, each as one argument per element"
        );
    }

    /// One raw lookup against `script`, with a budget nothing here can exhaust.
    fn raw_lookup(script: &Path, account: Option<&str>) -> Lookup {
        let budget = Duration::from_secs(5);
        lookup(
            script.to_str().unwrap(),
            "Claude Code-credentials",
            account,
            Instant::now() + budget,
            budget,
        )
    }

    /// The item's bytes as [`lookup`] reports them, for the byte-level
    /// assertions `Lookup::Found` cannot otherwise be made on.
    fn found(lookup: Lookup) -> Vec<u8> {
        match lookup {
            Lookup::Found(bytes) => bytes,
            Lookup::Absent => panic!("expected the item, got `absent`"),
            Lookup::Failed(failure) => panic!("expected the item, got {failure}"),
        }
    }

    /// F09: the trim is asserted on the raw bytes, before any parse. serde accepts
    /// trailing whitespace *outside* the JSON string, so a parsed-value assertion
    /// passes with or without the trim and proves nothing about it.
    ///
    /// These are byte-layer rules for the adapter. The real CLI presents data as
    /// plaintext only when it is printable ASCII (otherwise it hex-encodes it —
    /// see `real_security_contract_in_a_disposable_keychain`), so the
    /// "data that ends in a newline" case below is the rule the trim must obey,
    /// not something `security -w` would hand the reader as plaintext.
    #[test]
    fn exactly_one_presentation_newline_is_trimmed_from_the_raw_bytes() {
        let dir = tempfile::tempdir().unwrap();

        // No newline at all (not what `security -w` does, but the trim must not
        // depend on there being one): the bytes pass through untouched.
        let bare = fake_security(dir.path(), "printf '%s' 'ITEM'");
        assert_eq!(found(raw_lookup(&bare, None)), b"ITEM");

        // Exactly what `security -w` does: one added newline, removed.
        let one = fake_security(dir.path(), "printf '%s\\n' 'ITEM'");
        assert_eq!(found(raw_lookup(&one, None)), b"ITEM");

        // Item data that itself ends in a newline: two on the wire, one retained.
        let two = fake_security(dir.path(), "printf '%s\\n\\n' 'ITEM'");
        assert_eq!(found(raw_lookup(&two, None)), b"ITEM\n");

        // Only a newline at the very end is presentation; one inside the data is
        // the item's own byte.
        let inner = fake_security(dir.path(), "printf '%s\\n' 'IT\nEM'");
        assert_eq!(found(raw_lookup(&inner, None)), b"IT\nEM");
    }

    /// F04: the 1 MiB cap is on the *item*. `security -w` adds a newline of
    /// presentation after the data, so a cap-sized item arrives one byte over the
    /// cap and used to be rejected as oversized.
    #[test]
    fn the_cap_is_on_the_item_not_on_the_presentation_newline() {
        let dir = tempfile::tempdir().unwrap();
        let cap = MAX_HOST_CREDENTIAL_FILE_BYTES as usize;

        // Valid credential JSON padded to exactly the cap.
        let exactly = padded_credential(cap);
        assert_eq!(exactly.len(), cap);

        let item = dir.path().join("exactly-cap.json");
        std::fs::write(&item, &exactly).unwrap();
        let with_newline = fake_security(
            dir.path(),
            &format!("/bin/cat '{}'\nprintf '\\n'\n", item.display()),
        );
        let bytes = found(raw_lookup(&with_newline, None));
        assert_eq!(bytes.len(), cap, "the cap-sized item itself was collected");
        assert_eq!(bytes, exactly);
        // Selectable, not merely collected.
        assert_eq!(
            super::super::parse_anthropic(&bytes).unwrap().access_token,
            "KC_AT_CAP"
        );

        // The same item without the presentation newline.
        let without_newline =
            fake_security(dir.path(), &format!("exec /bin/cat '{}'\n", item.display()));
        assert_eq!(found(raw_lookup(&without_newline, None)), exactly);

        // One byte over the cap, with and without the presentation newline.
        let over = padded_credential(cap + 1);
        let over_item = dir.path().join("over-cap.json");
        std::fs::write(&over_item, &over).unwrap();
        for body in [
            format!("/bin/cat '{}'\nprintf '\\n'\n", over_item.display()),
            format!("exec /bin/cat '{}'\n", over_item.display()),
        ] {
            let script = fake_security(dir.path(), &body);
            assert!(
                matches!(
                    raw_lookup(&script, None),
                    Lookup::Failed(KeychainFailure::Oversized)
                ),
                "an item of {} bytes must be oversized, with or without the newline",
                over.len()
            );
        }
    }

    /// A valid credential JSON document of exactly `len` bytes: the bearer the
    /// test expects plus enough padding to reach the cap.
    fn padded_credential(len: usize) -> Vec<u8> {
        let head = br#"{"claudeAiOauth":{"accessToken":"KC_AT_CAP","expiresAt":1700000000000,"scopes":["user:inference"],"pad":""#;
        let tail = br#""}}"#;
        let pad = len - head.len() - tail.len();
        let mut bytes = head.to_vec();
        bytes.extend(std::iter::repeat_n(b'a', pad));
        bytes.extend_from_slice(tail);
        bytes
    }

    /// T6: both misses are "no item" rather than a failure, and a `security` that
    /// is not on `PATH` is "no item" too. (The trim itself is pinned on raw bytes
    /// by `exactly_one_presentation_newline_is_trimmed_from_the_raw_bytes`.)
    ///
    /// The call count is part of the contract ADR-0056 states: an item that is not
    /// there costs **two** exit-44 calls, not one, because the account-qualified
    /// miss falls through to the bare retry.
    #[test]
    fn both_misses_and_a_missing_program_are_absent() {
        let mut env = crate::test_env::guard();
        let dir = tempfile::tempdir().unwrap();
        // The account is resolved from the environment; naming it keeps the
        // expected argv below from depending on who runs the suite.
        env.set_var("USER", "agentvm-test-user");

        // Both queries miss.
        let missing = fake_security(dir.path(), "exit 44\n");
        env.set_var("AGENT_VM_TEST_SECURITY", &missing);
        assert!(read("Claude Code-credentials", ReadBudget::Launch).is_none());
        assert_eq!(
            calls(dir.path()),
            [
                "<find-generic-password><-a><agentvm-test-user><-w><-s><Claude Code-credentials>",
                "<find-generic-password><-w><-s><Claude Code-credentials>",
            ],
            "an absent item costs the qualified call and the bare retry"
        );

        // Not on `PATH` at all.
        env.set_var(
            "AGENT_VM_TEST_SECURITY",
            dir.path().join("definitely-not-here"),
        );
        assert!(read("Claude Code-credentials", ReadBudget::Launch).is_none());
    }

    /// T7: a failing, slow or oversized item is *unusable* — never a retry, and
    /// never a panic — and its message carries no child output.
    #[test]
    fn a_failing_slow_or_oversized_item_is_unusable_and_does_not_retry() {
        let mut env = crate::test_env::guard();
        let dir = tempfile::tempdir().unwrap();
        env.set_var("USER", "agentvm-test-user");

        let failing = fake_security(dir.path(), "echo 'STDERR-CANARY' >&2\nexit 1\n");
        env.set_var("AGENT_VM_TEST_SECURITY", &failing);
        let candidate = read("Claude Code-credentials", ReadBudget::Launch).unwrap();
        let reason = failure(Some(candidate));
        assert_eq!(
            reason,
            Unusable::KeychainUnreadable(KeychainFailure::Exit(Some(1)))
        );
        assert_eq!(reason.to_string(), "`security` exited with status 1");
        assert_eq!(calls(dir.path()).len(), 1, "a failure must not retry");
        assert!(!format!("{reason:?}").contains("STDERR-CANARY"));

        std::fs::remove_file(dir.path().join("security.log")).unwrap();
        let slow = fake_security(dir.path(), "exec /bin/sleep 30\n");
        env.set_var("AGENT_VM_TEST_SECURITY", &slow);
        let start = Instant::now();
        let candidate = read("Claude Code-credentials", ReadBudget::Hook).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(
            failure(Some(candidate)).to_string(),
            "timed out after 2s (is the login keychain locked?)"
        );
        assert!(
            elapsed < HOOK_KEYCHAIN_NOMINAL_COST + Duration::from_secs(1),
            "one hook read cost {elapsed:?}"
        );
        assert_eq!(calls(dir.path()).len(), 1, "a timeout must not retry");

        std::fs::remove_file(dir.path().join("security.log")).unwrap();
        // Larger than the cap and then *finished*: an endless writer would hit
        // the deadline instead, which is the previous case, not this one.
        let oversized = dir.path().join("oversized.json");
        let mut flood = b"{\"claudeAiOauth\":{\"accessToken\":\"".to_vec();
        flood.resize(
            crate::host_paths::MAX_HOST_CREDENTIAL_FILE_BYTES as usize + 10,
            b'a',
        );
        std::fs::write(&oversized, &flood).unwrap();
        let cat = fake_security(
            dir.path(),
            &format!("exec /bin/cat '{}'", oversized.display()),
        );
        env.set_var("AGENT_VM_TEST_SECURITY", &cat);
        let candidate = read("Claude Code-credentials", ReadBudget::Launch).unwrap();
        assert_eq!(
            failure(Some(candidate)),
            Unusable::KeychainUnreadable(KeychainFailure::Oversized)
        );
        assert_eq!(calls(dir.path()).len(), 1);
    }

    /// F10: the retry spends what is *left* of the one deadline, not a fresh
    /// budget of its own. Pure arithmetic, so this pins the rule without
    /// depending on how fast the machine is.
    #[test]
    fn a_retry_spends_only_the_remainder_of_the_shared_deadline() {
        let base = Instant::now();
        let deadline = base + Duration::from_secs(2);
        assert_eq!(
            remaining_budget(deadline, base),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            remaining_budget(deadline, base + Duration::from_millis(1_600)),
            Some(Duration::from_millis(400))
        );
        assert_eq!(remaining_budget(deadline, deadline), None);
        assert_eq!(
            remaining_budget(deadline, deadline + Duration::from_secs(1)),
            None
        );

        // And an exhausted share never spawns the CLI at all.
        let dir = tempfile::tempdir().unwrap();
        let script = fake_security(dir.path(), "printf '%s\\n' '{}'");
        let outcome = lookup(
            script.to_str().unwrap(),
            "Claude Code-credentials",
            None,
            Instant::now(),
            HOOK_KEYCHAIN_TIMEOUT,
        );
        assert!(
            matches!(
                outcome,
                Lookup::Failed(KeychainFailure::TimedOut(budget)) if budget == HOOK_KEYCHAIN_TIMEOUT
            ),
            "an exhausted deadline must be a timeout without a spawn"
        );
        assert!(calls(dir.path()).is_empty(), "no budget left, no child");
    }

    /// F06: the real `/usr/bin/security` contract, against a **disposable**
    /// keychain. Opt-in twice over — `#[ignore]` so an ordinary run reports it as
    /// `ignored` rather than as a pass, and `AGENT_VM_REAL_KEYCHAIN_CONTRACT=1`
    /// (checked below) because it executes the system binary. Run it with
    /// `AGENT_VM_REAL_KEYCHAIN_CONTRACT=1 cargo test -p agent-vm --bin agent-vm \
    ///  real_security_contract -- --ignored --nocapture`; everything it does is
    /// isolated:
    ///
    /// * the keychain is a uniquely named file in a fresh temporary directory,
    ///   created with `create-keychain` (which does **not** add it to the search
    ///   list — asserted before and after), and deleted at the end;
    /// * **every** item operation names it explicitly, as `security` takes the
    ///   keychain as a positional argument on this macOS;
    /// * the reader under test reaches it through the `cfg(test)` seam, which
    ///   names a wrapper whose only job is to append that path — so the argv the
    ///   reader builds is exactly the production shape
    ///   (`find-generic-password -a … -w -s …`), plus the explicit keychain;
    /// * the fixtures are nonsecret canaries and nothing is printed from them.
    ///
    /// The login keychain, the default search list and the real
    /// `Claude Code-credentials` item are never addressed.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "executes /usr/bin/security against a disposable keychain; opt in with AGENT_VM_REAL_KEYCHAIN_CONTRACT=1 and --ignored"]
    fn real_security_contract_in_a_disposable_keychain() {
        const SECURITY_BIN: &str = "/usr/bin/security";
        const KEYCHAIN_PASSWORD: &str = "agentvm-contract-only";
        const DATA: &str =
            r#"{"claudeAiOauth":{"accessToken":"CONTRACT-CANARY","expiresAt":1700000000000}}"#;

        if std::env::var("AGENT_VM_REAL_KEYCHAIN_CONTRACT").as_deref() != Ok("1") {
            eprintln!(
                "skipped: set AGENT_VM_REAL_KEYCHAIN_CONTRACT=1 to run the real \
                 `/usr/bin/security` contract against a disposable keychain"
            );
            return;
        }
        let mut env = crate::test_env::guard();
        let dir = tempfile::tempdir().unwrap();
        let keychain = dir
            .path()
            .join(format!("disposable-{}.keychain", std::process::id()));
        let unique = |name: &str| format!("agentvm-contract-{}-{name}", std::process::id());

        // A bounded invocation of the real binary. `host_cli` is the same runner
        // the reader uses, so a wedged `security` cannot hang the test.
        let run = |args: &[&str]| -> Result<Vec<u8>, String> {
            host_cli::run_capturing_stdout(
                SECURITY_BIN,
                args,
                Path::new("/"),
                Duration::from_secs(20),
                MAX_HOST_CREDENTIAL_FILE_BYTES,
            )
            .map_err(|failure| format!("{SECURITY_BIN} {args:?}: {failure:?}"))
        };
        let run_ok =
            |args: &[&str]| -> Vec<u8> { run(args).unwrap_or_else(|message| panic!("{message}")) };
        let search_list = || -> Vec<u8> { run_ok(&["list-keychains", "-d", "user"]) };
        let before = search_list();

        let keychain_path = keychain.to_str().unwrap();
        // Armed *before* the keychain exists: `create-keychain` can create the
        // file and then still fail or time out, and the file is the only thing
        // the cleanup needs to find.
        let _cleanup = KeychainCleanup(keychain.clone());
        run_ok(&["create-keychain", "-p", KEYCHAIN_PASSWORD, keychain_path]);
        run_ok(&["unlock-keychain", "-p", KEYCHAIN_PASSWORD, keychain_path]);
        assert_eq!(
            before,
            search_list(),
            "creating a disposable keychain must not touch the default search list"
        );

        let add = |account: &str, service: &str, extra: &[&str]| {
            let mut args = vec!["add-generic-password", "-a", account, "-s", service];
            args.extend_from_slice(extra);
            args.push(keychain_path);
            run_ok(&args);
        };
        // The read the adapter performs, plus the explicit keychain. `-w` means
        // "print only the password".
        fn read_argv<'a>(account: &'a str, service: &'a str, keychain: &'a str) -> Vec<&'a str> {
            vec![
                "find-generic-password",
                "-a",
                account,
                "-w",
                "-s",
                service,
                keychain,
            ]
        }
        let read_exit = |args: &[&str]| -> Option<i32> {
            match host_cli::run_capturing_stdout(
                SECURITY_BIN,
                args,
                Path::new("/"),
                Duration::from_secs(20),
                MAX_HOST_CREDENTIAL_FILE_BYTES,
            ) {
                Ok(_) => Some(0),
                Err(Failure::Exit(status)) => status,
                Err(other) => panic!("unexpected {other:?}"),
            }
        };

        // 1. Written as plaintext, read back as exactly the data plus the one
        //    newline `-w` appends.
        let plaintext_service = unique("plaintext");
        add("agentvm-test-user", &plaintext_service, &["-w", DATA]);
        let raw = run_ok(&read_argv(
            "agentvm-test-user",
            &plaintext_service,
            keychain_path,
        ));
        assert_eq!(
            String::from_utf8(raw).unwrap(),
            format!("{DATA}\n"),
            "`security -w` must print the item plus exactly one newline"
        );

        // 2. Written as hex — the form Claude Code passes as `-X` (it feeds this
        //    very option through `security -i`) — and read back as the intended
        //    bytes.
        let hex_service = unique("hex");
        let hex: String = DATA.bytes().map(|byte| format!("{byte:02x}")).collect();
        add("agentvm-test-user", &hex_service, &["-U", "-X", &hex]);
        let raw = run_ok(&read_argv("agentvm-test-user", &hex_service, keychain_path));
        assert_eq!(String::from_utf8(raw).unwrap(), format!("{DATA}\n"));

        // 3. The one contract surprise this test exists to pin: `-w` prints the
        //    item **hex-encoded** when its data is not printable ASCII (a
        //    trailing `\n` alone is enough), so such an item can never be read
        //    as JSON. That is a safe failure — the candidate is ineligible and
        //    the file location decides — not a silent misread, and Claude Code's
        //    credential JSON is printable.
        let nonprintable_service = unique("nonprintable");
        let nonprintable_hex: String = format!("{DATA}\n")
            .bytes()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        add(
            "agentvm-test-user",
            &nonprintable_service,
            &["-U", "-X", &nonprintable_hex],
        );
        let raw = run_ok(&read_argv(
            "agentvm-test-user",
            &nonprintable_service,
            keychain_path,
        ));
        assert_eq!(
            String::from_utf8(raw).unwrap(),
            format!("{nonprintable_hex}\n"),
            "`security -w` hex-encodes data that is not printable ASCII"
        );

        // 4. Two items under one service are told apart by account, so the
        //    account-qualified query is doing real work.
        let shared_service = unique("shared");
        add("agentvm-test-user", &shared_service, &["-w", DATA]);
        add(
            "agentvm-other-user",
            &shared_service,
            &["-w", "OTHER-ACCOUNT-DATA"],
        );
        assert_eq!(
            String::from_utf8(run_ok(&read_argv(
                "agentvm-test-user",
                &shared_service,
                keychain_path
            )))
            .unwrap(),
            format!("{DATA}\n")
        );
        assert_eq!(
            String::from_utf8(run_ok(&read_argv(
                "agentvm-other-user",
                &shared_service,
                keychain_path
            )))
            .unwrap(),
            "OTHER-ACCOUNT-DATA\n"
        );

        // 5. A missing item and a wrong account are both exit 44 — the reader's
        //    "no item for this query" signal.
        let absent = unique("absent");
        assert_eq!(
            read_exit(&read_argv("agentvm-test-user", &absent, keychain_path)),
            Some(44),
            "a missing item must be exit 44"
        );
        assert_eq!(
            read_exit(&read_argv("agentvm-nobody", &shared_service, keychain_path)),
            Some(44),
            "a wrong account must be exit 44"
        );

        // 6. The bare query finds an unambiguous item, so the reader's retry
        //    works against the real CLI (no ordering assumption: one match).
        let bare = vec![
            "find-generic-password",
            "-w",
            "-s",
            &plaintext_service,
            keychain_path,
        ];
        assert_eq!(
            String::from_utf8(run_ok(&bare)).unwrap(),
            format!("{DATA}\n")
        );

        // 7. Through the reader itself: the exact production argv, with the
        //    explicit keychain appended by the seam's wrapper, yields exactly the
        //    item's bytes (one presentation newline removed) and a parseable
        //    credential.
        let wrapper = dir.path().join("security");
        std::fs::write(
            &wrapper,
            format!("#!/bin/sh\nexec {SECURITY_BIN} \"$@\" '{keychain_path}'\n"),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        env.set_var("AGENT_VM_TEST_SECURITY", &wrapper);
        env.set_var("USER", "agentvm-test-user");
        let candidate = read(
            Box::leak(plaintext_service.clone().into_boxed_str()),
            ReadBudget::Launch,
        )
        .expect("the disposable keychain holds this item");
        assert_eq!(
            candidate.location,
            Location::MacKeychain {
                service: Box::leak(plaintext_service.clone().into_boxed_str()),
                account: Some("agentvm-test-user".into()),
            }
        );
        match candidate.outcome {
            Ok(parsed) => {
                assert_eq!(
                    parsed.access_token, "CONTRACT-CANARY",
                    "the plaintext and `-X` round trips must preserve the bytes"
                );
                assert_eq!(parsed.expires_at_ms, Some(1_700_000_000_000));
            }
            Err(unusable) => panic!("the item must parse, got {unusable}"),
        }

        // 8. A hex-encoded (non-printable) item is *ineligible* through the real
        //    reader too: it does not become a credential, it does not panic, and
        //    its message carries no item bytes.
        let leaked_service: &'static str = Box::leak(nonprintable_service.clone().into_boxed_str());
        let nonprintable_candidate =
            read(leaked_service, ReadBudget::Launch).expect("the item exists");
        match nonprintable_candidate.outcome {
            Err(Unusable::HostCredentialMalformed { .. }) => {}
            Err(other) => panic!("expected a malformed item, got {other}"),
            Ok(parsed) => panic!(
                "a hex-encoded item must not parse; got {} bytes of a token",
                parsed.access_token.len()
            ),
        }

        assert_eq!(
            before,
            search_list(),
            "the disposable keychain must never reach the default search list"
        );
    }

    /// Deletes only the disposable keychain, including while a panic unwinds.
    ///
    /// Bounded like every other child: an unbounded `status()` in a destructor
    /// would hang the whole test binary (and its CI job) if `security` wedged,
    /// which is precisely the failure the runner exists to prevent.
    #[cfg(target_os = "macos")]
    struct KeychainCleanup(std::path::PathBuf);

    #[cfg(target_os = "macos")]
    impl Drop for KeychainCleanup {
        fn drop(&mut self) {
            let path = self.0.to_str().unwrap_or_default();
            let _ = host_cli::run_discarding_stdout(
                "/usr/bin/security",
                &["delete-keychain", path],
                Path::new("/"),
                Duration::from_secs(20),
            );
        }
    }

    /// T10/R12: the seam is the variable, not a path comparison. With it unset,
    /// a fake `security` first on `PATH` is still never spawned.
    #[cfg(target_os = "macos")]
    #[test]
    fn unit_tests_cannot_reach_the_system_keychain() {
        let mut env = crate::test_env::guard();
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("security-was-run");
        let _script = fake_security(dir.path(), &format!("touch '{}'\n", marker.display()));
        env.remove_var("AGENT_VM_TEST_SECURITY");
        env.set_var(
            "PATH",
            format!(
                "{}:{}",
                dir.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
        assert!(read("Claude Code-credentials", ReadBudget::Launch).is_none());
        assert!(!marker.exists(), "a unit build must not spawn `security`");
    }
}
