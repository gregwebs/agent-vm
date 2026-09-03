//! The single parser for boolean environment variables (issue #65).
//!
//! Every `AGENT_VM_*` variable that takes a *value* (as opposed to the
//! presence-only debug switches such as `AGENT_VM_PROFILE`) is interpreted
//! here and nowhere else. Before this module four modules carried
//! copy-pasted `matches!` arms that had already drifted apart:
//! `msb_install` accepted `" True "` but not `yes`, while `pull`/`run`/`user`
//! accepted `YES` but not `True`.
//!
//! The accepted set is the union of those two dialects, so unifying them
//! could only widen what is accepted — no value that used to enable a knob
//! can now silently leave it off.
//!
//! User-facing documentation of the set lives in `USAGE.md`'s env-var table
//! and in `run.rs`'s `Environment:` help block. Both are held in lockstep
//! with [`TRUTHY`] by tests (`usage_doc_lists_exactly_the_parser_truthy_set`
//! here, `environment_help_block_lists_the_shared_truthy_set` in `run.rs`).

/// Values that enable a knob, matched after trimming surrounding whitespace
/// and ignoring ASCII case. `pub(crate)` so the doc-lockstep test in `run.rs`
/// can render the same list the help block must contain.
pub(crate) const TRUTHY: [&str; 4] = ["1", "true", "yes", "on"];

/// Whether a raw environment value enables its knob.
///
/// Empty and any unrecognised string are false. That asymmetry — no error, no
/// warning — is deliberate: every variable routed through here is an *opt-in*
/// whose `false` is the conservative direction (don't run as root, don't
/// auto-confirm a build, don't probe a registry, don't allow plain HTTP,
/// don't share the OCI cache), so a typo fails closed. A variable whose
/// default were "on" must not use this function without first giving the
/// parser a way to report "unrecognised".
pub(crate) fn is_truthy(value: &str) -> bool {
    let trimmed = value.trim();
    TRUTHY
        .iter()
        .any(|truthy| trimmed.eq_ignore_ascii_case(truthy))
}

/// [`is_truthy`] against the process environment; unset is false. A value
/// that is not valid UTF-8 reads as unset, matching every pre-existing call
/// site (all of which used `std::env::var`, not `var_os`).
pub(crate) fn enabled(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| is_truthy(&value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truthy_values_are_trimmed_and_case_insensitive() {
        for truthy in [
            "1", "true", "TRUE", "True", "tRuE", "yes", "YES", "Yes", "on", "ON", "On", " 1 ",
            "\ttrue\n",
        ] {
            assert!(is_truthy(truthy), "expected {truthy:?} to be truthy");
        }
        for falsy in [
            "", " ", "0", "false", "no", "off", "garbage", "truthy", "1 1", "yess",
        ] {
            assert!(!is_truthy(falsy), "expected {falsy:?} to be falsy");
        }
    }

    /// Guards against someone adding a value to `TRUTHY` that the
    /// trim/case handling doesn't reach: every entry must also round-trip
    /// uppercased, alternating-case, and whitespace-padded.
    #[test]
    fn every_truthy_constant_round_trips_in_all_ascii_cases() {
        for truthy in TRUTHY {
            assert!(is_truthy(truthy), "{truthy:?} should be truthy as-is");
            assert!(
                is_truthy(&truthy.to_ascii_uppercase()),
                "{truthy:?} should be truthy uppercased"
            );
            let alternating: String = truthy
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c.to_ascii_uppercase()
                    } else {
                        c.to_ascii_lowercase()
                    }
                })
                .collect();
            assert!(
                is_truthy(&alternating),
                "{truthy:?} should be truthy as {alternating:?}"
            );
            let padded = format!("  {truthy}  ");
            assert!(is_truthy(&padded), "{truthy:?} should be truthy padded");
        }
    }

    /// The regression guard for the union decision (issue #65): every value
    /// that was truthy under *either* pre-existing dialect must stay truthy
    /// here. Makes the widening argument executable instead of a comment.
    #[test]
    fn no_previously_accepted_value_became_falsy() {
        // Sites 1-4 (pull::env_truthy / run.rs / user.rs, byte-identical).
        for was_truthy in ["1", "true", "TRUE", "yes", "YES", "on", "ON"] {
            assert!(
                is_truthy(was_truthy),
                "{was_truthy:?} was truthy at sites 1-4 and must stay truthy"
            );
        }
        // Site 5 (msb_install::parse_flag: trimmed, case-insensitive, 1/true only).
        for was_truthy in ["1", "true", "TRUE", " true "] {
            assert!(
                is_truthy(was_truthy),
                "{was_truthy:?} was truthy at site 5 and must stay truthy"
            );
        }
    }

    /// [`enabled`] against the real process environment — the one thing
    /// [`is_truthy`]'s pure tests cannot cover. Goes through
    /// `test_env::guard()` (the crate's shared mutex + restore-on-drop
    /// helper, see `pull.rs`'s `env_override_forces_plain_http`) rather
    /// than a bare `unsafe set_var`/`remove_var`: a var name unique to this
    /// test buys logical isolation only, not soundness — `setenv` rewrites
    /// a process-wide array while sibling test threads sit in `getenv`.
    #[test]
    fn enabled_reads_the_process_environment() {
        const VAR: &str = "AGENT_VM_TEST_ENV_FLAG_ENABLED";
        let mut env = crate::test_env::guard();
        assert!(!enabled(VAR), "unset must be false");
        env.set_var(VAR, "On");
        assert!(enabled(VAR));
        env.set_var(VAR, "0");
        assert!(!enabled(VAR));
        env.remove_var(VAR);
        assert!(!enabled(VAR), "must be false again after cleanup");
    }

    /// [`enabled`]'s doc comment claims a non-UTF-8 value reads as unset
    /// (matching every pre-#65 call site, all of which used
    /// `std::env::var`, not `var_os`) — that claim had no test. Follows the
    /// same `OsStr::from_bytes` pattern as
    /// `msb_install::write_shared_cache_config_rejects_non_utf8_cache_path`,
    /// through `test_env::guard()` (see `enabled_reads_the_process_environment`).
    #[test]
    fn enabled_treats_non_utf8_value_as_unset() {
        use std::os::unix::ffi::OsStrExt;

        const VAR: &str = "AGENT_VM_TEST_ENV_FLAG_NON_UTF8";
        // 0x80 is not a valid standalone UTF-8 byte.
        let non_utf8 = std::ffi::OsStr::from_bytes(&[0x6f, 0x6e, 0x80]); // "on" + invalid byte
        let mut env = crate::test_env::guard();
        env.set_var(VAR, non_utf8);
        assert!(
            !enabled(VAR),
            "a non-UTF-8 value must read as unset, not truthy"
        );
        env.remove_var(VAR);
    }

    /// Doc lockstep, written so it cannot pass vacuously: assert both that
    /// USAGE.md marks exactly the four value-parsing vars with `(accepted:`
    /// AND that every one of those rows renders the current `TRUTHY` set.
    /// A future reformat that silently empties the loop fails the count
    /// assertion instead of passing for the wrong reason.
    #[test]
    fn usage_doc_lists_exactly_the_parser_truthy_set() {
        let rendered = TRUTHY.map(|v| format!("`{v}`")).join("/");
        let rows: Vec<&str> = include_str!("../../../USAGE.md")
            .lines()
            .filter(|line| line.contains("(accepted:"))
            .collect();
        assert_eq!(
            rows.len(),
            4,
            "USAGE.md must mark exactly the four value-parsing vars with `(accepted:`, found: {rows:?}"
        );
        for row in rows {
            assert!(
                row.contains(&rendered),
                "USAGE.md drifted from env_flag::TRUTHY: {row}"
            );
        }
    }
}
