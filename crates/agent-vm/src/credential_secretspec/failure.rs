//! Why a SecretSpec read could not produce a value (#202): the closed class a
//! launch reports to the user.
//!
//! Closed and `Copy`, with `&'static str` remedies, for the same reason
//! `secret_store::KeychainFailure` is: the alternative is a message assembled
//! from whatever the child said, and a third-party error text can carry a
//! value. Every variant here maps to *what to fix*, and none can carry one.
//!
//! `SecretSpecFailure::Undeclared` deliberately does not exist: the issue maps
//! both `missing` and `undeclared` to `Resolved::Missing`, and the SecretSpec
//! remedy for that outcome names both causes (see
//! `credential_resolver::WithheldCause::SecretspecMissing`).

/// A SecretSpec read that could not produce a value. `Debug` only: no
/// `Display`, so a variant can only reach the user through [`Self::message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretspecFailure {
    /// The configured `secretspec.executable` is missing, not a regular file,
    /// not executable, or could not be spawned.
    ExecutableMissing,
    /// The executable's target file is writable by group or others.
    ExecutableUntrusted,
    /// `serve --read-only` exited, or closed stdout, before answering
    /// `rpc.initialize`.
    StartupFailed,
    /// No accepted handshake within the startup budget.
    HandshakeTimedOut,
    /// `unsupported_version`, or a result that is not `secretspec.resolver`
    /// version 1 offering `resolver.get` **and** `resolver.release`.
    UnsupportedProtocol,
    /// The session advertised `resolver.set` or `resolver.delete`.
    NotReadOnly,
    /// `rpc.initialize` answered `operation_failed`/`invalid_params`: the
    /// manifest, profile or scope was refused.
    SessionRejected,
    /// `permission_denied`/`interaction_required`: the value would have to be
    /// generated or prompted for, or the provider denied access.
    PermissionDenied,
    /// The declaration uses `as_path`, which agent-vm does not support.
    RepresentationMismatch,
    /// The provider failed: `operation_failed`, `unavailable`, `internal`,
    /// `conflict` or an unknown kind (binary values land here).
    ProviderFailed,
    /// The request outlived its bound, or the server reported
    /// `deadline_exceeded`/`cancelled`.
    Unresponsive,
    /// A frame the client will not parse, a wrong id, `generated`/`path`
    /// results, or unusable negotiated `limits`.
    ProtocolViolation,
    /// The child exited while a request was outstanding.
    SessionLost,
    /// The launch had already closed its SecretSpec sessions.
    SessionClosed,
}

impl SecretspecFailure {
    /// The remedy, as one fixed sentence. It names what the user can do and
    /// never a value, a frame, or anything the child wrote.
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::ExecutableMissing => {
                "the configured `secretspec.executable` does not exist or is not an executable \
                 file; install SecretSpec 0.21 or newer (https://secretspec.dev) and set \
                 `secretspec.executable` to its absolute path"
            }
            Self::ExecutableUntrusted => {
                "the configured `secretspec.executable` is writable by group or others; agent-vm \
                 refuses to run it - fix its mode with `chmod go-w <path>`"
            }
            Self::StartupFailed => {
                "`secretspec serve --read-only` exited before completing the \
                 `secretspec.resolver/1` handshake; agent-vm needs SecretSpec 0.21 or newer (check \
                 `secretspec --version`)"
            }
            Self::HandshakeTimedOut => {
                "`secretspec serve --read-only` did not complete its handshake within 5 seconds"
            }
            Self::UnsupportedProtocol => {
                "the `secretspec` executable does not speak `secretspec.resolver` version 1 with \
                 the mandatory `resolver.get` and `resolver.release` capabilities; install a \
                 SecretSpec release that does (0.21 or newer)"
            }
            Self::NotReadOnly => {
                "`secretspec serve --read-only` offered write methods \
                 (`resolver.set`/`resolver.delete`); agent-vm refuses a session that could change \
                 SecretSpec values"
            }
            Self::SessionRejected => {
                "SecretSpec refused the session: the manifest could not be loaded, or its profile \
                 or scope is not declared; check with `secretspec check --no-prompt --file \
                 <manifest> --profile <profile>` (see `agent-vm doctor` for the configured values)"
            }
            Self::PermissionDenied => {
                "SecretSpec refused the read: the secret would have to be generated or prompted \
                 for, or the provider denied access; agent-vm only reads - set the value with \
                 SecretSpec, or unlock the provider"
            }
            Self::RepresentationMismatch => {
                "the SecretSpec declaration uses `as_path`, which agent-vm does not support; \
                 agent-vm needs the value itself"
            }
            Self::ProviderFailed => {
                "the SecretSpec provider could not resolve the secret (binary or undecodable \
                 values fail this way too); check with `secretspec check --no-prompt --file \
                 <manifest> --profile <profile>`"
            }
            Self::Unresponsive => {
                "SecretSpec did not answer before agent-vm stopped waiting; a provider may be \
                 waiting on an unlock or sign-in - unlock it and retry"
            }
            Self::ProtocolViolation => {
                "the `secretspec` executable sent a frame that does not follow \
                 `secretspec.resolver/1`; agent-vm stopped that session"
            }
            Self::SessionLost => {
                "`secretspec serve` exited while agent-vm was waiting for an answer"
            }
            Self::SessionClosed => "the launch had already closed its SecretSpec sessions",
        }
    }
}
