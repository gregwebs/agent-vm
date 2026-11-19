//! A fake `docker` on `PATH` for the image and launch-build harnesses.
//!
//! It records every invocation's argv NUL-separated into `FAKE_DOCKER_LOG`,
//! replays `FAKE_DOCKER_ARCHIVE` (to stdout for `buildx build`, to the
//! `--output` path for `image save`), and can fail, die by signal or linger on
//! demand. Nothing about the importer is faked: the archive is a real OCI
//! archive consumed by the real native loader inside the real binary.
//!
//! It also records what the launcher gave **each** invocation on stdin, as one
//! framed record per call in `FAKE_DOCKER_STDIN_LOG` (read with
//! [`stdin_records`]), which is how a test proves a launch build does not
//! consume the input meant for the guest. A cold launch build runs Docker twice,
//! so a single truncated file could let the second call erase what the first one
//! read.
//!
//! `--metadata-file F` marks the launch-build **probe**: after a successful run
//! it writes `{"containerimage.digest":"$FAKE_DOCKER_PROBE_DIGEST"}` to F when
//! that variable is set (and nothing otherwise, like a builder that reports no
//! digest). `FAKE_DOCKER_EXPORT_EXIT` fails only a non-probe build.
//!
//! `FAKE_DOCKER_PROBE_METADATA_UNREADABLE` writes that metadata and then makes it
//! unreadable, the one probe-metadata problem a fake file can pose and a
//! malformed one cannot: a file that exists but cannot be opened.
//!
//! Deliberate exception to `CODING_STANDARDS.md` ("Bash": `set -euo pipefail`):
//! this script depends on failing commands *inside* `if`/`&&` tests and on a
//! `case` fallthrough to report an unexpected subcommand, so `-e`, `-u` and
//! `pipefail` would each change what it is emulating rather than harden it.

#![allow(dead_code)]

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

pub fn write(path: &Path) {
    let script = r#"#!/bin/bash
# Fake Docker for agent-vm image build/import and launch-build tests. Records argv
# NUL-separated, replays a fixture archive, and can fail or die by signal on demand.
if [ -n "${FAKE_DOCKER_STDIN_LOG:-}" ]; then
  # One framed record per call, appended in call order, so a later call cannot
  # erase what an earlier one read.
  { printf 'STDIN\0'; cat; printf '\0END\0'; } >> "$FAKE_DOCKER_STDIN_LOG"
fi
{
  printf 'CALL\0'
  for a in "$@"; do printf '%s\0' "$a"; done
  printf 'END\0'
} >> "${FAKE_DOCKER_LOG:?}"

case "${1:-} ${2:-}" in
  "buildx build") mode=build ;;
  "image save")
    [ "${3:-}" = --output ] && [ -n "${4:-}" ] && [ "${5:-}" = -- ] && [ "$#" -eq 6 ] || { printf 'UNEXPECTED\0' >> "$FAKE_DOCKER_LOG"; exit 97; }
    mode=save; out="$4" ;;
  *) printf 'UNEXPECTED\0' >> "${FAKE_DOCKER_LOG:?}"; echo "fake docker: unexpected subcommand" >&2; exit 97 ;;
esac

metadata=
if [ "$mode" = build ]; then
  prev=
  for a in "$@"; do
    [ "$prev" = --metadata-file ] && metadata="$a"
    prev="$a"
  done
fi

emit_archive() {
  if [ "$mode" = save ]; then cat "$FAKE_DOCKER_ARCHIVE" > "$out"; else cat "$FAKE_DOCKER_ARCHIVE"; fi
}

if [ -n "${FAKE_DOCKER_SLEEP:-}" ]; then
  sleep "${FAKE_DOCKER_SLEEP}"
fi

printf '%s\n' "${FAKE_DOCKER_STDERR_MARKER:-}" >&2

if [ -n "${FAKE_DOCKER_STDERR_BYTES:-}" ]; then
  head -c "${FAKE_DOCKER_STDERR_BYTES}" /dev/zero | tr '\0' 'x' >&2
fi

if [ -n "${FAKE_DOCKER_SIGNAL:-}" ]; then
  kill "-${FAKE_DOCKER_SIGNAL}" "$$"
  sleep 1
  exit 98
fi

if [ -n "${FAKE_DOCKER_EXIT:-}" ] && [ "${FAKE_DOCKER_EXIT}" != "0" ]; then
  if [ -n "${FAKE_DOCKER_EMIT_ON_FAILURE:-}" ] && [ -n "${FAKE_DOCKER_ARCHIVE:-}" ]; then
    emit_archive
  fi
  exit "${FAKE_DOCKER_EXIT}"
fi

if [ -n "$metadata" ]; then
  # A real Docker writes the probe's metadata only after a successful build.
  if [ -n "${FAKE_DOCKER_PROBE_DIGEST:-}" ]; then
    printf '{"containerimage.digest":"%s"}\n' "$FAKE_DOCKER_PROBE_DIGEST" > "$metadata"
    if [ -n "${FAKE_DOCKER_PROBE_METADATA_UNREADABLE:-}" ]; then
      # A metadata file this process may not read, so the probe's digest cannot
      # reach the launcher even though the build succeeded (ADR-0071 §5).
      chmod 000 "$metadata"
    fi
  fi
elif [ -n "${FAKE_DOCKER_EXPORT_EXIT:-}" ] && [ "${FAKE_DOCKER_EXPORT_EXIT}" != "0" ]; then
  exit "${FAKE_DOCKER_EXPORT_EXIT}"
fi

if [ -n "${FAKE_DOCKER_ARCHIVE:-}" ]; then
  emit_archive
fi
exit 0
"#;
    fs::write(path, script).expect("write fake docker");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod fake docker");
}

/// Every fake-Docker invocation's argv, in order, from a NUL-separated log.
pub fn calls(log: &Path) -> Vec<Vec<OsString>> {
    let bytes = fs::read(log).unwrap_or_default();
    let mut calls: Vec<Vec<OsString>> = Vec::new();
    let mut current: Option<Vec<OsString>> = None;
    for token in bytes.split(|byte| *byte == 0) {
        match token {
            b"CALL" => current = Some(Vec::new()),
            b"END" => calls.push(current.take().expect("END after CALL")),
            b"UNEXPECTED" | b"" => {}
            other => {
                if let Some(call) = current.as_mut() {
                    call.push(OsString::from_vec(other.to_vec()));
                }
            }
        }
    }
    assert!(current.is_none(), "the docker log ended mid-call");
    calls
}

/// What each fake-Docker invocation read on stdin, in call order (record `i` is
/// [`calls`]`[i]`'s). Payloads must not contain NUL, the frame separator.
pub fn stdin_records(log: &Path) -> Vec<Vec<u8>> {
    const START: &[u8] = b"STDIN\0";
    const END: &[u8] = b"\0END\0";
    let bytes = fs::read(log).unwrap_or_default();
    let mut records = Vec::new();
    let mut rest = bytes.as_slice();
    while !rest.is_empty() {
        rest = rest
            .strip_prefix(START)
            .expect("a stdin record starts with STDIN");
        let end = rest
            .windows(END.len())
            .position(|window| window == END)
            .expect("a stdin record ends with END");
        records.push(rest[..end].to_vec());
        rest = &rest[end + END.len()..];
    }
    records
}
