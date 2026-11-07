//! A fake `docker` on `PATH` for the image and launch-build harnesses.
//!
//! It records every invocation's argv NUL-separated into `FAKE_DOCKER_LOG`,
//! replays `FAKE_DOCKER_ARCHIVE` (to stdout for `buildx build`, to the
//! `--output` path for `image save`), and can fail, die by signal or linger on
//! demand. Nothing about the importer is faked: the archive is a real OCI
//! archive consumed by the real native loader inside the real binary.
//!
//! It also records what the launcher gave it on **stdin** when
//! `FAKE_DOCKER_STDIN_LOG` names a file, which is how a test proves a launch
//! build does not consume the input meant for the guest.

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
  cat > "$FAKE_DOCKER_STDIN_LOG"
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
