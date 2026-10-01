#!/bin/sh
# Shared recipe-contract helper: bounded, status-preserving command execution.
#
# Canonical source: images/recipe-contract/run-report.sh
# Byte-identical copies live under images/tools/<tool>/contract/; regenerate
# them with `script/build/sync-recipe-contracts.sh --write`. Do not edit a copy.
#
# Usage: run-report.sh SECONDS STDOUT_FILE STDERR_FILE EXECUTABLE [ARG ...]
#
# Runs EXECUTABLE under `timeout SECONDS` with a private HOME/XDG scratch, so a
# tool that writes a config, prompts, or hangs cannot touch the image or the
# build. `--kill-after` follows the initial TERM with a KILL, so a tool that
# ignores TERM (or a descendant that does) bounds the run instead of hanging
# the build. Returns 0 only on execution status 0. Timeout, a signal, or any
# nonzero status is a failure; stdout and stderr stay in the named files for the
# owning hook to parse and to report. 75 is remapped to 1 so a tool that happens
# to exit 75 can never be mistaken for a classified transport failure.
#
# A bare command name is resolved against PATH with lstat semantics and the
# FIRST existing candidate is the one run -- a present-but-unusable candidate is
# reported, never skipped for a later executable. Absence is NOT classified
# here; a caller that allows a missing command must test for that itself.
set -eu

if [ "$#" -lt 4 ]; then
    echo "run-report.sh: usage: run-report.sh SECONDS STDOUT_FILE STDERR_FILE EXECUTABLE [ARG ...]" >&2
    exit 2
fi
seconds=$1
stdout_file=$2
stderr_file=$3
shift 3
executable=$1
shift

# Always create the capture files so a caller can read them on every outcome.
: >"$stdout_file"
: >"$stderr_file"

resolve_executable() {
    case "$1" in
        */*) printf '%s\n' "$1"; return 0 ;;
    esac
    saved_ifs=$IFS
    IFS=:
    set -f
    for dir in $PATH; do
        candidate="${dir:-.}/$1"
        if [ -e "$candidate" ] || [ -L "$candidate" ]; then
            IFS=$saved_ifs
            set +f
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    IFS=$saved_ifs
    set +f
    return 1
}

if ! executable_path=$(resolve_executable "$executable"); then
    echo "run-report.sh: $executable not found on PATH" >&2
    exit 1
fi

# lstat semantics: a dangling symlink "exists" but cannot be run, and reporting
# it as absent would let a broken install look like a soft-fail.
if [ -L "$executable_path" ] && [ ! -e "$executable_path" ]; then
    echo "run-report.sh: $executable_path is a dangling symlink" >&2
    exit 1
fi
if [ ! -e "$executable_path" ]; then
    echo "run-report.sh: $executable_path does not exist" >&2
    exit 1
fi

scratch=$(mktemp -d)
# The trap action is single-quoted, so it stays the literal `rm -rf "$scratch"`;
# the quoted expansion happens at cleanup time and its result is never re-parsed,
# so a TMPDIR containing a single quote cannot inject a command into the exit
# trap. (`trap "rm -rf '$scratch'"` would build a shell program out of the
# path.)
trap 'rm -rf "$scratch"' EXIT INT TERM HUP
HOME=$scratch
XDG_CONFIG_HOME=$scratch/.config
XDG_CACHE_HOME=$scratch/.cache
XDG_DATA_HOME=$scratch/.local/share
XDG_STATE_HOME=$scratch/.local/state
export HOME XDG_CONFIG_HOME XDG_CACHE_HOME XDG_DATA_HOME XDG_STATE_HOME
mkdir -p "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME"

status=0
timeout --kill-after=5 "$seconds" "$executable_path" "$@" >"$stdout_file" 2>"$stderr_file" || status=$?

if [ "$status" -eq 75 ]; then
    status=1
fi
exit "$status"
