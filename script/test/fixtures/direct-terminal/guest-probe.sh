#!/usr/bin/env bash
# Guest-side oracle for #400's direct terminal policy.
#
# Every mode prints a machine-checkable report on **guest stdout** and, where the
# mode separates channels, a distinct marker on guest stderr. The driver parses
# only these encoded lines: launcher notices, a host terminal's echo and a PTY's
# CRLF mapping can all be told apart from them, while a plain human sentence
# cannot. Handlers and state are installed *before* READY so a case never races
# its own trap.
#
# Copied into an owned test project for a native run; nothing here is host-side.
set -euo pipefail

mode="${1:-}"
case "$mode" in
identity|argv|input|stream-input|resize|wait|status) ;;
signal-handle|signal-ignore|signal-unhandled|signal-self-term) ;;
*)
    echo "guest-probe: unknown mode '${mode}'" >&2
    exit 64
    ;;
esac
shift || true

# ---------------------------------------------------------------- modes ---

probe_identity() {
    local tty0=0 tty1=0 tty2=0
    [ -t 0 ] && tty0=1
    [ -t 1 ] && tty1=1
    [ -t 2 ] && tty2=1
    echo "IDENTITY tty0=$tty0 tty1=$tty1 tty2=$tty2"
    echo "UID=$(id -u) GID=$(id -g)"
    echo "PWD=$(pwd -P)"
    echo "PATH=$PATH"
    echo "HOOK=${TERMINAL_HOOK:-absent}"
    echo "OUT marker"
    echo "ERR marker" >&2
    echo "IDENTITY-DONE"
}

probe_argv() {
    echo "ARGV n=$#"
    local index=0 argument
    for argument in "$@"; do
        printf 'ARGV[%d]=%s\n' "$index" "$argument"
        index=$((index + 1))
    done
    echo "ARGV-DONE"
}

probe_input() {
    # Raw mode is this mode's own setup, so no terminal echo can satisfy the hex
    # oracle: only the bytes the launcher forwarded can. A non-terminal stdin (the
    # boot-free driver's pipe stand-in) has no attributes to change, and the hex
    # oracle is unchanged.
    if [ -t 0 ]; then
        stty raw -echo
    fi
    echo "INPUT-READY"
    local bytes
    bytes="$(dd bs=1 count=3 2>/dev/null | od -An -tx1 | tr -d ' \n')"
    echo "bytes=$bytes"
    echo "ERR input" >&2
    echo "DONE"
    exit 7
}

probe_stream_input() {
    # Non-PTY guest stdin: no stty, no tty reads. The capture file and the trap
    # exist before READY so a cleanup can never replace the exit status.
    local capture
    capture="$(mktemp "${TMPDIR:-/tmp}/stream-input.XXXXXX")"
    trap 'rm -f "$capture"' EXIT
    echo "STREAM-READY"
    cat >"$capture"
    local size checksum hex
    size="$(wc -c <"$capture" | tr -d ' ')"
    checksum="$(cksum <"$capture" | awk '{print $1}')"
    hex="$(od -An -tx1 -v "$capture" | tr -d ' \n')"
    echo "STREAM bytes=$size cksum=$checksum hex=$hex"
    echo "STREAM-STDERR marker" >&2
    echo "STREAM-DONE"
    exit 23
}

probe_resize() {
    local winch_seen=0
    # The trap exists before the first size report: a resize that arrives early
    # must still be recorded.
    trap 'winch_seen=1' WINCH
    echo "SIZE $(stty size)"
    echo "RESIZE-READY"
    local attempt=0
    while [ "$attempt" -lt 10 ]; do
        attempt=$((attempt + 1))
        # `read` inside `if`: a timeout or a signal interruption is a failed
        # read, not an errexit trip. The ack is discarded on purpose — the state
        # it reports is read from the terminal and the trap instead.
        if IFS= read -r -t 1 _ack; then :; fi
        if [ "$winch_seen" = 1 ] && [ "$(stty size)" = "43 119" ]; then
            echo "RESIZED $(stty size)"
            echo "RESIZE-DONE"
            exit 7
        fi
    done
    echo "RESIZE-TIMEOUT winch=$winch_seen size=$(stty size)"
    exit 90
}

probe_wait() {
    echo "WAIT-READY"
    # Block on input until the session is faulted out from under us.
    cat >/dev/null
    echo "WAIT-EOF"
    exit 0
}

probe_status() {
    local status="${1:-0}"
    echo "STATUS-EXIT $status"
    exit "$status"
}

# -------------------------------------------------- host signal supervision --
#
# The guest behaviours a signal row needs. Each one reports SIGNAL-READY
# only after its traps are installed, so the driver never races the guest's own
# setup, and each trap names the signal it received: the launcher's status alone
# cannot tell a delivered signal from one that never arrived.

# The guest handles the signal and exits with its **own** status inside the
# grace. 42 is the witness: a launcher that lost the guest's status would report
# 128 + N (130/143) instead.
probe_signal_handle() {
    # One global rather than a local: a trap body is expanded when it *runs*, and
    # naming a global keeps that unambiguous.
    SIGNAL_EXIT="${1:-42}"
    trap 'echo "SIGNAL-TRAPPED INT"; exit "$SIGNAL_EXIT"' INT
    trap 'echo "SIGNAL-TRAPPED TERM"; exit "$SIGNAL_EXIT"' TERM
    echo "SIGNAL-READY"
    # A blocking builtin is not interruptible on every shell, so wait in short
    # bounded steps: the trap runs as soon as one of them returns, which keeps a
    # handled signal well inside the five-second grace. A step killed by the
    # forwarded signal must not trip `set -e`.
    while :; do
        sleep 1 || :
    done
}

# The guest records the signal and keeps running, so only the launcher's fixed
# grace (or a second interrupt) can end the session.
probe_signal_ignore() {
    trap "echo 'SIGNAL-IGNORED INT'" INT
    trap "echo 'SIGNAL-IGNORED TERM'" TERM
    echo "SIGNAL-READY"
    while :; do
        sleep 1 || :
    done
}

# No trap at all: the forwarded signal is meant to kill this shell. The marker
# after the wait is the discriminator — if the guest survives, it is printed and
# the row fails instead of trusting a status alone.
probe_signal_unhandled() {
    echo "SIGNAL-READY"
    sleep 300 || :
    echo "SIGNAL-SURVIVED"
    exit 0
}

# The guest kills **itself** with SIGTERM, and no host signal is involved.
#
# `kill -TERM "$$"` must run in this tracked top-level shell, never in a subshell,
# a background job or a pipeline: agentd's watcher owns the exit of the process it
# spawned, and a child shell's death would report that child instead. The host
# releases the kill by writing an unguessable token into a project-relative file
# it owns, which the guest sees through the project bind — so the death is
# deliberate, observed and ordered, not a race. The bounds are explicit: a
# readiness bound on the release file and a survival check after the kill.
probe_signal_self_term() {
    local release_name="${1:-}" token="${2:-}" deadline
    if [ -z "$release_name" ] || [ -z "$token" ]; then
        echo "SIGNAL-SELF-ARGV" >&2
        exit 64
    fi
    # A forwarded signal must not decide this row: the guest's own TERM is the
    # only identity it can report.
    trap - TERM
    echo "SIGNAL-READY"
    deadline=$((SECONDS + 120))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if [ -f "$release_name" ] && [ "$(cat "$release_name")" = "$token" ]; then
            # $$ is this shell. agentd's watcher owns its exit status.
            kill -TERM "$$"
            # Reaching this line means the signal was ignored or mishandled.
            echo "SIGNAL-SURVIVED"
            exit 0
        fi
        sleep 0.2 || :
    done
    echo "SIGNAL-RELEASE-TIMEOUT"
    exit 65
}

case "$mode" in
identity) probe_identity ;;
argv) probe_argv "$@" ;;
input) probe_input ;;
stream-input) probe_stream_input ;;
resize) probe_resize ;;
wait) probe_wait ;;
status) probe_status "$@" ;;
signal-handle) probe_signal_handle "$@" ;;
signal-ignore) probe_signal_ignore ;;
signal-unhandled) probe_signal_unhandled ;;
signal-self-term) probe_signal_self_term "$@" ;;
esac
