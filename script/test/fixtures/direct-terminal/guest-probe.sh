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
refuse|refuse-dns|alt|stall|exit-during) ;;
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

# ------------------------------------------- the access prompt (#501 slice 3) --
#
# Each mode prints a marker the driver can key on and then triggers one network
# refusal. The trigger is a TCP connect to TEST-NET-3 (203.0.113.10:443), which a
# default-deny launch refuses; `timeout` bounds it so an erroneously allowed
# destination fails the row instead of stalling it.

prompt_mode_mix() {
    # Button-event mouse with SGR encoding, bracketed paste, origin mode with a
    # scroll region, and a line-drawing character set: everything the prompt must
    # give back (§10.4).
    printf '\033[?2004h\033[?1002h\033[?1006h\033[3;20r\033[?6h\033(0'
}

# The refusal trigger's target and whether this row asks for the AC2 retry. The
# session/project rows use a *public* address: the sandbox's default-deny policy
# refuses it first, and after the allowance a retry can actually connect, which
# TEST-NET-3 could never show. A host without outbound internet cannot pass those
# rows; the receipt records both statuses so the reason is visible.
REFUSE_IP="${1:-203.0.113.10}"
REFUSE_PORT="${2:-443}"
REFUSE_RETRY="${3:-0}"
# The forced-end rows send two external SIGINTs; the first is forwarded to this
# guest, so the guest must survive it (a guest killed by the forwarded signal is a
# guest exit, not a forced end) and let the second force the launcher.
REFUSE_IGNORE="${4:-0}"
if [ "$REFUSE_IGNORE" = ignore ]; then
    trap '' INT TERM
fi

# Give the refusal time to reach the launcher's feed before this probe does what
# the case is about. The feed's ingestion side is the runtime's own 2 s fallback
# poll (`refusal/feed.rs`: "nothing here can shorten" it), and the rows measured
# it at 0.02-2.01 s on a real boot (2026-11-15). Without this window a probe that
# kept writing produced its output *before* the takeover, so the case raced the
# ingestion instead of testing the prompt: `prompt-deny` saw 38 of its 60 held
# lines forwarded ahead of the prompt, and a guest that exited immediately after
# its refused connect was gone before the question could be asked. The window is
# guest-side silence only; AC1's latency is measured from the connect, not here.
PROMPT_SETTLE_SECONDS=4
prompt_settle() {
    sleep "$PROMPT_SETTLE_SECONDS"
}

# Hold the session open until the driver releases it, so `access`/`access
# allowances` are queried while this session is still live (M12/C-F4). A timeout is
# a failure of the row, not a hang: 15 s bounds it.
prompt_hold() {
    echo "HOLD-READY"
    local released=""
    released="$(timeout 15 dd bs=1 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n' || true)"
    echo "HOLD-RELEASED hex=$released"
}

probe_refuse() {
    # Raw mode is the mode's own setup, so no terminal echo can satisfy the
    # `STDIN` oracle: only bytes the launcher actually forwarded can appear.
    if [ -t 0 ]; then
        stty raw -echo
    fi
    prompt_mode_mix
    echo "REFUSE-READY"
    local rc=0
    timeout 3 bash -c ": </dev/tcp/$REFUSE_IP/$REFUSE_PORT" || rc=$?
    echo "CONNECT rc=$rc"
    prompt_settle
    # Output written while the question is up must arrive after it, in order.
    local line
    for line in $(seq 0 59); do
        echo "LINE $line"
        sleep 0.05
    done
    # What the guest's stdin received: a prompt answer must never be here.
    local drained
    drained="$(timeout 1 dd bs=1 count=64 2>/dev/null | od -An -tx1 | tr -d ' \n' || true)"
    echo "STDIN $drained"
    if [ "$REFUSE_RETRY" = 1 ]; then
        # AC2's second half, under the live hold: after the answer, the same connect
        # must succeed without a restart.
        local retry=0
        timeout 3 bash -c ": </dev/tcp/$REFUSE_IP/$REFUSE_PORT" 2>/dev/null || retry=$?
        echo "RETRY rc=$retry"
    fi
    prompt_hold
    echo "REFUSE-DONE"
}

probe_refuse_dns() {
    prompt_mode_mix
    echo "REFUSE-READY"
    local rc=0
    timeout 3 getent hosts blocked.example >/dev/null 2>&1 || rc=$?
    echo "CONNECT rc=$rc"
    prompt_settle
    prompt_hold
    echo "REFUSE-DONE"
}

probe_alt() {
    # `alt ignore` keeps the guest alive through a forwarded SIGINT (the forced rows).
    if [ "${1:-0}" = ignore ]; then
        trap '' INT TERM
    fi
    printf '\033[?1049h'
    prompt_mode_mix
    # A background observer reports every size change, so the nudge's effect is
    # visible without polling from the driver. Its stdin is redirected explicitly:
    # POSIX gives an asynchronous list in a non-interactive shell `/dev/null`, and
    # `stty size` on /dev/null fails silently — the observer reported nothing for the
    # whole real-boot run and the nudge looked absent (round 5, F4).
    (
        last="$(stty size)"
        while :; do
            current="$(stty size)"
            if [ "$current" != "$last" ]; then
                echo "SIZE $current"
                last="$current"
            fi
            sleep 0.02
        done
    ) </dev/tty &
    echo "REFUSE-READY"
    local rc=0
    timeout 3 bash -c ': </dev/tcp/203.0.113.10/443' || rc=$?
    echo "CONNECT rc=$rc"
    prompt_settle
    # The guest stays alive through the leave and the nudge, so the size observer
    # below sees the redraw a real alternate-screen guest performs. The size read
    # *after* the takeover is the diagnostic that separates "the nudge never
    # reached the guest" from "the observer missed a 100 ms change".
    prompt_hold
    echo "SIZE-FINAL $(stty size)"
    echo "REFUSE-DONE"
}

probe_stall() {
    prompt_mode_mix
    echo "REFUSE-READY"
    # The sequence stalls *before* the refusal reaches the feed, so the launcher must
    # cut it with `CAN` (AC8). The trigger's own output goes to a file: nothing may
    # reach the terminal inside the stalled sequence. The sequence is held open for
    # six seconds, not two: the takeover decision waits for the refusal to reach
    # the feed (up to ~2 s after the connect), so a two-second stall usually closed
    # before the decision arrived and the row proved nothing.
    printf '\033[?20'
    local result
    result="$(mktemp "${TMPDIR:-/tmp}/stall.XXXXXX")"
    (
        local rc=0
        timeout 3 bash -c ': </dev/tcp/203.0.113.10/443' >/dev/null 2>&1 || rc=$?
        printf '%s' "$rc" >"$result"
    ) &
    sleep 6
    # Complete the sequence; the terminal (and the tracker) are at ground again.
    printf '04h'
    wait
    echo "CONNECT rc=$(cat "$result")"
    rm -f "$result"
    echo "STALL-DONE"
}

probe_exit_during() {
    prompt_mode_mix
    echo "REFUSE-READY"
    local rc=0
    timeout 3 bash -c ': </dev/tcp/203.0.113.10/443' || rc=$?
    echo "CONNECT rc=$rc"
    prompt_settle
    # 300 numbered KiB blocks of held output, then the guest's own status while the
    # question is up. The numbers let the driver check the payload's order and
    # completeness, not only a final marker (AC14).
    local block index
    block="$(printf 'x%.0s' $(seq 1 1024))"
    for index in $(seq 0 299); do
        printf 'BLOCK %s\n%s\n' "$index" "$block"
    done
    echo "EXIT-DURING-DONE"
    exit 7
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
refuse) probe_refuse "$@" ;;
refuse-dns) probe_refuse_dns "$@" ;;
alt) probe_alt "$@" ;;
stall) probe_stall ;;
exit-during) probe_exit_during ;;
signal-handle) probe_signal_handle "$@" ;;
signal-ignore) probe_signal_ignore ;;
signal-unhandled) probe_signal_unhandled ;;
signal-self-term) probe_signal_self_term "$@" ;;
esac
