#!/usr/bin/env python3
"""Boot-free controls for the #400 native driver and guest probe.

These controls prove the *oracle*: that the driver's exact-byte, EOF,
resize-handshake and restoration expectations actually distinguish a correct
session from a broken one. They need no VM, runtime or image, and they claim
nothing about the launcher's own adapters.

Each control runs the **real driver** with `--bin` pointed at a launcher
stand-in, so the driver's own expectation code, its PTY plumbing, its channel
assignments and its bounded deadlines are what get exercised. The stand-in plays
only the launcher's part (forward canonical or raw host bytes into the guest's
stdin pipe, close it at EOF) and has deliberately broken variants.

A rejection control asserts a *failure* verdict; it never treats a timeout as a
success, and every invocation is bounded.
"""

from __future__ import annotations

import errno
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
DRIVER = HERE / "direct-terminal.py"
STANDIN = HERE.parent / "fixtures" / "direct-terminal" / "launcher-standin.py"
PROBE = HERE.parent / "fixtures" / "direct-terminal" / "guest-probe.sh"

# A control's whole run, including a deliberately stalled one.
CONTROL_TIMEOUT = 60.0
# The driver's per-observation deadline under this contract: short, so a
# "never delivers EOF" control fails quickly instead of burning a minute.
CONTRACT_MARKER_DEADLINE = "8"


def assert_detached() -> None:
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError as error:
        if error.errno in (errno.ENXIO, errno.ENODEV, errno.ENOENT, errno.EPERM):
            return
        raise
    os.close(fd)
    raise SystemExit(
        "direct-terminal-contract: this process has a controlling terminal; run it "
        "detached (setsid) so each control's own PTY observation means something"
    )


def project_with_probe(root: Path) -> Path:
    project = root / "project"
    project.mkdir()
    (project / "guest-probe.sh").write_bytes(PROBE.read_bytes())
    return project


def run_driver(work: Path, *, case: str, standin_mode: str) -> tuple[bool, dict, str]:
    """Run the driver against the stand-in and return (accepted, receipt, log)."""

    project = project_with_probe(work)
    evidence = work / "evidence"
    evidence.mkdir()
    env = dict(os.environ)
    env["STANDIN_MODE"] = standin_mode
    env["DIRECT_TERMINAL_MARKER_DEADLINE"] = CONTRACT_MARKER_DEADLINE
    env["PATH"] = f"{STANDIN.parent}:{env.get('PATH', '')}"
    argv = [
        sys.executable,
        str(DRIVER),
        "--bin",
        str(STANDIN),
        "--project",
        str(project),
        "--image",
        "contract-image",
        "--runtime",
        str(work / "no-runtime"),
        "--state-root",
        str(work / "state"),
        "--case",
        case,
        "--form",
        "run",
        "--evidence",
        str(evidence),
        # A boot-free control's launcher is a stand-in: it has no session, refusal
        # log or allowance store, so the driver records `access` as skipped rather
        # than pretending a real CLI ran.
        "--standin",
    ]
    try:
        done = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=CONTROL_TIMEOUT,
            env=env,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired:
        return False, {"error": "the driver did not finish within the control timeout"}, ""
    receipt_path = evidence / f"{case}-run.json"
    receipt = json.loads(receipt_path.read_text()) if receipt_path.exists() else {}
    return done.returncode == 0 and receipt.get("verdict") == "pass", receipt, done.stdout + done.stderr


def control(
    results: list,
    name: str,
    expect_accept: bool,
    expect_error: str | tuple[str, ...] | None = None,
    **kwargs,
) -> None:
    with tempfile.TemporaryDirectory(prefix="dtc-") as tmp:
        accepted, receipt, log = run_driver(Path(tmp), **kwargs)
    if expect_accept:
        ok = accepted
        detail = (
            ""
            if ok
            else f"accepted={accepted} receipt={json.dumps(receipt)[:600]} log={log[-600:]}"
        )
    else:
        # A negative control succeeds only when the driver *completed* and its own
        # oracle rejected the stand-in with the expected diagnostic. Any failure at
        # all - a driver crash, a missing receipt, or this control's own timeout -
        # is a failed control, so a broken driver cannot masquerade as a
        # successful mutation rejection.
        expected = (expect_error,) if isinstance(expect_error, str) else (expect_error or ())
        error = str(receipt.get("error", ""))
        ok = (
            not accepted
            and receipt.get("verdict") == "fail"
            and bool(expected)
            and any(text in error for text in expected)
        )
        detail = (
            ""
            if ok
            else f"error={error[:400]!r} expected one of {expected} "
            f"receipt={json.dumps(receipt)[:400]}"
        )
    results.append((name, ok))
    print(f"{'ok  ' if ok else 'FAIL'} {name}" + ("" if not detail else ": " + detail))


def driver_module():
    """The real driver, imported so the fixed case inventory can be inspected."""

    import importlib.util

    spec = importlib.util.spec_from_file_location("direct_terminal_driver", DRIVER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# Every spelling that forces streaming from a terminal.
FORCE_OFF = ("-T", "--no-tty")
# Every spelling that forces a PTY.
FORCE_ON = ("-t", "--tty")


def inventory_controls(results: list) -> None:
    """Guards on the *native case inventory*, not on any single run.

    A native row proves only what its cases can distinguish. The force-off cases
    were once written with stdout redirected to a file, which auto already
    streams: `--no-tty` could have been ignored entirely and the row still
    passed. Nothing in the harness itself noticed, because a passing row looks
    identical either way. These controls make that class of silent
    de-discrimination a red build instead of a green native run.
    """

    driver = driver_module()
    cases = driver.CASES
    expect = driver.IDENTITY_EXPECTATIONS

    def check(name: str, ok: bool, detail: str = "") -> None:
        results.append((name, ok))
        print(f"{'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else ": " + detail))

    def forcing(case_name: str) -> tuple[str, ...]:
        return tuple(opt for opt in cases[case_name].options if opt in (*FORCE_OFF, *FORCE_ON))

    # The general invariant, so no future edit can weaken it: a case whose guest
    # is expected to stream while *both* host descriptors are terminals only
    # means something if an explicit force-off option is what made it stream.
    weakeners = []
    for name, case in cases.items():
        want = expect.get(name)
        if not want or want.get("guest_pty") is not False:
            continue
        assignment = case.assignment
        if assignment.get("stdin") == "tty" and assignment.get("stdout") == "tty":
            if not any(opt in FORCE_OFF for opt in case.options):
                weakeners.append(name)
    check(
        "inventory/every streamed case with two host terminals forces it",
        not weakeners,
        f"these cases would pass with the force-off option ignored: {weakeners}",
    )

    # Both spellings are exercised natively with both descriptors terminal, so
    # `--no-tty` cannot be a parse-only option and `-T` cannot be the only one.
    both_terminal = [
        name
        for name, case in cases.items()
        if case.assignment.get("stdin") == "tty"
        and case.assignment.get("stdout") == "tty"
        and any(opt in FORCE_OFF for opt in case.options)
    ]
    spellings = {opt for name in both_terminal for opt in cases[name].options if opt in FORCE_OFF}
    check(
        "inventory/force-off has a two-terminal case for both spellings",
        set(FORCE_OFF) <= spellings and len(both_terminal) >= 2,
        f"cases={both_terminal} spellings={sorted(spellings)}",
    )
    for name in both_terminal:
        want = expect[name]
        check(
            f"inventory/{name} streams with a separate guest stderr",
            want.get("err_channel") == "stderr",
            f"err_channel would not distinguish merged PTY output: {want}",
        )

    # Force-on is only discriminating with a redirected stdout: with both
    # descriptors terminal, auto already selects a PTY.
    forced_pty = [
        name for name, case in cases.items() if any(opt in FORCE_ON for opt in case.options)
    ]
    discriminating = [
        name
        for name in forced_pty
        if cases[name].assignment.get("stdout") == "file"
        and expect.get(name, {}).get("guest_pty") is True
    ]
    check(
        "inventory/force-on has a redirected-stdout case expecting a guest PTY",
        bool(discriminating) and "-t" in {opt for n in forced_pty for opt in cases[n].options},
        f"forced-pty cases={forced_pty} discriminating={discriminating}",
    )

    # The auto rule needs both of its halves represented, or one descriptor could
    # stop being measured without any row changing verdict.
    check(
        "inventory/auto has both-terminal (PTY) and redirected-stdout (stream) cases",
        expect.get("identity-auto", {}).get("guest_pty") is True
        and cases["identity-auto"].assignment.get("stdin") == "tty"
        and cases["identity-auto"].assignment.get("stdout") == "tty"
        and expect.get("identity-redirected", {}).get("guest_pty") is False
        and cases["identity-redirected"].assignment.get("stdin") == "tty"
        and cases["identity-redirected"].assignment.get("stdout") == "file"
        and not cases["identity-redirected"].options,
        "the auto cases no longer discriminate a stdin-only predicate",
    )

    # Both direct boundaries are exercised for every non-legacy case, so a form
    # cannot silently stop covering `--`.
    boundaries = {
        form: driver.launch_argv(Path("agent-vm"), ["-T"], form, ["true"])[2]
        for form in ("run", "separator")
    }
    check(
        "inventory/both command boundaries stay distinct",
        boundaries == {"run": "run", "separator": "--"},
        f"boundaries={boundaries}",
    )

    # Every row function this suite defines must actually be dispatched. A
    # function nobody registers is dead code in the worst way: a full run skips it
    # and a filtered run fails on an unknown row, so the row can never report
    # anything. `custom_image_direct_terminal_signal_self` spent a whole review
    # cycle in exactly that state, which is why this reads the registrations
    # rather than searching for a name.
    e2e_path = HERE.parent / "e2e.sh"
    e2e_text = e2e_path.read_text()
    defined = set(re.findall(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) *\{", e2e_text, re.M))
    registered = re.findall(r'^run_check "([^"]+)" ([A-Za-z_][A-Za-z0-9_]*)', e2e_text, re.M)
    dispatched = {function for _, function in registered}
    unregistered = sorted(
        function
        for function in defined
        if function.startswith("custom_image_direct_terminal_") and function not in dispatched
    )
    check(
        "inventory/every direct-terminal row function has a run_check",
        not unregistered,
        f"defined but never dispatched, so they can never run: {unregistered}",
    )
    unknown = sorted(
        {function for _, function in registered if function not in defined}
    )
    check(
        "inventory/every run_check names a function this file defines",
        not unknown,
        f"dispatched but not defined: {unknown}",
    )

    # The guest-signal identity rows, and the forced-shutdown oracle that keeps
    # them honest. A native row proves only what its cases can distinguish: a
    # forced teardown that reported the same 130/143 with the terminal restored
    # would look identical to a guest end, so the *shared* oracle is exercised
    # here against a fabricated forced record and must reject it. These are
    # harness controls, never native evidence.
    unhandled = {
        name: spec for name, spec in driver.SIGNAL_CASES.items() if name.endswith("-unhandled")
    }
    check(
        "inventory/the guest-signal rows cover every mode and signal",
        len(unhandled) == len(driver.SIGNAL_MODES) * len(driver.SIGNAL_NAMES)
        and all(
            spec["expect"] == 128 + int(spec["first"])
            and spec.get("teardown") == "ordinary"
            for spec in unhandled.values()
        )
        # The slice-1 twins are gone; any suffixed survivor would be a second row
        # whose name suggests it is the same case.
        and not any(name.endswith("-unhandled-slice1") for name in driver.SIGNAL_CASES),
        f"unhandled cases={sorted(unhandled)}",
    )

    self_signal = {
        name: spec
        for name, spec in driver.SIGNAL_CASES.items()
        if spec["behaviour"] == "self-signal"
    }
    check(
        "inventory/a self-signalled guest exists in both modes and sends no host signal",
        len(self_signal) == len(driver.SIGNAL_MODES)
        and all(
            spec["signals"] == []
            and spec["expect"] == 128 + signal.SIGTERM
            and spec.get("teardown") == "ordinary"
            for spec in self_signal.values()
        ),
        f"self-signal cases={sorted(self_signal)}",
    )

    # The oracle is the production one, not a copy: both the driver and these
    # controls call `guest_end_problems`.
    oracle = driver.guest_end_problems
    ordinary_text = "==> Stopping sandbox\n[SIGNAL-READY]"
    forced_text = "==> Interrupted by signal 2; tearing down the sandbox (exit 130)"
    # Both controls are *guest* ends: the forwarded `INT` the guest itself died of
    # (130) and a self-signalled `TERM` (143). The numbers are the same ones a
    # forced shutdown can produce, which is the whole point.
    guest_int = unhandled["signal-pty-int-unhandled"]
    guest_term = self_signal["signal-pty-self-term"]

    check(
        "accept/an ordinary guest end is accepted by the shared oracle",
        oracle(guest_int, 130, "ordinary teardown", ordinary_text, "INT") == [],
        f"problems={oracle(guest_int, 130, 'ordinary teardown', ordinary_text, 'INT')}",
    )
    # The negative controls: right status, right path string in the receipt, but
    # the launcher's own notice says it forced the end. They share the forced
    # notice with the row's own check, so what they prove is that the *notice*
    # alone overturns an otherwise perfect record - not two independent oracles.
    for name, spec, status, expected in (
        ("reject/a forced 130 is not the guest's own 130", guest_int, 130, "never report a forced"),
        ("reject/a forced 143 is not the guest's own 143", guest_term, 143, "never report a forced"),
    ):
        problems = oracle(spec, status, "ordinary teardown", forced_text, "INT")
        check(
            name,
            any(expected in problem for problem in problems),
            f"problems={problems}",
        )
    # And the receipt's own path must agree: a forced path is rejected even when
    # the output carries no forced notice at all.
    check(
        "reject/a forced launcher path is not a guest-signal end",
        any(
            "not the ordinary teardown" in problem
            for problem in oracle(guest_int, 130, "forced teardown", ordinary_text, "INT")
        ),
        "a forced launcher path was accepted",
    )
    # The diagnostic hint may only name the 255 reading where the number is
    # actually 255: a 137 or a 130 says nothing about a runtime that dropped
    # identity, and the failure text must not assign a layer nobody observed.
    check(
        "reject/a non-255 status never claims the runtime lost identity",
        all(
            driver.unhandled_hint(guest_int, status) == ""
            for status in (130, 137, 143, 254)
        ),
        f"hints={[driver.unhandled_hint(guest_int, s) for s in (130, 137, 143, 254)]}",
    )
    check(
        "accept/a 255 status still names the unknown-code reading",
        "255" in driver.unhandled_hint(guest_int, 255)
        and "unknown code -1" in driver.unhandled_hint(guest_int, 255),
        f"hint={driver.unhandled_hint(guest_int, 255)!r}",
    )

    # The harness must run every signal row by default: the #467 pending gate is
    # gone, and a gate that came back would silently certify unwitnessed rows.
    e2e = (HERE.parent / "e2e.sh").read_text()
    check(
        "inventory/the harness has no pending gate over the signal rows",
        "pending_case_reason" not in e2e
        and "AGENT_VM_E2E_INCLUDE_PENDING" not in e2e
        and "signal-pty-self-term signal-stream-self-term" in e2e,
        "e2e.sh still gates or omits a signal row",
    )


def main() -> int:
    assert_detached()
    for path in (DRIVER, STANDIN, PROBE):
        if not path.exists():
            print(f"direct-terminal-contract: missing {path}", file=sys.stderr)
            return 2

    results: list[tuple[str, bool]] = []

    # --- acceptance controls: a correct stand-in must pass -------------------
    control(results, "accept/identity with both descriptors terminal", True,
            case="identity-auto", standin_mode="ok")
    control(results, "accept/raw input A 1d B reaches the guest, code 7", True,
            case="input", standin_mode="ok")
    # The stand-in's guest inherits the driver's own terminal, so the sizes here
    # are the driver's shared geometry rather than a launcher constant.
    control(results, "accept/resize the host geometry then 43x119, code 7", True,
            case="resize", standin_mode="ok")
    control(results, "accept/streamed terminal stdin, exact bytes and code 23", True,
            case="stream-input-no-tty", standin_mode="ok")
    control(results, "accept/suffix tokens are guest argv", True,
            case="suffix-argv", standin_mode="ok")

    # `identity-redirected` is deliberately absent: whether the *guest* gets a
    # terminal there depends on the launcher's mode selection, which a stand-in
    # cannot reproduce. The channels it separates are asserted by the streamed
    # controls below, and the mode decision itself is native evidence.

    # A stand-in cannot reproduce "the guest keeps waiting for an EOF that never
    # comes" without also faking the launcher's own input lifetime, and a control
    # that cannot fail proves nothing — so that property is left to the Rust
    # session tests (a stream that ends without an exit event) and the native row,
    # and is not claimed here.

    # --- rejection controls: a broken stand-in must fail ---------------------
    control(results, "reject/a mangled escape byte changes the guest's hex", False,
            "guest saw", case="input", standin_mode="mangle-input")
    control(results, "reject/a truncated streamed payload fails the checksum", False,
            ("bytes=", "cksum="), case="stream-input-no-tty", standin_mode="stream-truncated")
    control(results, "reject/a missed resize notification fails", False,
            ("the guest timed out", "the guest never observed the resize", "the resize verdict"),
            case="resize", standin_mode="no-winch")
    control(results, "reject/an early exit before readiness fails", False,
            "the launcher exited with", case="identity-auto", standin_mode="early-exit")
    control(results, "reject/a terminal left raw fails the restoration check", False,
            "the host terminal was not restored", case="identity-auto", standin_mode="raw-leftover")

    # --- the access prompt's oracle: a correct prompt accepted, broken ones
    # rejected. The stand-in plays a launcher's takeover over the real probe; what
    # these prove is the *driver's* oracle, never the product's frames (those are
    # `access_prompt::screen`'s and the tmux oracle's).
    control(results, "accept/a correct prompt, answered with d", True,
            case="prompt-deny", standin_mode="prompt-ok")
    # The launcher's own cadence: exactly one cursor-position reply per question. A
    # driver that answers more than once never gets to the answer (H15).
    control(results, "accept/a driver that answers once against the launcher's cadence", True,
            case="prompt-deny", standin_mode="prompt-cadence")
    control(results, "reject/a leave without the mode re-apply fails", False,
            "did not re-apply", case="prompt-deny", standin_mode="prompt-no-modes")
    # The oracle's message changed when it stopped demanding every line after the
    # leave (a real boot's ingestion forwards some of them before the takeover):
    # the claim it rejects is the same, and both spellings are accepted so the
    # control cannot depend on one wording.
    control(results, "reject/a dropped held line fails the ordering oracle", False,
            ("once each and in order", "held lines"), case="prompt-deny",
            standin_mode="prompt-drop-line")
    control(results, "reject/a redraw after the leave fails", False,
            "a prompt frame was written after the leave", case="prompt-deny",
            standin_mode="prompt-redraw-after-leave")

    # --- the access prompt's inventory, on the case table itself -------------
    driver = driver_module()
    prompt = driver.PROMPT_CASES
    check = lambda name, ok, detail="": (
        results.append((name, ok)),
        print(f"{'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else ": " + detail)),
    )
    required = {
        "prompt-deny", "prompt-session", "prompt-project", "prompt-project-next",
        "prompt-guard", "prompt-answered-elsewhere", "prompt-alt-screen",
        "prompt-stall", "prompt-exit", "prompt-forced", "prompt-forced-alt",
        "prompt-runtime-loss", "prompt-runtime-loss-alt", "prompt-off-env",
    }
    check(
        "inventory/every prompt row the plan names exists",
        required <= set(prompt),
        f"missing={sorted(required - set(prompt))}",
    )
    # Every row must assert something about the launcher's own `access` command,
    # or about an absence: a row that only checked a status would pass on a
    # launcher that prompted and granted nothing.
    # Each row must name at least one expectation beyond the exit status: the
    # `access` command, an absence, or the terminal fact its criterion is about.
    # A row that only compared a status would pass on a launcher that prompted and
    # granted nothing.
    beyond_status = (
        "access", "off", "lines", "alt", "stall", "forced", "runtime_loss", "guard",
        "answered_elsewhere", "probe_stdin", "exit", "race_key", "result_says",
    )
    check(
        "inventory/every prompt row states an expectation beyond its status",
        all(any(spec.get(key) for key in beyond_status) for spec in prompt.values()),
        f"rows without one={[n for n, s in prompt.items() if not any(s.get(k) for k in beyond_status)]}",
    )
    # The deny row is the one that would catch discarded or reordered output: its
    # own expectation must keep the held-line check.
    check(
        "inventory/the deny row asserts the held lines",
        prompt["prompt-deny"].get("lines") is True,
        f"prompt-deny={prompt['prompt-deny']}",
    )
    # The rows that answer with a key must name one, and the rows that must not
    # answer must not (their oracle is what the absence proves).
    check(
        "inventory/only the answering rows name a key",
        prompt["prompt-deny"]["answer"] == b"d"
        and prompt["prompt-session"]["answer"] == b"s"
        and prompt["prompt-project-next"]["answer"] == b"p"
        and prompt["prompt-exit"]["answer"] is None
        and prompt["prompt-forced"]["answer"] is None
        and prompt["prompt-runtime-loss"]["answer"] is None,
        "an answer key changed shape",
    )
    # AC9's three shapes are all present and each turns the prompt off in its own
    # way: the setting, TERM, and a redirected stdout.
    check(
        "inventory/AC9 has the setting, TERM=dumb and a redirected stdout",
        prompt["prompt-off-env"]["env"].get("AGENT_VM_NO_ACCESS_PROMPT") == "1"
        and prompt["prompt-off-dumb"]["env"].get("TERM") == "dumb"
        and prompt["prompt-off-redirect"].get("stdout") == "file",
        "one of the three AC9 shapes is missing",
    )

    check(
        "inventory/forced and runtime loss cover both screens",
        all(
            prompt[f"prompt-{name}-alt"]["probe"][0] == "alt"
            and (
                prompt[f"prompt-{name}-alt"].get("forced") is True
                or prompt[f"prompt-{name}-alt"].get("runtime_loss") is True
            )
            for name in ("forced", "runtime-loss")
        ),
        "a screen is missing from the forced or runtime-loss rows",
    )
    # H12/H14: the probe's arguments must actually reach its mode functions. Grepping
    # the probe for the word "ignore" proved nothing while the dispatcher called
    # `probe_alt` with no arguments; the dispatcher lines are read instead.
    probe_text = (HERE.parent / "fixtures" / "direct-terminal" / "guest-probe.sh").read_text()
    forwarded = {
        "refuse": 'refuse) probe_refuse "$@" ;;',
        "refuse-dns": 'refuse-dns) probe_refuse_dns "$@" ;;',
        "alt": 'alt) probe_alt "$@" ;;',
    }
    check(
        "inventory/the probe forwards each mode's arguments",
        all(line in probe_text for line in forwarded.values()),
        f"missing dispatcher argument forwarding: "
        f"{[k for k, v in forwarded.items() if v not in probe_text]}",
    )
    check(
        "inventory/the alternate observer reads the real terminal",
        ") </dev/tty &" in probe_text,
        "an asynchronous list's stdin is /dev/null, so `stty size` would fail silently",
    )
    check(
        "inventory/the forced rows use a guest that survives the forwarded signal",
        all(
            "ignore" in prompt[f"prompt-forced{suffix}"]["probe"]
            for suffix in ("", "-alt")
        )
        and "trap '' INT TERM" in probe_text
        and 'if [ "${1:-0}" = ignore ]; then' in probe_text,
        "a guest killed by the forwarded SIGINT is a guest exit, not a forced end",
    )
    check(
        "inventory/AC12's race row sends a key while the CLI grant is in flight",
        prompt["prompt-answered-elsewhere"].get("race_key") == b"p"
        and prompt["prompt-answered-elsewhere"].get("access") == "first-answer-wins",
        "the race row does not exercise the prompt's conditional grant",
    )

    # --- inventory controls: the native matrix must stay discriminating ------
    inventory_controls(results)

    failed = [name for name, ok in results if not ok]
    print()
    print(f"{len(results)} controls, {len(results) - len(failed)} passed, {len(failed)} failed")
    if failed:
        print("failed controls: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
