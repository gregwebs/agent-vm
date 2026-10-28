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
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DRIVER = HERE / "direct-terminal.py"
STANDIN = HERE.parent / "fixtures" / "direct-terminal" / "launcher-standin.py"
PROBE = HERE.parent / "fixtures" / "direct-terminal" / "guest-probe.sh"

# A control's whole run, including a deliberately stalled one.
CONTROL_TIMEOUT = 120.0
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
    control(results, "accept/resize 24x80 then 43x119, code 7", True,
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
