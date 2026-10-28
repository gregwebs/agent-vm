#!/usr/bin/env python3
"""Run one command detached from any controlling terminal.

The #400 native driver refuses to start while it has a controlling terminal,
because a driver that inherited the operator's terminal could look correct while
its own PTY did nothing. That precondition is easy to state and easy to violate:
`bash script/test/e2e.sh custom-image` from an interactive shell inherits one.

So the wrapper detaches the driver itself instead of requiring an undisclosed
invocation environment. This is the one shim both the wrapper and its boot-free
control use, so the control proves the production path rather than a copy:

    python3 script/test/lib/detached-run.py PROGRAM [ARG...]

The child is a session leader with no controlling terminal (`setsid` semantics),
and its stdin is `/dev/null` so a case can never read the caller's keystrokes.
"""

from __future__ import annotations

import subprocess
import sys


def main(argv: list[str]) -> int:
    if not argv:
        print("detached-run: expected a program to run", file=sys.stderr)
        return 2
    return subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    ).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
