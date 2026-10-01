#!/usr/bin/env python3
"""Shared recipe-contract helper: the T5 "usable by any uid" command audit.

Canonical source: images/recipe-contract/check-tool-access.py
Byte-identical copies live under images/tools/<tool>/contract/; regenerate them
with `script/build/sync-recipe-contracts.sh --write`. Do not edit a copy.

Usage: check-tool-access.py [--content] TARGET [TARGET ...]

Each TARGET is a bare command name (resolved on PATH) or a path. Resolves the
path component by component, following symlinks, and requires the *all-class*
predicate on every path that must be traversed:

  * every directory, including `/`, satisfies (mode & 0o111) == 0o111, so a
    0701 directory that denies a non-owner in its group, or a 0001 executable
    that denies its owner, both fail;
  * the final target is a regular file with (mode & 0o111) == 0o111;
  * if the final target is a script (a `#!` shebang), its content is
    (mode & 0o444) == 0o444 and its shebang interpreter is audited the same way.
    The shebang is split the way the Linux kernel splits it: the interpreter is
    the path up to the first space/tab, and the remainder (trailing spaces/tabs
    removed) is passed to it as ONE argument. For `/usr/bin/env` that argument
    is the command name unless it is an `-S` split-string; `sh -e` names the
    (nonexistent) program `sh -e`, never `sh` with option `-e`. A `PATH`
    assignment (only reachable through `-S`) selects the effective PATH the
    interpreter is resolved under (or the auditor's PATH when it makes none);
    lookup-changing options we do not model are rejected rather than skipped.

With `--content`, instead of the executable predicate the final target only has
to be readable by all ((mode & 0o444) == 0o444) and no shebang interpreter is
resolved. That is how a recipe audits required *data* it ships (a bridge source,
a mandatory extension) whose ancestors must still be traversable by every uid.

This is deliberately stricter than "other execute": Unix permission selection
does not fall through from owner/group to other, so only all-class bits prove
access for *any* uid/gid. A present-but-unsuitable command is a failure; a later
PATH candidate is never substituted for it. Dangling and cyclic links and
non-regular final targets are rejected. Symlink permission bits themselves are
ignored (the kernel does not consult them); the target and both the lexical and
resolved ancestors are audited. Control characters are never treated as
whitespace (a CRLF shebang names `/bin/sh\\r`, which does not exist).

A POSIX access ACL on any audited path is rejected: st_mode cannot prove it does
not grant an arbitrary uid more than the mode bits suggest.
"""

import os
import stat
import sys

MAX_SYMLINKS = 40
# The kernel allows five nested script interpreters before ELOOP (observed on
# Linux 6.8: a chain of five scripts runs, a chain of six fails). Count the
# interpreter hops from the target; the sixth script tripwires the bound.
MAX_INTERPRETER_DEPTH = 5


class Violation(Exception):
    def __init__(self, path, reason):
        super().__init__("%s: %s" % (path, reason))
        self.path = path
        self.reason = reason


def _lstat(path):
    try:
        return os.lstat(path)
    except OSError:
        return None


class Resolver:
    """Resolves one path, recording every directory that must be traversable."""

    def __init__(self):
        self.dirs = []
        self.symlinks = 0

    def _dir(self, path, reason):
        self.dirs.append((path, reason))

    def resolve(self, path):
        self.symlinks = 0
        if path.startswith("/"):
            components = path.split("/")[1:]
        else:
            # A relative path keeps its lexical components. `os.path.abspath`
            # would collapse a `..` BEFORE the directory it leaves is ever
            # audited, so `private/../bin/tool` could certify a 0700 `private`.
            # Prefix the physical cwd instead and resolve `.`/`..` iteratively.
            components = os.getcwd().split("/")[1:] + path.split("/")
        resolved = [""]
        pending = [c for c in components]
        while pending:
            comp = pending.pop(0)
            if comp in ("", "."):
                continue
            if comp == "..":
                if len(resolved) <= 1:
                    continue
                self._dir("/".join(resolved), "directory before ..")
                resolved = resolved[:-1]
                continue
            cand = "/".join(resolved + [comp]) or "/"
            st = _lstat(cand)
            if st is None:
                raise Violation(cand, "does not exist")
            if stat.S_ISLNK(st.st_mode):
                self.symlinks += 1
                if self.symlinks > MAX_SYMLINKS:
                    raise Violation(
                        cand, "symlink chain exceeds %d links (cycle?)" % MAX_SYMLINKS
                    )
                self._dir("/".join(resolved) or "/", "directory containing a symlink")
                target = os.readlink(cand)
                parts = target.split("/")
                if target.startswith("/"):
                    resolved = [""]
                    parts = parts[1:]
                pending = [p for p in parts if p != ""] + pending
                continue
            if pending:
                if not stat.S_ISDIR(st.st_mode):
                    raise Violation(cand, "is not a directory")
                self._dir(cand, "directory on the path")
                resolved = resolved + [comp]
                continue
            return cand, st
        raise Violation(path, "resolves to no final component")


def _check_acl(path):
    # Absent on macOS and on non-Linux; on Linux an absent ACL raises ENODATA.
    try:
        value = os.getxattr(path, "system.posix_acl_access")
    except (OSError, AttributeError):
        return
    if value:
        raise Violation(path, "carries a POSIX access ACL")


def _check_dir(path):
    st = _lstat(path)
    if st is None:
        raise Violation(path, "directory does not exist")
    if not stat.S_ISDIR(st.st_mode):
        raise Violation(path, "is not a directory")
    if (st.st_mode & 0o111) != 0o111:
        raise Violation(
            path, "directory is not traversable by all (mode %o)" % (st.st_mode & 0o7777)
        )
    _check_acl(path)


def _env_split_string(raw, env):
    """Split a `env -S` string the way GNU env would, or refuse it.

    Only whitespace-separated words are supported; a quoting/backslash form
    whose exact word-splitting we do not model is refused, so the audit fails
    closed instead of certifying the wrong interpreter.
    """
    if any(ch in raw for ch in ("\\", "'", '"')):
        raise Violation(env, "unsupported env -S quoting")
    return raw.split()


def _env_interpreters(argument, env):
    """Parse `#!/usr/bin/env ...` into (command, effective-PATH or None).

    `argument` is the single optional argument the kernel hands env (or None
    when the shebang names no argument). Without `-S`, env treats the whole
    argument as one word, so `#!/usr/bin/env sh -e` tries to run a program
    literally named `sh -e` -- it does NOT split into `sh` with option `-e`.
    Only an `-S` split-string is split into words.

    Leading `NAME=VALUE` assignments and lookup-changing options are modelled
    for the split form: a `PATH` assignment yields the effective PATH the
    interpreter must be resolved under. Options whose effect on the lookup we do
    not model (`-i`, `-u`, `-C`, an unknown option) are rejected, never skipped,
    so the auditor never certifies an interpreter the kernel/env would not
    actually choose.
    """
    if argument is None:
        raise Violation(env, "env shebang names no interpreter")
    if argument == b"-S":
        raise Violation(env, "env -S needs its split string in the same argument")
    if argument.startswith(b"-S"):
        raw = argument[2:].lstrip(b" \t").decode("utf-8", "surrogateescape")
        split = _env_split_string(raw, env)
        tokens = [word.encode("utf-8", "surrogateescape") for word in split]
    else:
        tokens = [argument]

    path_override = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == b"--":
            index += 1
            break
        if token.startswith(b"-") and token != b"-":
            if token in (b"-i", b"--ignore-environment"):
                raise Violation(env, "env -i changes the interpreter lookup")
            if token in (b"-u", b"--unset"):
                index += 1
                if index >= len(tokens):
                    raise Violation(env, "env -u needs an argument")
                if tokens[index] == b"PATH":
                    raise Violation(env, "env -u PATH changes the interpreter lookup")
                index += 1
                continue
            if token.startswith(b"--unset="):
                if token.split(b"=", 1)[1] == b"PATH":
                    raise Violation(env, "env -u PATH changes the interpreter lookup")
                index += 1
                continue
            if token in (b"-C", b"--chdir") or token.startswith(b"--chdir="):
                raise Violation(env, "env -C changes the interpreter lookup")
            if token in (b"-0", b"--null", b"-v", b"--debug"):
                index += 1
                continue
            raise Violation(env, "unsupported env option %r" % token.decode("utf-8", "replace"))
        if b"=" in token and not token.startswith(b"="):
            name, _sep, value = token.partition(b"=")
            if name == b"PATH":
                path_override = value.decode("utf-8", "surrogateescape")
            index += 1
            continue
        break

    command = [tok.decode("utf-8", "surrogateescape") for tok in tokens[index:]]
    if not command:
        raise Violation(env, "env shebang names no interpreter")
    return command[0], path_override


def _parse_shebang(contents, inherited_path, path):
    """Return every (interpreter, effective-PATH) pair the shebang uses.

    A plain `#!/path/interp` yields one with no PATH override; `#!/usr/bin/env
    NAME ...` yields both the literal `env` path AND `NAME`, resolved under the
    PATH the shebang's own assignments select (not the auditor's PATH). Auditing
    only the auditor's PATH would certify an interpreter the kernel/env would
    never choose (the `#!/usr/bin/env -S PATH=... chosen` case).

    `inherited_path` is the PATH the process that runs THIS script was given. A
    shebang that sets no PATH of its own (a bare `#!/usr/bin/env NAME`, or the
    script reached after an outer `PATH=` assignment) inherits it rather than
    the auditor's original PATH: the kernel passes the environment down, so a
    nested interpreter the audit resolves on the wrong PATH is one the real
    build could never execute (the nested-env residual).

    The kernel's whitespace is only space and tab: a CRLF shebang names
    `/bin/sh\\r`, which does not exist, so it is reported as a missing
    interpreter rather than silently stripped to `/bin/sh`.
    """
    if not contents.startswith(b"#!"):
        return []
    line = contents.split(b"\n", 1)[0][2:]
    fields = _split_shebang_line(line)
    if fields is None:
        raise Violation(path, "shebang names no interpreter")
    name, argument = fields
    env = name.decode("utf-8", "surrogateescape")
    # `os.path.basename` here compares bytes with bytes; comparing bytes to a
    # str never matched, which silently disabled the whole env branch.
    if os.path.basename(name) == b"env":
        command, path_override = _env_interpreters(argument, env)
        effective = path_override if path_override is not None else inherited_path
        return [(env, inherited_path), (command, effective)]
    return [(env, inherited_path)]


def _split_shebang_line(line):
    """Split a `#!` line the way the Linux kernel does.

    Returns (interpreter_bytes, optional_argument_or_None) or None when the line
    names no interpreter. The kernel skips leading spaces/tabs, takes the
    interpreter path up to the first space/tab, skips the run of spaces/tabs
    after it, and passes the remainder of the line (trailing spaces/tabs
    removed) as ONE argument. Carriage returns are not whitespace.
    """
    start = 0
    while start < len(line) and line[start] in (0x20, 0x09):
        start += 1
    body = line[start:]
    if not body:
        return None
    for index, byte in enumerate(body):
        if byte in (0x20, 0x09):
            name = body[:index]
            argument = body[index:].strip(b" \t") or None
            break
    else:
        name = body
        argument = None
    if not name:
        return None
    return name, argument


def _resolve_and_audit_dirs(command, env_path):
    target = resolve_command(command, env_path)
    resolver = Resolver()
    final, st = resolver.resolve(target)
    for directory, _reason in resolver.dirs:
        _check_dir(directory)
    _check_dir("/")
    return final, st


def audit(command, active, completed, env_path=None, depth=0):
    final, st = _resolve_and_audit_dirs(command, env_path)

    if not stat.S_ISREG(st.st_mode):
        raise Violation(final, "final target is not a regular file")
    if (st.st_mode & 0o111) != 0o111:
        raise Violation(
            final, "not executable by all (mode %o)" % (st.st_mode & 0o7777)
        )
    _check_acl(final)

    # The seen key carries the effective PATH as well as the command, so the same
    # interpreter reached under a different inherited PATH is re-resolved (and
    # re-audited) rather than assumed identical. A key that is `active` is on the
    # current recursion stack: revisiting it is an interpreter cycle (the kernel
    # would raise ELOOP), never proof of health.
    key = (final, env_path)
    if key in active:
        raise Violation(final, "interpreter cycle (already being audited)")
    if key in completed:
        return final

    try:
        with open(final, "rb") as handle:
            head = handle.read(4096)
    except OSError as error:
        raise Violation(final, "cannot read: %s" % error) from error

    interpreters = _parse_shebang(head, env_path, final)
    if interpreters:
        if (st.st_mode & 0o444) != 0o444:
            raise Violation(
                final, "script is not readable by all (mode %o)" % (st.st_mode & 0o7777)
            )
        if depth >= MAX_INTERPRETER_DEPTH:
            raise Violation(
                final,
                "interpreter nesting exceeds %d scripts" % MAX_INTERPRETER_DEPTH,
            )
        active.add(key)
        try:
            for interpreter, effective in interpreters:
                audit(interpreter, active, completed, effective, depth + 1)
        finally:
            active.discard(key)
        completed.add(key)
    return final


def audit_content(command):
    """Audit a required non-executable file: all-class readable, ancestors open.

    A recipe ships data (a bridge source, a mandatory extension) that a later
    process reads; it does not need to be executable, but it must be readable by
    any uid and reachable through all-class ancestors. This resolves symlinks and
    audits the lexical and target ancestors exactly like `audit`.
    """
    final, st = _resolve_and_audit_dirs(command, None)

    if not stat.S_ISREG(st.st_mode):
        raise Violation(final, "final target is not a regular file")
    if (st.st_mode & 0o444) != 0o444:
        raise Violation(
            final, "not readable by all (mode %o)" % (st.st_mode & 0o7777)
        )
    _check_acl(final)
    return final


def resolve_command(command, env_path=None):
    if "/" in command:
        return command
    if env_path is None:
        path_value = os.environ.get("PATH", "")
    else:
        path_value = env_path
    for directory in path_value.split(os.pathsep):
        directory = directory or "."
        candidate = os.path.join(directory, command)
        if _lstat(candidate) is not None:
            # The first existing candidate is THE command; a later executable is
            # never substituted for a present-but-unusable one.
            return candidate
    raise Violation(command, "not found on PATH")


def main(argv):
    quiet = False
    content = False
    targets = []
    for arg in argv:
        if arg == "--quiet":
            quiet = True
        elif arg == "--content":
            content = True
        elif arg in ("-h", "--help"):
            print(__doc__.strip())
            return 0
        elif arg.startswith("-"):
            print("check-tool-access.py: unknown option %s" % arg, file=sys.stderr)
            return 2
        else:
            targets.append(arg)
    if not targets:
        print(
            "usage: check-tool-access.py [--content] TARGET [TARGET ...]",
            file=sys.stderr,
        )
        return 2

    active = set()
    completed = set()
    for target in targets:
        try:
            if content:
                final = audit_content(target)
            else:
                final = audit(target, active, completed)
        except Violation as violation:
            print("tool-access: %s: %s" % (violation.path, violation.reason), file=sys.stderr)
            return 1
        if not quiet:
            print("tool-access: ok %s" % final)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
