#!/usr/bin/env python3
"""Shared recipe-contract helper: per-slot install status records.

Canonical source: images/recipe-contract/install-status.py
Byte-identical copies live under images/tools/<tool>/contract/; regenerate them
with `script/build/sync-recipe-contracts.sh --write`. Do not edit a copy.

The build gate accepts a missing command ONLY when the recipe left a fresh,
strictly valid `absent-transport CODE` record. This helper owns the two
predicates that decision needs, so every recipe applies the same rules:

  path-state PATH
      Exit 0 when PATH is GENUINELY absent -- every existing ancestor is a real
      directory and the leaf itself has no directory entry. Exit 1 when anything
      is present-but-broken: a regular file, a directory, a dangling symlink
      (the link itself is a directory entry), an ancestor that is a non-directory
      (ENOTDIR) or a dangling ancestor symlink. Exit 2 when lstat fails for any
      other reason (a permission error on an ancestor, a symlink loop). A
      present-but-unusable or broken path must never be waved away by an absence
      record, so only exit 0 authorises the absence branch.

  code FILE
      Print the CODE of a strictly valid record and exit 0. The record must be
      exactly one newline-terminated line `absent-transport CODE` with a CODE
      from the classified transport vocabulary. Anything else -- the line inside
      a malformed multi-line record, no trailing newline, `installed`, `pending`,
      or an unknown code -- exits 1.

  record FILE
      Print the whole record if it is one of the known exact records
      (`installed`, `pending`, `absent-transport CODE`, `absent-pi`); else 1.
"""

import os
import stat
import sys

# These two sets mirror the classified-transport vocabulary written by
# download.sh (curl codes) and run-npm.sh (npm error codes). Keep them in sync.
CURL_CODES = frozenset(["5", "6", "7", "18", "28", "35", "52", "55", "56", "60"])
NPM_CODES = frozenset(
    ["EAI_AGAIN", "ENOTFOUND", "ECONNREFUSED", "ECONNRESET", "ETIMEDOUT"]
)
KNOWN_RECORDS = frozenset(["installed", "pending", "absent-pi"])


def path_state(path):
    """Exit 0 only when PATH is GENUINELY absent (see the module docstring).

    Walk every component so a broken *ancestor* is distinguished from a missing
    leaf: `lstat` of the whole path collapses both to ENOENT, which would let a
    dangling or non-directory ancestor read as a genuine absence.
    """
    if path in ("", "/"):
        return 2
    absolute = path.startswith("/")
    components = [c for c in path.split("/") if c != ""]
    current = ""
    for index, component in enumerate(components):
        if component == ".":
            continue
        if component == "..":
            # Cannot audit the directory `..` leaves without its prefix; refuse
            # closed rather than guess.
            return 2
        if not current:
            current = "/" + component if absolute else component
        else:
            current = current + "/" + component
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            return 0
        except NotADirectoryError:
            return 1
        except OSError:
            return 2
        last = index == len(components) - 1
        if stat.S_ISLNK(st.st_mode):
            if last:
                continue  # a symlink leaf is a directory entry: present
            try:
                target = os.stat(current)
            except FileNotFoundError:
                return 1  # dangling ancestor symlink: present but broken
            except OSError:
                return 2  # ancestor symlink loop / unreadable target
            if not stat.S_ISDIR(target.st_mode):
                return 1  # ancestor symlink to a non-directory
        elif not last and not stat.S_ISDIR(st.st_mode):
            return 1  # a present non-directory ancestor
    return 1


def read_record(path):
    """Return the record text, or None if it is not one exact line."""
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    # Exactly one newline-terminated line, no trailing bytes: a line embedded in
    # a longer malformed record must not count.
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        return None
    try:
        return data[:-1].decode("ascii")
    except UnicodeDecodeError:
        return None


def main(argv):
    if len(argv) != 2:
        sys.stderr.write(
            "usage: install-status.py {path-state PATH | code FILE | record FILE}\n"
        )
        return 2
    sub, arg = argv
    if sub == "path-state":
        return path_state(arg)
    if sub == "code":
        record = read_record(arg)
        if record is None or not record.startswith("absent-transport "):
            return 1
        code = record[len("absent-transport ") :]
        if code in CURL_CODES or code in NPM_CODES:
            print(code)
            return 0
        return 1
    if sub == "record":
        record = read_record(arg)
        if record is None:
            return 1
        if record in KNOWN_RECORDS:
            print(record)
            return 0
        if record.startswith("absent-transport ") and record[
            len("absent-transport ") :
        ] in (CURL_CODES | NPM_CODES):
            print(record)
            return 0
        return 1
    sys.stderr.write("install-status.py: unknown subcommand %s\n" % sub)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
