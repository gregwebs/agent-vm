#!/usr/bin/env bash
# Guest probe for the automatic Git metadata rows (#535, ADR-0062).
#
#   guest-gm-probe.sh PHASE COMMON_DIR [ALIAS]
#
#   PHASE        which row to render: ro | rw | off | control
#   COMMON_DIR   the host path of the linked worktree's *common* directory. The
#                automatic bind puts it at exactly this guest path, which is the
#                claim under test: the guest sees Git's own path, not a copy.
#   ALIAS        for `control`: a second, explicitly `:rw` mount of the same host
#                directory at a different guest path.
#
# Every line this prints starts with `GM-` and is compared whole, so a partial
# mount cannot pass. Rendering happens on failure too (`set -e` is disabled
# around the observations) because the harness compares exact lines.
#
# Nothing here is `bash -lc` (CONTRIBUTING.md): a login shell would read a profile
# from the image and change the environment the row is about.
set -uo pipefail

phase=${1:?PHASE}
common=${2:?COMMON_DIR are required}
alias_path=${3:-}

# One write target for every phase, so "denied" and "allowed" are the same file
# in the same directory and the alias comparison is not a different path.
probe="$common/objects/gm-probe"

# Every commit is pinned command-scoped as well as repo-locally, so the image's
# own `/etc/gitconfig` or user config cannot reintroduce signing or a hook.
git_gm() {
  command git \
    -c user.name=gm \
    -c user.email=gm@example.invalid \
    -c commit.gpgsign=false \
    -c tag.gpgsign=false \
    -c core.hooksPath=/dev/null \
    "$@"
}

attempt_write() {
  local target=$1
  if { printf 'gm-probe\n' >"$target"; } 2>/dev/null; then
    printf 'allowed'
  else
    printf 'denied'
  fi
}

if ! command -v git >/dev/null 2>&1; then
  printf 'GM-MISSING guest image has no git\n'
  exit 0
fi

case "$phase" in
ro)
  subject=$(git_gm log -1 --format=%s 2>/dev/null || printf '<no-log>')
  printf 'guest-change\n' >>tracked.txt
  changed=$(git_gm diff --name-only 2>/dev/null | tr '\n' ',' | sed 's/,$//' || printf '<no-diff>')
  write=$(attempt_write "$probe")
  if git_gm add tracked.txt >/dev/null 2>&1; then
    add=allowed
  else
    add=denied
  fi
  printf 'GM-N1 log=%s diff=%s write=%s add=%s\n' \
    "${subject:-<empty>}" "${changed:-<none>}" "$write" "$add"
  ;;
rw)
  git_gm add tracked.txt >/dev/null 2>&1 || true
  printf 'guest-commit\n' >>tracked.txt
  git_gm add tracked.txt >/dev/null 2>&1 || true
  if git_gm commit -q -m gm-probe >/dev/null 2>&1; then
    oid=$(git_gm rev-parse gm 2>/dev/null || printf '<no-ref>')
    printf 'GM-N2 commit=%s\n' "${oid:-<empty>}"
  else
    printf 'GM-N2 commit=refused\n'
  fi
  ;;
off)
  if [ -e "$common" ]; then
    printf 'GM-N3 present\n'
  elif git_gm rev-parse --git-dir >/dev/null 2>&1; then
    printf 'GM-N3 resolved\n'
  else
    printf 'GM-N3 absent\n'
  fi
  ;;
control)
  automatic=$(attempt_write "$probe")
  aliased=$(attempt_write "$alias_path/objects/gm-probe")
  printf 'GM-N4 automatic=%s alias=%s\n' "$automatic" "$aliased"
  ;;
*)
  printf 'GM-ERROR unknown phase %s\n' "$phase"
  exit 2
  ;;
esac
