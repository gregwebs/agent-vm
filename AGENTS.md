# AGENTS.md — conventions for coding agents working on this repo

Things that aren't obvious from the code and that I keep forgetting to
tell you. Read once, then act on them silently.

> The post-merge workspace version bump lives in
> [CONTRIBUTING.md](CONTRIBUTING.md#release--version-bump) — do it after
> every merge into `rewrite-microsandbox`.

## Submodule merges go first

`vendor/microsandbox` is a submodule with its own branches. When a
worktree changes both the agent-vm code and the vendored microsandbox
code, merge inside the submodule **before** merging the superproject —
otherwise the superproject merge will conflict on the gitlink and
you'll have to redo the submodule merge anyway. Pattern:

1. `cd vendor/microsandbox && git merge --no-ff <subm-feature-branch>`
2. `cd ../.. && git add vendor/microsandbox` (bumps the gitlink)
3. `git merge --no-ff <agent-vm-feature-branch>`
   (resolves the gitlink conflict to the merge SHA from step 1)

If the feature branch lives in a separate git worktree, the
submodule branches in that worktree's `.git/modules/...` are not
visible from the main worktree. Push them across with
`git -C <worktree>/vendor/microsandbox push <main-worktree>/.git/modules/vendor/microsandbox <branch>:<branch>`
before attempting the submodule merge.

## Isolate `AGENT_VM_STATE_DIR` when building agent-vm across worktrees

`agent-vm`'s private microsandbox home (`MSB_HOME/db/msb.db`) is a
single flat directory under `$AGENT_VM_STATE_DIR` (default
`$HOME/.local/state/agent-vm`), shared by *every* `agent-vm` build you
run on this host — it is not namespaced by which worktree/branch built
it (see `docs/adr/0004-single-shared-msb-home.md`). sea-orm migrations
are one-way, so running a build from a worktree vendoring a newer
microsandbox schema, then switching to one with an older schema, trips
a fail-fast guard (`msb_preflight.rs`) that blocks every command until
you run `agent-vm doctor --reset-msb-db` — which re-pulls images on
next boot.

If you're building and running `agent-vm shell`/`run` from more than
one worktree in the same session (or expect to), set
`AGENT_VM_STATE_DIR` to a distinct path per worktree first, e.g.
`export AGENT_VM_STATE_DIR="$HOME/.local/state/agent-vm-$(basename "$PWD")"`.
Hitting the guard isn't dangerous (nothing is deleted, the error names
the fix), just a time cost worth avoiding proactively.

## Don't relocate build output to `/tmp` or `/dev/shm`

If a build is too big, slow, or runs out of inodes, fix the root
cause. Don't sidestep by pointing `CARGO_TARGET_DIR` at tmpfs — that
loses everything on reboot, masks real disk pressure, and the next
agent will spend an hour relinking from cold.

## Don't `rm -rf` state directories from the assistant turn

Claude Code prompts on every `rm -rf` and it's painful. The repo
ships `/tmp/clean-state.sh` for state cleanup — use it, or write a
new short script if it doesn't cover your case. Inline `rm -rf` in
tool calls is a UX papercut for the human, not a safety win.

## When in doubt about scope, read the prior commit messages

Commits on this branch use a multi-paragraph "Why / How" style with
real examples (often live e2e output). Match the style; don't write
single-line commits for non-trivial changes. The commit body is
where future-you (or future-me) recovers the reasoning.
