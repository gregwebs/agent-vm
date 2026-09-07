# AGENTS.md — conventions for coding agents working on this repo


## Versioning

The workspace version bump lives in
[CONTRIBUTING.md](CONTRIBUTING.md#release--version-bump) — do it in the
feature branch, before the PR lands on `main`.

## Submodules

See [CONTRIBUTING.md](CONTRIBUTING.md#submodule-merges) for
working with submodules.


## Don't relocate build output to `/tmp` or `/dev/shm`

If a build is too big, slow, or runs out of inodes, fix the root
cause. Don't sidestep by pointing `CARGO_TARGET_DIR` at tmpfs — that
loses everything on reboot, masks real disk pressure, and the next
agent will spend an hour relinking from cold.

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues. See `docs/agents/issue-tracker.md`.

### Triage labels

Triage uses the five default canonical labels. See `docs/agents/triage-labels.md`.

### Domain docs

This repository uses a single-context domain-doc layout. See `docs/agents/domain.md`.
