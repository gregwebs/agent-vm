# AGENTS.md — conventions for coding agents working on this repo


## Versioning

The workspace version bump lives in
[CONTRIBUTING.md](CONTRIBUTING.md#release--version-bump) — do it in the
feature branch, before the PR lands on `main`.

## Submodules

See [CONTRIBUTING.md](CONTRIBUTING.md#submodule-merges) for
working with submodules.
You will need to init them when using a new git worktree.


## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues. See `docs/agents/issue-tracker.md`.

### Triage labels

Triage uses the five default canonical labels. See `docs/agents/triage-labels.md`.

### Domain docs

This repository uses a single-context domain-doc layout. See `docs/agents/domain.md`.

## Repo specific skills

Use /verus for writing proofs of properties of important functions.
