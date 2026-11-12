# Issue tracker: GitHub

Issues and PRDs for this repo live as GitHub issues. GitHub operations go through
the project's configured access workflow. Where that workflow requires a GitHub
App, the owner is the `/github-app` skill: read it, then run every GitHub command
through its dispatcher, `<skill-dir>/scripts/gh-app.sh`, which passes `gh`'s own
arguments through unchanged. Never run bare `gh`.

`<skill-dir>` is the directory holding the skill's `SKILL.md`. Body text goes in
a file, `--body-file FILE`, never `--body`. The skill stays canonical for App
setup, command shapes and failure modes; the commands below are only the shapes
these tracker conventions need.

Name the repository explicitly. This clone has two remotes (`origin` and
`wirenboard`), and `gh` resolves from the directory without following the remote
`git push` uses. Pass `--repo OWNER/REPO`, taking `OWNER/REPO` from
`git remote get-url origin`.

Below, `gh-app` is `<skill-dir>/scripts/gh-app.sh`, `gh-dep` is
`<skill-dir>/scripts/gh-app-issue-dependency.sh` and `gh-sub` is
`<skill-dir>/scripts/gh-app-issue-sub-issue.sh`.

## Conventions

- **Create an issue**: `gh-app issue create --title "..." --body-file FILE --label LABEL` (`--label` repeats).
- **Read an issue**: `gh-app issue view NUMBER --json number,title,state,labels,assignees,body,comments`, adding `--jq` to filter.
- **List issues**: `gh-app issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'`, adding `--label` and `--state` filters.
- **Comment on an issue**: `gh-app issue comment NUMBER --body-file FILE`.
- **Apply / remove labels**: `gh-app issue edit NUMBER --add-label "..."` / `--remove-label "..."`.
- **Close**: post the closing comment as above, then `gh-app issue close NUMBER` — `gh issue close` has no `--body-file`, so the comment stays its own command.

## Operations `gh` has no command for

`gh` has no command for issue dependencies or sub-issues. Two scripts from the
same skill call the API for them and resolve the issue numbers GitHub needs; both
take `--repo`.

- **Dependency edge**: `gh-dep add --blocked N --blocker N`, `gh-dep remove --blocked N --blocker N`, `gh-dep list --issue N`.
- **Sub-issue link**: `gh-sub add --parent N --child N`.

Any other operation runs through the same dispatcher with `gh`'s own arguments,
for example `gh-app pr view`, `gh-app pr diff`, `gh-app api`, `gh-app run view`.

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external PRs as feature requests; `/triage` reads this flag.)_

When set to `yes`, PRs run through the same labels and states as issues, through
the dispatcher's `gh pr` arguments:

- **Read a PR**: `gh-app pr view NUMBER --json number,title,body,labels,author,authorAssociation,comments,state` and `gh-app pr diff NUMBER` for the diff.
- **List external PRs for triage**: `gh-app pr list --state open --json number,title,body,labels,author,authorAssociation,comments` then keep only `authorAssociation` of `CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR`, or `NONE` (drop `OWNER`/`MEMBER`/`COLLABORATOR`).
- **Comment / label / close**: `gh-app pr comment NUMBER --body-file FILE`, `gh-app pr edit NUMBER --add-label "..."`/`--remove-label "..."`, `gh-app pr close NUMBER`.

GitHub shares one number space across issues and PRs, so a bare `#42` may be either — resolve with `gh-app pr view 42` and fall back to `gh-app issue view 42`.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Run `gh-app issue view NUMBER --json number,title,state,labels,assignees,body,comments`.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single issue with **child** issues as tickets.

- **Map**: a single issue labelled `wayfinder:map`, holding the Notes / Decisions-so-far / Fog body. `gh-app issue create --title "..." --body-file FILE --label wayfinder:map`.
- **Child ticket**: an issue linked to the map as a GitHub sub-issue (`gh-sub add --parent <map> --child <ticket>`). Where sub-issues aren't enabled, add the child to a task list in the map body and put `Part of #<map>` at the top of the child body. Labels: `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: GitHub's **native issue dependencies** — the canonical, UI-visible representation. Add an edge with `gh-dep add --blocked <child> --blocker <blocker>`: the child is the issue that cannot start, and the direction is the API's `blocked_by`. `gh-dep list --issue <n>` prints both directions. Where dependencies aren't available, fall back to a `Blocked by: #<n>, #<n>` line at the top of the child body. A ticket is unblocked when every blocker is closed: `gh-app issue view <blocker> --json state`.
- **Frontier query**: list the map's open children (`gh-app issue list --state open`, scoped to the map's sub-issues / task list), drop any with an open blocker (an open issue in the `blocked by:` direction of `gh-dep list --issue <n>`, or in the `Blocked by` line; `blocking:` edges never gate) or an assignee (`--json assignees`); first in map order wins.
- **Claim**: `gh-app issue edit <n> --add-assignee USER` — the session's first write. Name the person: `@me` resolves to whichever identity authenticated, which under the App is not the driving dev.
- **Resolve**: `gh-app issue comment <n> --body-file FILE`, then `gh-app issue close <n>`, then append a context pointer (gist + link) to the map's Decisions-so-far.
