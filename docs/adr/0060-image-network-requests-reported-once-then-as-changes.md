# ADR-0060: Image network requests are reported once per reference, then as changes

## Status

Accepted and implemented in 0.7.33
([#505](https://github.com/gregwebs/agent-vm/issues/505)). Extends
[ADR-0039](0039-non-authoritative-tool-network-requests.md)
to a new request source; the label contract is agent-vm-images ADR 0014
([PR #144](https://github.com/gregwebs/agent-vm-images/pull/144)).

## Context

Images now carry `org.agent-vm.network-requests.image.<component>` and
`…agent.<agent>` labels. The launcher validates the image config, labels
included, before boot. Unlike tool requests, which are reported every launch,
image requests rarely change and would repeat the same notice on every launch.

## Decision

Before boot, the launcher reports the selected image's requests that this
launch's grants do not cover. Requests never grant; coverage is ADR-0039's
lookup-free check.

- **Every group, no tool matching.** All `image.*` requests plus every
  `agent.*` label, grouped `for <agent>`. The launched tool never selects or
  filters a group: the user decides which agents matter. Groups are shown in
  full, even where the tool report already lists a host.
- **Unmet only; coverage filters additions only.** A fully covered group is
  omitted. Coverage removes covered requests from a first report and covered
  additions from a change report. It never hides a removal or an
  ignored-label line, so `--allow-internet-egress` is silent only when nothing
  was removed and nothing new is ignored. The trailer prints iff an unmet
  request was shown. There is no output-length cap.
- **Bounded input.** At most 64 request labels per image are considered: the
  first 64 `image.*`/`agent.*` keys in key byte order. Other keys under the
  prefix are counted and never budgeted, so they cannot crowd out a valid
  group. Request labels beyond 64 are reported once as an excess count, and that
  line says the report is partial. `doctor` applies the same bound and says when
  its picture is incomplete.

> *Amended in #505's implementation:* the sentence "The baseline is the labels,
> never what was printed." was wrong. Read literally, it advances the baseline on
> a quiet launch and then swallows a change the user never saw. The baseline is
> what was *shown*, kept **per group**. The sentence "Changing only grants never
> re-reports" is narrowed to the invariant below.

- **Once per reference, then changes, per group.** A host-wide display store
  under the state root keeps one entry per canonical *selected* reference (the
  retained default's digest when that is the source). The entry's **image request
  baseline** is the set last *shown* for each group: a group's full request set
  (covered requests included) as of the last launch that printed a line **for
  that group**, plus the ignored-label facts last shown.
  - A group with no recorded set is reported in the first form, listing its
    unmet requests. One launch can print first-form lines for some groups and
    change lines for others.
  - A group with a recorded set reports, against that set, the added requests
    that are unmet and every removed request.
  - A group's recorded set advances to its current set **iff that group's own
    line printed**. One group's line never advances another group's set.
  - A group change that prints no line for that group (every addition covered,
    nothing removed) leaves that group's set unchanged, whatever other groups
    print. The change is **pending**, and the first later launch on which an
    addition is unmet shows it.
  - A recorded group that disappears from the labels prints its removals and
    keeps an **empty** recorded set, so a later reappearance is reported as `+`.
    A group that was never shown has nothing recorded, so its disappearance
    prints nothing.
  - *Invariant, per (group, request):* a pair is shown as unmet at most once
    between shown removals of it; a grant change never re-reports a pair already
    shown, and can surface a pending pair for the first time; a pair is recorded
    only when its own group's line printed.
  - *Example:* release A declares `agent.codex=a.example`, and a deny-all launch
    shows `for codex a.example`. After a refresh to B (`a.example,b.example`), a
    launch with `--allow-egress b.example` prints nothing and codex keeps
    `{a.example}`. The next launch without that grant prints
    `changed: for codex +b.example`. The launch after that is silent. Had
    another group printed a line in the covered launch, codex would still have
    kept `{a.example}`.
- **The store is not authority.** It holds at most 256 references, least recently
  seen dropped. The serialized file is at most 8 MiB, measured on the exact bytes
  written; a write that would exceed it drops least-recently-seen references
  earlier, and a larger file is damaged. An entry records at most 128 groups;
  beyond that, empty sets of vanished groups are dropped (last in group order
  first), so such a group's reappearance is reported in the first form, listing
  the same requests. Last writer wins, with no lock. A damaged regular file means
  a full report and a rewrite, never a failed launch. A store path that is not a
  regular file (a symlink, a directory, a FIFO, a socket, a device) is never
  replaced: each launch reports in full and leaves it exactly as it was. The
  entry is written when a line is shown, even if the launch later fails. A quiet
  launch writes only to record the recency of an existing entry.
- **Contract edges.** No request labels and no entry: silent, and no store file is
  created. An invalid label: one "ignored" line, recorded so it is shown once. An
  unrecognized key under the prefix: counted, never named, shown once and again
  only when the count changes. A missing agent key is not reported ("not
  inventoried" needs tool matching). Local rootfs/disk images carry no labels.
- `agent-vm doctor` shows the current picture from the cache (bounded as above),
  without acquiring.

## Implementation

- **The label source.** The labels are read from the validated metadata of exactly
  the content the launch boots: the approved digest when one is approved,
  otherwise the candidate the launch is about to approve. No registry request, no
  receipt read, no extra cache read is added. Cache receipts are deliberately not
  the source — only a fresh acquisition writes one, so imported, built and
  cache-consumed content would be unlabeled.
- **The store.** `<state_root>/image-network-requests.json`, mode 0600, written by
  atomic replace with no lock. The schema is strict JSON at version 1
  (`deny_unknown_fields`): `null` for a baseline means no group line has been
  shown yet, a group key absent from the map has no recorded set, and a group key
  mapped to `[]` has an empty one. **One state has one encoding.** The decoder
  accepts only the exact bytes the encoder writes, so the refused second
  encodings include `{}`, a reordered or duplicate group key, reordered entry
  fields and extra whitespace. Each recorded request array and the `invalid`
  array must be strictly ascending in render order, so a duplicate or reordered
  array is damage too. Request spellings are canonicalised, because the stored
  set is compared verbatim with a later launch's.
- **The reference text.** The report's `{ref}` is the selection's escaped
  reference for an explicit source and the fixed text `the default boot image` for
  the default tier, which never renders a reference.
- **`doctor` reads msb's metadata path directly.** `GlobalCache::new` creates
  directories and normal metadata reads take leases that create lock files, so
  neither is allowed in a diagnostic that must write nothing. Doctor therefore
  derives `manifests/<hex sha256(Reference::to_string())>.json` itself and reads it
  bounded and no-follow. That duplicates one private rule of
  `vendor/microsandbox/crates/image/lib/cache/store.rs`; a differential test pins
  the derived path against `GlobalCache::image_metadata_path` for a tag, a digest,
  a Hub alias and a registry with a port. What that test does **not** detect: a
  change in the cache metadata schema or meaning, in approval selection, or in the
  cache-location rule. The read is a best-effort observation of what msb cached,
  not a re-validation; a concurrent refresh can make it stale, and metadata
  published by rename is never torn.

## Considered options

- **Report every launch**, like tool requests: repeats unchanged information.
- **Key on the booted digest**: a moving tag with unchanged labels would
  re-report content the user already saw.
- **Hash the key instead of storing hosts**: cannot say what changed.
- **Match `agent.<tool>` to the launched tool's name** (as #505 first proposed):
  a renamed or wrapper tool silently misses its group, and command-based
  guessing reports the wrong hosts.
- **Diff against grants as well as labels**: a dropped grant would re-trigger a
  notice for information the user already had; `doctor` covers that case.
- **Advance the baseline on a quiet launch**: simpler, and it permanently swallows
  a change the user never saw. Rejected.
- **Let any group's line advance every group's set**: the same swallow one level
  down, and rejected for the same reason.
- **Track shown requests individually instead of per group**: closes the residuals
  below, at the cost of forfeiting removals of never-shown hosts and of the
  "full request set by group" contract.

## Consequences

The built-in pi/opencode lists stay wider than their agent labels; whether to
narrow them is [#512](https://github.com/gregwebs/agent-vm/issues/512).

- **Image lines can exceed ADR-0039's 300-byte tool-line bound.** That bound is a
  property of the tool report. A maximal image report is about 2.2 MB: 64 admitted
  labels of 64 requests each, a disjoint change line of 8192 terms, and up to 128
  agent group lines.
- *The dropped-grant case.* A request that was covered when its group's first-form
  line printed is recorded without being shown, so a later removal of that grant
  does not report it. `agent-vm doctor` is the answer.
- *The same-launch residual.* A covered addition that arrives in the same launch
  as its own group's line is likewise recorded without being shown; if its grant
  is later removed, it does not reprint. `doctor` is the answer. Closing this needs
  per-request shown-tracking, which the request contract forbids: it keeps the
  image's full request set by group, and per-request tracking would also forfeit
  removals of never-shown hosts.
- A group that was never shown (fully covered on every launch that saw it)
  disappears silently.
- A symlinked or otherwise non-regular store path makes every launch report in
  full until the user removes it.
- *Suppression is possible for anyone who can write the state root.* A planted
  valid entry (or a foreign-owned file in a shared sticky state directory) makes
  the matching lines silent for as long as it is there, with the exit status
  unchanged. This is display state inside the stated trust — the writer can also
  read and rewrite the store — and `agent-vm doctor` is the remedy: it shows the
  current picture regardless of the store.
- *Accepted race (structural review, not proved).* The store path is re-examined,
  without following a final symlink, immediately before the atomic replace, but
  the examination and the rename are not atomic: a symlink created between them is
  replaced. The state root is the user's own directory, anyone who can race there
  can also read and rewrite the store, and the store holds no authority, so this is
  accepted rather than closed.
- Losing or damaging the store, or a write that is refused or fails, is outside the
  recorded sequence: the next launch reports against what was last stored, so a
  request can be shown again.
