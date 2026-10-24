# ADR-0038: Refuse writable exposure of the authority config directory

## Status

Accepted for [#323](https://github.com/gregwebs/agent-vm/issues/323), the guard
half of #302 A2. This guard did not accept persisted `[network]` authority.
Amended by [ADR-0040](0040-persisted-user-network-authority.md): #305 adds its verified user-tier read,
without changing this guard. Breaking guard release: **0.3.0**.

## Context

`~/.config/agent-vm/credentials.yaml` authorizes launch secrets today. A guest
that can write its directory can plant a normal-looking user-owned `0644`
file for a later launch. Read-time owner, mode and symlink checks cannot
recognize guest authorship. ADR-0040 adds network authority in the same
directory; this guard preceded that feature.

```text
launch P1 → writable window → plant authority in host config directory
launch P2 → read ordinary user-owned file → authorize a secret
                  ↑ refuse P1, not merely inspect P2's file
```

## Decision 1: Unconditional exposure guard

`protected_config_dir.rs` measures once in `mount::prepare`, before state
creation, fork preparation, credential capture or boot. Project, state,
guest-home and explicit writable live binds are checked. `ro` and `:fork`
are exempt: neither lets a guest rewrite the source. Discovered `follow-links`
targets are read-only today; filtering by writability covers any future
writable target. Nothing is masked, omitted or downgraded to an advisory.
Pi core-bind refusals retain precedence, followed by authority link checks,
config core checks, Pi explicit checks and config writable-mount checks.

### Resolution walk, not only a resolved ancestor chain

This amends [ADR-0020](0020-protect-host-pi-credential-files.md)'s route set
for **writes**, without changing its Pi policy. Record each directory in
which resolution looks up a name, its ancestors and the deepest existing
node; follow symlink text even through dangling links, failing closed on
errors or more than 40 symlink hops.

- **A1:** `.config → /external/config`. The home must be recorded: the guest
  could replace `.config`, even though it cannot read the external target
  through a dangling guest-space symlink. Pi's resolved-only walk omits home.
- **A2:** `agent-vm → /external/agent-vm`, dangling. Protect `/external`,
  where the guest could create the missing authority directory.

Existing bind roots are compared by `(dev, ino)` and canonical containment.
The spelled arm is a backstop, skipped for spellings containing `..`; it is
not TOCTOU protection. Containment-only entries include the spelled config
path and prospective full paths. A bind strictly inside the config directory
cannot reach its authority files and is allowed.

### Prospective directories and missing core sources

A missing state/home source is not safe merely because it does not yet exist.
**A3:** `.config → <state>/<hash P1>/home/.config` is dangling. Provisioning
would create P1's guest home, where its guest could plant credentials for P2.
Compare missing sources to every prospective lookup directory, each stored
as an existing anchor (path and identity) plus an unresolved component suffix.

Continue after missing components, assuming future real directories. A `..`
pops the missing suffix; once empty, resume real resolution. Truncating at the
first `..` both wrongly refused `<s>/P1/../other/.config` for P1 and missed
P2's exposure through `<s>/P1/../P2/.config`. A source's own missing suffix
containing `..` fails closed: `create_dir_all`'s intermediate creation is not
modelled. Relative state roots are anchored at the captured launch cwd;
diagnostic spelling is the uncollapsed `cwd.join(source)`.

**A3':** aliased existing anchors (macOS firmlink or Linux bind mount) match
by identity even when their paths differ. This is not #321: the anchor is
above the missing bind root and is measured, not a nested alias below it.

### Conservative name equivalence

**A3c:** an upper-case hash in a dangling link can name the lowercase hash
that provisioning creates on a case-insensitive volume. Byte equality misses
that exposure. The rule is platform-independent:

1. Anchors match by identity, or equal-length component lists under rule 3.
2. The source suffix is no longer than the destination suffix and matches
   every corresponding component under rule 3.
3. Names may match unless **both** are plain and differ other than in ASCII
   case. Plain means nonempty `[A-Za-z0-9._-]`, with no trailing `.`. Every
   non-plain name matches anything, including Unicode, spaces, `~`, `:`,
   invalid UTF-8 and trailing-dot names.

Fail closed rather than model each filesystem: missing directories cannot be
probed, equivalence can be inherited at creation, and APFS's normalization,
Kelvin-sign and ligature equivalence are not a small reviewable ASCII model.
The assumption is that no supported filesystem equates two plain names that
differ other than in ASCII case. This is engineering judgement, **not proved**.

Analysed over-refusal cost (not a measured rate): case variants on a
case-sensitive filesystem; missing non-plain names at hash/home depth; and
distinct existing anchors whose non-plain path components match through the
fallback, with matching suffixes. It costs a launch, never authority.
The missing-source message therefore says **“could be, or contain, a directory
in which agent-vm looks up names”**, not that it definitely contains the config
dir, and explains the name rule.

### Both homes, including raw HOME

Measure raw `$HOME` from the existing config helper and the account's `pw_dir`,
deduplicated. Pi's UTF-8 home selection is unchanged. With `HOME` unset no user
config is read, but a later launch may use the account home. Costs: two walks;
errors on either fail closed; a launch with HOME elsewhere still cannot expose
the account home's authority. A third HOME is not covered.

Raw non-UTF-8 bytes are legal in Unix environment variables on both platforms.
M11a is a filesystem-free subprocess assertion on the production
`MountContext.authority_home` field, including root mode. APFS rejects an
invalid-UTF-8 filename component with `EILSEQ`: M11b's real-directory exposure
layout is unreachable there. Linux filesystems accepting arbitrary bytes can
realize it. M11b probes filename support and prints a skip on rejection, then
runs end-to-end only on Linux. This is filesystem-dependent, not a promise
about every mountable filesystem. A skipped M11b supplies no refusal evidence.

## Decision 2: Unconditional launch-time link-count check

A pre-existing second name for `config.toml` can live inside an unrelated
writable bind. The guest can write-then-unlink (L1), or open-then-unlink-then-write
(L2); by the next read, the authority file has only one link and appears safe.
Refuse every launch while a measured regular `config.toml` has `nlink != 1`,
independent of content. A final-component symlink is not checked as a regular
file. No contents are read or echoed by this guard.

While the directory guard holds, an already linked file cannot be laundered
through a launch by this build. Host-created links mid-session remain trusted.
`credentials.yaml` link counts are deliberately excluded (#319).
`authority_file_singly_linked` and `authority_file_singly_linked_spec` share the
one-name rule with `config_authority::authority_refusal` (ADR-0040), in both
its executable and spec. A read-time-only rule is insufficient.

## Trusted boundary and accepted gaps

- Syscalls, runtime/kernel read-only semantics, canonicalization and `(dev, ino)`
  measurements; unreliable identity with no path match (NFS/SMB double mounts).
- Missing components later become real directories, or are created by trusted
  host processes. Host symlink creation/repointing changes the lookup after
  measurement and is not defended. The tree must remain stable through binding.
- #321: a nested host mount alias below an existing bind root is not walked;
  runtime lookups can cross that mount. Closing it needs a subtree walk or
  runtime no-cross-mount rule.
- #322 (related #114): the checked pathname is opened again at bind time;
  explicit binds use `follow_root_symlinks(true)`. Another launch's guest or
  a host process able to write the parent can swap it between observations.
  Core sources are also canonicalized again after provisioning.
- Older agent-vm builds and content they permitted; `agent-vm msb` passthrough,
  separately installed msb, Docker mounts, same-user host malware and other
  host processes are outside this launch boundary. Host-created hard links
  mid-session are not covered.
- Third HOME values, ACLs, and filesystems violating the plain-name assumption.
- #319 credentials hard links; symlinked `config.toml` targets writable from
  elsewhere (pre-existing tools/image risk; #305 rejects symlinked network
  authority). Credentials are already read `O_NOFOLLOW`.
- Neither home available: no core-bind protection; explicit mounts remain
  refused by Pi's `require_home`, and no user config is read.

### What the four contracts do not prove

The one-name, name-match, existing first-hit and prospective first-hit kernels
prove their stated comparisons, not that the walk collected the correct
routes, that missing nodes become real directories, that the name rule covers
any filesystem, that identities are reliable, or that the runtime binds the
checked object. `exposing_entry` reuses `byte_path_contains`'s contract.
I/O adapters and policy wiring need tests. Local plain-build tests are not
formal verification; CI's Verus gate is the contract source of truth.

## Consequences

0.3.0 deliberately breaks launches from `$HOME`, writable `--mount ~` and
`--mount ~/.config`, including users with no Pi installation. Run from a
project, choose read-only, or bind a narrower source; move state with
`AGENT_VM_STATE_DIR` when necessary. Hard-linked `config.toml` blocks every
launch until other links are removed or the file is replaced with a copy.
Non-launch verbs, including doctor, are unaffected.

Writable-bind routes to the credentials directory are guarded subject to the
accepted gaps; credentials file hard links stay open (#319). This guard release
rejected `[network]`. Amended by [ADR-0040](0040-persisted-user-network-authority.md): verified user-tier
network authority is accepted on top of the unchanged guard.

## Alternatives rejected

- Read-time checks alone: cannot detect guest authorship or link laundering.
- Guard only when `[network]` exists: a guest can add it.
- Reuse Pi's `measure_file`: misses A1/A2; extend `ProtectedFile` with a directory
  variant: inherits Pi advisories, ro refusals and fork omissions.
- Drop root-symlink following or pin descriptors here: runtime change, #322.
- Walk bind subtrees for nested aliases: #321, not this PR.
- Path-only prospective comparison: misses A3'; truncate at `..`: misses P2
  and falsely refuses P1; refuse relative state roots: compatibility break.
- Byte-only prospective names: misses A3c; model every filesystem: cannot probe
  missing directories and equivalence tables are not reviewable.
- Refuse on matching anchors alone: breaks ordinary first launches, e.g.
  state `~/st/<hash>` when `~/.config/agent-vm` is absent (both suffixes have
  two components but distinct plain names).
