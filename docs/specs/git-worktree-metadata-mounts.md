# Automatic Git metadata mounts for linked worktrees

Status: implemented in 0.7.37 ([ADR-0062](../adr/0062-automatic-git-metadata-mounts.md));
native rows GM-N1–GM-N4 passed on macOS arm64 (R15, receipt below).
Tracked in [#535](https://github.com/gregwebs/agent-vm/issues/535).

## Problem Statement

Launching agent-vm at a linked Git worktree mounts the checkout but not its
external Git metadata. The checkout's `.git` file therefore points to paths
missing in the guest. Users must identify and mount those paths manually even
to inspect repository history.

## Solution

Automatically discover the linked worktree rooted at the launch directory and
mount its required per-worktree and shared Git metadata at the existing host
paths. Do not mount the main checkout or another checkout's source tree.

Offer one per-launch option, before the route:

```sh
agent-vm --git-mount=ro pi     # default; no approval prompt
agent-vm --git-mount=rw pi     # explicit writable metadata for this launch
agent-vm --git-mount=off pi    # no automatic Git metadata mounts
```

| Mode | Additional automatic metadata mounts | Approval |
| --- | --- | --- |
| `ro` (default) | Read-only | None |
| `rw` | Writable | Explicit option for this launch; no remembered approval |
| `off` | None | None |

The option is a launch option for catalog tools, shell launches and direct
commands. It does not change the existing meaning of `--no-git`, which controls
GitHub credential handling rather than local filesystem access.

## User Stories

1. As a linked-worktree user, I want Git metadata available automatically, so that I do not need to discover external paths manually.
2. As a user inspecting a checkout, I want read-only metadata by default, so that automatic mounts do not grant new write access.
3. As a user inspecting history, I want Git log and diff commands to resolve the repository, so that the guest can understand my changes.
4. As a user scripting launches, I want default read-only access without approval, so that launches remain unattended.
5. As a user staging changes, I want explicit writable metadata, so that Git can update the index and object database.
6. As a user creating commits, I want explicit writable metadata, so that Git can update objects, refs and logs normally.
7. As a security-conscious user, I want write access chosen separately for each launch, so that one launch does not authorize later launches.
8. As a user declining extra access, I want an off mode, so that no metadata paths are mounted automatically.
9. As a user recovering from invalid metadata, I want off mode to bypass automount discovery, so that I can launch without this feature.
10. As a user isolating a checkout, I want only Git metadata added, so that another checkout's source directory is not exposed.
11. As a user with absolute or relative Git pointers, I want the required paths to resolve in the guest, so that supported worktrees retain their existing layout.
12. As a user launching from a subdirectory, I want the current mount scope preserved, so that this feature does not expose parent directories.
13. As a user of ordinary checkouts, I want existing behavior unchanged, so that this feature does not unexpectedly restrict or widen my project mount.
14. As a user declaring explicit mounts, I want those declarations preserved, so that an automatic mount does not silently override them.
15. As a user with conflicting mount declarations, I want an actionable pre-boot error, so that I can resolve the conflict deliberately.
16. As a user relying on protected host paths, I want the existing protections applied, so that automounting does not bypass them.
17. As a user with broken worktree metadata, I want a clear failure before boot, so that I do not receive a silently degraded Git environment.
18. As a user disabling GitHub credentials, I want local Git mounting controlled independently, so that filesystem access and credential handling remain distinct.
19. As a user of shell and direct-command launches, I want the same mode selection, so that access does not depend on the launched program.
20. As a user choosing read-only mode, I want its limits documented, so that I do not mistake it for repository-wide write protection or confidentiality.

## Implementation Decisions

### Scope and discovery

- Discover only a linked worktree whose root is the launch directory. Do not
  search ancestors or change the project directory, working directory, or
  project-state identity.
- An ordinary checkout or a directory without a linked worktree retains its
  existing behavior. Launching in a worktree subdirectory does not opt into
  ancestor discovery or parent-checkout mounts.
- Validate the linked-worktree metadata relationship before generating mount
  requests. The `.git` file is untrusted input, not permission to mount any
  directory it names. Resolve absolute and relative metadata paths while
  preserving the guest-visible path relationships Git needs.
- Include only required per-worktree and common Git metadata directories.
  Deduplicate directories already covered by the same automatic metadata bind;
  do not mount the main checkout as a shortcut. A bind that would contain
  another checkout — a worktree registered inside the common directory, or the
  launch directory itself under it — is refused rather than narrowed: a bare
  repository's directory is all metadata, so nothing smaller is a mount of it.
  The containment is measured on canonical host paths, for the project and for
  agent-vm's own host sources, so a symlinked guest spelling cannot hide it.
- Do not recursively discover submodules, external object stores or worktrees
  in extra mounts. This contract does not promise that such dependencies work.
- With `off`, do not discover or validate automatic Git metadata targets. All
  unrelated launch validation and protections still apply.

### Access and authority

- `ro` grants automatic read access to valid linked-worktree metadata without
  a prompt, approval store or ownership-based approval workflow. This is an
  intentional new automatic access source, distinct from a config mount.
- `rw` requires explicit selection on each launch. Do not persist that choice
  in project state or user configuration as part of this feature.
- Modes affect only the additional automatic mounts. They do not make the
  writable project mount, ordinary checkout metadata, or another explicit
  writable route read-only. Do not claim repository-wide enforcement. A
  declaration that encloses the metadata guest path is never shadowed by an
  automatic child bind: the same host directory merges (the declaration's access
  governs, in both modes) and anything else is refused before boot.
- Keep ordinary checkouts and explicit mount semantics unchanged. Do not
  rewrite host Git pointer files or repository configuration to implement
  these modes.
- Preserve mount claim rules: equivalent declarations merge; conflicting
  declarations are refused rather than overridden. Attribute an automatic
  request clearly in diagnostics.
- Apply existing protected-host-file, protected-config-directory, guest-path,
  core-volume and guest-HOME collision protections to the complete plan.
  Automounting is not an exemption.
- Recognized broken linked-worktree metadata, mount conflicts, and protection
  refusals fail before VM boot with an actionable error. Explain when
  `--git-mount=off` can be used to proceed without automatic Git mounts; never
  present it as bypassing other protections.
- Keep `--no-git` and `--no-config-mounts` in their existing scopes. Neither is
  an alias for `--git-mount=off`.

### Existing code seams

All code references in this section refer to commit
`ee12ad585b4d173bd8941e537793f908ea154425`, not uncommitted work:

- `crates/agent-vm/src/session.rs`, `ProjectSession::for_cwd`: existing
  canonical launch-directory and per-directory state identity; preserve it.
- `crates/agent-vm/src/run.rs`, `LaunchArgs` and `launch`: per-launch option
  parsing and orchestration before preparing the complete mount plan.
- `crates/agent-vm/src/user.rs`, `core_dir_volumes`: existing core-volume
  ordering, including guest HOME before the project bind; preserve it.
- `crates/agent-vm/src/mount.rs`, `MountOrigin`, `claim` and `prepare`:
  integrate automatic requests with the existing claim, protection and
  topology pipeline instead of creating an unguarded binding path.
- `crates/agent-vm/src/protected_host_files.rs` and
  `crates/agent-vm/src/protected_config_dir.rs`: existing exposure guards.
- `crates/agent-vm/build.rs`: compile-time Git path discovery is prior art,
  not existing runtime automount behavior or an authorization mechanism.

Respect ADR-0018's boundary-contract requirements when introducing or changing
pure decisions over untrusted metadata paths or mount authority. Do not weaken
the existing contracts to accommodate the feature.

## Testing Decisions

Test observable launch behavior, not a particular parser or internal helper.
Prefer the existing real-CLI launch seam, supplemented by native enforcement
checks; a generated read-only flag alone is not proof of runtime enforcement.

Code references below use the same pinned commit as above:

- Reuse `crates/agent-vm/tests/config_mounts.rs`'s pattern: isolated HOME,
  state and project directories; the real CLI; the launch-capable fake runtime
  in `crates/agent-vm/tests/support/fake_msb.rs`; and the
  `AGENT_VM_DEBUG_CONFIG` sandbox-config output. Observe host/guest bind paths,
  modes, refusals, runtime invocation and relevant filesystem snapshots.
- Create real temporary Git repositories and linked worktrees as fixtures.
  Cover the implicit default and explicit `ro`, `rw`, and `off`; verify that
  read-only discovery requires no terminal or approval and that write mode
  is not remembered.
- Cover absolute and relative metadata pointers, common/per-worktree overlap,
  invalid relationships and missing metadata. Verify that a pointer to an
  arbitrary non-Git directory cannot create an automatic mount.
- Verify no main-checkout source bind, no ancestor expansion from a worktree
  subdirectory, no recursive discovery, and no new automatic mounts for an
  ordinary checkout or non-repository directory.
- Cover equivalent declarations and conflicting explicit/config mounts,
  protected Pi files, protected config paths, core and guest-HOME collisions.
  Refusal must precede VM boot and must not publish fork data or provision
  launch state merely to report a deterministic mount-plan rejection.
- Verify independence from `--no-git` and `--no-config-mounts`, and that `off`
  bypasses broken automount discovery without disabling unrelated validation.
- Verify launch-option routing for catalog tools, shell and direct commands;
  option-like tokens after a tool verb remain tool arguments.
- Run native VM checks for enforcement: in `ro`, Git history/diff inspection
  works while a direct write through an automatic metadata bind fails and
  leaves the host unchanged. In `rw`, staging and committing succeed and the
  host observes the corresponding objects/ref updates. With `off`, no
  automatic metadata bind exists. Until these rows have run, record them as
  BLOCKED — never as a pass — and say so in the status line above.

  Passed 2026-11-08 on a MacBookPro18,3 (Apple M1 Pro, macOS 27.0.1, arm64),
  from a single idle host with no concurrent `agent-vm`/`msb` process:
  candidate `agent-vm 0.7.37 (f3b8a80…)` (sha256
  `10eac63f5429907b3ef9751bb3f93bd807aa19b7b2fbb26bd017bafe78ccfb1e`), image
  `ghcr.io/gregwebs/agent-vm-standard@sha256:04701db7…` (digest-pinned). The run
  reported 53 rows, 53 passed, 0 blocked, 0 failed; the seven `GM-` receipts are
  `GM-N1` (log/diff read, automatic write and `git add` denied),
  `GM-N1-host` (common-dir tree digest unchanged, probe absent), `GM-N2` (guest
  commit), `GM-N2-host` (branch moved, tip is that object, its parent is the
  baseline, `tracked.txt` at the tip carries the edit), `GM-N3`, `GM-N4` (one
  launch: automatic route denied, `--mount …:rw` alias allowed) and
  `GM-N4-host`. Receipts, candidate/runtime/host identities and per-row
  command records are in that run's evidence directory
  (`/private/tmp/avm-535-native.fLjvM9`, scratch: regenerate with
  `script/test/config-mounts-live.sh`).
- Include a control demonstrating that `ro` is not repository-wide write
  protection when a separate writable route exists; do not interpret this as
  failed enforcement of a read-only bind.
- Use focused unit/property tests and Verus checks where boundary decisions
  require them, without replacing end-to-end or native evidence.

## Out of Scope

- Automatic discovery from worktree subdirectories or extra-mounted roots.
- Mounting another checkout, changing the project root or merging project state.
- Recursive submodule or external-object-store dependency discovery.
- Read-access approval prompts, remembered approvals or a new approval store.
- Persisted write defaults or remembered write authorization.
- Repository-wide Git permissions, hook/config shielding, masking or granular
  writable overlays inside an otherwise read-only Git directory.
- Changing ordinary checkouts, explicit mount modes, GitHub credential policy,
  image selection or network permissions.

## Further Notes

### Accepted security trade-offs

Read-only preserves the integrity of that bind, not confidentiality. Shared Git
metadata can expose history, branches, objects and other worktree records; the
guest can disclose what it reads, including to a model provider. A structurally
valid relationship is not proof of permission to read that repository. The
user accepted automatic read-only exposure without approval.

Writable metadata includes shared refs, objects, configuration and hooks.
Guest modifications can affect sibling worktrees and can plant commands that
execute when the user later runs Git on the host. The explicit per-launch
write choice accepts that broader access; ordinary writable checkout exposure
is not hardened by this feature.

The check that keeps another checkout's source out of a bind reads Git's own
registrations (`<common>/worktrees/*/gitdir`). A checkout placed inside the
common directory that Git does **not** register — a clone copied in by hand —
is therefore not detected. That is the same class of prior-write-access
assumption as the accepted forgery below, and it is recorded rather than
papered over.

ADR-0046's verified-user-config rule remains intact: project configuration
still cannot declare config mounts. This feature deliberately adds a separate,
narrow automatic metadata source; do not generalize it into arbitrary
project-authored host mounts. ADR-0014's live-exclusion restrictions and the
ADR-0020/ADR-0038 host-path protections remain unchanged.
