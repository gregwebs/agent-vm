# ADR-0078: Project-config writer

## Status

Accepted for [#737](https://github.com/gregwebs/agent-vm/issues/737). Release:
**0.8.5**. Amends [ADR-0040](0040-persisted-user-network-authority.md),
[ADR-0067](0067-project-default-boot-image.md) and
[ADR-0073](0073-host-managed-project-config.md); complements
[ADR-0076](0076-sources-tables-trust-and-allow.md) and
[ADR-0077](0077-pinned-config-sources.md).

## Context

`image set-default --image REF` saves the invoking project's explicit boot-image
reference in the host-managed project config. It must not reformat a user file
merely to change root `image`, and it must not approve OCI content.

The project store is authority-bearing state. A path check followed by a later
write walk could measure one route and publish through another. A writer held in
a directory after its name moves could publish into a detached tree. Acquisition
and approval remain separate authorities.

## Decision

1. **Observe without mutation; bootstrap only to publish.** `snapshot()` is a
   read: it creates no directory, lock, or file. Its route identity contains only
   the directory levels that existed, its lock identity is optional, and its file
   state is either identity-plus-bytes or explicit absence. `save()` alone may
   create the verified absent store, its first lock, or the first lock in an
   existing store. Its locked publication state always has a lock identity.

2. **Bind publication to the live route.** The descriptor walk opens and checks
   `$HOME`, `.config`, `agent-vm`, `projects/`, and the project store in order.
   `.config` and `agent-vm` may follow an admitted alias; `projects/` and the
   store never do. An admitted alias has fully controlled ancestry, its canonical
   spelling must name the opened descriptor, and it must not resolve inside the
   active project. “Inside” is tested against the captured project `(dev, ino)`;
   each level also checks that the captured project root still has that identity.

   Under `config.lock`, and immediately before `renameat`, the fence re-states
   every admitted name from its descriptor above it. Thus a moved `projects/`, a
   retargeted `.config` or `agent-vm` alias, a changed lock, or changed route
   authority is a typed displaced conflict. The final fence also re-measures the
   current destination boundary: regular-file type, owner, mode, link count,
   identity, size and owner-write permission, plus the current authority of every
   directory used to publish. Authority can change without changing identity,
   size, or link count.

   `ENOENT` means either an absent name or an existing link with a missing target.
   Only the former is created. A dangling alias is refused rather than created
   over. A newly created directory is `chmod`ed by name through its verified
   parent before it is opened: ownership, not access to the new entry, permits
   that repair, so a masking umask cannot make the walk fail after creation.

3. **Compare and publish every plan.** The planner's `Unchanged` means only that
   the measured bytes need no edit. It still enters compare-and-publish with the
   snapshot bytes. `ConfigSave::Unchanged` is only the writer's post-lock answer
   after the snapshot, route, lock, and live bytes compare. Absent-to-present,
   present-to-absent, identity or byte changes, and displaced route or lock are
   typed conflicts. #737 neither renames nor replaces a project directory.

4. **Splice one token or one root boundary.** A root string `image` value is
   replaced in place. If absent, one root assignment is inserted before the first
   real table or array-of-tables header; an absent file receives an explicit
   `[[sources]]` `home` seed. No serializer is a fallback. The insertion scan is
   bounded by the end of the last root value, so a multiline root string whose
   last line begins with `#` remains content, while a genuine table note stays
   with its table. Existing bytes retain their spelling, BOM, comments, tabs,
   mixed or CRLF line endings, and final-newline state. An existing zero-byte
   file receives an assignment with no final newline; an absent file is a separate
   seeded case. The inserted line uses an adjacent line ending, or LF when none
   exists.

5. **Refuse outside the narrow edit boundary.** Invalid UTF-8, invalid TOML,
   duplicate keys, a non-string root `image`, an unambiguously mis-scoped
   `image`, an unreadable or oversized file, an unsafe file, and an unsafe route
   refuse without repair, reseed, ownership repair, or chmod of an existing entry.
   A non-string root `image` includes the parser's line and column when available.
   A read whose descriptor size changes — growth or shrinkage, including growth
   below the cap — refuses: `the project config changed while it was being read,
   so nothing was written; read it again and repeat`. Valid TOML with an unrelated
   schema, source, or approval error may receive this narrow edit; its unrelated
   bytes and source declarations remain unchanged. The finite policy for tables
   that own an `image` is beside `RawConfig`, which owns those schema field names.

6. **Keep acquisition, approval, and config publication separate.**
   `image set-default` acquires first, compares the acquired child with an
   observed approval for the same project, canonical reference, and host platform,
   then writes configuration. It writes no approval, retained default, or source
   pin. The acquisition's cache publication barrier remains held during
   publication (and until the success notice is attempted); `config.lock` is then
   acquired beneath that barrier. No cache, OCI, pin, or source lock is acquired
   from inside `config.lock`.

   Its success notice is: `Project boot image reference saved to the project
   config at <path>. Overrides and approvals are unchanged.`

## Consequences

- `image set-default --image REF` saves `REF` as root `image` in this project's
  `config.toml`. It does not write `default-image.json`; the retained default is
  a lower-precedence fallback.
- A typed conflict reports either `the project config changed after it was read,
  so nothing was written; read it again and repeat` or `the project config store
  or its config.lock changed after it was read, so nothing was written`. Review
  the current project config and repeat the command against the intended root
  `image`; the refused save changed nothing.
- A resulting file can be valid TOML yet fail the configuration loader for an
  unrelated schema, source, or approval problem. A successful narrow write does
  not claim that the catalog loads.
- `image show` reports the project-config reference when it wins. `doctor`
  diagnoses the configuration independently and can report a project selection
  while exiting non-zero for another problem.
- A newly supplied `ALIAS:image` is a parser refusal (status 2), before
  acquisition or a write. Its value-free advice is `set-default saves image =
  "REF" in the project config, where <alias>:image selects a sourced file's image
  instead of naming one; spell an OCI image tagged "image" with its registry (for
  example docker.io/library/NAME:image)`. Runtime refusals, including acquisition,
  approval mismatch, and typed save conflict, exit 1. Runtime errors redact
  stored/default references; `image show` and `image pins` are the explicit
  disclosure surfaces.
- If an existing approval names a different child, the command writes nothing.
  For an in-use held reference, the advice is `Re-resolve and approve the held
  reference with `agent-vm image pull --image REF` (it replaces that reference's
  approval with what it acquires now), or re-run image set-default with the
  immutable digest reference (repo@sha256:...) of the content you intend.` For
  any target, reacquire the intended immutable digest and run `image set-default`
  with that digest to roll back. A digest does not bypass OCI authority.
- The editor UX belongs to #739. This record supplies snapshot and
  compare-and-publish, not an editor, retained temporary buffer, full edited-config
  validation, `show`, `diff`, `approve`, source review, or in-place `rm`.

## Rejected alternatives

- **A path classifier followed by a second walk:** the classifier and the write
  could describe different routes. The descriptor walk is the measured route.
- **Re-serialising with `toml_edit`:** the pinned `DocumentMut::to_string`
  normalises CRLF to LF, adds a missing final newline, and moves a leading comment
  below an inserted root key.
- **Replacing the project directory:** a concurrent or stale writer could publish
  into a detached directory; the permanent directory and lock preserve the
  coordination identity.
- **Serialising approval through `config.lock`:** config publication writes no
  approval. A combined protocol would need its own specified lock order.

## Accepted limits

- The final fence and `renameat` are separate operations. A same-user `chmod` or
  rename can land in that gap.
- Alias ancestry is verified during the walk. If a parent is replaced later, the
  replacement is caught only when that level's own canonical-identity tie is
  checked.
- The captured project-root identity is not part of the publish fence. It cannot
  redirect the store, because publication is descriptor-bound.
- There is no power-loss durability promise: the writer calls `File::flush`, not
  `fsync`, and `TempEntry` cleanup only attempts unlink.
- POSIX mode checks do not predict ACLs, filesystem flags, or read-only mounts;
  the measurable result is a commit syscall failure.
- A moved tag can acquire B while a contemporaneous approval of A for the same
  canonical reference wins the next launch. The command saves a reference, not a
  digest. When that saved project-config selection wins, the launch banner prints
  its reference, not the digest, which is where this accepted window can mislead
  a user.

## Follow-on work

#739 inherits the verified writer's snapshot and compare-and-publish seam. Its
config save and source approval/reset remain separate actions unless its owner
specifies a joint publication protocol and lock order. #749 owns
`default_tools`, `use_tools`, and `RawConfig`; the writer preserves those keys
byte-for-byte and adds neither fields nor a schema registry.

## References

- [ADR-0073](0073-host-managed-project-config.md) — project-config route and
  read authority.
- [ADR-0076](0076-sources-tables-trust-and-allow.md) and
  [ADR-0077](0077-pinned-config-sources.md) — source semantics and pins.
- `crates/agent-vm/src/project_config_writer.rs` — verified writer and exact
  byte-edit planner.
- `crates/agent-vm/src/boot_image/upgrade.rs` — command ordering and notices.
