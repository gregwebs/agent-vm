# codex layer — vendored installer

`install.upstream.sh` is a verbatim snapshot of OpenAI's published Codex
installer from the exact release it installs:

- source: `https://github.com/openai/codex/releases/download/rust-v0.159.3/install.sh`
- retrieved: 2026-10-01
- SHA-256: `150e3cf675682efeaac115aa3747add3f27887896d04ce6d0b56478d8b428bf6`

It is provenance, not an executable guard target, and is never run. The snapshot
is byte-identical to the release asset.

## License / attribution

The upstream snapshot is redistributed here under the Codex project's Apache
License 2.0 (SPDX `Apache-2.0`, Copyright 2025 OpenAI), not under this
repository's own license. The full license text is in `vendor/LICENSE` and the
provenance/attribution record is in `vendor/NOTICE`.

`install.sh` is the runnable patched copy. `install.patch` is the reviewable
patch; applying it to the snapshot reproduces `install.sh` byte-for-byte (see
`script/test/codex-installer.sh`). `git apply` it from a directory holding the
snapshot renamed `install.sh`.

## Trust boundary

The snapshot is pinned; the release metadata and assets it downloads are fetched
at build time and checksum-verified against the release manifest. That detects
corruption, not independent signing, and does not prevent upstream replacing an
exact-version asset. `chmod`/mode repairs keep the result usable by any uid; they
are not a supply-chain guarantee.

## Patch hunks

1. **Exact version only.** `CODEX_RELEASE` has no `latest` default;
   `normalize_version` no longer maps empty/`latest` to `latest`, and
   `validate_version` rejects empty and floating values instead of returning
   early. The owning hook validates first; this is defence in depth.
2. **releases.openai.com path removed.** `RELEASES_BASE_URL`,
   `PREFER_RELEASES_OPENAI_COM`, `releases_url_for_asset`,
   `resolve_release_from_releases` and the fallback URLs are gone: builds always
   use the exact GitHub release tag.
3. **`download_file`/`download_text` route through the shared classified helper**
   (`contract/download.sh`), so a transport failure is a receipt + 75 and every
   other failure is hard. `download_text` buffers to a file so a classified 75
   is not lost in a pipe.
4. **`download_file_with_fallback` is fallback-free.** There is exactly one
   exact GitHub asset, and any failure (75 included) propagates immediately,
   before checksum/verification runs.
5. **No latest resolution.** `resolve_release_from_github` always uses the
   exact-tag metadata URL and rejects a mismatched tag. The `latest`
   channel/lookup URLs are removed. The auto-updater guard that remains only
   compares the (already exact) `RELEASE` and has no lookup.
6. **Native subprocesses never see the transport receipt.** The script keeps the
   receipt path privately (`AGENT_VM_RECEIPT_PATH`) and `unset`s
   `AGENT_VM_TRANSPORT_RECEIPT`, handing it only to `download.sh`. A native
   `codex` exit 75 (or one that writes the receipt path) is therefore a hard
   failure, never a transport classification -- the plan requires native code
   never to receive the receipt environment.
7. **Strict release metadata validation.** `parse_release_metadata` now requires
   exactly one complete JSON document (rejecting missing commas and trailing
   garbage) and rejects duplicate/conflicting `tag_name` and duplicate per-asset
   name/digest records before any value is used; the hand-written balance
   scanner accepted all four.
8. **Bounded native probes.** `version_from_binary` and `verify_visible_command`
   run the native `--version` through the shared bounded, status-preserving
   `run-report.sh` (60s, `--kill-after`), so a hung or TERM-ignoring native
   fails the install instead of hanging the build before the verify gate runs.
