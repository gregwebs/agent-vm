# opencode layer — vendored installer

`install.upstream.sh` is a verbatim snapshot of OpenCode's published installer:

- source: `https://opencode.ai/install`
- retrieved: 2026-10-01
- SHA-256: `fc3c1b2123f49b6df545a7622e5127d21cd794b15134fc3b66e1ca49f7fb297e`

It is provenance, not an executable guard target, and is never run.

## License / attribution

The upstream snapshot is redistributed here under the OpenCode project's MIT
License (SPDX `MIT`, Copyright (c) 2025 opencode), not under this repository's
own license. The full license text is in `vendor/LICENSE` and the
provenance/attribution record is in `vendor/NOTICE`.

`install.sh` is the runnable patched copy. `install.patch` is the reviewable
patch; applying it to the snapshot reproduces `install.sh` byte-for-byte (see
`script/test/opencode-installer.sh`). `git apply` it from a directory holding the
snapshot renamed `install.sh`.

## Trust boundary

The snapshot is pinned; the exact release archive it downloads is fetched at
build time. Upstream publishes no separate checksum for the archive, so integrity
comes from TLS plus the exact-version tag, not independent signing. `chmod`/mode
repairs keep the result usable by any uid; they are not a supply-chain guarantee.

## Patch hunks

1. **Exact version only.** An empty `VERSION` is rejected instead of falling back
   to the GitHub `latest` release, and the `latest` lookup, its `specific_version`
   parse and the release-existence HEAD probe are removed. The exact asset URL is
   the authority.
2. **`download_and_install` routes through the shared classified helper**
   (`contract/download.sh`), so a transport failure is a receipt + 75 and every
   other failure is hard. The progress-download machinery it replaced
   (`download_with_progress`, `print_progress`, `unbuffered_sed`) is removed.
3. **The already-installed skip is removed.** `check_version` no longer exits 0
   when a matching command happens to be present, so an inherited command cannot
   mask a skipped install.
4. **Upstream lint fixes folded in:** the `GITHUB_PATH` redirect is quoted.
5. **Private scratch with trap cleanup.** `download_and_install` uses
   `mktemp -d` under `TMPDIR` (a private, random `opencode_install.XXXXXX`)
   plus an EXIT/INT/TERM/HUP trap, so a classified transport failure (or any
   other error under `set -e`) removes the download scratch instead of leaving
   `opencode_install_*` leftovers for a degraded image to ship.
