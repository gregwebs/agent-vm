# claude layer — vendored installer

`install.upstream.sh` is a verbatim snapshot of Anthropic's published installer
(`https://claude.ai/install.sh`, retrieved 2026-09-30). It is provenance, not an
executable guard target, and is never run.

`install.sh` is the runnable patched copy. `install.patch` is the reviewable
patch; applying it to the snapshot reproduces `install.sh` byte-for-byte (see
`script/test/claude-installer.sh`). `git apply` it from a directory holding the
snapshot renamed `install.sh`.

## Trust boundary

The snapshot is pinned; the assets it downloads are fetched at build time and
checksum-verified against the vendor's manifest. That detects corruption, not
independent signing, and does not prevent upstream replacing an exact-version
asset. `chmod`/mode repairs keep the result usable by any uid; they are not a
supply-chain guarantee.

## Patch hunks

1. **Exact TARGET only.** Rejects empty, `stable`, `latest`, ranges and URLs;
   requires `AGENT_VM_CONTRACT_DIR`.
2. **curl required up front.** wget and the progress variant are not download
   policies here.
3. **`download_file` routes through the shared classified helper**
   (`contract/download.sh`), so a transport failure is a receipt + 75 and every
   other failure is hard.
4. **zstd asset path disabled.** Its download is wrapped in `2>/dev/null ||
   true`, which would swallow a classified transport result; the verified
   uncompressed exact asset is used.
5. **No channel fetch.** `version="$TARGET"` replaces the `/latest` fetch.
6. **Final binary download propagates the classified 75** with `|| exit $?`.
7. **Native install bounded and normalized.** `claude install TARGET` runs with
   the receipt environment removed and cleared, under
   `timeout --kill-after=5 300` (TERM, then SIGKILL, so a TERM-ignoring native
   installer cannot hang the build), and any nonzero is normalized to a hard
   failure.
