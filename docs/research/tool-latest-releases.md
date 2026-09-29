# Resolving each tool's latest release from the launcher

**Research date:** 2026-09-29

**Question:** [#195](https://github.com/gregwebs/agent-vm/issues/195), part of map
[#194](https://github.com/gregwebs/agent-vm/issues/194). For each shipped **tool layer**
(`images/tools/{dsh,pi,codex,opencode,claude,copilot}`, plus the `pi` layer's
`pi-claude-bridge` in `images/tools/pi/bridge`), this doc answers four questions.
What does "latest" mean? Which query returns that version number without installing
anything? Can the layer's Dockerfile install an **exact** version passed as a build arg?
What does the lookup do when the network is down, and can "unreachable" be told
apart from "not published"?

**Local snapshot:** repo at `bb99445` ("Make every tool layer easy to
version-upgrade (#192)"). The upstream installers were fetched on the research date
from the URLs the Dockerfiles use. Network observations came from macOS with npm
10.9.2 and curl. The versions observed that day are listed in
[Observed values](#observed-values-2026-09-29).

This is a record of facts, not a recommendation.

## Summary table

| Tool (layer) | Source of "latest" | Version query (no install) | Exact-version install from a build arg? | Offline / failure signal |
|---|---|---|---|---|
| `codex` | GitHub Release marked latest on `openai/codex` (tag `rust-vX.Y.Z`). The current installer reads `releases.openai.com/codex/channels/latest` first and uses GitHub only as a fallback. | `curl -fsSL https://api.github.com/repos/openai/codex/releases/latest \| jq -r .tag_name` (what `agent-versions.sh` does). The same `tag_name` comes from `https://releases.openai.com/codex/channels/latest`. | **Not today.** The build arg is only a cache key. The installer does support it: `CODEX_RELEASE=<ver>` env or `--release <ver>`, and it strips `rust-v`/`v`. | curl exit 6/7/28 = unreachable. An HTTP 404 on `releases/tags/rust-v<ver>` or `releases.openai.com/codex/releases/<ver>/release.json` = not published. GitHub rate limiting returns 403/429. The installer itself merges these into one message. |
| `opencode` | GitHub Release marked latest on `anomalyco/opencode` (tag `vX.Y.Z`) | `curl -fsSL https://api.github.com/repos/anomalyco/opencode/releases/latest \| jq -r .tag_name` (what `agent-versions.sh` does) | **Not today.** The build arg is only a cache key. The installer does support it: `VERSION=<ver>` env or `--version <ver>`, and it strips a leading `v`. | Same GitHub signals as codex. The installer's latest path uses `curl -s` without `-f`, so offline, rate-limited and garbage responses all end as "Failed to fetch version information". Its exact path reports a real 404 as "Release … not found". |
| `claude` | `downloads.claude.ai` native `latest` channel. `stable` is a separate channel. | `curl -fsSL https://downloads.claude.ai/claude-code-releases/latest` returns a bare version string (what `agent-versions.sh` does) | **Not today.** The build arg is only a cache key. The installer supports an exact version or channel as a **positional argument** (`bash -s 2.1.89`), but `agent-vm-install` passes the installer no arguments. Even an exact install still downloads the `latest` binary first and runs `<latest> install <ver>`. | curl exit 6/7 = unreachable. A 404 (S3 `NoSuchKey`) on `…/<ver>/manifest.json` = not published. |
| `copilot` | npm `@github/copilot` dist-tag `latest` | `npm view @github/copilot dist-tags.latest` (what `agent-versions.sh` does) | **Yes, already** (since #192): `npm install -g "@github/copilot@${AGENT_VERSION_COPILOT:-latest}"` | `npm view … --json` exits 1 in both cases, but `.error.code` differs: `E404` = not published, `ENOTFOUND`/`ECONNREFUSED`/`ETIMEDOUT` = unreachable. |
| `dsh` | npm `@deepseek-ai/dsh` dist-tag `latest`, a release candidate (plus `pnpm` `latest`, which is only bumped on request) | `resolve_npm_version @deepseek-ai/dsh` in `npm-pin.sh`: one `npm view PKG dist-tags versions --json` | **No, by design.** The Dockerfile runs `npm ci` against the committed lockfile and takes no version arg. A new version needs a regenerated lock (`upgrade-dsh.sh`) with layout checks. | `npm-pin.sh` tells them apart: the query failed = "registry unreachable?"; the query succeeded without the version = "not a published version". |
| `pi` | npm `@earendil-works/pi-coding-agent` dist-tag `latest` | `resolve_npm_version @earendil-works/pi-coding-agent` | **No, by design.** Committed lockfile plus `npm ci`. A new version needs `upgrade-pi.sh`, which regenerates the lock and refills five integrity hashes from the registry. | Same as `dsh` |
| `pi-claude-bridge` (in `pi`) | npm `pi-claude-bridge` dist-tag `latest` | `resolve_npm_version pi-claude-bridge` | **No, by design.** Committed lockfile plus `npm ci --legacy-peer-deps --omit=optional`. A new version needs `upgrade-bridge.sh`. | Same as `dsh` |

## How the repo resolves versions today

### Installer layers: `script/build/agent-versions.sh`

- It prints `tool=version` lines for codex, opencode, claude and copilot
  (`script/build/agent-versions.sh:1-4`, `:95-98`). `dsh` and `pi` are "deliberately
  absent": their cache key is the lockfile's bytes (`:29-30`).
- **codex / opencode:** `github_latest_tag` runs `curl -fsSL … api.github.com/repos/<repo>/releases/latest | jq -r .tag_name`
  and sends `Authorization: Bearer $GH_TOKEN` when that variable is set
  (`:65-73`, `:75-78`). The repos are `openai/codex` and `anomalyco/opencode`.
  opencode is pinned to the real repo because `sst/opencode` only resolves through a
  rename redirect (`:17-21`). Confirmed: `api.github.com/repos/sst/opencode/releases/latest`
  answers `301` to `/repositories/975734319/releases/latest`.
- **claude:** `curl -fsSL https://downloads.claude.ai/claude-code-releases/latest`
  (`:79-80`). The script says npm dist-tags would be the wrong source because they
  "move on a separate cadence" (`:22-26`).
- **copilot:** `npm view @github/copilot dist-tags.latest` (`:81-82`).
- **Validation:** an empty or `null` codex/opencode tag fails, and a claude or copilot
  value that doesn't match `[0-9]*.[0-9]*.[0-9]*` fails (`:84-93`). The keys are raw
  tags: codex `rust-v0.159.0`, opencode `v1.18.33`.
- **Failure policy:** any single lookup failure exits non-zero for the whole script,
  and it emits `::error::` under Actions (`:32-37`, `:57-63`). The script can't tell
  "unreachable" from "not found". It only knows that the lookup failed.
- **Callers:** CI appends the output to `$GITHUB_OUTPUT`, so a failure fails the job
  (`.github/workflows/build-image.yml:110-122`). `images/build.sh` instead warns and
  builds **without** keys, which reuses cached agents (`images/build.sh:227-240`).
- **The launcher does not call it.** The launcher's local compose passes exactly one
  build arg, `BASE_IMAGE=` (`crates/agent-vm/src/layer.rs:1800-1804`), so a locally
  composed installer layer freezes its agent version at first build
  ([ADR-0019](../adr/0019-tool-free-base-and-per-tool-layers.md) D8;
  `images/tools/README.md:157-161`).

### Lockfile layers: `script/build/npm-pin.sh`

- `resolve_npm_version PACKAGE [WANTED]` runs one
  `npm view "$package" dist-tags versions --json`
  (`script/build/npm-pin.sh:26-34`). It then decides locally: `dist-tags[WANTED]`
  first, otherwise WANTED must appear in `versions`. An empty WANTED means `latest`
  (`:29`, `:37-40`).
- Failure split: if `npm view` itself fails, it reports
  `npm could not query … (registry unreachable?)`. If the query succeeds but nothing
  matches, it reports `…@… is not a published version` (`:31-33`, `:41-44`).
- One case is misclassified: an **unknown package** makes `npm view` fail with
  `E404`, which the script reports as a failed query rather than "not published". The
  script says so itself (`:24-25`).
- Callers: `upgrade-dsh.sh:74-79`, `upgrade-pi.sh:60`, `upgrade-bridge.sh:56`. They
  are host-side scripts that rewrite `package.json` + `package-lock.json`. The
  Dockerfiles never see a version argument (`images/tools/README.md:101-121`).

## Per tool

### `codex`

- **Dockerfile:** `RUN : "codex ${AGENT_VERSION_CODEX}" && HOME=/opt/agent agent-vm-install codex sh https://github.com/openai/codex/releases/latest/download/install.sh`
  (`images/tools/codex/Dockerfile:15-18`). The `:` no-op puts the arg into the RUN
  text, so it acts only as a cache key.
- **The installer URL** is a GitHub "latest release asset" redirect. On the research
  date it answered `302` to `…/releases/download/rust-v0.159.0/install.sh`, so each
  release carries its own copy of the installer at a versioned URL.
- **What the installer calls latest** (upstream `install.sh`, fetched 2026-09-29):
  - `RELEASE="${CODEX_RELEASE:-latest}"`. `--release VERSION` overrides it, and the
    usage text documents both.
  - `normalize_version` strips `rust-v` and `v`. `validate_version` accepts only
    `x.y.z[-alpha[.N[.M]]|-beta[.N]]`.
  - With `CODEX_INSTALLER_USE_RELEASES_OPENAI_COM` defaulting to `true`,
    `resolve_release` first tries `https://releases.openai.com/codex/channels/latest`
    (for an exact version, `…/codex/releases/<ver>/release.json`). It falls back to
    `https://api.github.com/repos/openai/codex/releases/latest` (or
    `…/releases/tags/rust-v<ver>`) with the warning "releases.openai.com is
    unavailable; falling back to GitHub Releases."
  - **Drift:** `agent-versions.sh:16-17` says the installer's "own resolver hits the
    same endpoint" as its GitHub `releases/latest` query. That is now true only on
    the fallback path. On the research date both sources returned
    `tag_name: rust-v0.159.0`.
- **Definition of GitHub "latest":** "the most recent non-prerelease, non-draft
  release, sorted by the created_at attribute"
  ([GitHub REST docs, Get the latest release](https://docs.github.com/en/rest/releases/releases#get-the-latest-release)).
- **Other channel:** npm `@openai/codex` has `latest: 0.159.0` plus `alpha` and
  per-platform tags. The layer does not use it.
- **Exact version:** supported by the installer through the `CODEX_RELEASE` env var.
  Because `agent-vm-install` runs `"$shell" "$tmp"` with no arguments
  (`images/Dockerfile:257-277`), an env var on the RUN line is the only way to pass
  it without changing the helper. The Dockerfile doesn't do this today.
- **Failure behaviour:**
  - Probes: `api.github.com/repos/openai/codex/releases/tags/rust-v0.0.1` answers
    `404`, `releases.openai.com/codex/releases/0.0.1/release.json` answers `404`, and
    `…/0.159.0/release.json` answers `200`.
  - The installer loses that distinction. Its `download_text` uses `curl -fsSL`, and
    a failed GitHub metadata fetch always ends with "Could not fetch GitHub release
    metadata for Codex <ver>. GitHub API may be unavailable or rate limited." followed
    by `exit 1`.

### `opencode`

- **Dockerfile:** `RUN : "opencode ${AGENT_VERSION_OPENCODE}" && HOME=/opt/agent agent-vm-install opencode bash https://opencode.ai/install …`
  (`images/tools/opencode/Dockerfile:19-24`). The arg is only a cache key.
- **The installer** (`https://opencode.ai/install`, fetched 2026-09-29):
  - `requested_version=${VERSION:-}`, overridable with `-v|--version <version>`.
    Usage example: `curl -fsSL https://opencode.ai/install | bash -s -- --version 1.0.180`.
  - With no version set, it downloads
    `https://github.com/anomalyco/opencode/releases/latest/download/$filename`. It
    reads the version from `curl -s https://api.github.com/repos/anomalyco/opencode/releases/latest`
    by running `sed` over `tag_name`. An empty result prints "Failed to fetch version
    information" and exits 1.
  - With a version set, it strips a leading `v` and downloads
    `…/releases/download/v<ver>/$filename`. First it runs
    `curl -sI -w %{http_code} …/releases/tag/v<ver>`, and only a `404` produces
    "Error: Release v<ver> not found".
- **Other channel:** npm `opencode-ai` had `latest: 1.18.33`, the same as the GitHub
  tag `v1.18.33`. The layer does not use it.
- **Exact version:** supported by the installer through the `VERSION` env var or
  `--version`. The Dockerfile doesn't use either today.
- **Failure behaviour:**
  - On the latest path, `curl -s` without `-f` means an offline error, a
    rate-limit 403 body and an HTML page all produce "Failed to fetch version
    information".
  - On the exact path, an offline check gives `http_code` `000`, which isn't `404`,
    so the installer goes on to the download, which then fails. A real missing
    release gets its own message.
  - Probes: `github.com/anomalyco/opencode/releases/tag/v0.0.0-nope` and
    `api.github.com/…/releases/tags/v0.0.0-nope` both answer `404`.

### `claude`

- **Dockerfile:** `RUN : "claude ${AGENT_VERSION_CLAUDE}" && HOME=/opt/agent agent-vm-install claude bash https://claude.ai/install.sh`
  (`images/tools/claude/Dockerfile:15-17`). The arg is only a cache key.
- **The installer** (`https://claude.ai/install.sh`, fetched 2026-09-29):
  - `TARGET="$1"` must match `stable|latest|x.y.z[-…]`.
  - It then **always** fetches `$DOWNLOAD_BASE_URL/latest`, with
    `DOWNLOAD_BASE_URL=https://downloads.claude.ai/claude-code-releases` ("Always
    download latest version (which has the most up-to-date installer)"). It rejects a
    non-version body, fetches `…/<latest>/manifest.json`, verifies a SHA-256, and
    runs `"$binary_path" install ${TARGET:+"$TARGET"}`.
  - So resolving an exact version happens inside the closed-source `claude install`
    subcommand, and the `latest` endpoint must be reachable even for a pinned install.
    I did not inspect how `claude install <ver>` reports a missing version.
- **Official docs:** "The native installer accepts either a specific version number
  or a release channel (`latest` or `stable`)", e.g.
  `curl -fsSL https://claude.ai/install.sh | bash -s 2.1.89`. After that,
  `claude --version` "prints the exact version you passed". `stable` is "typically
  about one week old, skipping releases with major regressions"
  ([Claude Code setup: Install a specific version](https://code.claude.com/docs/en/setup#install-a-specific-version)).
- **Channels on the research date:** `…/latest` → `2.1.284`, `…/stable` → `2.1.277`.
  npm `@anthropic-ai/claude-code` dist-tags were `latest 2.1.284`, `next 2.1.284`
  and `stable 2.1.277`, which matched that day, but the repo deliberately does not
  key on npm (`agent-versions.sh:22-26`).
- **Exact version:** supported by the installer as a **positional argument**. `agent-vm-install` passes none
  (`images/Dockerfile:264-268`), so pinning would need a helper change or an
  argument-forwarding wrapper. There is no env-var equivalent in `install.sh`.
- **Failure behaviour:**
  - `…/0.0.1/manifest.json` answers `404` with S3 XML `NoSuchKey`, while
    `…/2.1.284/manifest.json` answers `200`.
  - `curl -f` gives exit `22` for the 404, and `6` (DNS) or `7` (connect) when
    unreachable.
  - The installer's own message for a non-version `latest` body names both causes:
    "This can happen if the download service is unreachable or not available in your
    region".

### `copilot`

- **Dockerfile:** `RUN npm install -g "@github/copilot@${AGENT_VERSION_COPILOT:-latest}"`
  (`images/tools/copilot/Dockerfile:14-17`). The arg is both the cache key and the
  installed version, and when it is unset (the launcher's local compose) npm
  installs `latest`. This is the one installer layer that already installs an exact
  version; see commit `bb99445` (#192).
- **Source:** npm dist-tag `latest`. npm's docs: "By default, `npm install <pkg>`
  (without any @<version> or @<tag> specifier) installs the latest tag"
  ([npm-dist-tag](https://docs.npmjs.com/cli/v10/commands/npm-dist-tag)). On the
  research date: `{"latest":"1.0.89","prerelease":"1.0.90-2"}`.
- **Query:** `npm view @github/copilot dist-tags.latest`. A lighter raw endpoint is
  `GET https://registry.npmjs.org/-/package/@github%2fcopilot/dist-tags`, which
  returned `{"latest":"1.0.89","prerelease":"1.0.90-2"}`.
- **Failure behaviour:** see [npm signals](#npm-signals-copilot-dsh-pi-pi-claude-bridge).

### `dsh`, `pi`, `pi-claude-bridge` (lockfile layers)

- **Dockerfiles:** `dsh` COPYs `package.json package-lock.json` and runs
  `npm ci --ignore-scripts …` (`images/tools/dsh/Dockerfile:44-49`). `pi` does the
  same through `install-pi.sh` (`images/tools/pi/Dockerfile:30-32`), and the bridge
  through `install-pi-packages.sh` (`:48-50`). None of them declares a version ARG.
  The pi Dockerfile says it "resolves NO version" (`:7-9`).
- **Pins today:** `@deepseek-ai/dsh 0.1.5-rc.2` + `pnpm 11.11.0`
  (`images/tools/dsh/package.json`), `@earendil-works/pi-coding-agent 0.87.1`
  (`images/tools/pi/package.json`), and `pi-claude-bridge 0.8.0`
  (`images/tools/pi/bridge/package.json`).
- **Latest on the research date:**
  - dsh: `{"alpha":"0.1.7-alpha.2","latest":"0.1.7-rc.2","next":"0.2.0-rc.2"}`, so
    `latest` is a release candidate, as `images/tools/README.md:141-142` warns.
  - pi: `{"legacy-node20":"0.74.2","latest":"0.87.1"}`, equal to the pin.
  - bridge: `{"latest":"0.9.0"}`, ahead of the `0.8.0` pin.
  - pnpm: `latest 12.6.0`, with the pin on `11.x`.
- **Why an exact-version build arg does not fit these layers:**
  - `npm ci` installs exactly the committed tree, including every transitive version
    and integrity hash.
  - Moving the pin also changes things that only the upgrade scripts check:
    - `upgrade-pi.sh` regenerates the lock and refills `integrity` for five
      shrinkwrap siblings (`upgrade-pi.sh:74-107`).
    - `upgrade-dsh.sh` updates the lock incrementally and rejects a
      `dsh-sandbox-local` nested under `dsh-base` (`upgrade-dsh.sh:93-131`).
    - `upgrade-bridge.sh` needs `--legacy-peer-deps` and rejects packages that Pi's
      loader aliases (`upgrade-bridge.sh:71-93`).
  - For `dsh` the lock is load-bearing, not just reproducibility: a floating
    `npm install` can nest `dsh-sandbox-local` where the plugin loader can't find it
    (`images/tools/dsh/Dockerfile:6-15`).
  - Each run needs `npm` and `jq` on the host plus network access
    (`require_tools jq npm`).

## Offline and failure signals

### GitHub API (`codex`, `opencode`)

- Unreachable: curl exits `6` (could not resolve host), `7` (could not connect), or
  `28` (timeout), and `-w '%{http_code}'` prints `000`. Exits 6 and 7 were confirmed
  locally.
- Not published: an HTTP `404` on `releases/tags/<tag>`. With `-f`, curl exits `22`.
- Rate-limited: "If you exceed your primary rate limit, you will receive a `403` or
  `429` response, and the `x-ratelimit-remaining` header will be `0`". The
  unauthenticated limit is 60 requests per hour
  ([GitHub REST rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)).
  Under `-f` that is also exit `22`, so telling it apart from a 404 needs the status
  code, not just the exit code.
- `releases/latest` has no "not published" case for a repo that has releases. It
  always names *some* release.

### `downloads.claude.ai` (`claude`)

- Unreachable: curl exit `6`/`7`.
- Not published: `404` with S3 `NoSuchKey` XML on `/<ver>/manifest.json`.
- `/latest` and `/stable` return a bare version string. `agent-versions.sh` and
  `install.sh` both reject non-version bodies.

### npm signals (`copilot`, `dsh`, `pi`, `pi-claude-bridge`)

Observed with npm 10.9.2:

| Case | Exit | Error code (stderr, or `.error.code` with `--json`) |
|---|---|---|
| `npm view @github/copilot@0.0.0-nope version` (package exists, version doesn't) | 1 | `E404` "No match found for version 0.0.0-nope" |
| `npm view @nope-zzz/nope-zzz …` (package doesn't exist) | 1 | `E404` "Not Found - GET …" |
| `--registry https://nonexistent.invalid` | 1 | `ENOTFOUND` "This is a problem related to network connectivity." |
| `--registry http://127.0.0.1:9` | 1 | `ECONNREFUSED` |
| `npm view @github/copilot dist-tags.latest --offline` | 0 | none: printed `1.0.89` from the local cache |

- `npm-pin.sh`'s comment "Asking npm for `PKG@WANTED` instead cannot tell an
  unpublished version from an unreachable registry: both exit 1" (`:20-22`) is true
  of the **exit code**. The `--json` error object does tell them apart (`E404` vs a
  network code).
- npm can answer from its cache. With `--offline` (or `prefer-offline`), a lookup
  "succeeds" with a possibly stale dist-tag and gives no network signal.
- Raw registry HTTP: `GET /@github%2fcopilot/0.0.0-nope` → `404`,
  `GET /@nope-zzz%2fnope-zzz` → `404`. The abbreviated
  `GET /-/package/<pkg>/dist-tags` endpoint returned `200` for a real package but
  `401` (not `404`) for a nonexistent one.

## Observed values (2026-09-29)

| Tool | Latest | Where |
|---|---|---|
| codex | `rust-v0.159.0` | GitHub `releases/latest`, and `releases.openai.com/codex/channels/latest` `tag_name`. npm `@openai/codex` `latest` = `0.159.0`. |
| opencode | `v1.18.33` | GitHub `releases/latest`. npm `opencode-ai` `latest` = `1.18.33`. |
| claude | `2.1.284` (`stable` = `2.1.277`) | `downloads.claude.ai/claude-code-releases/{latest,stable}` |
| copilot | `1.0.89` (`prerelease` = `1.0.90-2`) | npm dist-tags |
| dsh | `0.1.7-rc.2` (pin `0.1.5-rc.2`) | npm dist-tags |
| pi | `0.87.1` (pin `0.87.1`) | npm dist-tags |
| pi-claude-bridge | `0.9.0` (pin `0.8.0`) | npm dist-tags |
| pnpm (dsh) | `12.6.0` (pin `11.11.0`) | npm dist-tags |
