# npm-dist

Templates and tooling for distributing `agent-vm` via npm.

## Layout

- `agent-vm/` — the user-facing main package. Tiny JS launcher
  (`bin/agent-vm.js`) that detects `${platform}-${arch}` at runtime
  and `execve`s the prebuilt native binary from the matching
  per-platform subpackage. Declares per-platform subpackages as
  `optionalDependencies` so npm installs only the right one.
- `agent-vm-linux-x64/`, `agent-vm-linux-arm64/` — per-platform
  subpackages. Each ships the prebuilt `bin/agent-vm`, `bin/msb`,
  and `lib/libkrunfw.so.<LIBKRUNFW_VERSION>` (`vendor/microsandbox/
  justfile`'s `LIBKRUNFW_VERSION`, e.g. `5.6.1` — it bumps
  independently of the msb version, so don't hard-code it here). agent-vm finds `msb` and `libkrunfw` via
  `current_exe()`-relative paths so a user's separate microsandbox
  install never shadows them.
- Future per-platform subpackages: `-darwin-arm64`, `-darwin-x64`,
  `-win32-x64`. Add to the launcher's `PLATFORM_PACKAGES` map and to
  the main package's `optionalDependencies`.

## How releases happen

CI populates each subpackage's `bin/` and `lib/` with freshly
cross-compiled artifacts, rewrites every `package.json` version
field to match the release tag, and runs `npm publish` for each
package. See `.github/workflows/release-npm.yml`.

The standard image has independent releases in
[agent-vm-images](https://github.com/gregwebs/agent-vm-images). The binary carries an
immutable initial index recommendation; successfully acquired retained selections
survive launcher releases. Default consumption requires no Docker/image sources.
Matching archives are explicitly imported with `agent-vm msb image load --input
FILE --tag REF`; see [USAGE](../USAGE.md#explicit-builds-and-archive-import).
Before releasing a changed recommendation, follow the native evidence/release hold
in [CONTRIBUTING](../CONTRIBUTING.md#release--version-bump).

## Local smoke test

On native Linux, copy these templates into an owned staging directory, populate
platform `bin/` and `lib/` with the candidate and matching reviewed runtime/firmware,
and set all package versions/optional dependencies consistently. Use `npm pack
--ignore-scripts` for main and platform packages, then install both local tarballs
with `npm install --prefix OWNED_PREFIX --ignore-scripts PLATFORM.tgz MAIN.tgz`.
Inspect tar listings for source/recipe absence and invoke
`OWNED_PREFIX/node_modules/.bin/agent-vm --help`. Do not use `npm link`, global
installation, arbitrary operator firmware or user caches for this test. Use private
HOME/state/XDG config and `AGENT_VM_SHARE_MSB_CACHE=0`. This boot-free dispatch
smoke does not prove native VM consumption; run `e2e.sh released-image` on the
installed package as documented in CONTRIBUTING.
