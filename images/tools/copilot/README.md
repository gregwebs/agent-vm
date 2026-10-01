# copilot layer

Installs the GitHub Copilot CLI from npm at an exact, committed version.

- `Dockerfile` pins `AGENT_VERSION_COPILOT` (default `1.0.90`) and labels the
  image `org.agent-vm.version.copilot=<that value>`. The label records the
  *selection*; the build gate decides health.
- `install-copilot.sh` validates the supplied slot as canonical semver before
  any network call, then runs exactly `npm install -g @github/copilot@<version>`.
  A dist-tag, range or URL is rejected. An npm failure is hard.
- `verify-copilot.sh` runs a bounded `copilot --version`, requires exit 0 before
  parsing, and accepts only the recorded banner plus the one known footer. It
  then audits T5 (any-uid access) with the shared `check-tool-access.py`
  resolver.

## Exact-version contract

Ordinary and release builds install the committed default. A launcher override
passes the same `AGENT_VERSION_COPILOT` build argument; there is no
`latest` fallback and no build-time npm lookup. Bump with
`script/build/agent-versions.sh --write` (see images/tools/README.md).

## Recorded transcript

Captured from `@github/copilot@1.0.90` on linux/arm64, exit 0:

```text
GitHub Copilot CLI 1.0.90.
Run 'copilot update' to check for updates.
```

The parser pins that shape: only the first line is the version (with its
sentence-final period), and the only accepted trailing line is the footer. A
different banner or an extra line fails the build rather than being guessed at.
