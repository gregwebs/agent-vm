#!/bin/sh
# Installs the exact GitHub Copilot CLI version this layer was given.
#
# Bind-mounted into the layer's Dockerfile, never COPYed, so it stays out of the
# shipped image. The version is validated BEFORE any network call: a dist-tag
# (`latest`, `next`), a range (`^1.0.0`), a URL or a whitespace/newline-bearing
# value is rejected rather than handed to npm, which would silently resolve it.
# The grammar is the shared canonical semver: leading-zero numeric components
# and leading-zero prerelease numeric identifiers are not exact versions.
# An npm install failure is hard -- copilot is never soft-failable, because a
# partial global tree is a broken agent.
set -eu

version="${AGENT_VM_VERSION_COPILOT:?install-copilot.sh needs AGENT_VM_VERSION_COPILOT}"

case "$version" in
    *[!0-9A-Za-z.+-]*)
        echo "install-copilot.sh: not an exact version: '$version'" >&2
        exit 1
        ;;
esac
if ! printf '%s' "$version" |
    grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'; then
    echo "install-copilot.sh: not an exact semver version: '$version'" >&2
    exit 1
fi

npm install -g "@github/copilot@${version}"
chmod -R a+rX "$(npm root -g)/@github/copilot"
rm -rf /root/.npm
