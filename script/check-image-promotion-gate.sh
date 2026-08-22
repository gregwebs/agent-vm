#!/bin/bash
set -euo pipefail

usage() {
    echo "usage: $0 MINIMUM MAIN_VERSION LINUX_X64_VERSION LINUX_ARM64_VERSION" >&2
    exit 2
}

[ "$#" = 4 ] || usage
minimum=$1
main=$2
x64=$3
arm64=$4
version_pattern='^[0-9]+\.[0-9]+\.[0-9]+$'

for version in "$minimum" "$main" "$x64" "$arm64"; do
    if ! [[ "$version" =~ $version_pattern ]]; then
        echo "version '$version' is not a stable semantic version" >&2
        exit 1
    fi
done

if [ "$main" != "$x64" ] || [ "$main" != "$arm64" ]; then
    echo "main and Linux launcher packages must publish the same version (main=$main x64=$x64 arm64=$arm64)" >&2
    exit 1
fi

IFS=. read -r minimum_major minimum_minor minimum_patch <<< "$minimum"
IFS=. read -r main_major main_minor main_patch <<< "$main"
if (( main_major < minimum_major \
    || (main_major == minimum_major && main_minor < minimum_minor) \
    || (main_major == minimum_major && main_minor == minimum_minor && main_patch < minimum_patch) )); then
    echo "published launcher $main is older than required $minimum" >&2
    exit 1
fi
