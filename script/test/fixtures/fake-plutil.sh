#!/bin/bash
# Hermetic entitlement queries used by macos.sh build tests.
set -euo pipefail
case "${2:-}" in
    *hypervisor*)
        value="${FAKE_HYPERVISOR_ENTITLEMENT:-true}"
        [[ "$value" != missing ]] || exit 1
        printf "%s\n" "$value"
        ;;
    *disable-library-validation*)
        value="${FAKE_LIBRARY_ENTITLEMENT:-true}"
        [[ "$value" != missing ]] || exit 1
        printf "%s\n" "$value"
        ;;
    *) exit 3 ;;
esac
