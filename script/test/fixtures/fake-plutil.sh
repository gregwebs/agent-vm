#!/bin/bash
# Hermetic entitlement queries and plist lints used by macos.sh build tests.
set -euo pipefail
case "${1:-}" in
    -lint)
        [[ "${FAKE_NOTIFIER_PLIST_INVALID:-}" != 1 ]] || exit 1
        printf "%s: OK\n" "${2:-}"
        exit 0
        ;;
esac
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
