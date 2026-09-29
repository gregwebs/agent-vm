#!/usr/bin/env bash
# SPIKE (throwaway) -- run the generated-Dockerfile composition spike.
#
#   ./spike.sh generate   emit build files from the real tool sources
#   ./spike.sh measure    build the fixture twice and print the rebuild cascade
#   ./spike.sh all        both (default)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "${1:-all}" in
    generate) exec python3 "$here/generate.py" ;;
    measure)  exec python3 "$here/measure.py" ;;
    all)
        python3 "$here/generate.py"
        echo
        exec python3 "$here/measure.py"
        ;;
    *)
        echo "usage: $0 [generate|measure|all]" >&2
        exit 2
        ;;
esac
