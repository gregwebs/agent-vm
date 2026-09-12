#!/bin/bash
# Fake `plutil` fixture for script/test/build-workflow.sh.
#
# Two callers: `import-image.sh` extracts the msb inspect JSON's *root* `digest`
# key to build the Docker base link (issue #98), and `macos.sh` queries the
# hypervisor / disable-library-validation entitlements.
#
# Deliberately hermetic -- the whole suite runs on Linux CI, so it may not
# depend on the Apple-only `/usr/bin/plutil`. When a real plutil is present it
# is used for cross-validation; set REAL_PLUTIL to a non-existent path to force
# and prove the portable awk fallback:
#   REAL_PLUTIL=/no/plutil bash script/test/build-workflow.sh
# Both paths keep `plutil -extract digest raw -expect string` semantics: a
# missing key, a non-string value, or unparseable JSON exits non-zero, and the
# awk fallback must extract only the root-level `digest`, never the nested
# `config.digest` (issue-#98 review S1/T1).
#
# shellcheck disable=SC2154  # FAKE_* and REAL_PLUTIL come from the test harness
set -euo pipefail
case "${2:-}" in
    digest)
        json="$(cat)"
        printf "plutil extract digest input=%s\n" "$json" >>"$FAKE_LOG"
        [[ "${FAKE_PLUTIL_FAIL:-}" != 1 ]] || exit 1
        real_plutil="${REAL_PLUTIL:-/usr/bin/plutil}"
        if [[ -x "$real_plutil" ]]; then
            printf '%s' "$json" | "$real_plutil" -extract digest raw -expect string -o - -
        else
            printf '%s' "$json" | awk '
                function ws(c) { return c == " " || c == "\t" || c == "\r" || c == "\n" }
                { s = s $0 }
                END {
                    n = length(s)
                    i = 1
                    while (i <= n && ws(substr(s, i, 1))) i++
                    if (i > n || substr(s, i, 1) != "{") exit 1
                    depth = 0; instr = 0; esc = 0
                    for (i = 1; i <= n; i++) {
                        c = substr(s, i, 1)
                        if (esc) { esc = 0; continue }
                        if (instr) {
                            if (c == "\\") { esc = 1; continue }
                            if (c == "\"") { instr = 0 }
                            continue
                        }
                        if (c == "\"") {
                            if (depth == 1 && substr(s, i, 8) == "\"digest\"") {
                                j = i + 8
                                while (j <= n && ws(substr(s, j, 1))) j++
                                if (j <= n && substr(s, j, 1) == ":") {
                                    j++
                                    while (j <= n && ws(substr(s, j, 1))) j++
                                    if (j > n || substr(s, j, 1) != "\"") exit 2
                                    j++
                                    val = ""
                                    while (j <= n) {
                                        c2 = substr(s, j, 1)
                                        if (c2 == "\\") { val = val c2 substr(s, j + 1, 1); j += 2; continue }
                                        if (c2 == "\"") { print val; exit 0 }
                                        val = val c2
                                        j++
                                    }
                                    exit 3
                                }
                            }
                            instr = 1
                            continue
                        }
                        if (c == "{") depth++
                        else if (c == "}") depth--
                    }
                    exit 1
                }
            '
        fi
        ;;
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
