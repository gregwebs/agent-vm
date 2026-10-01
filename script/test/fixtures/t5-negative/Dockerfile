# Built-image fixtures for the T5 "usable by any uid" command audit
# (images/recipe-contract/check-tool-access.py), used by
# script/test/shipped-tool-recipes.sh. Each case is a real filesystem state in a
# real image, audited as a numeric uid so the owner/group negatives are genuine
# (a root-run `os.access` would mask them).
#
# The host fixture suite script/test/tool-access.sh covers the same predicates
# without Docker; this one adds the numeric-owner and numeric-gid cases the plan
# requires and proves the checker runs identically inside a shipped base.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER root

RUN set -eux; \
    # --- a valid, repaired tree (0755) that must pass -----------------------
    mkdir -p /t5/pass/bin /t5/pass/one/two; \
    printf '#!/bin/sh\necho hi\n' > /t5/pass/bin/cmd; \
    chmod 0755 /t5/pass/bin/cmd; \
    printf '#!/bin/sh\necho hi\n' > /t5/pass/one/two/cmd; \
    chmod 0755 /t5/pass/one /t5/pass/one/two /t5/pass/one/two/cmd; \
    # relative multi-hop links that must still resolve and pass -------------
    mkdir -p /t5/pass/multi; \
    printf '#!/bin/sh\necho hi\n' > /t5/pass/multi/real; \
    chmod 0755 /t5/pass/multi/real; \
    ln -s real /t5/pass/multi/one; \
    ln -s one /t5/pass/multi/two; \
    # --- executable symlink into a 0700 target parent ----------------------
    # The parent is owned by the auditing uid so the checker can traverse far
    # enough to see the mode (a root-owned 0700 parent would fail earlier with a
    # less specific "does not exist").
    mkdir -p /t5/neg/symlink0700/bin /t5/neg/symlink0700/priv; \
    printf '#!/bin/sh\necho hi\n' > /t5/neg/symlink0700/priv/real; \
    chmod 0755 /t5/neg/symlink0700/priv/real; \
    chown 12345:23456 /t5/neg/symlink0700/priv; \
    chmod 0700 /t5/neg/symlink0700/priv; \
    ln -s /t5/neg/symlink0700/priv/real /t5/neg/symlink0700/bin/link; \
    # --- 0700 directory containing the PATH symlink ------------------------
    mkdir -p /t5/neg/dir0700/bin; \
    ln -s /t5/pass/bin/cmd /t5/neg/dir0700/bin/tool; \
    chown 12345:23456 /t5/neg/dir0700/bin; \
    chmod 0700 /t5/neg/dir0700/bin; \
    # --- 0700 executable owned by root -------------------------------------
    mkdir -p /t5/neg/root0700; \
    printf '#!/bin/sh\necho hi\n' > /t5/neg/root0700/cmd; \
    chmod 0700 /t5/neg/root0700/cmd; \
    # --- 0701 directory, group gid 23456, audited as uid 12345:23456 -------
    # --- 0701 group-match directory, owner uid 12345:23456 ------------------
    # Mode audit: the checker can traverse (owner x) far enough to see the
    # missing GROUP execute bit, so it rejects the all-class predicate. The
    # kernel would in fact allow the 12345 owner, so this is a mode-audit case,
    # not an execution-denial case.
    mkdir -p /t5/neg/gid0701/bin; \
    printf '#!/bin/sh\necho hi\n' > /t5/neg/gid0701/bin/cmd; \
    chmod 0755 /t5/neg/gid0701/bin/cmd; \
    chmod 0701 /t5/neg/gid0701; \
    chown 12345:23456 /t5/neg/gid0701 /t5/neg/gid0701/bin; \
    # --- 0701 directory owned by ROOT with the auditing gid 23456 -----------
    # Execution denial: the audited uid 12345 is neither the owner (root) nor
    # other, and the group class (23456, no execute) denies it, so the kernel
    # actually refuses to traverse. A 12345-owned directory let the audited uid
    # traverse via its owner bits and never demonstrated the group-match denial
    # (review F6).
    mkdir -p /t5/neg/gid0701-deny/bin; \
    printf '#!/bin/sh\necho hi\n' > /t5/neg/gid0701-deny/bin/cmd; \
    chmod 0755 /t5/neg/gid0701-deny/bin/cmd; \
    chmod 0701 /t5/neg/gid0701-deny; \
    chown root:23456 /t5/neg/gid0701-deny; \
    chown 12345:23456 /t5/neg/gid0701-deny/bin; \
    # --- 0001 executable, owner uid 12345, audited as uid 12345:45678 ------
    mkdir -p /t5/neg/owner0001; \
    printf '#!/bin/sh\necho hi\n' > /t5/neg/owner0001/cmd; \
    chown 12345:45678 /t5/neg/owner0001/cmd; \
    chmod 0001 /t5/neg/owner0001/cmd; \
    # --- unreadable 0111 script (the auditor owns it, so the mode is
    #     reachable and the read is genuinely denied) -------------------------
    mkdir -p /t5/neg/script0111; \
    printf '#!/bin/sh\necho hi\n' > /t5/neg/script0111/cmd; \
    chown 12345:23456 /t5/neg/script0111/cmd; \
    chmod 0111 /t5/neg/script0111/cmd; \
    # --- dangling link -----------------------------------------------------
    mkdir -p /t5/neg/dangling/bin; \
    ln -s nowhere /t5/neg/dangling/bin/link; \
    # --- symlink cycle -----------------------------------------------------
    mkdir -p /t5/neg/cycle/bin; \
    ln -s b /t5/neg/cycle/bin/a; \
    ln -s a /t5/neg/cycle/bin/b; \
    # --- SP1: `#!/usr/bin/env NAME` where NAME is a 0700 PATH interpreter --
    # The npm CLI shebangs look like this; the PATH interpreter, not just
    # `/usr/bin/env`, must be audited.
    mkdir -p /t5/neg/env0700/bin /t5/neg/env0700/interp; \
    printf '#!/bin/sh\necho interp\n' > /t5/neg/env0700/interp/private-interp; \
    chmod 0700 /t5/neg/env0700/interp/private-interp; \
    printf '#!/usr/bin/env private-interp\necho hi\n' > /t5/neg/env0700/bin/tool; \
    chmod 0755 /t5/neg/env0700/bin/tool; \
    # --- SP1: a relative command path keeps the directory `..` leaves ------
    # `os.path.abspath` used to collapse `private/../bin/tool`, hiding the
    # 0700 `private`; the equivalent absolute path was always rejected.
    mkdir -p /t5/neg/lexical0700/private /t5/neg/lexical0700/bin; \
    printf '#!/bin/sh\necho hi\n' > /t5/neg/lexical0700/bin/tool; \
    chmod 0755 /t5/neg/lexical0700/bin/tool; \
    chmod 0700 /t5/neg/lexical0700/private; \
    # --- SP1 repaired positive: a 0755 PATH interpreter passes -------------
    mkdir -p /t5/pass/env/bin /t5/pass/env/interp; \
    printf '#!/bin/sh\necho interp\n' > /t5/pass/env/interp/public-interp; \
    chmod 0755 /t5/pass/env/interp/public-interp; \
    printf '#!/usr/bin/env public-interp\necho hi\n' > /t5/pass/env/bin/tool; \
    chmod 0755 /t5/pass/env/bin/tool; \
    # --- SP1: `#!/usr/bin/env -S PATH=... NAME` selects NAME under the PATH
    #     the shebang sets, not the auditor's PATH ---------------------------
    mkdir -p /t5/neg/envpath/bin /t5/neg/envpath/bad /t5/neg/envpath/good; \
    printf '#!/bin/sh\necho bad\n' > /t5/neg/envpath/bad/chosen; \
    chmod 0700 /t5/neg/envpath/bad/chosen; \
    printf '#!/bin/sh\necho good\n' > /t5/neg/envpath/good/chosen; \
    chmod 0755 /t5/neg/envpath/good/chosen; \
    printf '#!/usr/bin/env -S PATH=/t5/neg/envpath/bad chosen\necho hi\n' \
        > /t5/neg/envpath/bin/tool; \
    chmod 0755 /t5/neg/envpath/bin/tool; \
    # --- SP1 repaired positive for the PATH-changing env -S form -----------
    mkdir -p /t5/pass/envpath/bin /t5/pass/envpath/good; \
    printf '#!/bin/sh\necho good\n' > /t5/pass/envpath/good/chosen; \
    chmod 0755 /t5/pass/envpath/good/chosen; \
    printf '#!/usr/bin/env -S PATH=/t5/pass/envpath/good chosen\necho hi\n' \
        > /t5/pass/envpath/bin/tool; \
    chmod 0755 /t5/pass/envpath/bin/tool; \
    # --- SP1: a nested `#!/usr/bin/env NAME` inherits the effective PATH ----
    # `tool` runs `env -S PATH=.../bad chosen`; `chosen`'s own env shebang sets
    # no PATH, so `inner` must be resolved under `bad` (0700 => reject), never
    # on the auditor's PATH (which holds a good `inner`).
    mkdir -p /t5/neg/envnested/bin /t5/neg/envnested/bad /t5/neg/envnested/good; \
    printf '#!/usr/bin/env inner\necho bad\n' > /t5/neg/envnested/bad/chosen; \
    chmod 0755 /t5/neg/envnested/bad/chosen; \
    printf '#!/bin/sh\necho bad-inner\n' > /t5/neg/envnested/bad/inner; \
    chmod 0700 /t5/neg/envnested/bad/inner; \
    printf '#!/bin/sh\necho good-inner\n' > /t5/neg/envnested/good/inner; \
    chmod 0755 /t5/neg/envnested/good/inner; \
    printf '#!/usr/bin/env -S PATH=/t5/neg/envnested/bad chosen\necho hi\n' \
        > /t5/neg/envnested/bin/tool; \
    chmod 0755 /t5/neg/envnested/bin/tool; \
    # --- SP1 repaired positive for the nested inherited-PATH form ----------
    mkdir -p /t5/pass/envnested/bin /t5/pass/envnested/bad; \
    printf '#!/usr/bin/env inner\necho good\n' > /t5/pass/envnested/bad/chosen; \
    chmod 0755 /t5/pass/envnested/bad/chosen; \
    printf '#!/bin/sh\necho good-inner\n' > /t5/pass/envnested/bad/inner; \
    chmod 0755 /t5/pass/envnested/bad/inner; \
    printf '#!/usr/bin/env -S PATH=/t5/pass/envnested/bad chosen\necho hi\n' \
        > /t5/pass/envnested/bin/tool; \
    chmod 0755 /t5/pass/envnested/bin/tool
