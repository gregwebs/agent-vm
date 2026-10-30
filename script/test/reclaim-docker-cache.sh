#!/usr/bin/env bash
# Reclaim the Docker build cache that local image builds leave behind (#473).
#
# The e2e harness must never prune this cache. It owns its refs and removes them
# (#455), and its fixture builds are content-addressed — the per-run id is only
# in the tag, never in a layer, a build arg or a label — so a repeat run *reuses*
# cache instead of adding to it. Measured: a fixture build that hit cache took
# 0.9s and created no record, and a full `custom-image` run (nine fixture builds)
# created no record at all. The condition matters: a cold builder, an evicted
# cache, or a changed fixture pays for that build again. What is ruled out either
# way is a *per-run* deposit, which is why this cache cannot be attributed to a
# run id and a trap must not touch it.
#
# What does accumulate is the cache of builds whose content changes: the Rust
# agent image, base images, an operator's own `agent-vm image build`. That cache
# belongs to the operator, not to a run, so it is not the trap's to remove and
# no run id can own it. Reclaiming it is an explicit decision, made here:
#
#   report (default)  read the cache and print what a prune would free
#   --prune           one `docker buildx prune --force`, then read it again
#
# The target is the buildx *builder* the client has selected (`docker buildx ls`
# shows which one, and it may be a container or remote builder rather than the
# docker-context daemon); pass --builder to name one explicitly. BuildKit will
# not prune a cache record a build is using, so `--force` removes only what the
# builder reports as reclaimable — and nothing happens here until it is asked.
#
# Dangling images are not this tool's business: they are measured at ~60kB
# against 32GB of cache, and the e2e refs that would become dangling are already
# removed by the harness that created them.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: script/test/reclaim-docker-cache.sh [--prune] [--builder NAME]

Read the Docker build cache this host's image builds have left, and optionally
reclaim what the selected builder reports as reclaimable.

  (no flags)      Report the cache totals and what a prune would free. Removes
                  nothing.
  --prune         Run one `docker buildx prune --force`, then report again.
  --builder NAME  Read/prune this builder instead of the selected one.

Run this on the dedicated serial e2e host, not on a shared developer daemon:
`--prune` deletes cache that other local builds would otherwise reuse. Check
`docker buildx ls` first: with several builders, the selected one decides what
is read and pruned.
EOF
}

# Exit 2 for a malformed invocation, 1 for a failed observation or prune: the
# caller must be able to tell "you asked wrong" from "the builder did not answer".
usage_error() {
    echo "usage error: $*" >&2
    usage >&2
    exit 2
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

builder=""
prune=false
while (($#)); do
    case "$1" in
    --prune) prune=true ;;
    --builder)
        [ $# -ge 2 ] || usage_error "--builder needs a builder name"
        # An empty name would fall through to the selected builder, and one that
        # looks like an option would be read as a flag: both prune something the
        # operator did not name, so neither is a value this script accepts.
        case "$2" in
        '' | -*) usage_error "--builder needs a builder name, not '$2'" ;;
        esac
        builder="$2"
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *) usage_error "unsupported argument: $1" ;;
    esac
    shift
done

# One argv shape per subcommand, so the contract can pin what is issued rather
# than how this script is written.
run_du() {
    if [ -n "$builder" ]; then
        docker buildx du --builder "$builder"
    else
        docker buildx du
    fi
}

run_prune() {
    if [ -n "$builder" ]; then
        docker buildx prune --force --builder "$builder"
    else
        docker buildx prune --force
    fi
}

label="the selected buildx builder"
[ -z "$builder" ] || label="$builder"

report() {
    local phase="$1" output="$2" summary=""
    # Print the builder's own totals, never a number this script computed: a size
    # it derived itself could disagree with what the prune actually frees. Both
    # fields are required — a format that dropped one would otherwise read as
    # "nothing to reclaim", which is a different observation from "no cache".
    if ! summary="$(printf '%s\n' "$output" | awk '
        /^(Shared|Private|Reclaimable|Total):/ {
            if ($2 ~ /^[0-9]+(\.[0-9]+)?(B|kB|MB|GB|TB)$/) { print "  " $0; seen = seen $1 }
        }
        END { exit (index(seen, "Reclaimable:") && index(seen, "Total:")) ? 0 : 1 }')"; then
        fail "docker buildx du for $label printed no recognisable Reclaimable/Total sizes, so this script cannot say what is reclaimable (output: $output)"
    fi
    printf '%s (%s):\n' "$phase" "$label"
    printf '%s\n' "$summary"
}

before=""
if ! before="$(run_du 2>&1)"; then
    fail "could not read the build cache for $label; nothing was pruned:
$before"
fi
report "build cache before" "$before"

if [ "$prune" = false ]; then
    echo "nothing was pruned; pass --prune to remove the reclaimable cache"
    exit 0
fi

receipt=""
if ! receipt="$(run_prune 2>&1)"; then
    fail "docker buildx prune failed for $label; this script cannot say what it already removed. Read the cache again without --prune to see the current totals:
$receipt"
fi
# The builder's prune summary is the receipt: it names what it freed, and it is
# the only party that knows.
printf '%s\n' "$receipt"

after=""
if ! after="$(run_du 2>&1)"; then
    fail "docker buildx prune reported success but the build cache for $label could not be read again:
$after"
fi
report "build cache after" "$after"
