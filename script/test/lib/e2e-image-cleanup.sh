#!/usr/bin/env bash
# The Docker refs one e2e run owns, and their removal (#455).
#
# Sourced by script/test/e2e.sh, whose `docker` wrapper carries the operator's
# DOCKER_CONFIG/BUILDX_CONFIG, and by script/test/e2e-image-cleanup-contract.sh,
# whose `docker` stub records argv. The seam is the `docker` command: this lib
# names no daemon and no client configuration, and it sets no shell options.
#
# Ownership is `RUN_ID`: every ref the harness creates embeds "-$RUN_ID:" before
# the tag (the comment above the `RUN_ID` assignment there explains why the
# suffix is fresh per run). This file is designed to be dumped into a bare child
# with `declare -f` (the `h16-trap` control's pattern), so a consumer that means
# to exercise removal must define both `RUN_ID` and a `docker` function; without
# `RUN_ID` the sweep is a no-op.

#   owned_images_cleanup <run-status>
#
# status 0: list, batch `docker image rm` the marked refs, then re-list. The
#   batch's exit status is not the verdict — measured, `docker image rm a b`
#   exits 1 while still removing `a` when `b` is held by a container, and exits 1
#   while removing the present ref when another argument is absent. A ref still
#   listed afterwards is a real failure and is named. A ref absent from the first
#   listing is never named, so an already-removed ref (including one another
#   client untagged between the two listings) is not a failure, and no daemon
#   prose is ever parsed.
# status non-zero: remove nothing and print the refs plus one copy-pasteable
#   `docker image rm` line. A failed run keeps its scratch for diagnosis
#   (CONTRIBUTING.md's "Persisted network live check"): the fixtures `apk add`
#   from live mirrors, the published registry refs cannot be rebuilt at all, and
#   the same failure path deletes $OWNED_BUILDER with its build cache.
owned_images_cleanup() {
  local status="${1:-0}" listing ref rm_output marked
  local grep_status=0
  local -a candidates=() still=()
  # No marker, no ownership: the caller is not a run, or is a `declare -f` child
  # that did not define one. Returning here is also what keeps an unset `RUN_ID`
  # from aborting a `set -u` child inside the trap.
  [ -n "${RUN_ID:-}" ] || return 0
  if ! listing="$(docker image ls --format '{{.Repository}}:{{.Tag}}')"; then
    if [ "$status" -eq 0 ]; then
      echo "    FAIL: could not list local images, so this run's own refs cannot be shown removed" >&2
      return 1
    fi
    echo "e2e: could not list Docker images to show run $RUN_ID's refs; the run log names them" >&2
    return 0
  fi
  # grep's own status separates "no ref carries the marker" (1) from "the filter
  # failed" (>=2), and only the first one is an empty candidate set: a failed
  # observation must never read as this run owning nothing.
  marked="$(printf '%s\n' "$listing" | grep -E -- "-${RUN_ID}:[^:]*$")" || grep_status=$?
  if [ "$grep_status" -ge 2 ]; then
    if [ "$status" -eq 0 ]; then
      echo "    FAIL: could not filter the image listing for this run's refs (grep exit $grep_status)" >&2
      return 1
    fi
    echo "e2e: could not filter the Docker image listing for run $RUN_ID's refs; the run log names them" >&2
    return 0
  fi
  while IFS= read -r ref; do
    if [ -n "$ref" ]; then
      candidates+=("$ref")
    fi
  done <<EOF
$marked
EOF
  # Nothing marked means nothing this run owns is left. No further daemon call
  # and no receipt, so a filtered run cannot report removals it never attempted.
  [ "${#candidates[@]}" -gt 0 ] || return 0
  if [ "$status" -ne 0 ]; then
    echo "e2e: preserving this run's Docker refs for failure evidence (run id $RUN_ID)" >&2
    printf '    %s\n' "${candidates[@]}" >&2
    printf '    remove them with: docker image rm %s\n' "${candidates[*]}" >&2
    return 0
  fi
  # `--`: the arguments are daemon data, not code. A valid Docker reference
  # cannot begin with `-`, so this is only defence in depth.
  if ! rm_output="$(docker image rm -- "${candidates[@]}" 2>&1)"; then
    # Shown for the operator, never parsed: the verdict is the re-listing below.
    printf '%s\n' "$rm_output" | grep -vE '^(Untagged|Deleted): ' >&2 || true
  fi
  if ! listing="$(docker image ls --format '{{.Repository}}:{{.Tag}}')"; then
    echo "    FAIL: could not list local images after removing this run's refs" >&2
    return 1
  fi
  for ref in "${candidates[@]}"; do
    if printf '%s\n' "$listing" | grep -qxF -- "$ref"; then
      still+=("$ref")
    fi
  done
  if [ "${#still[@]}" -gt 0 ]; then
    echo "    FAIL: ${#still[@]} of this run's own refs survived removal:" >&2
    printf '        %s\n' "${still[@]}" >&2
    echo "    owned images: $((${#candidates[@]} - ${#still[@]})) removed, ${#still[@]} still present" >&2
    return 1
  fi
  echo "    owned images: ${#candidates[@]} removed, 0 still present"
  return 0
}
