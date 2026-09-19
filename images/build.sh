#!/usr/bin/env bash
# Build the agent-vm OCI images and push them to a host-local registry.
#
# Two images are built and published (issue #84): the tool-free
# `agent-vm-base:latest` and the composed `agent-vm-template:latest` (the base
# plus the four shipped tool layers, chained in declaration order). A launch
# whose configured tool set differs from the default composes from the base.
#
# microsandbox pulls images from registries by reference, so we run a tiny
# registry:2 container bound to 127.0.0.1:5000 and treat it as our local
# image store. The registry is shared across `agent-vm setup` runs; we
# create it on demand and recover by hand if a prior session left it in a
# bad state (running but no port published, crashed inside, etc.).
#
# Intermediate tool layers are `--load`ed into the daemon (they are not
# published) and the next step builds `FROM` the daemon tag. This needs a
# builder whose driver shares the daemon's image store (the `docker` driver,
# which `docker/setup-buildx-action` with `driver: docker` also uses). If your
# default builder is `docker-container`, either create a `docker`-driver
# builder (`docker buildx create --driver docker --use`) or use the published
# images and `script/build/import-image.sh`.

set -euo pipefail

REGISTRY_NAME="${AGENT_VM_REGISTRY_NAME:-agent-vm-registry}"
REGISTRY_PORT="${AGENT_VM_REGISTRY_PORT:-5000}"
IMAGE_TAG="${AGENT_VM_IMAGE_TAG:-localhost:${REGISTRY_PORT}/agent-vm-template:latest}"
BASE_TAG="${AGENT_VM_BASE_IMAGE_TAG:-localhost:${REGISTRY_PORT}/agent-vm-base:latest}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The four shipped tool layers, in declaration order — matching
# crates/agent-vm/src/default-tools.toml, the launcher's chain order, and CI's
# build order. The last one produces the composed template, so it is split out
# (no negative array indexing, which macOS's bash 3.2 lacks).
INTERMEDIATE_LAYERS=(codex opencode claude)
FINAL_LAYER=copilot

# Returns 0 if /v2/ on the registry port answers within the timeout.
# Quiet — caller decides whether to log.
poll_registry() {
    local attempts="${1:-50}" i
    for ((i = 0; i < attempts; i++)); do
        curl -fsS "http://127.0.0.1:${REGISTRY_PORT}/v2/" >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    return 1
}

dump_registry_diagnostics() {
    {
        echo "Container state:"
        docker ps -a --filter "name=${REGISTRY_NAME}" \
            --format '  status={{.Status}}  ports={{.Ports}}' 2>/dev/null || true
        echo "Port bindings:"
        docker inspect "${REGISTRY_NAME}" \
            --format '  {{json .NetworkSettings.Ports}}' 2>/dev/null || true
        echo "Last 30 lines of container logs:"
        docker logs --tail 30 "${REGISTRY_NAME}" 2>&1 | sed 's/^/  /' || true
    } >&2
}

create_registry() {
    echo "==> Creating local registry ${REGISTRY_NAME} on 127.0.0.1:${REGISTRY_PORT}"
    docker run -d \
        --name "${REGISTRY_NAME}" \
        --restart=always \
        -p "127.0.0.1:${REGISTRY_PORT}:5000" \
        registry:2 >/dev/null
}

recreate_registry() {
    echo "==> Removing stale ${REGISTRY_NAME} container"
    dump_registry_diagnostics
    docker rm -f "${REGISTRY_NAME}" >/dev/null 2>&1 || true
    create_registry
}

# Idempotent: bring the registry container into a "running and answering on
# 127.0.0.1:${REGISTRY_PORT}" state, no matter how it was left.
#
# Cases:
#   - missing            → create.
#   - running, healthy   → nothing.
#   - running, unhealthy → recreate (was probably started in a past session
#     without the right `-p` mapping, or the registry process crashed).
#   - stopped/etc        → start; recreate if still unhealthy after start.
ensure_registry() {
    local state
    # `docker inspect` on a missing container can emit a stray blank line to
    # stdout before exiting non-zero (seen on Docker 29.x), so `|| echo
    # missing` alone yields "\nmissing" and never matches the case below.
    # Strip all whitespace and treat empty as missing.
    state=$(docker inspect --type container -f '{{.State.Status}}' "${REGISTRY_NAME}" 2>/dev/null || true)
    state=$(printf '%s' "${state}" | tr -d '[:space:]')
    [ -z "${state}" ] && state=missing

    case "${state}" in
        running)
            if poll_registry 5; then
                return 0
            fi
            echo "==> ${REGISTRY_NAME} is running but 127.0.0.1:${REGISTRY_PORT} is unresponsive"
            recreate_registry
            ;;
        missing)
            create_registry
            ;;
        *)
            echo "==> Starting existing registry container ${REGISTRY_NAME} (was: ${state})"
            docker start "${REGISTRY_NAME}" >/dev/null
            # registry:2 takes ~100ms after start to bind 5000 — short poll
            # is normal. If the container was misconfigured (no port mapping)
            # this longer poll will time out, and we recreate from scratch.
            if poll_registry 25; then
                return 0
            fi
            echo "==> ${REGISTRY_NAME} did not become reachable after restart"
            recreate_registry
            ;;
    esac

    echo "==> Waiting for registry on 127.0.0.1:${REGISTRY_PORT} to accept connections"
    if poll_registry 50; then
        return 0
    fi
    {
        echo "Registry did not become reachable on 127.0.0.1:${REGISTRY_PORT} after 10s."
        echo "This is past our auto-recovery — Docker itself is probably misbehaving."
    } >&2
    dump_registry_diagnostics
    return 1
}

# The zstd registry exporter. Use `type=registry` so layers are zstd-compressed
# on the way to the registry — gzip→zstd is the dominant per-layer cost during
# `agent-vm setup`, and a benchmark on /usr/lib showed ~24× faster end-to-end
# ingest with no change to microsandbox (`tar_ingest.rs:427` already accepts the
# `application/vnd.oci.image.layer.v1.tar+zstd` media type).
#
# `force-compression=true` re-emits even already-compressed base-image layers as
# zstd; without it, only the layers we ADD are zstd while everything from the
# base image stays gzip, partially defeating the win. `registry.insecure=true`
# lets us push to the loopback HTTP registry. We use `compression-level=3`
# (zstd's default) — the bench shows diminishing returns past that for
# binary-heavy layers.
REGISTRY_OUTPUT="type=registry,push=true,registry.insecure=true,compression=zstd,compression-level=3,force-compression=true"

# Extra buildx args shared by every step: the host-CA shim (TLS-intercept dev
# hosts) and the `AGENT_INSTALL_SOFT_FAIL` policy. The tool layers inherit the
# base's baked CA, but the installers they run still need host network access
# and the soft-fail arg, so these flags go on every step.
#
# If the host is itself behind a TLS-intercept proxy (agent-vm-inside-agent-vm
# during local dev, or a corporate egress MITM), the buildkit container's
# outbound HTTPS sees the proxy's CA and curl/apt fail with "unable to verify
# the legitimacy of the server". Detect the host CA and:
#   - pass it as a buildx secret (the base Dockerfile imports it
#     conditionally; no-op when the secret is absent),
#   - key the RUN-cache invalidation off its mtime (CA_SHIM_CACHEBUST — see the
#     Dockerfile comment for why secret content alone doesn't invalidate the
#     cache),
#   - run the RUN steps in the host network namespace, because buildkit's
#     default bridge stack drops some HTTPS connections (curl 56 `SSL_read:
#     unexpected eof`) mid-redirect through the MITM proxy.
# Production CI has no such host CA and skips all of this.
EXTRA=()
HOST_CA="${AGENT_VM_BUILD_HOST_CA:-/usr/local/share/ca-certificates/microsandbox-ca.crt}"
MITM_DETECTED=
if [ -f "${HOST_CA}" ]; then
    echo "==> Including host CA ${HOST_CA} as buildx secret (TLS-intercept proxy detected)"
    EXTRA+=(--secret "id=hostca,src=${HOST_CA}")
    EXTRA+=(--build-arg "CA_SHIM_CACHEBUST=$(stat -c %Y "${HOST_CA}")")
    EXTRA+=(--allow "network.host")
    EXTRA+=(--network "host")
    MITM_DETECTED=1
fi

# AGENT_INSTALL_SOFT_FAIL — independent toggle (not tied to CA detection) so a
# clean-network developer rebuilding during an upstream installer outage can opt
# in, and someone debugging installer changes on a MITM host can force hard-fail
# with `AGENT_VM_BUILD_SOFT_FAIL_AGENTS=0`.
#
# Default policy: MITM-detected hosts → soft-fail (the same TLS interception
# that triggers the CA shim also hits curl 56 on some GitHub release-asset
# URLs); clean hosts → hard-fail (matching production CI).
SOFT_FAIL="${AGENT_VM_BUILD_SOFT_FAIL_AGENTS:-${MITM_DETECTED}}"
if [ -n "${SOFT_FAIL}" ] && [ "${SOFT_FAIL}" != "0" ]; then
    echo "==> Soft-fail mode enabled for agent installers (AGENT_VM_BUILD_SOFT_FAIL_AGENTS=0 to disable)"
    EXTRA+=(--build-arg "AGENT_INSTALL_SOFT_FAIL=1")
fi

# `build_intermediate` `--load`s each layer into the daemon so the next step's
# `FROM` can reference it. That only works on a builder whose driver shares the
# daemon's image store (the `docker` driver). Fail up front with an actionable
# message rather than letting buildx fail opaquely partway through the chain.
require_docker_driver() {
    # Read `inspect` once into a variable: piping it into `grep -q` under
    # `set -o pipefail` would report a false failure, because `grep -q` exits as
    # soon as it matches and `docker` then dies of SIGPIPE.
    local info driver
    info=$(docker buildx inspect 2>/dev/null || true)
    driver=$(printf '%s\n' "$info" | awk -F': *' '/^Driver:/{print $2; exit}')
    if [ "$driver" = "docker" ]; then
        return 0
    fi
    {
        echo "the active buildx builder uses the '${driver:-unknown}' driver, not 'docker'."
        echo "  This script --loads intermediate tool layers into the daemon, which only"
        echo "  works when the current builder shares the daemon's image store."
        echo "  Fix: docker buildx create --driver docker --use"
        echo "  Or build via the loop in macos-build.md and import the tags directly."
    } >&2
    return 1
}

build_base() {
    echo "==> Building ${BASE_TAG} (tool-free base, zstd layers)"
    docker buildx build \
        -t "${BASE_TAG}" \
        "${EXTRA[@]}" \
        --output "${REGISTRY_OUTPUT}" \
        -f "${SCRIPT_DIR}/Dockerfile" \
        "${SCRIPT_DIR}"
}

# One intermediate tool layer, `--load`ed into the daemon so the next step's
# `FROM` can reference it. ${1} is the tool name (a directory under
# images/tools/); ${2} is the reference this step builds FROM.
build_intermediate() {
    local tool="$1" from="$2"
    echo "==> Building tool layer ${tool} FROM ${from}"
    docker buildx build \
        -t "agent-vm-${tool}-build:latest" \
        --build-arg "BASE_IMAGE=${from}" \
        "${EXTRA[@]}" \
        --load \
        "${SCRIPT_DIR}/tools/${tool}"
}

# The final tool layer (copilot) produces the published composed template.
build_template() {
    local from="$1"
    echo "==> Building ${IMAGE_TAG} (composed default: base + tool layers, zstd layers)"
    docker buildx build \
        -t "${IMAGE_TAG}" \
        --build-arg "BASE_IMAGE=${from}" \
        "${EXTRA[@]}" \
        --output "${REGISTRY_OUTPUT}" \
        "${SCRIPT_DIR}/tools/${FINAL_LAYER}"
}

build_and_push() {
    build_base

    local prev="${BASE_TAG}" tool
    # Every layer but the last is an unpublished intermediate.
    for tool in "${INTERMEDIATE_LAYERS[@]}"; do
        build_intermediate "${tool}" "${prev}"
        prev="agent-vm-${tool}-build:latest"
    done
    build_template "${prev}"
}

main() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "docker not found on PATH; agent-vm setup needs Docker installed" >&2
        exit 1
    fi
    if ! docker buildx version >/dev/null 2>&1; then
        echo "docker buildx not available — install Docker 20.10+ or 'docker buildx install'" >&2
        exit 1
    fi
    require_docker_driver
    ensure_registry
    build_and_push
    echo "==> ${BASE_TAG} and ${IMAGE_TAG} ready"
}

main "$@"
