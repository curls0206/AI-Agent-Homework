#!/bin/sh
# Entrypoint of the vulnrepair Agent image.
#   demo                         built-in offline CWE-79 demo (fixed candidates, no LLM)
#   solve <cwe79|cwe22|cwe89|cwe78> [repair options]   let an LLM repair one vulnerable app
#   test [unittest options]      run the whole test suite (incl. nested-Podman isolation tests)
#   evidence                     re-run the three failure cases and write traces to $OUT_DIR/evidence
#   shell                        interactive shell
#   <anything else>              passed to `python3 -m vulnrepair`
set -eu

SANDBOX_TAG="vulnrepair-sandbox:local"
OUT_DIR="${VULNREPAIR_OUT:-/out}"

log() { echo "[agent] $*" >&2; }

# Nested Podman can only enforce pids / memory / cpu limits when the controllers are delegated
# to child cgroups. Fail closed instead of silently running the sandbox without limits.
setup_cgroups() {
    if [ ! -f /sys/fs/cgroup/cgroup.controllers ] || [ ! -w /sys/fs/cgroup ]; then
        log "ERROR: cgroup v2 is not writable. Run the container with --privileged."
        exit 2
    fi
    mkdir -p /sys/fs/cgroup/agent-init
    for pid in $(cat /sys/fs/cgroup/cgroup.procs); do
        echo "$pid" > /sys/fs/cgroup/agent-init/cgroup.procs 2>/dev/null || true
    done
    if ! echo "+cpu +memory +pids" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null; then
        log "ERROR: cannot delegate cpu/memory/pids controllers; sandbox limits would not apply."
        exit 2
    fi
}

ensure_sandbox_image() {
    if ! podman image exists "$SANDBOX_TAG"; then
        log "building sandbox image (first run only; needs network access to pull the base image)"
        podman build --isolation=oci --network=none -t "$SANDBOX_TAG" -f /app/sandbox/Containerfile /app/sandbox >&2
    fi
    VULNREPAIR_SANDBOX_IMAGE="sha256:$(podman image inspect "$SANDBOX_TAG" --format '{{.Id}}')"
    export VULNREPAIR_SANDBOX_IMAGE
}

solve() {
    if [ "$#" -lt 1 ]; then
        log "usage: solve <cwe79|cwe22|cwe89|cwe78> [vulnrepair repair options]"
        exit 2
    fi
    name="$1"; shift
    mkdir -p "$OUT_DIR"
    fixtures="$(mktemp -d /work/fixtures.XXXXXX)"
    python3 -m vulnrepair fixture "$name" --out "$fixtures" --mode "${VULNREPAIR_MODE:-located}" >/dev/null
    set +e
    python3 -m vulnrepair repair "$fixtures/$name/scenario.json" \
        --runner podman --harness-dir "$fixtures/$name/harness" --output "$OUT_DIR" "$@" \
        > "$fixtures/summary.json"
    status=$?
    set -e
    cat "$fixtures/summary.json"
    run_dir="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['artifact_dir'])" "$fixtures/summary.json" 2>/dev/null || true)"
    if [ -n "$run_dir" ]; then
        echo
        python3 -m vulnrepair show-trace "$run_dir"
    fi
    exit "$status"
}

command="${1:-demo}"
[ "$#" -gt 0 ] && shift

case "$command" in
    shell)
        setup_cgroups; ensure_sandbox_image
        exec sh
        ;;
    demo)
        setup_cgroups; ensure_sandbox_image
        mkdir -p "$OUT_DIR"
        exec python3 -m vulnrepair demo --runner podman --output "$OUT_DIR" "$@"
        ;;
    solve)
        setup_cgroups; ensure_sandbox_image
        solve "$@"
        ;;
    evidence)
        setup_cgroups; ensure_sandbox_image
        exec python3 /app/scripts/collect_failure_evidence.py --out "$OUT_DIR/evidence" "$@"
        ;;
    test)
        setup_cgroups; ensure_sandbox_image
        export VULNREPAIR_PODMAN_IMAGE="$VULNREPAIR_SANDBOX_IMAGE"
        exec python3 -m unittest discover -s /app/tests "$@"
        ;;
    *)
        setup_cgroups; ensure_sandbox_image
        exec python3 -m vulnrepair "$command" "$@"
        ;;
esac
