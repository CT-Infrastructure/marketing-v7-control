#!/usr/bin/env bash
set -euo pipefail
# No capability fallback: unsupported namespace creation is a failing gate.
mode=${1:-run}
case "$mode" in
  run)
    root=$(mktemp -d "${RUNNER_TEMP:?}/f07-ci.XXXXXXXXXXXX")
    printf 'F07_ROOT=%s\n' "$root" >> "${GITHUB_ENV:?}"
    cleanup_runtime() {
      python -B tests/harness/ci_evidence.py cleanup-runtime "$root"
    }
    trap cleanup_runtime EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT
    mkdir "$root/runtime" "$root/upload"
    python -B tests/harness/ci_evidence.py native-bootstrap "$root"
    python -m venv --copies "$root/deps"
    "$root/deps/bin/python" -m pip --disable-pip-version-check install --no-cache-dir --no-index --require-hashes --only-binary=:all: -r tests/harness/requirements-ci.lock
    # Direct reviewed wheel URLs remain usable with --no-index; no index resolution.
    python -B tests/harness/ci_evidence.py namespace-supervise "$root" "$GITHUB_SHA" "$F07_CANDIDATE_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"
    python -B tests/harness/ci_evidence.py check "$root/upload" "$GITHUB_SHA" "$F07_CANDIDATE_SHA"
    ;;
  metadata)
    python -B tests/harness/ci_evidence.py metadata "${F07_ROOT:?}/upload" "$GITHUB_SHA" "$F07_CANDIDATE_SHA"
    ;;
  cleanup)
    if [[ -n "${F07_ROOT:-}" ]]; then
      python -B tests/harness/ci_evidence.py cleanup "$F07_ROOT"
    fi
    ;;
  *) exit 2 ;;
esac
