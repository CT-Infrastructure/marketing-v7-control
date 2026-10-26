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
    pythonlib=$(python -B tests/harness/ci_evidence.py python-library)
    python -m venv --copies "$root/deps"
    "$root/deps/bin/python" -m pip --disable-pip-version-check install --no-cache-dir --no-index --require-hashes --only-binary=:all: -r tests/harness/requirements-ci.lock
    # Direct reviewed wheel URLs remain usable with --no-index; no index resolution.
    python -B tests/harness/ci_evidence.py diagnostic namespace START
    if "$root/native/payload/usr/bin/bwrap" --unshare-all --die-with-parent --new-session \
      --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 --symlink usr/bin /bin \
      --ro-bind /opt /opt --ro-bind /etc/ld.so.cache /etc/ld.so.cache --proc /proc --dev /dev \
      --ro-bind "$GITHUB_WORKSPACE" "$GITHUB_WORKSPACE" --ro-bind "$root/deps" "$root/deps" \
      --bind "$root/runtime" "$root/runtime" --bind "$root/upload" "$root/upload" \
      --clearenv --setenv PATH /usr/bin:/bin --setenv TMPDIR "$root/runtime" \
      --setenv PYTHONDONTWRITEBYTECODE 1 --setenv F07_NETWORK_NAMESPACE_EXPECTED 1 \
      --setenv LD_LIBRARY_PATH "$pythonlib" \
      --chdir "$GITHUB_WORKSPACE" "$root/deps/bin/python" -B tests/harness/ci_evidence.py run \
      "$root/upload" "$GITHUB_SHA" "$F07_CANDIDATE_SHA" 2>"$root/runtime/namespace.stderr"; then
      python -B tests/harness/ci_evidence.py namespace-result 0
    else
      python -B tests/harness/ci_evidence.py diagnostic namespace FAIL
      exit 1
    fi
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
