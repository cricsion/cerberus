#!/usr/bin/env bash
# Build the scan sandbox image with pinned versions + smoke-test the result.
#
#   cp versions.env.example versions.env   # fill versions + checksums
#   ./harness/sandbox/docker/build.sh cyber-sandbox:local
#
# Build context is the REPO ROOT: the Dockerfile copies harness/rules into
# the image so in-container semgrep runs the same custom rules as the host.
set -euo pipefail

IMAGE_TAG="${1:-cyber-sandbox:local}"
ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT_DIR"

VERSIONS_FILE="harness/sandbox/docker/versions.env"
if [[ ! -f "$VERSIONS_FILE" ]]; then
    echo "missing $VERSIONS_FILE: cp harness/sandbox/docker/versions.env.example harness/sandbox/docker/versions.env and fill it in" >&2
    exit 1
fi
set -a; . "./$VERSIONS_FILE"; set +a

case "${WITH_NODE:-0}" in
    0|1) ;;
    *) echo "WITH_NODE must be 0 or 1 in $VERSIONS_FILE" >&2; exit 1 ;;
esac
case "${WITH_GO:-0}" in
    0|1) ;;
    *) echo "WITH_GO must be 0 or 1 in $VERSIONS_FILE" >&2; exit 1 ;;
esac
if [[ "${WITH_NODE:-0}" == "1" && -z "${NODE_VERSION:-}" ]]; then
    echo "NODE_VERSION is required when WITH_NODE=1 in $VERSIONS_FILE" >&2
    exit 1
fi
if [[ "${WITH_GO:-0}" == "1" && -z "${GO_VERSION:-}" ]]; then
    echo "GO_VERSION is required when WITH_GO=1 in $VERSIONS_FILE" >&2
    exit 1
fi

ARGS=()
for v in GITLEAKS_VERSION GITLEAKS_SHA256_X64 GITLEAKS_SHA256_ARM64 \
         OSV_SCANNER_VERSION OSV_SCANNER_SHA256_X64 OSV_SCANNER_SHA256_ARM64 \
         SEMGREP_VERSION OPENGREP_VERSION OPENGREP_SHA256_X64 OPENGREP_SHA256_ARM64 \
         CHECKOV_VERSION BANDIT_VERSION \
         BEARER_VERSION BEARER_SHA256_X64 BEARER_SHA256_ARM64 \
         TRUFFLEHOG_VERSION TRUFFLEHOG_SHA256_X64 TRUFFLEHOG_SHA256_ARM64 \
         GOSEC_VERSION GOSEC_SHA256_X64 GOSEC_SHA256_ARM64 \
         NJSSCAN_VERSION ATHERIS_VERSION FLAWFINDER_VERSION \
         WITH_NODE NODE_VERSION WITH_GO GO_VERSION; do
    if [[ -n "${!v:-}" ]]; then
        ARGS+=(--build-arg "$v=${!v}")
    else
        # Optional toolchains may be empty/unset; required pins may not.
        case "$v" in
            WITH_NODE) ARGS+=(--build-arg WITH_NODE=0) ;;
            WITH_GO) ARGS+=(--build-arg WITH_GO=0) ;;
            # Version pins for a disabled toolchain are never used by the
            # Dockerfile (its `if [ "$WITH_X" = "1" ]` guards them), so they
            # stay optional: an empty value must not fail the build.
            NODE_VERSION|GO_VERSION) ARGS+=(--build-arg "$v=") ;;
            *) echo "required build arg $v is empty in $VERSIONS_FILE" >&2; exit 1 ;;
        esac
    fi
done

echo "[build] ${IMAGE_TAG} (context: repo root)"
docker build -f harness/sandbox/docker/Dockerfile "${ARGS[@]}" -t "$IMAGE_TAG" .

echo "[smoke] versions"
docker run --rm "$IMAGE_TAG" semgrep --version
docker run --rm "$IMAGE_TAG" opengrep --version
docker run --rm "$IMAGE_TAG" gitleaks version
docker run --rm "$IMAGE_TAG" osv-scanner --version
docker run --rm "$IMAGE_TAG" checkov --version

echo "[smoke] jq + skills"
docker run --rm "$IMAGE_TAG" jq --version
docker run --rm "$IMAGE_TAG" sh -c 'test -f /opt/harness-skills/gitleaks/SKILL.md && test -f /opt/harness-skills/osv-scanner/SKILL.md && test -f /opt/harness-skills/checkov/SKILL.md'
docker run --rm "$IMAGE_TAG" sh -c 'for t in gitleaks osv-scanner checkov; do test -d "/opt/harness-skills/$t/references" || exit 1; done'
docker run --rm "$IMAGE_TAG" cat /opt/harness-skills/gitleaks/SKILL.md | diff -q - harness/skills/gitleaks/SKILL.md

echo "[smoke] offline rule scan with no network (must succeed)"
TMP_REPO="$(mktemp -d)"
printf 'import os\nos.system("echo " + input())\n' > "$TMP_REPO/evil.py"
docker run --rm --network none -v "$TMP_REPO:/scan:ro" "$IMAGE_TAG" \
    semgrep scan --config /opt/scan-rules/harness --metrics off --quiet /scan
rm -rf "$TMP_REPO"

echo "[smoke] checkov JSON parses offline"
TMP_IAC="$(mktemp -d)"
printf 'FROM alpine:3.20\nRUN echo hi\n' > "$TMP_IAC/Dockerfile"
docker run --rm --network none -v "$TMP_IAC:/scan:ro" "$IMAGE_TAG" sh -c \
    'checkov -d /scan -o json --skip-download --quiet --output-file-path /work >/dev/null 2>&1; rc=$?; [ "$rc" = 1 ] && jq -e ".results.failed_checks | length > 0" /work/results_json.json >/dev/null'
rm -rf "$TMP_IAC"

echo "[smoke] network must be unreachable (curl is not in the image)"
# d/k has /dev/tcp, dash does not; run the probe under bash explicitly.
if docker run --rm --network none "$IMAGE_TAG" bash -c 'exec 3<>/dev/tcp/example.com/443' 2>/dev/null; then
    echo "WARNING: outbound TCP from the sandbox apparently works with --network none" >&2
else
    echo "network denied, as designed"
fi

echo "[done] ${IMAGE_TAG}"
