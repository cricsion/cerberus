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
         PWNTOOLS_VERSION CAPSTONE_VERSION BINWALK_VERSION \
         FFUF_VERSION FFUF_SHA256_X64 FFUF_SHA256_ARM64 \
         NUCLEI_VERSION NUCLEI_SHA256_X64 NUCLEI_SHA256_ARM64 \
         HTTPX_VERSION HTTPX_SHA256_X64 HTTPX_SHA256_ARM64 \
         KATANA_VERSION KATANA_SHA256_X64 KATANA_SHA256_ARM64 \
         GAU_VERSION GAU_SHA256_X64 GAU_SHA256_ARM64 \
         SQLMAP_VERSION ARJUN_VERSION MITMPROXY_VERSION \
         WITH_NODE NODE_VERSION CODEGRAPH_VERSION WITH_GO GO_VERSION; do
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
docker run --rm "$IMAGE_TAG" sh -c 'cd /opt/harness-skills && for t in \
    gdb afl valgrind pwntools binwalk httpx katana gau arjun; do \
    test -s "$t/SKILL.md" || exit 1; done && echo "offensive runbooks ok"'
docker run --rm "$IMAGE_TAG" cat /opt/harness-skills/gitleaks/SKILL.md | diff -q - harness/skills/gitleaks/SKILL.md

echo "[smoke] Tier-1 analysis toolchain (debug/RE/fuzz/extract)"
docker run --rm "$IMAGE_TAG" sh -c 'command -v gdb valgrind objdump afl-fuzz binwalk pwn'
docker run --rm "$IMAGE_TAG" sh -c 'gdb --version | head -1 && valgrind --version && objdump --version | head -1'
docker run --rm "$IMAGE_TAG" sh -c 'python3 -c "import pwn, binwalk; print(\"pwntools+binwalk ok\")"'
docker run --rm "$IMAGE_TAG" sh -c 'binwalk --help >/dev/null 2>&1 && echo "binwalk CLI ok"'

echo "[smoke] Tier-2 dynamic web/API binaries"
docker run --rm "$IMAGE_TAG" sh -c 'ffuf -V && nuclei -version && httpx -version && katana -version'
docker run --rm "$IMAGE_TAG" sh -c 'command -v gau sqlmap arjun mitmdump && sqlmap --version && mitmdump --version'

# codegraph CLI (D9/D10): only present on WITH_NODE=1 lanes.
if [[ "${WITH_NODE:-0}" == "1" ]]; then
    echo "[smoke] codegraph CLI present + telemetry disabled"
    # `command -v` must resolve to a real executable, not a shell builtin/alias
    # (an empty pin would otherwise "pass" a parse-only check with no CLI).
    docker run --rm "$IMAGE_TAG" sh -c 'test -x "$(command -v codegraph)"'
    docker run --rm "$IMAGE_TAG" sh -c 'codegraph version | grep -q .'
    docker run --rm "$IMAGE_TAG" sh -c 'codegraph telemetry status | grep -qi disabled'

    echo "[smoke] codegraph index + gate, offline on a tiny fixture (no network)"
    # Fixture is generated in-container under the writable /work, so no host
    # mount (and no repo fixture) is involved. Env hygiene comes from the image.
    # The jq gate parse runs in-container too (jq is baked in), like the
    # checkov smoke above -- no host jq dependency.
    docker run --rm --network none "$IMAGE_TAG" sh -c '
        set -eu
        mkdir -p /work/cg/src
        printf "def main():\n    return helper()\n\ndef helper():\n    return 1\n" > /work/cg/src/a.py
        codegraph init /work/cg >/dev/null 2>&1
        codegraph index -q /work/cg
        codegraph status -j /work/cg | jq -e ".index.state == \"complete\" and .index.pendingRefs == 0" >/dev/null
    '
fi

echo "[smoke] offline rule scan with no network (must succeed)"
TMP_REPO="$(mktemp -d)"
printf 'import os\nos.system("echo " + input())\n' > "$TMP_REPO/evil.py"
docker run --rm --network none -v "$TMP_REPO:/scan:ro" "$IMAGE_TAG" \
    semgrep scan --config /opt/scan-rules/harness --metrics off --quiet /scan
rm -rf "$TMP_REPO"

echo "[smoke] vendored upstream rules fire offline (weak-crypto fixture)"
TMP_CRYPTO="$(mktemp -d)"
printf 'import cryptography\n_insecure = cryptography.hazmat.primitives.hashes.MD5()\n' > "$TMP_CRYPTO/a.py"
docker run --rm --network none -v "$TMP_CRYPTO:/scan:ro" "$IMAGE_TAG" sh -c \
    'semgrep scan --config /opt/scan-rules/harness/vendor/semgrep-rules --metrics off /scan | grep -q insecure-hash-algorithm'
rm -rf "$TMP_CRYPTO"

echo "[smoke] vendored-rules provenance (versions.env rev named in baked NOTICE.md)"
[[ -n "${SEMGREP_RULES_REV:-}" ]] || { echo "SEMGREP_RULES_REV missing in $VERSIONS_FILE" >&2; exit 1; }
docker run --rm "$IMAGE_TAG" sh -c "grep -qF '${SEMGREP_RULES_REV}' /opt/scan-rules/harness/vendor/semgrep-rules/NOTICE.md"

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
