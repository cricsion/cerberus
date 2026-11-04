#!/usr/bin/env bash
# Build the scan sandbox image with pinned versions + smoke-test the result.
#
#   cp versions.env.example versions.env   # fill versions
#   ./sandbox/docker/build.sh cerberus-sandbox:local
#
# Build context is the REPO ROOT (this checkout, however it is named): the
# Dockerfile copies rules/ and skills/ into the image so in-container semgrep
# runs the same custom rules as the host.
set -euo pipefail

IMAGE_TAG="${1:-cerberus-sandbox:local}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

VERSIONS_FILE="sandbox/docker/versions.env"
if [[ ! -f "$VERSIONS_FILE" ]]; then
    echo "missing $VERSIONS_FILE: cp sandbox/docker/versions.env.example sandbox/docker/versions.env and fill it in" >&2
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
for v in GITLEAKS_VERSION \
         OSV_SCANNER_VERSION \
         SEMGREP_VERSION OPENGREP_VERSION \
         CHECKOV_VERSION BANDIT_VERSION \
         BEARER_VERSION \
         TRUFFLEHOG_VERSION \
         GOSEC_VERSION \
         NJSSCAN_VERSION ATHERIS_VERSION FLAWFINDER_VERSION \
         PWNTOOLS_VERSION CAPSTONE_VERSION BINWALK_VERSION \
         FFUF_VERSION \
         NUCLEI_VERSION \
         HTTPX_VERSION \
         KATANA_VERSION \
         GAU_VERSION \
         SQLMAP_VERSION ARJUN_VERSION MITMPROXY_VERSION PYTHON_BASE_IMAGE \
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
# Stable named builder (docker-container driver): its build cache lives in the
# builder's own volume, which survives Docker Desktop restarts, and this driver
# is the one that can adopt --cache-to/--cache-from backends later. The first
# run after creation bootstraps cold by design. --builder pins every
# invocation explicitly (no reliance on buildx-use state); --load exports the
# result into the daemon's image store so the smoke suite can use the tag.
# Remote cache (deferred, optDocker 4.6) — uncomment once a registry ref exists:
#   --cache-from type=registry,ref=<registry>/cerberus-sandbox:cache \
#   --cache-to   type=registry,ref=<registry>/cerberus-sandbox:cache,mode=max \
docker buildx inspect cyber >/dev/null 2>&1 \
    || docker buildx create --name cyber --driver docker-container >/dev/null
docker buildx build --builder cyber --load \
    -f sandbox/docker/Dockerfile "${ARGS[@]}" -t "$IMAGE_TAG" .

# Smoke checks: batched into exactly TWO container invocations:
# 1. Container 1: Toolchain, versions, python imports, and skills layout (online/default)
# 2. Container 2: Offline rule scanning, codegraph indexing, checkov IaC, and hermetic isolation (--network none)

[[ -n "${SEMGREP_RULES_REV:-}" ]] || { echo "SEMGREP_RULES_REV missing in $VERSIONS_FILE" >&2; exit 1; }

echo "[smoke 1/2] toolchain, versions, python imports & skills (batched)"
docker run --rm \
    -v "$ROOT_DIR/skills/gitleaks/SKILL.md:/tmp/host_gitleaks_skill.md:ro" \
    "$IMAGE_TAG" bash -c '
    set -euo pipefail

    # Core scanners & CLI tools
    semgrep --version
    opengrep --version
    gitleaks version
    osv-scanner --version
    checkov --version
    bandit --version
    bearer --version
    trufflehog --version
    gosec -version
    njsscan --version
    flawfinder --version
    jq --version

    # Tier-1 analysis & RE/debug binaries
    for t in gdb valgrind objdump afl-fuzz binwalk pwn; do
        command -v "$t" >/dev/null || exit 1
    done
    gdb --version | head -1
    valgrind --version
    objdump --version | head -1
    binwalk --help >/dev/null 2>&1

    # Python packages
    python3 -c "import pwn, binwalk, atheris; print(\"pwntools+binwalk+atheris ok\")"

    # Tier-2 dynamic web binaries
    ffuf -V
    nuclei -version
    httpx -version
    katana -version
    for t in gau sqlmap arjun mitmdump; do
        command -v "$t" >/dev/null || exit 1
    done
    sqlmap --version
    mitmdump --version

    # Codegraph CLI (when WITH_NODE=1)
    if [ "'"${WITH_NODE:-0}"'" = "1" ]; then
        test -x "$(command -v codegraph)"
        codegraph version | grep -q .
        codegraph telemetry status | grep -qi disabled
    fi

    # Skills layout and reference trees
    test -f /opt/cerberus-skills/gitleaks/SKILL.md
    test -f /opt/cerberus-skills/osv-scanner/SKILL.md
    test -f /opt/cerberus-skills/checkov/SKILL.md
    for t in gitleaks osv-scanner checkov; do test -d "/opt/cerberus-skills/$t/references" || exit 1; done
    for t in gdb afl valgrind pwntools binwalk httpx katana gau arjun; do test -s "/opt/cerberus-skills/$t/SKILL.md" || exit 1; done
    cmp -s /opt/cerberus-skills/gitleaks/SKILL.md /tmp/host_gitleaks_skill.md || exit 1
    grep -qF "'"${SEMGREP_RULES_REV}"'" /opt/scan-rules/cerberus/vendor/semgrep-rules/NOTICE.md
    echo "toolchain, runbooks, and skills ok"
'

echo "[smoke 2/2] offline execution, fixtures & network isolation (--network none)"
docker run --rm --network none "$IMAGE_TAG" bash -c '
    set -euo pipefail

    # 1. codegraph index + gate on in-memory fixture (when WITH_NODE=1)
    if [ "'"${WITH_NODE:-0}"'" = "1" ]; then
        mkdir -p /work/cg/src
        printf "def main():\n    return helper()\n\ndef helper():\n    return 1\n" > /work/cg/src/a.py
        codegraph init /work/cg >/dev/null 2>&1
        codegraph index -q /work/cg
        codegraph status -j /work/cg | jq -e ".index.state == \"complete\" and .index.pendingRefs == 0" >/dev/null
    fi

    # 2. offline rule scan with harness custom rules
    mkdir -p /work/scan-evil
    printf "import os\nos.system(\"echo \" + input())\n" > /work/scan-evil/evil.py
    timeout 600 semgrep scan --config /opt/scan-rules/cerberus --metrics off --quiet /work/scan-evil

    # 3. offline rule scan with vendored upstream rules (weak crypto)
    mkdir -p /work/scan-crypto
    printf "import cryptography\n_insecure = cryptography.hazmat.primitives.hashes.MD5()\n" > /work/scan-crypto/a.py
    timeout 600 semgrep scan --config /opt/scan-rules/cerberus/vendor/semgrep-rules --metrics off /work/scan-crypto | grep -q insecure-hash-algorithm

    # 4. checkov offline IAC parsing
    mkdir -p /work/scan-iac
    printf "FROM alpine:3.20\nRUN echo hi\n" > /work/scan-iac/Dockerfile
    checkov -d /work/scan-iac -o json --skip-download --quiet --output-file-path /work >/dev/null 2>&1 || true
    jq -e ".results.failed_checks | length > 0" /work/results_json.json >/dev/null

    # 5. network isolation: egress must fail closed
    if exec 3<>/dev/tcp/example.com/443 2>/dev/null; then
        echo "WARNING: outbound TCP from the sandbox works with --network none" >&2
        exit 1
    fi
    echo "offline rule execution and network isolation ok"
'

echo "[done] ${IMAGE_TAG}"
