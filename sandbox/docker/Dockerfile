# Scan sandbox image: everything the agent's shell needs at scan time, so the
# RUNNING container rarely needs egress (which `sandbox.network` controls:
# bridge = full egress by default, none = no egress; see
# harness/sandbox/docker_backend.py).
#
# Network is available HERE (build time) and only here for the pinned
# toolchain -- the build-then-pin posture from DESIGN_GUIDE.md step 2.
#
# BUILD (build context = REPO ROOT, so the bundled rules can be copied in):
#   docker build -f harness/sandbox/docker/Dockerfile -t cyber-sandbox:local .
#
# Verify:
#   docker run --rm cyber-sandbox:local semgrep --version
#   docker run --rm cyber-sandbox:local gitleaks version
#   docker run --rm cyber-sandbox:local osv-scanner --version
#   docker run --rm cyber-sandbox:local checkov --version
#   # an offline rule scan must also work with NO network at run time
#   docker run --rm --network none cyber-sandbox:local \
#       semgrep scan --config /opt/scan-rules/harness --metrics off /repo
FROM python:3.11-slim-bookworm

# --- pinned tool versions (fill versions.env, then pass --build-arg) --------
# Deliberately no defaults: an unpinned gray-area version is worse than a
# failed build. Get current versions with:
#   gh release view gitleaks/gitleaks --json tagName -q .tagName
#   gh release view google/osv-scanner --json tagName -q .tagName   # 1.x line
#   gh release view opengrep/opengrep --json tagName -q .tagName
#   pip index versions semgrep | head -1
#   pip index versions checkov | head -1
ARG TARGETARCH
ARG GITLEAKS_VERSION
ARG GITLEAKS_SHA256_X64
ARG GITLEAKS_SHA256_ARM64
ARG OSV_SCANNER_VERSION
ARG OSV_SCANNER_SHA256_X64
ARG OSV_SCANNER_SHA256_ARM64
ARG SEMGREP_VERSION
ARG OPENGREP_VERSION
ARG OPENGREP_SHA256_X64
ARG OPENGREP_SHA256_ARM64
ARG CHECKOV_VERSION
ARG BANDIT_VERSION
ARG ATHERIS_VERSION
ARG FLAWFINDER_VERSION
ARG BEARER_VERSION
ARG BEARER_SHA256_X64
ARG BEARER_SHA256_ARM64
ARG TRUFFLEHOG_VERSION
ARG TRUFFLEHOG_SHA256_X64
ARG TRUFFLEHOG_SHA256_ARM64
ARG GOSEC_VERSION
ARG GOSEC_SHA256_X64
ARG GOSEC_SHA256_ARM64
ARG NJSSCAN_VERSION
# Node/Go are OFF by default: add only when the targets you scan need their
# test suites runnable. Each costs image size and startup time.
ARG WITH_NODE=0
ARG NODE_VERSION=20
ARG WITH_GO=0
ARG GO_VERSION

# --- OS layer ---------------------------------------------------------------
# git (repo context/history), build-essential (native wheels + PoC builds),
# clang builds Atheris from source on arm64, where PyPI publishes no wheel;
# jq: agent JSON slicing of scanner output; curl is only a build-time fetcher
# (purged below).
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl build-essential clang libclang-rt-dev jq \
    && rm -rf /var/lib/apt/lists/*

# --- Node (opt-in) -----------------------------------------------------------
RUN if [ "$WITH_NODE" = "1" ]; then \
        curl -fsSL "https://deb.nodesource.com/setup_${NODE_VERSION}.x" | bash - \
        && apt-get install -y --no-install-recommends nodejs \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# --- Go (opt-in, official tarball; bookworm's golang is too old) ------------
RUN if [ "$WITH_GO" = "1" ]; then \
        case "${TARGETARCH}" in \
          amd64) go_arch=amd64;; \
          arm64) go_arch=arm64;; \
          *) echo "unsupported TARGETARCH for Go: ${TARGETARCH}" >&2; exit 1;; \
        esac; \
        curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz" \
        | tar -xz -C /usr/local; \
    fi

# --- scan toolchain (mirrors harness/tools/sast.py, one tool per sast tool) --
# semgrep_scan     -> semgrep
# opengrep_scan    -> opengrep    (NOT on PyPI: built from its own repo tag)
# secrets_scan     -> gitleaks (no network ever needed)
# sca_scan         -> osv-scanner (needs osv.dev egress at scan time)
# iac_check        -> checkov (the in-container skill passes --skip-download; the
#                     image also sets BC_SKIP_MAPPING=TRUE and
#                     CKV_SKIP_PACKAGE_UPDATE_CHECK=True. Without --skip-download
#                     checkov calls Prisma Cloud's API to enrich remediation links.
#                     The host indexer wrapper is left as-is.)
# Extra agent-driven scanners (semgrep/opengrep siblings, run via `execute`,
# one skill each under harness/skills/): bandit (pip), bearer (dataflow),
# trufflehog (verified secrets), gosec (Go), njsscan (Node), atheris
# (verification fuzzing), flawfinder (C/C++). NEVER installed on the host: these are
# image-only, so the only consumer is the in-sandbox agent.
#
# Python scanners + test runners (pip resolves interpreter-compatible wheels).
# setuptools is pinned <81 on purpose: 84 removed the legacy pkg_resources
# module, which semgrep's opentelemetry chain imports at import time.
# njsscan: Node.js security rules. Installed ISOLATED (its own dependency
# tree under /opt/njsscan, invoked via PYTHONPATH by the wrapper script)
# because it pins its own semgrep version: sharing the pip line with the
# pinned image semgrep would either fail resolution or silently upgrade it.
# Node is NOT required -- njsscan is pure Python over its bundled semgrep.
RUN pip install --no-cache-dir --target /opt/njsscan "njsscan==${NJSSCAN_VERSION}" \
    && printf '%s\n' \
        '#!/bin/sh' \
        '# njsscan runner: isolated deps (own semgrep), pinned image semgrep untouched.' \
        'exec env PYTHONPATH=/opt/njsscan python3 /opt/njsscan/bin/njsscan "$@"' \
        > /usr/local/bin/njsscan \
    && chmod 0755 /usr/local/bin/njsscan \
    && command -v njsscan \
    && env PYTHONPATH=/opt/njsscan python3 -c "import njsscan"

RUN pip install --no-cache-dir \
        "setuptools<81" \
        "semgrep==${SEMGREP_VERSION}" \
        "bandit==${BANDIT_VERSION}" \
        "checkov==${CHECKOV_VERSION}" \
        "flawfinder==${FLAWFINDER_VERSION}" \
        pytest coverage \
    && CLANG_BIN=/usr/bin/clang pip install --no-cache-dir \
        "atheris==${ATHERIS_VERSION}"

# opengrep: install the pinned release binary, sha256-verified like the other
# release artifacts below (building from the source tree does not produce an
# `opengrep` entry point -- the repo's pip install yields only
# semgrep_pre_commit_package). Per-arch asset, so it runs natively on both
# amd64 and arm64 instead of under qemu.
ARG OPENGREP_VERSION
ARG OPENGREP_SHA256_X64
ARG OPENGREP_SHA256_ARM64
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sha="${OPENGREP_SHA256_X64}"; asset=opengrep_manylinux_x86;; \
      arm64) sha="${OPENGREP_SHA256_ARM64}"; asset=opengrep_manylinux_aarch64;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1;; \
    esac; \
    curl -fsSL "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${asset}" -o /usr/local/bin/opengrep; \
    echo "${sha}  /usr/local/bin/opengrep" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/opengrep; \
    command -v opengrep

# bearer: dataflow/PII scanner. A different engine lineage from the semgrep
# family, so its findings overlap differently -- that is the point of running
# it alongside them.
ARG BEARER_VERSION
ARG BEARER_SHA256_X64
ARG BEARER_SHA256_ARM64
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sha="${BEARER_SHA256_X64}"; asset="bearer_${BEARER_VERSION}_linux_amd64.tar.gz";; \
      arm64) sha="${BEARER_SHA256_ARM64}"; asset="bearer_${BEARER_VERSION}_linux_arm64.tar.gz";; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1;; \
    esac; \
    curl -fsSL "https://github.com/Bearer/bearer/releases/download/v${BEARER_VERSION}/${asset}" -o /tmp/bearer.tar.gz; \
    echo "${sha}  /tmp/bearer.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/bearer.tar.gz -C /usr/local/bin bearer; \
    rm -f /tmp/bearer.tar.gz; \
    bearer --version

# trufflehog: verified-secret detection incl. git history. Agents run it on
# the current tree by default (--no-update): verified findings are high
# confidence, unverified are lower-confidence leads for gitleaks to confirm.
ARG TRUFFLEHOG_VERSION
ARG TRUFFLEHOG_SHA256_X64
ARG TRUFFLEHOG_SHA256_ARM64
ARG GOSEC_VERSION
ARG GOSEC_SHA256_X64
ARG GOSEC_SHA256_ARM64
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sha="${TRUFFLEHOG_SHA256_X64}"; asset="trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz";; \
      arm64) sha="${TRUFFLEHOG_SHA256_ARM64}"; asset="trufflehog_${TRUFFLEHOG_VERSION}_linux_arm64.tar.gz";; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1;; \
    esac; \
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/${asset}" -o /tmp/trufflehog.tar.gz; \
    echo "${sha}  /tmp/trufflehog.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog; \
    rm -f /tmp/trufflehog.tar.gz; \
    trufflehog --version

# gosec: the Go security specialist (bandit's Go counterpart). Static binary,
# no toolchain needed at run time.
ARG GOSEC_VERSION
ARG GOSEC_SHA256_X64
ARG GOSEC_SHA256_ARM64
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sha="${GOSEC_SHA256_X64}"; asset="gosec_${GOSEC_VERSION}_linux_amd64.tar.gz";; \
      arm64) sha="${GOSEC_SHA256_ARM64}"; asset="gosec_${GOSEC_VERSION}_linux_arm64.tar.gz";; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1;; \
    esac; \
    curl -fsSL "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/${asset}" -o /tmp/gosec.tar.gz; \
    echo "${sha}  /tmp/gosec.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gosec.tar.gz -C /usr/local/bin gosec; \
    rm -f /tmp/gosec.tar.gz; \
    gosec --version

# The harness's OWN custom rules (always applied by semgrep_scan on the
# host). Copied in so an in-container `semgrep --config /opt/scan-rules/
# harness` matches host behavior EXACTLY. Registry packs (p/...) are NOT
# baked in: registry packs download on first use, which needs the egress
# that `sandbox.network` may or may not allow at run time
# at run time. Extend this dir if you need more offline rulesets.
COPY harness/rules /opt/scan-rules/harness
# Scanner usage skills: served to the agent through the skills route on its
# backend (harness/agents/deep.py, SKILLS_ROUTE); copied in at the SAME path
# so in-container reads (e.g. `cat` via execute) agree with the routed file
# tools. Content is the build-time snapshot -- rebuild after editing skills.
COPY harness/skills /opt/harness-skills

# gitleaks + osv-scanner: release binaries, checksum-verified at build.
# (A mismatched ARG SHA fails the build -- fail closed, not silently.)
# Per-arch assets: an x64-only binary crashes under qemu on arm64 hosts
# (Go runtime fault), so each tool takes the binary for TARGETARCH.
ARG GITLEAKS_VERSION
ARG GITLEAKS_SHA256_X64
ARG GITLEAKS_SHA256_ARM64
ARG OSV_SCANNER_VERSION
ARG OSV_SCANNER_SHA256_X64
ARG OSV_SCANNER_SHA256_ARM64
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) gl_sha="${GITLEAKS_SHA256_X64}"; gl_asset=x64; osv_sha="${OSV_SCANNER_SHA256_X64}"; osv_asset=amd64;; \
      arm64) gl_sha="${GITLEAKS_SHA256_ARM64}"; gl_asset=arm64; osv_sha="${OSV_SCANNER_SHA256_ARM64}"; osv_asset=arm64;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1;; \
    esac; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_asset}.tar.gz" -o /tmp/gl.tgz; \
    echo "${gl_sha}  /tmp/gl.tgz" | sha256sum -c -; \
    tar -xzf /tmp/gl.tgz -C /usr/local/bin gitleaks; \
    curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${osv_asset}" -o /usr/local/bin/osv-scanner; \
    echo "${osv_sha}  /usr/local/bin/osv-scanner" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/osv-scanner; \
    rm -f /tmp/gl.tgz


# --- hardening ----------------------------------------------------------------
# Drop the fetcher: nothing at run time should carry curl. Non-root runtime
# identity matching the backend's default --user 1000:1000. The container
# rootfs is --read-only; /tmp and /work are tmpfs mounts from `docker run`.
RUN apt-get purge -y curl && apt-get autoremove -y \
    && useradd --uid 1000 --create-home --shell /bin/bash sandbox \
    && mkdir -p /work && chown 1000:1000 /work \
    && chmod 1777 /tmp

USER 1000:1000
ENV HOME=/work TMPDIR=/tmp GIT_PAGER=cat PAGER=cat TERM=dumb
# Never try to phone home.
ENV SEMGREP_SEND_METRICS=off BC_SKIP_MAPPING=TRUE CKV_SKIP_PACKAGE_UPDATE_CHECK=True

CMD ["sleep", "infinity"]
