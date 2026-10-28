# Scan sandbox image: everything the agent's shell needs at scan time, so the
# RUNNING container rarely needs egress (which `sandbox.network` controls:
# bridge = full egress by default, none = no egress; see
# harness/sandbox/docker_backend.py).
#
# Network is available HERE (build time) and only here for the pinned
# toolchain -- the build-then-pin posture from DESIGN_GUIDE.md step 2.
#
# BUILD VIA build.sh, which fills the pins from versions.env into
# --build-args and drives a stable BuildKit builder:
#   ./harness/sandbox/docker/build.sh cyber-sandbox:local
# A bare `docker build` without --build-arg fails closed at the first FROM:
# the python base is digest-pinned via PYTHON_BASE_IMAGE (versions.env), and
# an unpinned gray-area version is a failed build, never a soft fallback.
#
# Stage layout: the six release-binary fetches are independent dl-* stages
# (they run CONCURRENTLY in BuildKit's build DAG), each checksum-verified in
# place, and the final stage only COPYs the binaries out -- the fetch
# tooling, the /tmp residue, and curl's dl-time install never reach the
# image. atheris builds in its own stage; that stage's build toolchain is
# not copied out (only the small ASan runtime libs it preloads at fuzz time
# do). NB: the final image still carries clang because Debian's afl++ package
# hard-depends on clang-14/clang (afl-clang-fast instrumentation); see the
# RE/debug apt layer.
#
# Verify:
#   docker run --rm cyber-sandbox:local semgrep --version
#   docker run --rm cyber-sandbox:local gitleaks version
#   docker run --rm cyber-sandbox:local osv-scanner --version
#   docker run --rm cyber-sandbox:local checkov --version
#   # an offline rule scan must also work with NO network at run time
#   docker run --rm --network none cyber-sandbox:local \
#       semgrep scan --config /opt/scan-rules/harness --metrics off /repo

# Global scope: each stage redeclares the args it uses. These single-name
# lines also mirror build.sh's `for v in ...` build-arg loop (checked by
# tests/test_skills.py::test_every_build_script_arg_is_declared_in_dockerfile
# ); no defaults for the version pins -- empty pins must fail the build
# loudly, not silently build an unpinned image.
ARG TARGETARCH
# Digest-pinned base (manifest-list digest so amd64+arm64 both resolve).
ARG PYTHON_BASE_IMAGE
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
# The Dockerfile ARG defaults for Node/Go are OFF. build.sh overrides them
# from versions.env (the shipped file sets WITH_NODE=1). Each toolchain costs
# image size and startup time, so disable it in versions.env when not needed.
# NODE_VERSION must be >= 22.5: the codegraph CLI reads its index through
# node:sqlite, which does not exist on older Node (its package.json `engines`
# field understates this -- see the codegraph version pin below).
ARG WITH_NODE=0
ARG NODE_VERSION=22
# codegraph CLI pin (no default -- see the install layer below). Required by
# build.sh even when WITH_NODE=0, so a missing/empty pin fails the build loudly.
ARG CODEGRAPH_VERSION
ARG WITH_GO=0
ARG GO_VERSION
ARG PWNTOOLS_VERSION
ARG CAPSTONE_VERSION
ARG BINWALK_VERSION
ARG BINWALK_SHA256
ARG SQLMAP_VERSION
ARG ARJUN_VERSION
ARG MITMPROXY_VERSION
ARG FFUF_VERSION
ARG FFUF_SHA256_X64
ARG FFUF_SHA256_ARM64
ARG NUCLEI_VERSION
ARG NUCLEI_SHA256_X64
ARG NUCLEI_SHA256_ARM64
ARG HTTPX_VERSION
ARG HTTPX_SHA256_X64
ARG HTTPX_SHA256_ARM64
ARG KATANA_VERSION
ARG KATANA_SHA256_X64
ARG KATANA_SHA256_ARM64
ARG GAU_VERSION
ARG GAU_SHA256_X64
ARG GAU_SHA256_ARM64

# --- dl-* parallel downloader stages -----------------------------------------
# Shared fetcher base: apt+curl runs ONCE and is cached; per-tool stages
# below inherit it and run concurrently. Everything they produce is copied
# out in the final stage, so none of this is main-image content.
FROM ${PYTHON_BASE_IMAGE} AS dl-base
# Keep apt's downloaded debs in cache mounts (docker-clean would purge
# /var/cache/apt after every install otherwise), so any later cold layer
# (new pin, changed base) reuses packages instead of re-downloading them.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean \
 && echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' \
      > /etc/apt/apt.conf.d/keep-cache \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        binutils ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*

# opengrep: install the pinned release binary, sha256-verified like the other
# release artifacts below (building from the source tree does not produce an
# `opengrep` entry point -- the repo's pip install yields only
# semgrep_pre_commit_package). Per-arch asset, so it runs natively on both
# amd64 and arm64 instead of under qemu.
FROM dl-base AS dl-opengrep
ARG TARGETARCH
ARG OPENGREP_VERSION OPENGREP_SHA256_X64 OPENGREP_SHA256_ARM64
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
FROM dl-base AS dl-bearer
ARG TARGETARCH
ARG BEARER_VERSION BEARER_SHA256_X64 BEARER_SHA256_ARM64
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sha="${BEARER_SHA256_X64}"; asset="bearer_${BEARER_VERSION}_linux_amd64.tar.gz";; \
      arm64) sha="${BEARER_SHA256_ARM64}"; asset="bearer_${BEARER_VERSION}_linux_arm64.tar.gz";; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1;; \
    esac; \
    curl -fsSL "https://github.com/Bearer/bearer/releases/download/v${BEARER_VERSION}/${asset}" -o /tmp/bearer.tar.gz; \
    echo "${sha}  /tmp/bearer.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/bearer.tar.gz -C /usr/local/bin bearer; \
    strip /usr/local/bin/bearer; \
    rm -f /tmp/bearer.tar.gz; \
    bearer --version

# trufflehog: verified-secret detection incl. git history. Agents run it on
# the current tree by default (--no-update): verified findings are high
# confidence, unverified are lower-confidence leads for gitleaks to confirm.
FROM dl-base AS dl-trufflehog
ARG TARGETARCH
ARG TRUFFLEHOG_VERSION TRUFFLEHOG_SHA256_X64 TRUFFLEHOG_SHA256_ARM64
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
FROM dl-base AS dl-gosec
ARG TARGETARCH
ARG GOSEC_VERSION GOSEC_SHA256_X64 GOSEC_SHA256_ARM64
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sha="${GOSEC_SHA256_X64}"; asset="gosec_${GOSEC_VERSION}_linux_amd64.tar.gz";; \
      arm64) sha="${GOSEC_SHA256_ARM64}"; asset="gosec_${GOSEC_VERSION}_linux_arm64.tar.gz";; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1;; \
    esac; \
    curl -fsSL "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/${asset}" -o /tmp/gosec.tar.gz; \
    echo "${sha}  /tmp/gosec.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gosec.tar.gz -C /usr/local/bin gosec; \
    strip /usr/local/bin/gosec; \
    rm -f /tmp/gosec.tar.gz; \
    gosec --version

# web-tier binaries (ffuf/nuclei/httpx/katana/gau): one stage, same
# release-tarball + checksum recipe, per-arch assets.
FROM dl-base AS dl-webkit
ARG TARGETARCH
ARG FFUF_VERSION FFUF_SHA256_X64 FFUF_SHA256_ARM64
ARG NUCLEI_VERSION NUCLEI_SHA256_X64 NUCLEI_SHA256_ARM64
ARG HTTPX_VERSION HTTPX_SHA256_X64 HTTPX_SHA256_ARM64
ARG KATANA_VERSION KATANA_SHA256_X64 KATANA_SHA256_ARM64
ARG GAU_VERSION GAU_SHA256_X64 GAU_SHA256_ARM64
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) garch=amd64;; \
      arm64) garch=arm64;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1;; \
    esac; \
    if [ "${garch}" = "amd64" ]; then \
      ffuf_sha="${FFUF_SHA256_X64}"; nuclei_sha="${NUCLEI_SHA256_X64}"; \
      httpx_sha="${HTTPX_SHA256_X64}"; katana_sha="${KATANA_SHA256_X64}"; \
      gau_sha="${GAU_SHA256_X64}"; \
    else \
      ffuf_sha="${FFUF_SHA256_ARM64}"; nuclei_sha="${NUCLEI_SHA256_ARM64}"; \
      httpx_sha="${HTTPX_SHA256_ARM64}"; katana_sha="${KATANA_SHA256_ARM64}"; \
      gau_sha="${GAU_SHA256_ARM64}"; \
    fi; \
    curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${garch}.tar.gz" -o /tmp/ffuf.tgz; \
    echo "${ffuf_sha}  /tmp/ffuf.tgz" | sha256sum -c -; \
    tar -xzf /tmp/ffuf.tgz -C /usr/local/bin ffuf; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${garch}.zip" -o /tmp/nuclei.zip; \
    echo "${nuclei_sha}  /tmp/nuclei.zip" | sha256sum -c -; \
    unzip -o -q /tmp/nuclei.zip -d /tmp/nuclei-out nuclei; \
    mv /tmp/nuclei-out/nuclei /usr/local/bin/nuclei; \
    curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${garch}.zip" -o /tmp/httpx.zip; \
    echo "${httpx_sha}  /tmp/httpx.zip" | sha256sum -c -; \
    unzip -o -q /tmp/httpx.zip -d /tmp/httpx-out httpx; \
    mv /tmp/httpx-out/httpx /usr/local/bin/httpx; \
    curl -fsSL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${garch}.zip" -o /tmp/katana.zip; \
    echo "${katana_sha}  /tmp/katana.zip" | sha256sum -c -; \
    unzip -o -q /tmp/katana.zip -d /tmp/katana-out katana; \
    mv /tmp/katana-out/katana /usr/local/bin/katana; \
    curl -fsSL "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_${garch}.tar.gz" -o /tmp/gau.tgz; \
    echo "${gau_sha}  /tmp/gau.tgz" | sha256sum -c -; \
    tar -xzf /tmp/gau.tgz -C /usr/local/bin gau; \
    chmod 0755 /usr/local/bin/ffuf /usr/local/bin/nuclei /usr/local/bin/httpx \
             /usr/local/bin/katana /usr/local/bin/gau; \
    rm -rf /tmp/ffuf.tgz /tmp/nuclei.zip /tmp/nuclei-out /tmp/httpx.zip \
           /tmp/httpx-out /tmp/katana.zip /tmp/katana-out /tmp/gau.tgz; \
    command -v ffuf nuclei httpx katana gau

# gitleaks + osv-scanner: release binaries, checksum-verified at build.
# (A mismatched ARG SHA fails the build -- fail closed, not silently.)
# Per-arch assets: an x64-only binary crashes under qemu on arm64 hosts
# (Go runtime fault), so each tool takes the binary for TARGETARCH.
FROM dl-base AS dl-gitleaks-osv
ARG TARGETARCH
ARG GITLEAKS_VERSION GITLEAKS_SHA256_X64 GITLEAKS_SHA256_ARM64
ARG OSV_SCANNER_VERSION OSV_SCANNER_SHA256_X64 OSV_SCANNER_SHA256_ARM64
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

# binwalk: firmware analysis tool source tarball, sha256-verified at build.
FROM dl-base AS dl-binwalk
ARG BINWALK_VERSION BINWALK_SHA256
RUN set -eu; \
    curl -fsSL "https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v${BINWALK_VERSION}.tar.gz" -o /tmp/binwalk.tar.gz; \
    echo "${BINWALK_SHA256}  /tmp/binwalk.tar.gz" | sha256sum -c -; \
    mkdir -p /usr/local/src && mv /tmp/binwalk.tar.gz /usr/local/src/binwalk.tar.gz

# --- atheris builder stage -----------------------------------------------------
# atheris publishes x86_64 wheels only; on arm64 it compiles from source via
# clang. This stage isolates that build: its compiler toolchain is not copied
# out, and the final image keeps only the small ASan runtime (libclang-rt-dev)
# that instrumented targets preload at fuzz time. (clang is nevertheless
# present at run time as afl++'s hard Debian dependency -- see the RE/debug
# apt layer -- so this stage is isolation, not a clang-free image.) With the
# pip cache mount below, the arm64 compile happens at most once per pin bump.
FROM ${PYTHON_BASE_IMAGE} AS atheris-build
ARG ATHERIS_VERSION
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential clang libclang-rt-dev \
 && rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    CLANG_BIN=/usr/bin/clang pip install --no-compile --target /atheris \
        "atheris==${ATHERIS_VERSION}" \
 && PYTHONPATH=/atheris python3 -c "import atheris"

# --- mitmproxy builder stage ---------------------------------------------------
# Isolated install tree (/opt/mitmproxy), built concurrently via BuildKit DAG.
FROM ${PYTHON_BASE_IMAGE} AS mitmproxy-build
ARG MITMPROXY_VERSION
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip install --no-compile --target /opt/mitmproxy \
        "mitmproxy==${MITMPROXY_VERSION}" \
        "bcrypt<5"

# --- wheel builder stage -------------------------------------------------------
# Pre-builds binary wheels for sdists (capstone 4.0.2 has no aarch64 wheel on PyPI)
# concurrently in the BuildKit DAG. The main distro stage only unpacks the .whl.
FROM ${PYTHON_BASE_IMAGE} AS wheel-builder
ARG CAPSTONE_VERSION
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
 && rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip wheel --no-deps --no-cache-dir "capstone==${CAPSTONE_VERSION}" -w /wheels

# --- codegraph builder stage ---------------------------------------------------
# Isolated Node/codegraph install: runs concurrently, strips node headers (65MB)
# and symlinks the bundled node binary (116MB) to /usr/bin/node.
FROM ${PYTHON_BASE_IMAGE} AS codegraph-build
ARG WITH_NODE=0
ARG NODE_VERSION=22
ARG CODEGRAPH_VERSION
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=cache,target=/root/.npm,sharing=locked \
    mkdir -p /out/usr/bin /out/usr/lib \
 && if [ "$WITH_NODE" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
     && curl -fsSL "https://deb.nodesource.com/setup_${NODE_VERSION}.x" -o /tmp/node-setup.sh \
     && bash /tmp/node-setup.sh \
     && apt-get install -y --no-install-recommends nodejs \
     && npm install -g --no-cache "@colbymchenry/codegraph@${CODEGRAPH_VERSION}" \
     && rm -rf /usr/include/node /tmp/* \
     && for d in /usr/lib/node_modules/@colbymchenry/codegraph/node_modules/@colbymchenry/codegraph-linux-*; do \
            if [ -f "$d/node" ]; then ln -sf /usr/bin/node "$d/node"; fi; \
        done \
     && cp -a /usr/bin/node /usr/bin/npm /usr/bin/npx /out/usr/bin/ \
     && if [ -e /usr/bin/corepack ]; then cp -a /usr/bin/corepack /out/usr/bin/; fi \
     && cp -a /usr/lib/node_modules /out/usr/lib/ \
     && if [ -e /usr/bin/codegraph ]; then cp -a /usr/bin/codegraph /out/usr/bin/; fi \
     && if [ -e /usr/local/bin/codegraph ]; then cp -a /usr/local/bin/codegraph /out/usr/bin/; fi; \
    fi

# --- main image ----------------------------------------------------------------
FROM ${PYTHON_BASE_IMAGE} AS distro
ARG TARGETARCH
ARG SEMGREP_VERSION BANDIT_VERSION CHECKOV_VERSION FLAWFINDER_VERSION NJSSCAN_VERSION
ARG PWNTOOLS_VERSION CAPSTONE_VERSION BINWALK_VERSION SQLMAP_VERSION ARJUN_VERSION MITMPROXY_VERSION
ARG WITH_NODE NODE_VERSION CODEGRAPH_VERSION WITH_GO GO_VERSION

# --- OS layer ------------------------------------------------------------------
# git (repo context/history), build-essential (native wheels + PoC builds),
# libclang-rt-dev ships the ASan runtime that atheris's instrumented targets
# preload (the atheris build's clang use is isolated in atheris-build; note
# afl++ below pulls clang-14/clang into this image as a hard dependency); jq:
# agent JSON slicing of scanner output; curl exists here only for the opt-in
# Node lane's setup script -- it is purged before the image is sealed.
# Least-volatile-first: nothing below this layer can invalidate it except a
# base-image change.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean \
 && echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' \
      > /etc/apt/apt.conf.d/keep-cache \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        jq \
        libclang-rt-dev \
 && rm -rf /var/lib/apt/lists/*

# --- Node + codegraph CLI (staged concurrently in codegraph-build) ------------
COPY --from=codegraph-build /out/ /
RUN if [ "$WITH_NODE" = "1" ]; then \
        command -v node npm codegraph \
     && codegraph version; \
    fi

# --- Go (opt-in, official tarball; bookworm's golang is too old) ------------
RUN if [ "$WITH_GO" = "1" ]; then \
        case "${TARGETARCH}" in \
          amd64) go_arch=amd64;; \
          arm64) go_arch=arm64;; \
          *) echo "unsupported TARGETARCH for Go: ${TARGETARCH}" >&2; exit 1;; \
        esac; \
        curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz" \
        | tar -xz -C /usr/local \
        && if [ -d /usr/local/go/bin ]; then ln -sf /usr/local/go/bin/* /usr/local/bin/; fi; \
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
# (verification fuzzing), flawfinder (C/C++). NEVER installed on the host: these
# are image-only, so the only consumer is the in-sandbox agent.
#
# njsscan: Node.js security rules. Rides the SHARED pip line below (like
# bandit/flawfinder): the image semgrep pin (see versions.env) IS njsscan's
# own pin — njsscan 1.0.1 hard-pins semgrep==1.172.0, verbatim — so a single
# shared dependency tree serves both tools and the isolated /opt/njsscan
# tree + wrapper script of the previous layout are gone. At scan time
# njsscan does NOT import semgrep in-process: it shells out to the `semgrep`
# binary on PATH (via libsast), which resolves to this shared install.

# Python scanners + test runners (pip resolves interpreter-compatible wheels).
# setuptools is pinned <81 on purpose: 84 removed the legacy pkg_resources
# module, which semgrep's opentelemetry chain imports at import time.
# atheris builds in the `atheris-build` stage above (its build toolchain is
# not copied out) and merges into site-packages at the COPY block below.
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip install --no-compile \
        "bandit==${BANDIT_VERSION}" \
        "checkov==${CHECKOV_VERSION}" \
        "flawfinder==${FLAWFINDER_VERSION}" \
        "njsscan==${NJSSCAN_VERSION}" \
        "semgrep==${SEMGREP_VERSION}" \
        "setuptools<81" \
        coverage pytest \
    && command -v njsscan

# --- RE/debug lane, apt half ---------------------------------------------------
# Split from the pip half (was one 648MB RUN): a TOC/pin bump on either side
# no longer re-runs the other's ~600MB of work. Each layer keys on its own
# ARGs only. Exotic qemu emulators pruned (keeping x86 and arm targets).
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
 && apt-get install -y --no-install-recommends \
        afl++ \
        binutils \
        dnsutils \
        file \
        gdb \
        netcat-openbsd \
        qemu-user-static \
        unzip \
        valgrind \
 && rm -rf /var/lib/apt/lists/* \
 && find /usr/bin -name 'qemu-*-static' \
        ! -name 'qemu-x86_64-static' \
        ! -name 'qemu-i386-static' \
        ! -name 'qemu-arm-static' \
        ! -name 'qemu-aarch64-static' \
        -delete \
 && for t in gdb afl-fuzz valgrind objdump; do command -v "$t" >/dev/null || exit 1; done

# --- RE/debug lane, pip half ---------------------------------------------------
# Pre-built capstone wheel copied from wheel-builder stage: instant wheel unpack.
# binwalk rides a pinned, sha256-verified release archive from dl-binwalk.
COPY --from=dl-binwalk /usr/local/src/binwalk.tar.gz /tmp/binwalk.tar.gz
COPY --from=wheel-builder /wheels/ /tmp/wheels/
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip install --no-compile \
        --find-links=/tmp/wheels \
        "capstone==${CAPSTONE_VERSION}" \
        "pwntools==${PWNTOOLS_VERSION}" \
        /tmp/binwalk.tar.gz \
 && rm -rf /tmp/binwalk.tar.gz /tmp/wheels \
 && command -v binwalk

ARG SQLMAP_VERSION
ARG ARJUN_VERSION
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip install --no-compile \
        "arjun==${ARJUN_VERSION}" \
        "sqlmap==${SQLMAP_VERSION}" \
    && command -v sqlmap arjun

COPY --from=mitmproxy-build /opt/mitmproxy /opt/mitmproxy
RUN printf '%s\n' \
        '#!/bin/sh' \
        '# mitmdump runner: isolated deps (own mitmproxy tree), pinned deps untouched.' \
        'exec env PYTHONPATH=/opt/mitmproxy python3 /opt/mitmproxy/bin/mitmdump "$@"' \
        > /usr/local/bin/mitmdump \
 && chmod 0755 /usr/local/bin/mitmdump \
 && command -v mitmdump \
 && env PYTHONPATH=/opt/mitmproxy python3 -c "import mitmproxy"

# --- binaries from the dl-* stages + the atheris merge ------------------------
# COPY --from preserves exec modes, so the checksum-verified, chmod-performed
# binaries arrive exactly as the dl stages produced them.
COPY --from=dl-opengrep /usr/local/bin/opengrep /usr/local/bin/opengrep
COPY --from=dl-bearer /usr/local/bin/bearer /usr/local/bin/bearer
COPY --from=dl-trufflehog /usr/local/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=dl-gosec /usr/local/bin/gosec /usr/local/bin/gosec
COPY --from=dl-webkit /usr/local/bin/ffuf /usr/local/bin/ffuf
COPY --from=dl-webkit /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=dl-webkit /usr/local/bin/httpx /usr/local/bin/httpx
COPY --from=dl-webkit /usr/local/bin/katana /usr/local/bin/katana
COPY --from=dl-webkit /usr/local/bin/gau /usr/local/bin/gau
COPY --from=dl-gitleaks-osv /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=dl-gitleaks-osv /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner
# atheris: the builder stage's --target tree (zero-dependency package) merges
# onto the shared site-packages (the distro interpreter's package root — NOT
# dist-packages, which is only for Debian's own system python).
COPY --from=atheris-build /atheris/ /usr/local/lib/python3.11/site-packages/

# --- hardening ----------------------------------------------------------------
# Drop the fetcher: nothing at run time should carry curl. Non-root runtime
# identity matching the backend's default --user 1000:1000. The container
# rootfs is --read-only; /tmp and /work are tmpfs mounts from `docker run`.
RUN apt-get purge -y curl && apt-get autoremove -y \
    && useradd --uid 1000 --create-home --shell /bin/bash sandbox \
    && mkdir -p /work && chown 1000:1000 /work \
    && chmod 1777 /tmp \
    && find /usr/local/lib/python3.11 -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true \
    && find /usr/local/lib/python3.11 -type f -name "*.pyc" -delete 2>/dev/null || true

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
# These two COPY layers are the LAST content layers, so a skills/rules edit
# invalidates seconds of build, not minutes of downloads.
COPY harness/skills /opt/harness-skills

USER 1000:1000
ENV HOME=/work TMPDIR=/tmp GIT_PAGER=cat PAGER=cat TERM=dumb
# Never try to phone home. SEMGREP_ENABLE_VERSION_CHECK=0 is load-bearing for
# offline scans: under `--network none`, semgrep 1.172's version check stalls
# ~100s before scanning, blowing the backend's 120s default command timeout.
# Disabling it is also the right telemetry posture (it is a phone-home).
ENV SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
    BC_SKIP_MAPPING=TRUE CKV_SKIP_PACKAGE_UPDATE_CHECK=True
# codegraph hygiene (D9): no daemon, no telemetry, no update check -- the CLI is
# only ever the indexer lane's subprocess. Mirrors the metrics/update-check
# switches above; `CODEGRAPH_NO_DAEMON` also keeps it from spawning a background
# process in the read-only, network-restricted sandbox.
ENV CODEGRAPH_NO_DAEMON=1 CODEGRAPH_TELEMETRY=0 DO_NOT_TRACK=1 CODEGRAPH_NO_UPDATE_CHECK=1
# No bytecode writes: the runtime rootfs is read-only and /work is a tmpfs.
ENV PYTHONDONTWRITEBYTECODE=1

CMD ["sleep", "infinity"]
