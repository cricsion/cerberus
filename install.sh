#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-${ROOT_DIR}/.venv}"
INSTALL_DEV=0

usage() {
    cat <<'EOF'
Usage: ./install.sh [--dev] [--help]

Create/update a virtual environment, install Cerberus in editable mode, and
build and smoke-test the Docker scan-toolchain image.
Options:
  --dev     Also install development dependencies (pytest and ruff).
  --help    Show this help message.

Set VENV_DIR to choose a different virtual-environment path.
Requires Python 3.12, Docker with Buildx, and sandbox/docker/versions.env.
EOF
}

while (($#)); do
    case "$1" in
        --dev) INSTALL_DEV=1 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if ! command -v python3.12 >/dev/null 2>&1; then
    echo "Python 3.12 is required but python3.12 was not found on PATH." >&2
    echo "Install Python 3.12, then re-run ./install.sh." >&2
    exit 1
fi

PYTHON_VERSION="$(python3.12 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [[ "$PYTHON_VERSION" != "3.12" ]]; then
    echo "Expected Python 3.12, found ${PYTHON_VERSION}." >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required to build the Cerberus scan-toolchain image." >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed but its daemon is not available. Start Docker and retry." >&2
    exit 1
fi
if ! docker buildx version >/dev/null 2>&1; then
    echo "Docker Buildx is required to build the scan-toolchain image." >&2
    exit 1
fi
if [[ ! -f "${ROOT_DIR}/sandbox/docker/versions.env" ]]; then
    echo "Missing sandbox/docker/versions.env." >&2
    echo "Create it from sandbox/docker/versions.env.example and review the version pins." >&2
    exit 1
fi

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    echo "[install] Creating virtual environment at ${VENV_DIR}"
    python3.12 -m venv "$VENV_DIR"
fi

if [[ "$INSTALL_DEV" == 1 ]]; then
    echo "[install] Installing Cerberus and development dependencies"
    "${VENV_DIR}/bin/python" -m pip install -e "${ROOT_DIR}[dev]"
else
    echo "[install] Installing Cerberus"
    "${VENV_DIR}/bin/python" -m pip install -e "$ROOT_DIR"
fi

echo "[install] Verifying CLI"
"${VENV_DIR}/bin/cerberus" --help >/dev/null
echo "[install] Building and smoke-testing Docker scan-toolchain image"
bash "${ROOT_DIR}/sandbox/docker/build.sh"
echo "Installed successfully. Activate the environment with:"
echo "  source \"${VENV_DIR}/bin/activate\""
