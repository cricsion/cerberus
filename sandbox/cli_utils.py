"""Subprocess and naming seams shared by every sandbox backend.

Nothing here knows about docker or sbx: these are the two ways this package
runs a CLI -- one reading AT MOST a byte budget, one collecting a small fixed
output -- plus the sanitiser for untrusted agent ids. They live in their own
module so ONE monkeypatched seam covers every backend, and so neither backend
module is the accidental owner of shared code (sbx used to import these from
docker_backend, which made docker look like the base).
"""
from __future__ import annotations

import os
import re
import select
import subprocess
import time

# Tag an exec's command line so the client-hang backstop kills ONLY this
# exec's shell, never a concurrent agent's (the sandbox is shared).
EXEC_TAG = "cyber_exec_tag"


def run_cli(argv: list[str], *, timeout: float) -> subprocess.CompletedProcess:
    """subprocess.run seam (monkeypatched in tests). Small fixed output."""
    return subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, errors="replace", timeout=timeout,
    )


def run_bounded(argv: list[str], *, timeout: float, byte_cap: int
                ) -> tuple[str, int | None, bool]:
    """Run a command reading AT MOST byte_cap bytes of combined output.

    A PIPE with no cap means a chatty command buffers its whole output in
    THIS process before any check: one `python -c 'while True: print(...)''`
    for the full command timeout drives harness RSS into the GBs (measured
    ~380 MB/s), times `concurrency` parallel agents. Reading in chunks and
    stopping at the cap turns that into a bounded, truncated result. The
    process is killed on cap exceed (in-container `timeout` is the
    backstop; this is the harness-side backstop).

    Returns (output, exit_code, truncated).
    """
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL)
    fd = proc.stdout.fileno()
    chunks: list[bytes] = []
    total = 0
    truncated = False
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                raise subprocess.TimeoutExpired(argv, timeout)
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            if total + len(chunk) > byte_cap:
                keep = byte_cap - total
                if keep > 0:
                    chunks.append(chunk[:keep])
                total += len(chunk)
                truncated = True
                proc.kill()
                break
            chunks.append(chunk)
            total += len(chunk)
    except subprocess.TimeoutExpired:
        proc.kill()
        # Give the kill a moment, then collect whatever is left.
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        try:
            rest = proc.stdout.read() or b""
        except Exception:
            rest = b""
        chunks.append(rest)
        raise
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.stdout.close()
        except Exception:
            pass
    return (b"".join(chunks).decode("utf-8", errors="replace"),
            proc.returncode, truncated)


def safe_slug(text: str | None, default: str = "agent") -> str:
    """Filesystem-safe per-agent scratch name.

    Agent ids carry unit names from the partitioner model (untrusted text):
    they must never be able to steer the scratch path (no ``..``, no ``/``,
    no leading dash) inside the shared sandbox.
    """
    slug = re.sub(r"[^a-z0-9_.-]+", "_", str(text or "").strip().lower())
    slug = slug.strip("._-")
    return slug[:48] or default
