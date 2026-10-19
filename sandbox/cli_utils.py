"""Subprocess and naming seams shared by every sandbox backend: a byte-budgeted
runner, a small-output runner, and the untrusted-agent-id sanitiser. Living
here gives tests ONE monkeypatch seam covering every backend.
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


def run_cli(argv: list[str], *, timeout: float,
            env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """subprocess.run seam (monkeypatched in tests). Small fixed output."""
    return subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, errors="replace", timeout=timeout, env=env,
    )


def run_bounded(argv: list[str], *, timeout: float, byte_cap: int,
                env: dict[str, str] | None = None
                ) -> tuple[str, int | None, bool]:
    """Run a command reading AT MOST byte_cap bytes of combined output.

    Kills the process on cap exceed so a chatty command cannot drive harness
    memory up; the in-container ``timeout`` is the backstop. Returns (output,
    exit_code, truncated).
    """
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL, env=env)
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
    """Filesystem-safe per-agent scratch name: agent ids are untrusted and must
    never steer the scratch path (no ``..``, ``/``, leading dash)."""
    slug = re.sub(r"[^a-z0-9_.-]+", "_", str(text or "").strip().lower())
    slug = slug.strip("._-")
    return slug[:48] or default
