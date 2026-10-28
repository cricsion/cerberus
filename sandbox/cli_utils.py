"""Subprocess and naming seams shared by every sandbox backend: byte-budgeted
runners (merged and split-stream variants) and the untrusted-agent-id
sanitiser. Living here gives tests ONE monkeypatch seam covering every
backend.
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

# Multiplier >1 keeps a byte-budgeted read loop from stopping mid-line.
BYTE_CAP_FACTOR = 4


def run_cli(argv: list[str], *, timeout: float,
            env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """subprocess.run seam (monkeypatched in tests). Small fixed output."""
    return subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, errors="replace", timeout=timeout, env=env,
    )


def run_bounded(argv: list[str], *, timeout: float, byte_cap: int,
                env: dict[str, str] | None = None,
                cwd: str | None = None) -> tuple[str, int | None, bool]:
    """Run a command reading AT MOST byte_cap bytes of combined output.

    Kills the process on cap exceed so a chatty command cannot drive harness
    memory up; the in-container ``timeout`` is the backstop. Returns (output,
    exit_code, truncated).
    """
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL, env=env, cwd=cwd)
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


def run_bounded_streams(argv: list[str], *, timeout: float, byte_cap: int,
                        env: dict[str, str] | None = None,
                        cwd: str | None = None) -> tuple[str, str, int | None,
                                                         bool]:
    """``run_bounded`` with stdout/stderr separated (like
    ``subprocess.run(capture_output=True)`` had produced it).

    One combined byte budget across both streams: the budget protects harness
    memory; per-stream trimming stays the caller's decision. Kills the
    process on cap exceed or deadline exceed like ``run_bounded`` — and
    raises ``subprocess.TimeoutExpired`` on deadline for the same contract.
    Returns (stdout, stderr, exit_code, truncated).
    """
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, env=env, cwd=cwd)
    pipes = {proc.stdout.fileno(): [], proc.stderr.fileno(): []}
    by_pipe = {proc.stdout.fileno(): proc.stdout,
               proc.stderr.fileno(): proc.stderr}
    total = 0
    truncated = False
    capped = False
    deadline = time.monotonic() + timeout

    def kill_and_drain() -> None:
        nonlocal capped
        capped = True
        proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        # A dedicated reader may still hold buffered bytes; non-blocking read
        # picks up whatever is already there and skips the rest.
        for fd in list(pipes):
            stream = by_pipe[fd]
            try:
                os.set_blocking(fd, False)
                rest = stream.read(min(65536, max(0, byte_cap - total))) or b""
                if rest:
                    pipes[fd].append(rest)
            except (OSError, ValueError):
                pass

    open_fds = list(pipes)
    try:
        while open_fds:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                kill_and_drain()
                raise subprocess.TimeoutExpired(argv, timeout)
            ready, _, _ = select.select(open_fds, [], [], remaining)
            if not ready:
                kill_and_drain()
                raise subprocess.TimeoutExpired(argv, timeout)
            for fd in ready:
                chunk = os.read(fd, 65536)
                if not chunk:
                    open_fds.remove(fd)
                    continue
                if total + len(chunk) > byte_cap:
                    keep = max(0, byte_cap - total)
                    if keep:
                        pipes[fd].append(chunk[:keep])
                    total += len(chunk)
                    kill_and_drain()
                    break
                pipes[fd].append(chunk)
                total += len(chunk)
    except subprocess.TimeoutExpired:
        raise
    # Natural EOF on every stream (or a kill above): pick up the exit code.
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.stdout.close()
            proc.stderr.close()
        except Exception:
            pass
    decode = lambda fd: b"".join(pipes[fd]).decode("utf-8", errors="replace")
    return (decode(proc.stdout.fileno()), decode(proc.stderr.fileno()),
            proc.returncode, truncated or capped)


def safe_slug(text: str | None, default: str = "agent") -> str:
    """Filesystem-safe per-agent scratch name: agent ids are untrusted and must
    never steer the scratch path (no ``..``, ``/``, leading dash)."""
    slug = re.sub(r"[^a-z0-9_.-]+", "_", str(text or "").strip().lower())
    slug = slug.strip("._-")
    return slug[:48] or default
