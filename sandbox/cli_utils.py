"""Subprocess and naming seams shared by every sandbox backend: the
byte-budgeted separated-streams runner and the untrusted-agent-id sanitiser.
Living here gives tests ONE monkeypatch seam covering every backend.
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

# The exec output cap counts COMBINED stream bytes (stdout + stderr together,
# both here and in docker_channel's SDK reader). The >1 multiplier keeps a
# read loop from stopping mid-line at the exact cap.
BYTE_CAP_FACTOR = 4


def run_bounded_streams(argv: list[str], *, timeout: float, byte_cap: int,
                        env: dict[str, str] | None = None,
                        cwd: str | None = None
                        ) -> tuple[str, str, int | None, bool]:
    """Run a command capturing stdout/stderr SEPARATELY (subprocess.run's
    capture_output=True shape), still byte-budgeted.

    The cap counts COMBINED bytes (this runner and docker_channel's SDK
    reader share that accounting) so a chatty stderr cannot outspend a
    quiet stdout. Kills the process on cap exceed or deadline; returns
    (stdout, stderr, exit_code, truncated) and raises TimeoutExpired on
    the deadline path.
    """
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                            env=env, cwd=cwd)
    out_fd, err_fd = proc.stdout.fileno(), proc.stderr.fileno()
    state = {"total": 0, "truncated": False}
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []

    def _drain(fd: int, sink: list[bytes]) -> bool:
        """Read one ready fd; False when it hit EOF."""
        chunk = os.read(fd, 65536)
        if not chunk:
            return False
        room = byte_cap - state["total"]
        state["total"] += len(chunk)
        if room > 0:
            sink.append(chunk[:room])
        if room < len(chunk):
            state["truncated"] = True
        return True

    def _reap(kill: bool) -> None:
        try:
            if kill:
                proc.kill()
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    deadline = time.monotonic() + timeout
    open_fds = [out_fd, err_fd]
    try:
        while open_fds:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                _reap(kill=False)   # already killed: collect, then raise
                raise subprocess.TimeoutExpired(argv, timeout)
            ready, _, _ = select.select(open_fds, [], [], remaining)
            if not ready:
                proc.kill()
                _reap(kill=False)
                raise subprocess.TimeoutExpired(argv, timeout)
            for fd in ready:
                if not _drain(fd, out_chunks if fd == out_fd else err_chunks):
                    open_fds.remove(fd)
            if state["total"] > byte_cap:
                # Over budget: kill now so a chatty command cannot keep the
                # harness waiting.
                _reap(kill=True)
                break
    finally:
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except Exception:
                pass
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
    return (b"".join(out_chunks).decode("utf-8", errors="replace"),
            b"".join(err_chunks).decode("utf-8", errors="replace"),
            proc.returncode, state["truncated"])


def safe_slug(text: str | None, default: str = "agent") -> str:
    """Filesystem-safe per-agent scratch name: agent ids are untrusted and must
    never steer the scratch path (no ``..``, ``/``, leading dash)."""
    slug = re.sub(r"[^a-z0-9_.-]+", "_", str(text or "").strip().lower())
    slug = slug.strip("._-")
    return slug[:48] or default
