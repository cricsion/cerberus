"""Mechanical PoC / Reproduction Test Stamper and Regen Loop.

Executes direct-call in-process reproduction tests inside the sandbox container,
checks the Two-Sided Sentinel Contract on stdout strictly, prevents reflected
tracebacks from masquerading as verified, and stamps immutable mechanical receipts.
"""
from __future__ import annotations

import base64
import copy
import logging
import os
import re
import threading
from pathlib import Path
from typing import Any

from cerberus.config import as_bool
from cerberus.paths import to_repo_relative
from cerberus.schemas import PocItem, PocReceipt

_logger = logging.getLogger(__name__)

# Mutex serializing sandbox executions across concurrent worker threads to
# prevent port clashes, loopback socket races, and tmpfs state pollution.
_SANDBOX_EXEC_LOCK = threading.Lock()

DEFAULT_SENTINEL_RE = re.compile(r"^\[POC_PROVEN(?::[a-zA-Z0-9_\-]+)?\]\r?$", re.MULTILINE)
DEFAULT_CONTROL_RE = re.compile(r"^\[POC_CONTROL_PASSED(?::[a-zA-Z0-9_\-]+)?\]\r?$", re.MULTILINE)
SHARED_POC_DIR = "/work/_shared/poc"
MAX_SCRIPT_BYTES = 256 * 1024

RUNNER_BY_EXT: dict[str, str] = {
    ".py": "python3",
    ".js": "node",
    ".cjs": "node",
    ".mjs": "node",
    ".ts": "tsx",
    ".go": "go run",
    ".sh": "bash",
    ".bash": "bash",
    ".rb": "ruby",
    ".php": "php",
}

LANGUAGE_TO_EXT: dict[str, str] = {
    "python": ".py",
    "py": ".py",
    "javascript": ".js",
    "js": ".js",
    "node": ".js",
    "nodejs": ".js",
    "typescript": ".ts",
    "ts": ".ts",
    "go": ".go",
    "golang": ".go",
    "bash": ".sh",
    "sh": ".sh",
    "shell": ".sh",
    "ruby": ".rb",
    "rb": ".rb",
    "php": ".php",
}


def _safe_id(raw_id: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in str(raw_id).strip())
    cleaned = cleaned.strip("._-")
    return cleaned or "poc"


def _resolve_filename(poc: dict, script: str) -> str:
    """Resolve script filename from agent poc metadata (filename, language, or shebang).

    Accepts any filename or language chosen by the agent without restriction.
    """
    raw_fname = str(poc.get("filename") or "").strip()
    if raw_fname:
        base = Path(raw_fname).name
        ext = "".join(c for c in Path(base).suffix if c.isalnum() or c == ".").lower()
        safe_stem = _safe_id(Path(base).stem)
        return f"{safe_stem}{ext}" if ext else safe_stem

    lang = str(poc.get("language") or "").strip().lower()
    if lang in LANGUAGE_TO_EXT:
        return f"poc{LANGUAGE_TO_EXT[lang]}"
    elif lang:
        cleaned_lang = "".join(c for c in lang if c.isalnum())
        if cleaned_lang:
            return f"poc.{cleaned_lang}"

    # Check shebang line at start of script
    first_line = script.split("\n", 1)[0].strip() if script else ""
    if first_line.startswith("#!"):
        if "node" in first_line:
            return "poc.js"
        if "go" in first_line:
            return "poc.go"
        if "bash" in first_line or "sh" in first_line:
            return "poc.sh"
        if "ruby" in first_line:
            return "poc.rb"
        if "php" in first_line:
            return "poc.php"
        if "perl" in first_line:
            return "poc.pl"
        if "lua" in first_line:
            return "poc.lua"

    return "poc.py"


def _extract_stdout(res: Any) -> str:
    """Extract stdout across both local backends and Docker ExecuteResponse (.output)."""
    if hasattr(res, "stdout") and res.stdout is not None:
        return str(res.stdout)
    if hasattr(res, "output") and res.output is not None:
        return str(res.output)
    return ""


def _extract_stderr(res: Any) -> str:
    if hasattr(res, "stderr") and res.stderr is not None:
        return str(res.stderr)
    return ""


def _extract_exit_code(res: Any) -> int:
    """Extract exit code; defaults to -1 (never success) if missing or None."""
    code = getattr(res, "exit_code", -1)
    return -1 if code is None else int(code)


def materialize_poc(finding: dict, backend: Any, run_id: str | None = None,
                    repo_path: str | Path | None = None) -> tuple[Path | None, str | None]:
    """Write repro script to host persistent storage and container shared tmpfs.

    Host path: .cerberus/<run_id>/scratch/poc/<finding_id>/poc.py
    Container path: /work/_shared/poc/<finding_id>/poc.py
    """
    poc = finding.get("poc")
    if hasattr(poc, "model_dump"):
        poc = poc.model_dump()
    if not isinstance(poc, dict):
        return None, None
    script = poc.get("script") or poc.get("code") or ""
    if not isinstance(script, str) or not script.strip():
        return None, None

    script_bytes = script.encode("utf-8")
    if len(script_bytes) > MAX_SCRIPT_BYTES:
        _logger.warning("PoC script exceeds size limit (%d bytes)", len(script_bytes))
        return None, None

    fid = _safe_id(finding.get("id") or "finding")
    rid = _safe_id(run_id or os.environ.get("RUN_ID") or "latest")
    fname = _resolve_filename(poc, script)

    # 1. Host persistent path (confined under .cerberus)
    host_repo = Path(repo_path or os.environ.get("TARGET_REPO") or ".").resolve()
    host_poc_dir = host_repo / ".cerberus" / rid / "scratch" / "poc" / fid
    host_file = host_poc_dir / fname
    try:
        host_poc_dir.mkdir(parents=True, exist_ok=True)
        host_file.write_text(script, encoding="utf-8")
    except Exception as exc:
        _logger.warning("Failed to persist PoC script to host %s: %s", host_file, exc)

    # 2. In-container path (survives phase reset under /work/_shared)
    container_file = f"{SHARED_POC_DIR}/{fid}/{fname}"
    if backend is not None and hasattr(backend, "execute"):
        try:
            b64 = base64.b64encode(script_bytes).decode("ascii")
            setup_cmd = (
                f"mkdir -p {SHARED_POC_DIR}/{fid} && "
                f"echo {b64} | base64 -d > {container_file} && "
                f"chmod +x {container_file}"
            )
            backend.execute(setup_cmd, timeout=15)
        except Exception as exc:
            _logger.warning("Failed to materialize PoC into container %s: %s", container_file, exc)

    return host_file, container_file


def stamp_receipts(findings: list[dict], backend: Any, cfg: dict | None = None,
                   run_id: str | None = None) -> list[dict]:
    """Execute candidate reproduction tests and stamp mechanical execution receipts.

    Rules:
    - Exit code must be 0 and stdout must match DEFAULT_SENTINEL_RE.
    - Control run (--control) must exit 0 and emit DEFAULT_CONTROL_RE.
    - Stamped receipts are ground truth; LLMs cannot alter or bypass receipts.
    """
    if not findings or backend is None:
        return findings

    cfg = cfg or {}
    poc_cfg = cfg.get("poc") if isinstance(cfg.get("poc"), dict) else {}
    if not as_bool(poc_cfg.get("enabled", True)):
        return findings

    repro_runs = max(1, int(poc_cfg.get("repro_runs", 3)))
    timeout = max(5, int(poc_cfg.get("timeout", 600)))

    with _SANDBOX_EXEC_LOCK:
        for f in findings:
            if not isinstance(f, dict):
                continue
            poc = f.get("poc")
            if hasattr(poc, "model_dump"):
                poc = poc.model_dump()
            if not isinstance(poc, dict) or not (poc.get("script") or poc.get("code")):
                continue

            host_path, container_path = materialize_poc(f, backend, run_id=run_id)
            if not container_path:
                continue

            # Universal Execution:
            # 1. If agent provided a verified command referencing the script, use it
            # 2. Else if script has a shebang (#!/...), execute directly via container chmod +x
            # 3. Else if extension matches a known interpreter, invoke that interpreter
            # 4. Else fallback to direct execution
            script_text = poc.get("script") or poc.get("code") or ""
            first_line = script_text.split("\n", 1)[0].strip() if script_text else ""
            ext = Path(container_path).suffix.lower()
            agent_cmd = str(poc.get("command") or "").strip()

            if agent_cmd and (container_path in agent_cmd or Path(container_path).name in agent_cmd):
                cmd = agent_cmd
            elif first_line.startswith("#!"):
                cmd = container_path
            elif ext in RUNNER_BY_EXT:
                cmd = f"{RUNNER_BY_EXT[ext]} {container_path}"
            else:
                cmd = container_path

            successes = 0
            outputs: list[str] = []
            for _ in range(repro_runs):
                try:
                    res = backend.execute(cmd, timeout=timeout)
                    stdout = _extract_stdout(res)
                    stderr = _extract_stderr(res)
                    exit_code = _extract_exit_code(res)
                    combined = f"STDOUT:\n{stdout[:1000]}\nSTDERR:\n{stderr[:1000]}"
                    outputs.append(combined)

                    # Stdout-only line-anchored match coupled with zero exit code
                    if exit_code == 0 and DEFAULT_SENTINEL_RE.search(stdout):
                        successes += 1
                except Exception as exc:
                    outputs.append(f"EXECUTION_ERROR: {exc}")

            # Control check execution: strictly validated flag
            raw_control = str(poc.get("control") or "--control").strip()
            control_flag = raw_control if re.match(r"^--[a-zA-Z0-9_\-]+$", raw_control) else "--control"
            control_cmd = f"{cmd} {control_flag}"
            control_status: str = "skipped"

            try:
                cres = backend.execute(control_cmd, timeout=timeout)
                c_stdout = _extract_stdout(cres)
                c_stderr = _extract_stderr(cres)
                c_exit = _extract_exit_code(cres)
                outputs.append(f"CONTROL STDOUT:\n{c_stdout[:1000]}\nCONTROL STDERR:\n{c_stderr[:1000]}")

                if DEFAULT_SENTINEL_RE.search(c_stdout):
                    control_status = "violated"
                elif c_exit == 0 and DEFAULT_CONTROL_RE.search(c_stdout):
                    control_status = "passed"
                else:
                    control_status = "invalid"
            except Exception as exc:
                control_status = "invalid"
                outputs.append(f"CONTROL_EXECUTION_ERROR: {exc}")

            receipt = {
                "runs": repro_runs,
                "successes": successes,
                "control_status": control_status,
                "outputs": outputs,
                "error": None,
                "stamped_by": "cerberus",
            }

            if control_status == "violated":
                poc["status"] = "attempted"
                receipt["error"] = "Control check emitted vulnerability sentinel (control violated)"
            elif control_status == "invalid":
                poc["status"] = "attempted"
                receipt["error"] = "Control check crashed or failed sentinel contract (invalid control)"
            elif successes == repro_runs and control_status == "passed":
                poc["status"] = "proven"
            else:
                poc["status"] = "attempted"

            poc["receipt"] = receipt
            f["poc"] = poc

    return findings


def run_poc_regen(refuted_findings: list[dict], backend: Any, cfg: dict,
                  threat_md: str = "", run_id: str | None = None,
                  round_num: int = 1) -> list[dict]:
    """Lightweight PoC verification pass for findings that survived static checks.

    Since Hunters author and verify reproduction tests interactively in
    the container, this pass ensures scripts are materialized and stamps mechanical receipts.
    """
    if not refuted_findings or backend is None:
        return refuted_findings

    stamp_receipts(refuted_findings, backend, cfg=cfg, run_id=run_id)
    for f in refuted_findings:
        if isinstance(f, dict):
            f["_needs_poc_regen"] = False
    return refuted_findings
