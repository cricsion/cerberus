"""Rich-backed CLI viewer helpers (optional dependency): every public function
degrades to a plain fallback when Rich is missing.

View-only rendering and console utilities used by ``harness.cli`` subcommands
(status/inspect/runs/findings/doctor). Nothing here runs a scan — the
interactive TUI was removed and ``harness scan`` is the single scan path.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from harness.schemas import SEVERITY_ORDER

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - environment without rich
    Console = None  # type: ignore[assignment]
    Panel = None  # type: ignore[assignment]
    Table = None  # type: ignore[assignment]
    Text = None  # type: ignore[assignment]
    RICH_AVAILABLE = False


SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def make_console() -> "Console":
    """A Rich console when available, else ``None`` (plain print fallback)."""
    if not RICH_AVAILABLE:
        return None  # type: ignore[return-value]
    return Console()


# Untrusted text must never reach the terminal raw: ANSI/OSC retitles the window,
# and Rich parses str as markup (stray "[" raises MarkupError) — use rich.text.Text.
_TERMINAL_ESCAPE_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"        # OSC ... BEL or ST
    r"|\x1b\[[0-9;?]*[ -/]*[@-~]"               # CSI ... final byte
    r"|\x1b[@-Z\\-_]"                           # other ESC introducers
    r"|[\x00-\x08\x0b-\x1f\x7f\u0080-\u009f]"   # C0/C1 controls (keep \t, \n)
)


def clean_untrusted(text: Any) -> str:
    """Strip terminal control sequences from untrusted display text."""
    return _TERMINAL_ESCAPE_RE.sub("", str(text))


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def render_findings(console: Any, findings: list[dict], *, limit: int = 200) -> None:
    if not findings:
        if console is not None:
            console.print("[dim]no findings[/dim]")
        else:
            print("no findings")
        return

    rows = sorted(
        (f for f in findings if isinstance(f, dict)),
        key=lambda f: (
            SEVERITY_ORDER.get(str(f.get("severity", "medium")).lower(), 5),
            -float(f.get("confidence", 0) or 0),
        ),
    )[:limit]

    if not RICH_AVAILABLE or console is None:
        for f in rows:
            print(clean_untrusted(
                f"{f.get('severity','?').upper():8} "
                f"{f.get('cwe','?')} "
                f"{f.get('path','?')}:{f.get('start_line','?')} "
                f"conf={float(f.get('confidence',0) or 0):.2f} "
                f"status={f.get('status','?')}"
            ))
        return

    table = Table(title=f"Findings ({len(rows)} of {len(findings)})", expand=False)
    table.add_column("Sev", style="bold", no_wrap=True)
    table.add_column("CWE", no_wrap=True)
    table.add_column("Location", overflow="fold")
    table.add_column("Conf", justify="right", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Title", overflow="fold")

    for f in rows:
        sev = str(f.get("severity", "medium")).lower()
        style = SEVERITY_STYLE.get(sev, "")
        table.add_row(
            Text(clean_untrusted(sev.upper()), style=style),
            Text(clean_untrusted(f.get("cwe", "?"))),
            Text(clean_untrusted(f"{f.get('path', '?')}:{f.get('start_line', '?')}")),
            f"{float(f.get('confidence', 0) or 0):.2f}",
            Text(clean_untrusted(f.get("status", "?"))),
            Text(clean_untrusted(f.get("title", ""))),
        )
    console.print(table)


def view_run(run_dir: Path, *, console: Any = None, agent: Any = None,
              timeline: bool = False) -> int:
    run_dir = Path(run_dir)
    console = console or (Console() if RICH_AVAILABLE else None)
    meta_path = run_dir / "scan_meta.json"
    findings_path = run_dir / "findings.json"
    meta = _read_json(meta_path) if meta_path.is_file() else None
    findings = _read_json(findings_path) if findings_path.is_file() else None
    if not isinstance(findings, list):
        findings = []

    events_path = run_dir / "agents.jsonl"
    agent_events = []
    try:
        if events_path.is_file():
            for line in events_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    agent_events.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass

    if agent is not None or timeline:
        filtered = agent_events
        if agent is not None:
            filtered = [e for e in filtered
                        if str(e.get("agent_id")) == str(agent)]
        if console is None:
            for e in filtered:
                print(clean_untrusted(
                    f"{e.get('ts')} {e.get('agent_id')} {e.get('state')} {e.get('message')}"))
            return 0
        from rich.panel import Panel as _Panel
        lines = []
        for e in filtered:
            parts = [str(e.get("agent_id", "?")), str(e.get("state", "?"))]
            if e.get("message"):
                parts.append(str(e.get("message")))
            if e.get("elapsed_s") is not None:
                parts.append(f"{e.get('elapsed_s')}s")
            lines.append(" ".join(parts))
        title = Text(clean_untrusted(f"Timeline: {agent if agent is not None else 'all'}"))
        console.print(_Panel(Text(clean_untrusted("\n".join(lines) if lines else "(no events)")),
                            title=title, border_style="cyan"))
        return 0

    if console is None:
        print(clean_untrusted(f"run: {run_dir}"))
        if isinstance(meta, dict):
            print(clean_untrusted(json.dumps(meta, indent=2)))
        render_findings(None, findings)
        return 0

    header_lines = [f"run: {run_dir}"]
    if isinstance(meta, dict):
        for key in ("repo", "files", "findings", "fail_on", "min_confidence",
                    "threat_model_source", "threat_quality", "tools_used",
                    "hunter_coverage"):
            if key in meta and meta[key] is not None:
                header_lines.append(f"{key}: {meta[key]}")
    console.print(Panel(Text(clean_untrusted("\n".join(header_lines))),
                        title="Run", border_style="cyan"))
    render_findings(console, findings)

    artifacts = [p.name for p in run_dir.iterdir() if p.is_file()] if run_dir.is_dir() else []
    if artifacts:
        console.print(Panel(Text(clean_untrusted("\n".join(sorted(artifacts)))),
                            title="Artifacts", border_style="dim"))
    return 0


def list_runs(runs_dir: str | Path, *, limit: int = 50, console: Any = None) -> int:
    base = Path(runs_dir)
    console = console or (Console() if RICH_AVAILABLE else None)
    runs: list[tuple[float, Path, dict]] = []
    if base.is_dir():
        for child in base.iterdir():
            if not child.is_dir():
                continue
            meta = _read_json(child / "scan_meta.json")
            if not isinstance(meta, dict):
                continue
            try:
                mtime = (child / "scan_meta.json").stat().st_mtime
            except OSError:
                mtime = 0.0
            runs.append((mtime, child, meta))
    runs.sort(key=lambda x: x[0], reverse=True)
    runs = runs[: max(1, int(limit))]

    if console is None or not RICH_AVAILABLE:
        for _, child, meta in runs:
            print(clean_untrusted(
                f"{child.name}\tfiles={meta.get('files')}\tfindings={meta.get('findings')}\t{meta.get('repo')}"))
        return 0

    table = Table(title=f"Runs ({len(runs)})")
    table.add_column("Run", overflow="fold")
    table.add_column("Repo", overflow="fold")
    table.add_column("Files", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Status mix", overflow="fold")
    for _, child, meta in runs:
        table.add_row(
            Text(clean_untrusted(child.name)),
            Text(clean_untrusted(meta.get("repo", ""))),
            Text(clean_untrusted(meta.get("files", ""))),
            Text(clean_untrusted(meta.get("findings", ""))),
            Text(clean_untrusted(f"crit/high gate: {meta.get('fail_on', '')}")),
        )
    console.print(table)
    return 0


def doctor(config_path: str, *, console: Any = None) -> int:
    console = console or (Console() if RICH_AVAILABLE else None)
    lines: list[str] = []
    # Config load (best-effort, redacted).
    try:
        from harness.config import load_config

        cfg = load_config(config_path)
        if isinstance(cfg, dict):
            lines.append(f"config: loaded from {config_path}")
            for key in ("base_url", "hunter_model", "validator_model", "concurrency",
                        "effort", "sandbox"):
                if key in cfg:
                    lines.append(f"  {key}: {cfg.get(key)}")
    except Exception as e:
        lines.append(f"config: error ({type(e).__name__}: {e})")

    lines.append("pipeline binaries:")
    for binary in ("docker", "sbx", "gitleaks", "osv-scanner", "checkov"):
        path = shutil.which(binary)
        lines.append(f"  {binary}: {path if path else 'not found'}")
    lines.append("sandbox-image tools (validated by the image build's self-test):")
    for binary in ("semgrep", "opengrep"):
        path = shutil.which(binary)
        lines.append(f"  {binary}: {path if path else 'not on host'}")

    # Rich.
    lines.append(f"rich: {'available' if RICH_AVAILABLE else 'not installed'}")

    # Env presence (names only, never values).
    for env_name in ("BASE_URL", "API_KEY", "HUNTER_MODEL", "VALIDATOR_MODEL",
                     "EFFORT", "CONCURRENCY"):
        present = bool(os.environ.get(env_name))
        lines.append(f"env {env_name}: {'set' if present else 'unset'}")

    if console is None or not RICH_AVAILABLE:
        for line in lines:
            print(clean_untrusted(line))
        return 0
    console.print(Panel(Text(clean_untrusted("\n".join(lines))),
                        title="Doctor", border_style="cyan"))
    return 0
