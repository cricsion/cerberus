"""Rich-backed CLI viewer helpers

View-only rendering and console utilities used by ``harness.cli`` subcommands
(status/inspect/runs/findings). Nothing here runs a scan — the
interactive TUI was removed and ``harness scan`` is the single scan path.
Non-TTY streams and ``NO_COLOR`` receive the same layout with styles stripped
by rich.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from harness.schemas import sort_findings

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme


THEME = Theme({
    "meta": "dim",         # metadata weight: stamps, labels, durations, hints
    "accent": "cyan",      # running glyph + panel borders
    "ok": "green",         # succeeded
    "err": "red",          # failed
    "timeout": "magenta",  # timed-out
    "warn": "yellow",      # canceled / warnings
    "gate.pass": "green",
    "gate.fail": "bold red",
    "empty": "green dim",  # the zero-findings marker
    "sev.critical": "bold red",
    "sev.high": "red",
    "sev.medium": "yellow",
    "sev.low": "blue",
    "sev.info": "dim",
})

SEVERITY_STYLE = {
    "critical": "sev.critical",
    "high": "sev.high",
    "medium": "sev.medium",
    "low": "sev.low",
    "info": "sev.info",
}

_HYGIENE = {"markup": False, "emoji": False, "highlight": False, "theme": THEME}


def make_console(**kwargs) -> "Console":
    """A themed Rich console
    Extra kwargs pass through (e.g. ``width``, ``force_terminal``, ``file``)."""
    base = dict(_HYGIENE)
    base.update(kwargs)
    return Console(**base)


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


def print_panel(console, lines: list[str], *, title: str,
                border_style: str = "accent") -> None:
    """One panel shell for every view print: a cleaned, titled text box."""
    body = "\n".join(lines) if lines else "(no events)"
    console.print(Panel(Text(clean_untrusted(body)),
                        title=Text(clean_untrusted(str(title))),
                        border_style=border_style))


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def render_findings(console: Any, findings: list[dict], *, limit: int = 200) -> None:
    if not findings:
        console.print(Text("no findings", style="meta"))
        return

    rows = sort_findings(list(findings))[:limit]

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
    console = console or Console()
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
        lines = []
        for e in filtered:
            parts = [str(e.get("agent_id", "?")), str(e.get("state", "?"))]
            if e.get("message"):
                parts.append(str(e.get("message")))
            if e.get("elapsed_s") is not None:
                parts.append(f"{e.get('elapsed_s')}s")
            lines.append(" ".join(parts))
        title = f"Timeline: {agent if agent is not None else 'all'}"
        print_panel(console, lines, title=title)
        return 0

    header_lines = [f"run: {run_dir}"]
    if isinstance(meta, dict):
        for key in ("repo", "files", "findings", "fail_on", "min_confidence",
                    "threat_model_source", "threat_quality", "tools_used"):
            if key in meta and meta[key] is not None:
                header_lines.append(f"{key}: {meta[key]}")
    print_panel(console, header_lines, title="Run")
    render_findings(console, findings)

    artifacts = [p.name for p in run_dir.iterdir() if p.is_file()] if run_dir.is_dir() else []
    if artifacts:
        print_panel(console, sorted(artifacts), title="Artifacts",
                    border_style="meta")
    return 0


def agent_status(run_dir: Path, console: Any = None) -> int:
    """One run's agent state report"""
    run_dir = Path(run_dir)
    console = console or Console()
    summary_path = run_dir / "agent_summary.json"
    events_path = run_dir / "agents.jsonl"
    summary = None
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    lines = [f"run: {run_dir}"]
    if isinstance(summary, dict):
        lines.append(f"total: {summary.get('total')}")
        lines.append("by state: " + ", ".join(
            f"{k}={v}" for k, v in (summary.get('by_state') or {}).items()))
        lines.append("by role: " + ", ".join(
            f"{k}={v}" for k, v in (summary.get('by_role') or {}).items()))
        if summary.get("running"):
            lines.append("running: " + ", ".join(summary.get("running", [])))
        if summary.get("failed"):
            lines.append("failed: " + ", ".join(summary.get("failed", [])))
    else:
        lines.append("no agent_summary.json found")
    if events_path.is_file():
        lines.append(f"events: {sum(1 for _ in events_path.open())} (agents.jsonl)")
    pid_path = run_dir / "scan.pid"
    if pid_path.is_file():
        lines.append(f"pid: {pid_path.read_text().strip()}")
    print_panel(console, lines, title="Agent status")
    return 0 if (summary is not None or events_path.is_file()) else 1


def list_runs(runs_dir: str | Path, *, limit: int = 50, console: Any = None) -> int:
    base = Path(runs_dir)
    console = console or Console()
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
