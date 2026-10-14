"""Rich-backed CLI/TUI helpers for the vuln harness.

This module is optional: every public function degrades to a plain fallback
when Rich is not installed, so ``harness.cli`` can import it safely.
"""
from __future__ import annotations

import contextlib
import contextvars
import io
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except Exception:  # pragma: no cover - environment without rich
    Console = None  # type: ignore[assignment]
    Layout = None  # type: ignore[assignment]
    Live = None  # type: ignore[assignment]
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


def make_console(*, force_plain: bool = False, no_color: bool = False) -> "Console":
    if not RICH_AVAILABLE or force_plain:
        # Console with record=False still works; use stdout.
        if RICH_AVAILABLE:
            return Console(no_color=True, force_terminal=False)
        return None  # type: ignore[return-value]
    return Console(no_color=no_color)


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
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                str(f.get("severity", "medium")).lower(), 5
            ),
            -float(f.get("confidence", 0) or 0),
        ),
    )[:limit]

    if not RICH_AVAILABLE or console is None:
        for f in rows:
            print(
                f"{f.get('severity','?').upper():8} "
                f"{f.get('cwe','?')} "
                f"{f.get('path','?')}:{f.get('start_line','?')} "
                f"conf={float(f.get('confidence',0) or 0):.2f} "
                f"status={f.get('status','?')}"
            )
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
            Text(sev.upper(), style=style),
            str(f.get("cwe", "?")),
            f"{f.get('path', '?')}:{f.get('start_line', '?')}",
            f"{float(f.get('confidence', 0) or 0):.2f}",
            str(f.get("status", "?")),
            str(f.get("title", "")),
        )
    console.print(table)


def render_summary(console: Any, state: dict[str, Any], out: Path) -> None:
    findings = state.get("verified", []) or []
    by_status: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        by_status[str(f.get("status", "?"))] = by_status.get(str(f.get("status", "?")), 0) + 1
        by_sev[str(f.get("severity", "?")).lower()] = by_sev.get(
            str(f.get("severity", "?")).lower(), 0
        ) + 1

    lines = [
        f"repo: {state.get('repo')}",
        f"files: {len(state.get('files', []) or [])}",
        f"findings: {len(findings)}",
        "by severity: " + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items())),
        "by status: " + ", ".join(f"{k}={v}" for k, v in sorted(by_status.items())),
        f"output: {out}",
    ]
    if state.get("threat_model_source"):
        lines.append(f"threat model: {state.get('threat_model_source')}")
    tq = state.get("threat_quality") or {}
    if tq:
        lines.append(f"threat quality: {tq.get('score', '?')}/100")

    if not RICH_AVAILABLE or console is None:
        for line in lines:
            print(line)
        return
    console.print(Panel("\n".join(lines), title="Scan summary", border_style="cyan"))


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
                    import json as _json
                    agent_events.append(_json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass

    if agent is not None or timeline:
        filtered = agent_events
        if agent is not None:
            filtered = [e for e in filtered
                        if str(e.get("agent_id")) == str(agent)]
        if console is None:
            for e in filtered:
                print(f"{e.get('ts')} {e.get('agent_id')} {e.get('state')} {e.get('message')}")
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
        console.print(_Panel("\n".join(lines) if lines else "(no events)",
                            title=f"Timeline: {agent if agent is not None else 'all'}",
                            border_style="cyan"))
        return 0

    if console is None:
        print(f"run: {run_dir}")
        if isinstance(meta, dict):
            print(json.dumps(meta, indent=2))
        render_findings(None, findings)
        return 0

    header_lines = [f"run: {run_dir}"]
    if isinstance(meta, dict):
        for key in ("repo", "files", "findings", "fail_on", "min_confidence",
                    "threat_model_source", "threat_quality", "tools_used"):
            if key in meta and meta[key] is not None:
                header_lines.append(f"{key}: {meta[key]}")
    console.print(Panel("\n".join(header_lines), title="Run", border_style="cyan"))
    render_findings(console, findings)

    artifacts = [p.name for p in run_dir.iterdir() if p.is_file()] if run_dir.is_dir() else []
    if artifacts:
        console.print(Panel("\n".join(sorted(artifacts)), title="Artifacts", border_style="dim"))
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
            print(f"{child.name}\tfiles={meta.get('files')}\tfindings={meta.get('findings')}\t{meta.get('repo')}")
        return 0

    table = Table(title=f"Runs ({len(runs)})")
    table.add_column("Run", overflow="fold")
    table.add_column("Repo", overflow="fold")
    table.add_column("Files", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Status mix", overflow="fold")
    for _, child, meta in runs:
        table.add_row(
            child.name,
            str(meta.get("repo", "")),
            str(meta.get("files", "")),
            str(meta.get("findings", "")),
            f"crit/high gate: {meta.get('fail_on', '')}",
        )
    console.print(table)
    return 0


def doctor(config_path: str, *, console: Any = None) -> int:
    console = console or (Console() if RICH_AVAILABLE else None)
    lines: list[str] = []
    # Config load (best-effort, redacted).
    try:
        from harness.config import load_config

        cfg = None
        try:
            cfg = load_config(config_path)
        except TypeError:
            cfg = load_config()
        if isinstance(cfg, dict):
            lines.append(f"config: loaded from {config_path}")
            for key in ("base_url", "hunter_model", "validator_model", "concurrency",
                        "effort", "sandbox"):
                if key in cfg:
                    lines.append(f"  {key}: {cfg.get(key)}")
    except Exception as e:
        lines.append(f"config: error ({type(e).__name__}: {e})")

    # Binaries.
    for binary in ("semgrep", "opengrep", "gitleaks", "osv-scanner", "checkov", "docker", "sbx"):
        path = shutil.which(binary)
        lines.append(f"{binary}: {path if path else 'not found'}")

    # Rich.
    lines.append(f"rich: {'available' if RICH_AVAILABLE else 'not installed'}")

    # Env presence (names only, never values).
    for env_name in ("BASE_URL", "API_KEY", "HUNTER_MODEL", "VALIDATOR_MODEL",
                     "EFFORT", "CONCURRENCY"):
        present = bool(os.environ.get(env_name))
        lines.append(f"env {env_name}: {'set' if present else 'unset'}")

    if console is None or not RICH_AVAILABLE:
        for line in lines:
            print(line)
        return 0
    console.print(Panel("\n".join(lines), title="Doctor", border_style="cyan"))
    return 0


def run_scan_rich(
    repo: str,
    *,
    out: Path,
    scan_kwargs: dict[str, Any],
    console: Any = None,
) -> int:
    """Run a scan with a compact Rich live status block (no alt screen)."""
    console = console or (Console() if RICH_AVAILABLE else None)
    # Graceful degradation outside a TTY or without Rich.
    try:
        is_tty = bool(console is not None and getattr(console, "is_terminal", False))
    except Exception:
        is_tty = False
    if (not RICH_AVAILABLE or console is None or not is_tty):
        # Plain path: invoke run_scan directly (thread-free).
        from harness.pipeline import run_scan
        from harness.reporting.reports import write_html, write_json, write_junit, write_markdown, write_sarif

        try:
            out.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            print(f"cannot create output dir {out}: {e}", file=sys.stderr)
            return 1
        try:
            state = run_scan(repo, **scan_kwargs)
        except Exception as e:
            print(f"scan failed: {e}", file=sys.stderr)
            return 1
        try:
            findings = state.get("verified", [])
            write_json(findings, out / "findings.json")
            write_sarif(findings, out / "results.sarif")
            write_markdown(findings, out / "report.md")
            write_html(findings, out / "report.html")
            write_junit(findings, out / "junit.xml")
            threat_md = state.get("threat_model_md", "") or ""
            if threat_md.strip():
                (out / "THREAT_MODEL.md").write_text(threat_md)
            meta = {
                "repo": repo,
                "files": len(state.get("files", [])),
                "findings": len(findings),
                "threat_model_source": state.get("threat_model_source", "summary"),
            }
            (out / "scan_meta.json").write_text(json.dumps(meta, indent=2))
            # Persist agent visibility artifacts from registry dump.
            _persist_agent_artifacts(out, state)
        except Exception as e:
            print(f"artifact write warning: {e}", file=sys.stderr)
        print(f"files={len(state.get('files', []))} findings={len(state.get('verified', []))} out={out}")
        return 0

    try:
        from harness.progress import RichLiveSink
    except Exception:
        RichLiveSink = None

    from harness.pipeline import run_scan
    import threading, io, time, contextlib

    state_holder: dict[str, Any] = {"state": None, "error": None}
    log_lines: list[str] = []
    live_sink = RichLiveSink() if RichLiveSink is not None else None
    agent_events: list[dict[str, Any]] = []

    class _Capture(io.StringIO):
        def write(self, s: str) -> int:  # type: ignore[override]
            if s:
                for part in s.splitlines():
                    if part.strip():
                        log_lines.append(part)
                        if len(log_lines) > 500:
                            del log_lines[0: len(log_lines) - 500]
            return len(s)

        def flush(self) -> None:  # type: ignore[override]
            pass

    def worker() -> None:
        cap = _Capture()
        kwargs = dict(scan_kwargs)
        kwargs.setdefault("progress_sink", live_sink)
        kwargs.setdefault("agent_events", agent_events)
        try:
            kwargs.setdefault("agent_events_path", out / "agents.jsonl")
        except Exception:
            pass
        try:
            with contextlib.redirect_stdout(cap):
                st = run_scan(repo, **kwargs)
            state_holder["state"] = st
        except Exception as e:  # noqa: BLE001 - UI boundary
            state_holder["error"] = e
            log_lines.append(f"ERROR: {type(e).__name__}: {e}")

    thread = threading.Thread(target=worker, name="harness-scan", daemon=True)
    thread.start()

    def _render_block() -> Any:
        latest: dict[str, dict] = {}
        try:
            if live_sink is not None:
                latest, _ = live_sink.snapshot()
        except Exception:
            pass
        if not latest and agent_events:
            for e in agent_events:
                if isinstance(e, dict):
                    latest[e.get("agent_id")] = e
        total = len(latest)
        running = [aid for aid, e in latest.items() if str(e.get("state")) == "running"]
        queued = [aid for aid, e in latest.items() if str(e.get("state")) == "queued"]
        done = [aid for aid, e in latest.items() if str(e.get("state")) == "succeeded"]
        failed = [aid for aid, e in latest.items() if str(e.get("state")) == "failed"]
        lines = [f"Harness scan  repo={repo}  out={out}"]
        lines.append(f"Agents: total {total}  running {len(running)}  queued {len(queued)}  done {len(done)}  failed {len(failed)}")
        for aid in running[:3]:
            e = latest.get(aid) or {}
            msg = str(e.get("message") or "")
            elapsed = e.get("elapsed_s", 0)
            lines.append(f"  running: {aid}  {elapsed:.0f}s  {msg}".rstrip())
        if queued:
            lines.append("  queued: " + ", ".join(queued[:5]) + ("..." if len(queued) > 5 else ""))
        # Explicit backoff/rate-limit events emitted by the model/retry path.
        rate_limited = None
        for aid, e in list(latest.items()):
            msg = str((e or {}).get("message") or "")
            if "rate_limited" in msg:
                rate_limited = (aid, msg)
        if rate_limited is None:
            for e in reversed(agent_events or []):
                msg = str((e or {}).get("message") or "")
                if "rate_limited" in msg:
                    rate_limited = (e.get("agent_id"), msg)
                    break
        if rate_limited is not None:
            aid, msg = rate_limited
            lines.append(f"  backoff: {aid} {msg}".strip()[:120])
        # limit to ~8 lines
        lines = lines[:8]
        from rich.panel import Panel as _Panel
        return _Panel("\n".join(lines), border_style="cyan", title="Scan monitor")

    with Live(_render_block(), console=console, refresh_per_second=4, screen=False) as live:
        while thread.is_alive():
            live.update(_render_block())
            time.sleep(0.25)

    if state_holder.get("error") is not None:
        console.print(f"[red]scan failed: {state_holder['error']}[/red]")
        return 1

    state = state_holder.get("state") or {}
    # Persist artifacts (mirrors cmd_scan).
    try:
        from harness.reporting.reports import write_html, write_json, write_junit, write_markdown, write_sarif

        findings = state.get("verified", [])
        out.mkdir(parents=True, exist_ok=True)
        write_json(findings, out / "findings.json")
        write_sarif(findings, out / "results.sarif")
        write_markdown(findings, out / "report.md")
        write_html(findings, out / "report.html")
        write_junit(findings, out / "junit.xml")
        threat_md = state.get("threat_model_md", "") or ""
        if threat_md.strip():
            (out / "THREAT_MODEL.md").write_text(threat_md)
        meta = {
            "repo": repo,
            "files": len(state.get("files", [])),
            "findings": len(findings),
            "threat_model_source": state.get("threat_model_source", "summary"),
        }
        (out / "scan_meta.json").write_text(json.dumps(meta, indent=2))
        _persist_agent_artifacts(out, state)
    except Exception as e:  # noqa: BLE001
        console.print(f"[yellow]artifact write warning: {e}[/yellow]")

    render_summary(console, state, out)
    render_findings(console, state.get("verified", []))
    console.print(f"[dim]outputs: {out}[/dim]")
    return 0


def _persist_agent_artifacts(out: Path, state: dict[str, Any]) -> None:
    try:
        import json as _json
        events = state.get("agent_events") or []
        handles = state.get("agent_handles") or []
        # Prefer registry handle dump for agents.jsonl.
        rows = handles if handles else events
        # Deduplicate by final agent state: if handles present, use one row per agent.
        if handles:
            data = handles
        else:
            # Collapse events to last per agent.
            last: dict[str, dict] = {}
            for e in events:
                if isinstance(e, dict):
                    last[e.get("agent_id")] = e
            data = list(last.values())
        try:
            out.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        with (out / "agents.jsonl").open("w", encoding="utf-8") as f:
            for row in data:
                f.write(_json.dumps(row) + "\n")
        # Summary.
        from collections import Counter
        by_state: dict[str, int] = Counter()
        by_role: dict[str, int] = Counter()
        for row in data:
            if not isinstance(row, dict):
                continue
            by_state[str(row.get("state", ""))] += 1
            by_role[str(row.get("role", ""))] += 1
        summary = {
            "total": len({r.get("agent_id") for r in data if isinstance(r, dict)} or data),
            "by_state": dict(by_state),
            "by_role": dict(by_role),
            "failed": [r.get("agent_id") for r in data
                       if isinstance(r, dict) and str(r.get("state")) == "failed"],
            "running": [r.get("agent_id") for r in data
                        if isinstance(r, dict) and str(r.get("state")) == "running"],
            "run_id": state.get("repo"),
        }
        # Merge any provided agent_summary.
        if isinstance(state.get("agent_summary"), dict):
            summary.update({k: v for k, v in state["agent_summary"].items()
                           if k not in summary or summary[k] is None})
        (out / "agent_summary.json").write_text(_json.dumps(summary, indent=2))
    except Exception:
        pass


run_scan_tui = run_scan_rich
