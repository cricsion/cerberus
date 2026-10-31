"""Scan-time UI: header, append-only stage/agent progress lines, end receipt.

This module is the only place that decides how ``harness scan`` renders.

* Two visual weights only — content normal, metadata dim.
* One glyph vocabulary: ``✓`` done, ``▶`` running, ``✗`` failed, ``⏱``
  timed-out, ``⊘`` canceled.
* Durations are right-aligned; stage/agent names occupy a fixed column.
* Append-only lines: no cursor movement, no ``Live``, no alternate screen.
* Every dynamic string goes through :func:`clean_untrusted` and is rendered
  as a :class:`rich.text.Text` — never as a markup string.

Rendering is Rich-only. Non-TTY streams and
``NO_COLOR`` naturally receive the same layout with styles stripped. Style
names resolve through :data:`harness.reporting.view.THEME` (semantic keys:
``meta``/``ok``/``err``/...), so the vocabulary lives in one place.
"""
from __future__ import annotations

import re
import sys
import threading
import time
from pathlib import Path
from typing import Any

from harness.reporting.view import (
    SEVERITY_STYLE,
    THEME,
    clean_untrusted,
)
from harness.config import get_config

from rich.cells import cell_len
from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from rich.text import Text


# Visual constants -----------------------------------------------------------

STAGE_WIDTH = 15
AGENT_WIDTH = 28
LABEL_WIDTH = 12
TIMESTAMP_WIDTH = 11  # "[HH:MM:SS] "

_GLYPHS = {
    "running": ("▶", "accent"),
    "succeeded": ("✓", "ok"),
    "failed": ("✗", "err"),
    "timed-out": ("⏱", "timeout"),
    "canceled": ("⊘", "warn"),
}
_SEVERITIES = ("critical", "high", "medium", "low", "info")

_ARTIFACTS = (("report.md", "report.md"), ("report.html", "report.html"),
              ("findings.json", "findings.json"),
              ("results.sarif", "sarif"), ("junit.xml", "junit"))

# Small formatting helpers ---------------------------------------------------


def duration_s(value: Any) -> str:
    """Human duration: ``42s`` · ``8m32s`` · ``1h04m`` (non-positive → ``0s``)."""
    try:
        total = float(value)
    except (TypeError, ValueError):
        return "0s"
    if total <= 0:
        return "0s"
    total = int(total)
    if total < 60:
        return f"{total}s"
    if total < 3600:
        minutes, seconds = divmod(total, 60)
        return f"{minutes}m{seconds:02d}s"
    hours, rest = divmod(total, 3600)
    minutes = rest // 60
    return f"{hours}h{minutes:02d}m"


def short_path(path: Any, max_len: int = 40) -> str:
    """Shorten a path from the LEFT, keeping the tail."""
    text = clean_untrusted(str(path)).strip()
    if not text:
        return "…"
    if len(text) <= max_len:
        return text
    room = max(3, max_len - 2)
    tail = text[-room:]
    cut = tail.find("/")
    if 0 <= cut < len(tail) - 1:
        tail = tail[cut + 1:]
    out = "…/" + tail
    if len(out) > max_len:
        out = "…" + out[-(max_len - 1):]
    return out


def _state_value(state: Any) -> str:
    value = getattr(state, "value", None)
    return str(value if value is not None else state).strip().lower()


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(str(value).strip()))
        except (TypeError, ValueError):
            return default


def _clip(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if cell_len(text) <= width:
        return text
    if width == 1:
        return "…"
    out = text
    while out and cell_len(out) + 1 > width:
        out = out[:-1]
    return out + "…"


def _pad(text: str, width: int) -> str:
    if cell_len(text) > width:
        text = _clip(text, width)
    return text + " " * max(0, width - cell_len(text))


def _model_name(cfg: dict, role: str) -> str:
    try:
        from harness.config import get_model_kwargs

        return str((get_model_kwargs(cfg, role) or {}).get("model") or "")
    except Exception:
        return ""


def _findings_count(evt: Any) -> int:
    progress = getattr(evt, "progress", None) or {}
    if not isinstance(progress, dict):
        return 0
    return max(0, _int(progress.get("findings_produced"), 0))


_VALIDATOR_CELL_RE = re.compile(r"^validator:.+:c\d+:v\d+$")


def _agent_kind(agent_id: str, role: str) -> str:
    if _VALIDATOR_CELL_RE.match(agent_id):
        return "validator_cell"
    if agent_id.startswith("validator:") or role.startswith("validator:"):
        return "validator_unit"
    if agent_id == "validator" or role == "validator":
        return "validator_pool"
    if agent_id.startswith("hunter:") or role == "hunter":
        return "hunter"
    return "other"


def _severity_counts(findings: Any) -> dict[str, int]:
    counts = {sev: 0 for sev in _SEVERITIES}
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        sev = str(finding.get("severity") or "info").strip().lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# Reporter -------------------------------------------------------------------


class ScanReporter:
    """Renders harness scan progress to stderr and the receipt to stdout."""

    def __init__(self, *, no_color: bool = False, agent_log: str = "normal",
                 err_console: Any = None, out_console: Any = None,
                 heartbeat: bool | None = None) -> None:
        self.agent_log = "quiet" if str(agent_log).strip().lower() == "quiet" else "normal"
        self._lock = threading.RLock()
        self._details: dict[str, str] = {}
        self._agent_state: dict[str, str] = {}
        self._stages_done = 0
        # Heartbeat:
        # agent_id -> wall-clock start, only when ≥1 agent is running.
        self._starts: dict[str, float] = {}
        self._hb_thread: threading.Thread | None = None
        self._hb_stop = threading.Event()
        self._hb_s = float(get_config()["ui"]["heartbeat_s"])
        kwargs = {"markup": False, "emoji": False, "highlight": False,
                  "theme": THEME}
        if no_color:
            kwargs["no_color"] = True
        self._err = (err_console if err_console is not None
                     else Console(file=sys.stderr, **kwargs))
        self._out = (out_console if out_console is not None
                     else Console(**kwargs))
        self._hb_ready = (self.agent_log != "quiet" and bool(
            heartbeat if heartbeat is not None else self._auto_heartbeat()))

    # -- header --------------------------------------------------------------

    def header(self, repo: Any, cfg: dict | None = None, *, fail_on: str = "high",
               focus: Any = None, vulns: Any = None, votes: Any = None) -> None:
        """Indented key/value header; optional rows only when non-default."""
        cfg = cfg if isinstance(cfg, dict) else {}
        rows: list[tuple[str, str]] = [("repo", short_path(repo))]
        hunter = _model_name(cfg, "hunter") or "default"
        validator = _model_name(cfg, "validator") or "default"
        rows.append(("models", f"hunter {hunter} · validator {validator}"))
        try:
            from harness.config import effective_config

            run_cfg = effective_config(cfg)
            conc, effort = run_cfg["concurrency"], run_cfg["effort"]
            backend = str(run_cfg["sandbox"].get("backend") or "local").strip().lower()
        except Exception:
            conc, effort, backend = "?", "?", "?"
        rows.append(("run", f"conc {conc} · effort {effort} · gate {fail_on}"))
        if backend == "docker":
            rows.append(("sandbox", backend))
        options: list[str] = []
        if focus:
            focus_text = focus if isinstance(focus, str) else ", ".join(
                str(f) for f in focus if str(f).strip())
            if focus_text:
                options.append(f"focus {focus_text}")
        if vulns:
            options.append(f"vulns {short_path(vulns)}")
        if votes is not None:
            options.append(f"votes {votes}")
        if options:
            rows.append(("options", " · ".join(options)))

        width = _console_width(self._err)
        for key, value in rows:
            label = _pad(key, 10)
            budget = max(0, width - 10 - 1)
            line = Text()
            line.append(label, style="meta")
            line.append(" " + _clip(clean_untrusted(value), budget))
            self._err.print(line, no_wrap=True, overflow="ignore")
        self._err.print()

    # -- stage details -------------------------------------------------------

    def detail(self, stage: Any, text: Any) -> None:
        """Buffer one detail line for a stage (rendered at ``stage_done``)."""
        value = clean_untrusted(text)
        variants = {str(stage), str(stage).replace("_", "-")}
        if value.startswith("["):
            close = value.find("] ")
            if close > 0 and value[1:close] in variants:
                value = value[close + 2:]
        with self._lock:
            self._details[str(stage)] = value

    def stage_done(self, stage: Any, elapsed: Any, ok: bool = True,
                   error: str = "") -> None:
        """One line per stage: glyph · padded name · detail · right duration."""
        name = _clip(clean_untrusted(stage), STAGE_WIDTH)
        duration = duration_s(elapsed)
        with self._lock:
            detail = self._details.pop(str(stage), "")
            self._stages_done += 1
            gap = self._stages_done > 1

        stamp = time.strftime("%X")
        console = self._err
        width = _console_width(console)
        if gap:
            console.print()
        if ok:
            budget = width - TIMESTAMP_WIDTH - STAGE_WIDTH - len(duration) - 4
            detail = _clip(detail, max(0, budget))
            left = f"[{stamp}] "
            length = (TIMESTAMP_WIDTH + 2 + STAGE_WIDTH
                      + (1 + cell_len(detail) if detail else 0))
            pad = max(2, width - length - cell_len(duration))
            line = Text()
            line.append(left, style="meta")
            line.append("✓ ", style="ok")
            line.append(_pad(name, STAGE_WIDTH))
            if detail:
                line.append(" " + detail, style="meta")
            line.append(" " * pad)
            line.append(duration, style="meta")
            console.print(line, no_wrap=True, overflow="ignore")
        else:
            budget = width - TIMESTAMP_WIDTH - len("failed after") - 2
            err = _clip(clean_untrusted(error), max(0, budget))
            line = Text()
            line.append(f"[{stamp}] ", style="meta")
            line.append("✗ ", style="err")
            line.append(_pad(name, STAGE_WIDTH), style="err")
            line.append(f" failed after {duration}", style="err")
            if err:
                line.append(f" · {err}", style="err")
            console.print(line, no_wrap=True, overflow="ignore")
        _flush(console)

    # -- agent events --------------------------------------------------------

    def on_event(self, evt: Any) -> None:
        """One append-only line per meaningful agent transition."""
        if self.agent_log == "quiet":
            return
        agent_id = clean_untrusted(getattr(evt, "agent_id", "") or "")
        role = clean_untrusted(getattr(evt, "role", "") or "")
        state = _state_value(getattr(evt, "state", ""))
        with self._lock:
            if agent_id:
                self._agent_state[agent_id] = state
                # Elapsed-from-start tracking for the heartbeat line.
                if state == "running":
                    elapsed = _int(getattr(evt, "elapsed_s", 0), 0)
                    try:
                        self._starts.setdefault(
                            agent_id, time.time() - max(0.0, float(elapsed)))
                    except (TypeError, ValueError):
                        self._starts.setdefault(agent_id, time.time())
                    if (self._hb_ready and self._hb_thread is None
                            and not self._hb_stop.is_set()):
                        self._start_heartbeat()
                elif state in ("succeeded", "failed", "timed-out", "canceled"):
                    self._starts.pop(agent_id, None)
        if not agent_id:
            agent_id = role or "agent"

        kind = _agent_kind(agent_id, role)
        if kind == "validator_cell":
            # One line per validator LLM call, real id validator:<unit>:cN:vM.
            if state in ("pending", "queued"):
                return
            self._agent_line(evt, agent_id, state, kind)
            return
        if kind == "validator_unit":
            if state == "failed":
                self._agent_line(evt, agent_id, state, kind)
            return
        if kind == "validator_pool":
            if state in ("pending", "queued"):
                return
            self._agent_line(evt, agent_id, state, kind)
            return
        if state in ("pending", "queued"):
            return
        if state in ("running", "succeeded", "failed", "timed-out", "canceled"):
            self._agent_line(evt, agent_id, state, kind)

    def _tally(self) -> str:
        counts = {"running": 0, "succeeded": 0, "queued": 0, "failed": 0}
        with self._lock:
            items = list(self._agent_state.items())
        for agent_id, state in items:
            if not agent_id.startswith("hunter:"):
                continue
            if state in counts:
                counts[state] += 1
        parts = []
        if counts["running"]:
            parts.append(f"{counts['running']} running")
        if counts["succeeded"]:
            parts.append(f"{counts['succeeded']} done")
        if counts["queued"]:
            parts.append(f"{counts['queued']} queued")
        if counts["failed"]:
            parts.append(f"{counts['failed']} failed")
        return " · ".join(parts)

    def _agent_line(self, evt: Any, agent_id: str, state: str,
                    kind: str) -> None:
        stamp = time.strftime("%X")
        name = _pad(agent_id, AGENT_WIDTH)
        duration = duration_s(getattr(evt, "elapsed_s", 0))
        error = clean_untrusted(getattr(evt, "error", "") or "")
        message = clean_untrusted(getattr(evt, "message", "") or "")
        model = clean_untrusted(getattr(evt, "model", "") or "")
        findings = _findings_count(evt) if kind == "hunter" else 0
        tally = self._tally() if kind == "hunter" else ""

        console = self._err
        width = _console_width(console)
        line = Text()
        line.append("  ")
        line.append(f"[{stamp}] ", style="meta")
        glyph, style = _GLYPHS.get(state, ("?", ""))
        line.append(glyph + " ", style=style)
        line.append(name)

        if state == "running":
            line.append("running")
            if model:
                line.append("  " + _clip(model, max(8, width - 44)), style="meta")
            if tally:
                line.append("  " + tally, style="meta")
            console.print(line, no_wrap=True, overflow="ignore")
            _flush(console)
            return

        if state == "succeeded":
            if kind == "hunter":
                label = f"{findings} findings"
                line.append(label, style="meta" if findings == 0 else "")
            else:
                detail = _clip(message or "completed",
                               max(0, width - AGENT_WIDTH - TIMESTAMP_WIDTH - 20))
                line.append(detail)
            if tally:
                line.append("  " + tally, style="meta")
            pad = max(2, width - cell_len(line.plain) - cell_len(duration))
            line.append(" " * pad)
            line.append(duration, style="meta")
            console.print(line, no_wrap=True, overflow="ignore")
            _flush(console)
            return

        # failed / timed-out / canceled
        line.append(state, style=style)
        if error:
            budget = max(0, width - cell_len(line.plain) - cell_len(duration) - 6)
            line.append(" · " + _clip(error, budget), style=style)
        if tally:
            line.append("  " + tally, style="meta")
        pad = max(2, width - cell_len(line.plain) - cell_len(duration))
        line.append(" " * pad)
        line.append(duration, style="meta")
        console.print(line, no_wrap=True, overflow="ignore")
        _flush(console)

    # -- heartbeat ------------------------------

    def _auto_heartbeat(self) -> bool:
        """Auto-gate: real terminal only (never inside pytest redirects)."""
        try:
            if not sys.stderr.isatty():
                return False
        except Exception:
            return False
        return bool(getattr(self._err, "is_terminal", False))

    def _start_heartbeat(self) -> None:
        """Lazily start the daemon timer; the loop prints one line per tick
        while at least one agent is running. Called with the lock held."""
        bound = threading.Thread(target=self._heartbeat_loop,
                                 name="scan-heartbeat", daemon=True)
        self._hb_thread = bound
        bound.start()

    def _heartbeat_loop(self) -> None:
        while not self._hb_stop.wait(self._hb_s):
            try:
                self.heartbeat_tick()
            except Exception:
                pass

    def heartbeat_tick(self, now: float | None = None) -> None:
        """One heartbeat line while agents run."""
        if not self._hb_ready or self._hb_stop.is_set():
            return
        with self._lock:
            items = dict(self._starts)
        if not items:
            return
        now = time.time() if now is None else float(now)
        longest_id, longest = "", 0.0
        for aid, start in items.items():
            wait = max(0.0, now - start)
            if wait >= longest:  # >= keeps the first-inserted winner stable
                longest, longest_id = wait, aid
        if not longest_id:
            return
        self._hb_line(len(items), longest_id, longest)

    def _hb_line(self, count: int, agent_id: str, elapsed: float) -> None:
        """``[HH:MM:SS] ▶ running 3 · longest hunter:auth 4m12s`` (no indent:
        a system line at stage level, not an agent line)."""
        stamp = time.strftime("%X")
        name = clean_untrusted(agent_id)
        dur = duration_s(elapsed)
        console = self._err
        width = _console_width(console)
        body = f"running {count} · longest "
        room = max(8, width - TIMESTAMP_WIDTH - cell_len(body) - cell_len(dur)
                   - 2)
        line = Text()
        line.append(f"[{stamp}] ", style="meta")
        glyph, style = _GLYPHS["running"]
        line.append(glyph + " ", style=style)
        line.append(body, style="meta")
        line.append(_clip(name, room))
        line.append(" " + dur, style="meta")
        console.print(line, no_wrap=True, overflow="ignore")
        _flush(console)

    def close(self) -> None:
        """Stop the heartbeat thread (idempotent — called at receipt time).
        Also drops tracked starts so a stray post-close tick stays silent."""
        with self._lock:
            self._starts.clear()
        self._hb_stop.set()
        self._hb_thread = None

    # -- receipt -------------------------------------------------------------

    def done(self, *, findings: Any, out: Any, fail_on: str = "high",
             min_confidence: float = 0.6, gated: Any = None,
             elapsed: Any = 0, state: dict | None = None) -> None:
        """The end receipt: dim label column, values, PASS/FAIL verdict."""
        findings = [f for f in (findings or []) if isinstance(f, dict)]
        gated = [f for f in (gated or []) if isinstance(f, dict)]
        state = state if isinstance(state, dict) else {}
        out_path = Path(str(out))

        console = self._out
        console.print(Rule(style="meta"))
        # Table.grid: boxless, headerless by construction (sic: identical to
        # Table(box=None, show_header=False); padding/collapse kept for bytes).
        table = Table.grid(padding=(0, 2), pad_edge=False,
                           collapse_padding=False)
        value_width = max(20, _console_width(console) - LABEL_WIDTH - 8)
        table.add_column(style="meta", width=LABEL_WIDTH, no_wrap=True)
        table.add_column(width=value_width, no_wrap=True,
                         overflow="ellipsis")

        table.add_row(Text("findings"),
                      self._severity_text(findings, len(gated)))
        duplicates = sum(1 for f in findings if f.get("duplicate_of"))
        if duplicates:
            table.add_row(Text("duplicates"),
                          Text(f"{duplicates} collapsed"))
        quality = state.get("threat_quality")
        if isinstance(quality, dict) and quality.get("score") is not None:
            source = clean_untrusted(state.get("threat_model_source") or "")
            value = f"{quality.get('score')}/100"
            if source:
                value += f" · source={source}"
            table.add_row(Text("threat-model"), Text(clean_untrusted(value)))
        tools = sorted({str(t) for t in (state.get("tools_used") or []) if t})
        if tools:
            table.add_row(Text("tools"),
                          Text(clean_untrusted(" · ".join(tools)), style="meta"))
        table.add_row(Text("artifacts"),
                      self._artifacts_text(out_path))
        table.add_row(Text("gate"), self._gate_text(fail_on, min_confidence,
                                                    not gated))
        table.add_row(Text("time"), Text(duration_s(elapsed)))

        console.print(table)
        if gated:
            for line in self._gate_detail_texts(gated[:5]):
                console.print(line)
        console.print(Rule(style="meta"))
        console.print(self._hint_text(out_path))
        _flush(console)

    # -- receipt pieces ------------------------------------------------------

    def _severity_text(self, findings: list[dict], gated: int) -> Any:
        counts = _severity_counts(findings)
        if not findings:
            return Text("✓ no findings", style="empty")
        text = Text()
        first = True
        for sev in _SEVERITIES:
            count = counts.get(sev, 0)
            if not count:
                continue
            if not first:
                text.append(" · ", style="meta")
            text.append(f"{count} {sev}", style=SEVERITY_STYLE.get(sev, ""))
            first = False
        if first:
            text.append("0 findings", style="meta")
        if gated:
            text.append(f"  ({gated} gated)", style="meta")
        return text

    def _artifacts_text(self, out_path: Path) -> Any:
        text = Text(clean_untrusted(short_path(out_path)))
        present = [label for name, label in _ARTIFACTS
                   if _is_file(out_path / name)]
        if present:
            text.append("  " + " · ".join(present), style="meta")
        return text

    def _gate_text(self, fail_on: str, min_confidence: float,
                   passed: bool) -> Any:
        text = Text()
        text.append(f"fail-on={clean_untrusted(fail_on)} · min-conf "
                    f"{_fmt_conf(min_confidence)}", style="meta")
        text.append("  ")
        if passed:
            text.append("✓ PASS", style="gate.pass")
        else:
            text.append("✗ FAIL", style="gate.fail")
        return text

    def _gate_detail_texts(self, gated: list[dict]) -> list[Any]:
        lines = []
        for finding in gated:
            sev = str(finding.get("severity") or "info").strip().lower()
            cwe = clean_untrusted(finding.get("cwe") or "?")
            location = clean_untrusted(
                f"{finding.get('path', '?')}:{finding.get('start_line', '?')}")
            title = clean_untrusted(finding.get("title") or "")
            line = Text()
            line.append("✗ ", style="err")
            line.append(f"{sev} ", style=SEVERITY_STYLE.get(sev, ""))
            line.append(f"{cwe} {location}")
            if title:
                line.append(" " + title)
            lines.append(line)
        return lines

    def _hint_text(self, out_path: Path) -> Any:
        raw = str(out_path)
        return Text(clean_untrusted(
            f"open {raw}/report.html  ·  harness inspect {raw}"), style="meta")


# Module helpers -------------------------------------------------------------


def _fmt_conf(value: Any) -> str:
    try:
        return f"{float(value):g}"
    except (TypeError, ValueError):
        return str(value)


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _console_width(console: Any) -> int:
    try:
        return int(console.width)
    except Exception:
        return 80


def _flush(console: Any) -> None:
    try:
        console.file.flush()
    except Exception:
        pass


def build_reporter(no_color: bool = False,
                   agent_log: str = "normal") -> ScanReporter:
    """Build the scan reporter (rich-only rendering is always available)."""
    return ScanReporter(no_color=no_color, agent_log=agent_log)


def render_confirmation(console: Any, payload: dict, *, limit: int = 20) -> None:
    """Compact findings table for the human-review prompt."""
    findings = payload.get("findings") if isinstance(payload, dict) else None
    findings = [f for f in (findings or []) if isinstance(f, dict)][:limit]
    console.print(Text("HUMAN REVIEW REQUIRED (confirmed critical/high)",
                       style="warn"))
    if not findings:
        console.print(Text("(no finding rows in payload)", style="meta"))
        return
    table = Table(box=None, show_header=True, pad_edge=False)
    table.add_column("Sev", no_wrap=True)
    table.add_column("CWE", no_wrap=True)
    table.add_column("Location", overflow="fold")
    table.add_column("Conf", justify="right", no_wrap=True)
    table.add_column("Title", overflow="fold")
    for finding in findings:
        sev = str(finding.get("severity") or "medium").strip().lower()
        try:
            confidence = f"{float(finding.get('confidence', 0) or 0):.2f}"
        except (TypeError, ValueError):
            confidence = "?"
        table.add_row(
            Text(clean_untrusted(sev.upper()),
                 style=SEVERITY_STYLE.get(sev, "")),
            Text(clean_untrusted(finding.get("cwe") or "?")),
            Text(clean_untrusted(
                f"{finding.get('path', '?')}:{finding.get('start_line', '?')}")),
            Text(confidence),
            Text(clean_untrusted(finding.get("title") or "")),
        )
    console.print(table)


__all__ = ["ScanReporter", "build_reporter", "duration_s", "short_path",
           "render_confirmation", "STAGE_WIDTH", "AGENT_WIDTH"]
