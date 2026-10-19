from __future__ import annotations

import functools
import json
import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

_logger = logging.getLogger(__name__)


def _bookkeep_method(fn):
    """Agent-registry bookkeeping must never sink a scan: fatal-class errors
    (provider config errors, harness bugs per is_fatal_error) propagate;
    anything else logs at debug and returns None. This is the single boundary —
    pipeline/cli call sites stay bare (no per-call try/except guards)."""
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        from harness.fallback import run_fail_open  # lazy: fallback → deep imports at call time
        return run_fail_open(
            f"agent-registry.{fn.__name__}",
            lambda: fn(self, *args, **kwargs),
            default=None,
            logger=_logger,
        )
    return wrapper


class AgentState(str, Enum):
    pending = "pending"
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    canceled = "canceled"
    timed_out = "timed-out"

    @classmethod
    def normalize(cls, value):
        if isinstance(value, cls):
            return value
        if value is None:
            return cls.pending
        text = str(value).strip().lower()
        aliases = {"timedout": "timed-out", "timed out": "timed-out",
                   "timeout": "timed-out", "cancelled": "canceled",
                   "complete": "succeeded", "completed": "succeeded",
                   "success": "succeeded", "error": "failed"}
        text = aliases.get(text, text)
        for member in cls:
            if member.value == text or member.name == text:
                return member
        for member in cls:
            if member.value in text or member.name in text:
                return member
        return cls.pending

    @property
    def terminal(self):
        return self in (AgentState.succeeded, AgentState.failed,
                       AgentState.canceled, AgentState.timed_out)

TERMINAL_STATES = {AgentState.succeeded, AgentState.failed,
                   AgentState.canceled, AgentState.timed_out}

def _state_str(state) -> str:
    """One canonical value-string for normalized AgentState handles/events."""
    return state.value if hasattr(state, "value") else str(state)


@dataclass
class AgentStats:
    tool_calls: int = 0
    files_read: int = 0
    findings_produced: int = 0
    last_tool: Optional[str] = None
    last_path: Optional[str] = None

    def to_dict(self):
        return asdict(self)

    def increment(self, *, tool_calls=0, files_read=0,
                  findings_produced=0, **extra):
        self.tool_calls += int(tool_calls or 0)
        self.files_read += int(files_read or 0)
        self.findings_produced += int(findings_produced or 0)
        for k, v in extra.items():
            if hasattr(self, k):
                try:
                    setattr(self, k, getattr(self, k) + int(v or 0))
                except (TypeError, ValueError):
                    setattr(self, k, v)
            else:
                setattr(self, k, v)

@dataclass
class AgentHandle:
    agent_id: str
    role: str
    unit: Optional[str] = None
    state: Any = AgentState.pending
    model: Optional[str] = None
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    thread_id: Optional[int] = None
    stats: AgentStats = None
    error: Optional[str] = None
    parent_stage: str = ""
    run_id: str = ""

    def __post_init__(self):
        if self.stats is None:
            self.stats = AgentStats()
        self.state = AgentState.normalize(self.state)

    @property
    def elapsed_s(self):
        now = time.time()
        start = self.started_at
        end = self.finished_at
        if start is None:
            return 0.0
        return float((end if end is not None else now) - start)

    def to_dict(self):
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "unit": self.unit,
            "state": _state_str(self.state),
            "model": self.model,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_s": round(self.elapsed_s, 3),
            "thread_id": self.thread_id,
            "stats": self.stats.to_dict(),
            "error": self.error,
            "parent_stage": self.parent_stage,
            "run_id": self.run_id,
        }

@dataclass
class AgentEvent:
    ts: float
    run_id: str
    agent_id: str
    parent_stage: str = ""
    role: str = ""
    unit: Optional[str] = None
    state: Any = AgentState.pending
    message: str = ""
    progress: dict = field(default_factory=dict)
    model: Optional[str] = None
    error: Optional[str] = None
    elapsed_s: float = 0.0

    def __post_init__(self):
        self.state = AgentState.normalize(self.state)
        if self.progress is None:
            self.progress = {}
        if not isinstance(self.progress, dict):
            try:
                self.progress = dict(self.progress)
            except Exception:
                self.progress = {"value": self.progress}
        try:
            self.ts = float(self.ts)
        except (TypeError, ValueError):
            self.ts = time.time()
        try:
            self.elapsed_s = float(self.elapsed_s)
        except (TypeError, ValueError):
            self.elapsed_s = 0.0

    def to_dict(self):
        return {
            "ts": self.ts,
            "run_id": self.run_id,
            "agent_id": self.agent_id,
            "parent_stage": self.parent_stage,
            "role": self.role,
            "unit": self.unit,
            "state": _state_str(self.state),
            "message": self.message,
            "progress": self.progress or {},
            "model": self.model,
            "error": self.error,
            "elapsed_s": self.elapsed_s,
        }


class AgentRegistry:
    def __init__(self, run_id="", *, sink=None, on_event=None, events_path=None):
        self.run_id = run_id or ""
        self._lock = threading.RLock()
        self._agents = {}
        self._order = []
        self.events = []
        self.sink = sink
        self.on_event = on_event
        # Cross-process agent visibility: append events to this path when set.
        self.events_path = Path(events_path) if events_path is not None else None

    @_bookkeep_method
    def create(self, agent_id, role, unit=None, *, model=None, parent_stage="",
               state=AgentState.pending, thread_id=None, run_id=None,
               message="", **stats_kwargs):
        aid = str(agent_id)
        effective_run = self.run_id if run_id is None else run_id
        handle = AgentHandle(
            agent_id=aid,
            role=str(role),
            unit=None if unit is None else str(unit),
            state=state,
            model=None if model is None else str(model),
            thread_id=None if thread_id is None else thread_id,
            parent_stage=parent_stage or "",
            run_id=effective_run or self.run_id or "",
        )
        if stats_kwargs:
            try:
                handle.stats.increment(**stats_kwargs)
            except Exception:
                pass
        with self._lock:
            self._agents[aid] = handle
            if aid not in self._order:
                self._order.append(aid)
            evt = self._make_event(handle, AgentState.normalize(state),
                                   message=message or "created",
                                   progress=_stats_progress(handle))
            self.events.append(evt)
        self._dispatch(evt)
        return handle

    def get(self, agent_id):
        aid = _agent_id(agent_id)
        with self._lock:
            return self._agents.get(aid)

    def all(self):
        with self._lock:
            return [self._agents[aid] for aid in self._order if aid in self._agents]

    @_bookkeep_method
    def transition(self, agent_id, state, *, message="", error=None, model=None,
                   progress=None, ts=None, **kw):
        aid = _agent_id(agent_id)
        handle = None
        evt = None
        with self._lock:
            handle = self._agents.get(aid)
            if handle is None:
                handle = AgentHandle(agent_id=aid,
                                     role=str(kw.get("role", "agent")),
                                     unit=kw.get("unit", None),
                                     run_id=self.run_id,
                                     parent_stage=kw.get("parent_stage", ""),
                                     model=None if model is None and kw.get("model") is None else kw.get("model", model))
                self._agents[aid] = handle
                if aid not in self._order:
                    self._order.append(aid)
            new_state = AgentState.normalize(state)
            cur = AgentState.normalize(handle.state)
            if cur.terminal and not new_state.terminal:
                new_state = cur
            if cur.terminal and new_state.terminal and cur != new_state:
                new_state = cur
            now = time.time() if ts is None else float(ts)
            handle.state = new_state
            if model is not None:
                handle.model = None if model is None else str(model)
            elif kw.get("model") is not None and model is None:
                handle.model = str(kw.get("model"))
            if error is not None:
                handle.error = None if error is None else str(error)
            if new_state == AgentState.running and handle.started_at is None:
                handle.started_at = now
            if new_state.terminal and handle.finished_at is None:
                handle.finished_at = now
            if handle.thread_id is None:
                handle.thread_id = threading.get_ident()
            if isinstance(progress, dict):
                try:
                    handle.stats.increment(
                        tool_calls=progress.get("tool_calls", 0) or 0,
                        files_read=progress.get("files_read", 0) or 0,
                        findings_produced=progress.get("findings_produced", 0) or 0,
                    )
                except Exception:
                    pass
            for k in ("tool_calls", "files_read", "findings_produced"):
                if k in kw:
                    try:
                        handle.stats.increment(**{k: kw[k]})
                    except Exception:
                        pass
            prog = progress if isinstance(progress, dict) else _stats_progress(handle)
            if not isinstance(prog, dict):
                prog = _stats_progress(handle)
            evt = self._make_event(handle, new_state,
                                   message=message or str(new_state.value),
                                   progress=prog, error=handle.error,
                                   model=handle.model)
            self.events.append(evt)
        self._dispatch(evt)
        return handle

    def dump(self):
        with self._lock:
            return [h.to_dict() for h in self.all()]

    def summary(self):
        handles = self.all()
        by_state = {}
        by_role = {}
        for h in handles:
            st = _state_str(h.state)
            by_state[st] = by_state.get(st, 0) + 1
            by_role[h.role] = by_role.get(h.role, 0) + 1
        failed = [h.agent_id for h in handles if h.state is AgentState.failed]
        running = [h.agent_id for h in handles
                   if h.state is AgentState.running]
        return {
            "total": len(handles),
            "by_state": by_state,
            "by_role": by_role,
            "failed": failed,
            "running": running,
            "run_id": self.run_id,
        }

    def events_list(self):
        with self._lock:
            return [e.to_dict() for e in self.events]

    def _make_event(self, handle, state, *, parent_stage="", role="", unit=None,
                    run_id=None, model=None, message="", progress=None, error=None,
                    ts=None, elapsed_s=None, agent_id=None, **kw):
        if handle is not None:
            if not parent_stage:
                parent_stage = getattr(handle, "parent_stage", "") or ""
            if not role:
                role = getattr(handle, "role", "") or ""
            if unit is None:
                unit = getattr(handle, "unit", None)
            if model is None:
                model = getattr(handle, "model", None)
            if error is None:
                error = getattr(handle, "error", None)
            if agent_id is None:
                agent_id = getattr(handle, "agent_id", None)
            if run_id is None:
                run_id = getattr(handle, "run_id", None) or self.run_id
        aid = agent_id if agent_id is not None else (handle.agent_id if handle else "")
        rid = run_id if run_id is not None else self.run_id
        if elapsed_s is None:
            elapsed_s = handle.elapsed_s if handle is not None else 0.0
        prog = dict(progress) if isinstance(progress, dict) else {}
        st = AgentState.normalize(state)
        now = time.time() if ts is None else float(ts)
        msg = message
        if kw:
            for k, v in kw.items():
                if k not in ("state",):
                    prog.setdefault(k, v)
        return AgentEvent(
            ts=now,
            run_id=rid or self.run_id or "",
            agent_id=str(aid),
            parent_stage=parent_stage or "",
            role=role or "",
            unit=None if unit is None else str(unit),
            state=st,
            message=msg or "",
            progress=prog,
            model=None if model is None else str(model),
            error=None if error is None else str(error),
            elapsed_s=float(elapsed_s or 0.0),
        )

    def _append_event_to_path(self, evt):
        path = self.events_path
        if not path:
            return
        try:
            p = Path(path)
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
            d = evt.to_dict() if hasattr(evt, "to_dict") else (evt if isinstance(evt, dict) else {})
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps(d) + "\n")
                f.flush()
        except Exception:
            pass

    def _dispatch(self, evt):
        d = evt.to_dict() if hasattr(evt, "to_dict") else evt
        try:
            if self.sink is not None and hasattr(self.sink, "on_event"):
                self.sink.on_event(evt)
        except Exception:
            pass
        try:
            if callable(self.on_event):
                self.on_event(evt)
        except Exception:
            pass
        try:
            if callable(self.sink) and not hasattr(self.sink, "on_event"):
                self.sink(evt)
        except Exception:
            pass
        try:
            self._append_event_to_path(evt)
        except Exception:
            pass

def _agent_id(value):
    if value is None:
        return ""
    if isinstance(value, AgentHandle):
        return value.agent_id
    if isinstance(value, AgentEvent):
        return value.agent_id
    if isinstance(value, dict):
        for key in ("agent_id", "id", "agent"):
            if key in value and value.get(key) is not None:
                return str(value.get(key))
        return str(value.get("agent_id", ""))
    return str(value)

def _stats_progress(handle):
    if handle is None or not hasattr(handle, "stats"):
        return {}
    st = getattr(handle, "stats", None)
    if hasattr(st, "to_dict"):
        return st.to_dict()
    if hasattr(st, "__dataclass_fields__"):
        return asdict(st)
    return dict(st)

__all__ = ["AgentState", "AgentStats", "AgentHandle", "AgentEvent",
           "AgentRegistry", "TERMINAL_STATES"]
