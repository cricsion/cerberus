from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, Protocol, runtime_checkable

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
    cancel_token: Any = None
    stats: AgentStats = None
    error: Optional[str] = None
    parent_stage: str = ""
    run_id: str = ""

    def __post_init__(self):
        if self.cancel_token is None:
            self.cancel_token = threading.Event()
        if self.stats is None:
            self.stats = AgentStats()
        try:
            self.state = AgentState.normalize(self.state)
        except Exception:
            pass

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
            "state": (self.state.value if hasattr(self.state, "value")
                      else str(self.state)),
            "model": self.model,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_s": round(self.elapsed_s, 3),
            "thread_id": self.thread_id,
            "stats": self.stats.to_dict() if hasattr(self.stats, "to_dict")
            else asdict(self.stats) if hasattr(self.stats, "__dataclass_fields__")
            else dict(self.stats or {}),
            "error": self.error,
            "parent_stage": self.parent_stage,
            "run_id": self.run_id,
            "canceled": bool(self.cancel_token.is_set()) if hasattr(
                self.cancel_token, "is_set") else False,
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
        try:
            self.state = AgentState.normalize(self.state)
        except Exception:
            pass
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
            "state": (self.state.value if hasattr(self.state, "value")
                      else str(self.state)),
            "message": self.message,
            "progress": self.progress or {},
            "model": self.model,
            "error": self.error,
            "elapsed_s": self.elapsed_s,
        }

    def to_json(self, **kw):
        return json.dumps(self.to_dict(), **kw)

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def __getitem__(self, key):
        return self.to_dict()[key]

    def keys(self):
        return self.to_dict().keys()

    def __contains__(self, key):
        return key in self.to_dict()

    def __iter__(self):
        return iter(self.to_dict())

    def __eq__(self, other):
        if isinstance(other, AgentEvent):
            return self.to_dict() == other.to_dict()
        if isinstance(other, dict):
            return self.to_dict() == other
        return NotImplemented

    def __str__(self):
        return json.dumps(self.to_dict())

@runtime_checkable
class ProgressSink(Protocol):
    def on_event(self, event):
        ...

class PlainSink:
    def __init__(self, stream=None, fmt="[agents] {agent_id} {state} {message}"):
        self.stream = stream
        self.fmt = fmt

    def on_event(self, event):
        d = event.to_dict() if hasattr(event, "to_dict") else dict(event or {})
        try:
            line = self.fmt.format(**d)
        except Exception:
            line = "[agents] %s %s %s" % (
                d.get("agent_id", "?"), d.get("state", "?"),
                d.get("message", ""))
        tail = ""
        if d.get("unit"):
            tail += " unit=%s" % d["unit"]
        if d.get("model"):
            tail += " model=%s" % d["model"]
        if d.get("error"):
            tail += " error=%s" % d["error"]
        out = line + tail
        stream = self.stream
        if stream is None:
            import sys as _sys
            stream = _sys.stderr
        try:
            stream.write(out + "\n")
            stream.flush()
        except Exception:
            try:
                print(out)
            except Exception:
                pass

class RichLiveSink:
    def __init__(self, console=None, max_events=1000):
        self.console = console
        self.max_events = int(max_events)
        self.events = []
        self.latest = {}
        self._lock = threading.Lock()

    def on_event(self, event):
        d = event.to_dict() if hasattr(event, "to_dict") else dict(event or {})
        with self._lock:
            self.events.append(d)
            if len(self.events) > self.max_events:
                del self.events[: len(self.events) - self.max_events]
            aid = d.get("agent_id")
            if aid is not None:
                self.latest[aid] = d

    def snapshot(self):
        with self._lock:
            return dict(self.latest), list(self.events)

class AgentRegistry:
    def __init__(self, run_id="", *, sink=None, on_event=None,
                 progress_sink=None, events_path=None, **kw):
        self.run_id = run_id or (kw.get("run_id") if isinstance(kw.get("run_id"), str) else "")
        self._lock = threading.RLock()
        self._agents = {}
        self._order = []
        self.events = []
        self.sink = progress_sink if progress_sink is not None else sink
        if self.sink is None and "sink" in kw:
            self.sink = kw.get("sink")
        self.on_event = on_event
        if self.on_event is None and "callback" in kw:
            self.on_event = kw.get("callback")
        if self.sink is None and callable(self.on_event) and hasattr(self.on_event, "on_event"):
            self.sink, self.on_event = self.on_event, None
        # Cross-bin agent visibility: append events to this JSONL path when set.
        _ep = events_path
        if _ep is None:
            for _key in ("events_path", "agents_path", "jsonl_path",
                         "persist_path", "agents_jsonl"):
                if _key in kw and kw.get(_key) is not None:
                    _ep = kw.get(_key)
                    break
        self.events_path = None
        if _ep is not None:
            try:
                from pathlib import Path as _Path
                self.events_path = _Path(_ep)
            except Exception:
                self.events_path = _ep
        # PID tracking for the owning scan process (best-effort).
        try:
            self.pid = kw.get("pid", None)
            if self.pid is None:
                import os as _os
                self.pid = _os.getpid()
        except Exception:
            self.pid = None

    def create(self, agent_id, role, unit=None, *, model=None, parent_stage="",
               state=AgentState.pending, thread_id=None, run_id=None,
               message="", emit=True, **stats_kwargs):
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
            evt = None
            if emit:
                evt = self._make_event(handle, AgentState.normalize(state),
                                       message=message or "created",
                                       progress=_stats_progress(handle))
                self.events.append(evt)
        if emit and evt is not None:
            self._dispatch(evt)
        return handle

    def get(self, agent_id):
        aid = _agent_id(agent_id)
        with self._lock:
            return self._agents.get(aid)

    def all(self):
        with self._lock:
            return [self._agents[aid] for aid in self._order if aid in self._agents]

    def transition(self, agent_id, state, *, message="", error=None, model=None,
                   progress=None, ts=None, emit=True, **kw):
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
            if new_state in TERMINAL_STATES and handle.finished_at is None:
                handle.finished_at = now
            if handle.thread_id is None:
                try:
                    handle.thread_id = threading.get_ident()
                except Exception:
                    pass
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
            if emit:
                prog = progress if isinstance(progress, dict) else _stats_progress(handle)
                if not isinstance(prog, dict):
                    prog = _stats_progress(handle)
                evt = self._make_event(handle, new_state,
                                       message=message or str(new_state.value),
                                       progress=prog, error=handle.error,
                                       model=handle.model)
                self.events.append(evt)
        if emit and evt is not None:
            self._dispatch(evt)
        return handle

    def update_stats(self, agent_id, *positional, **kw):
        aid = _agent_id(agent_id)
        updates = {}
        for p in positional:
            if isinstance(p, dict):
                updates.update(p)
        updates.update(kw)
        if "stats" in updates and isinstance(updates["stats"], dict):
            updates.update(updates.pop("stats"))
        handle = None
        evt = None
        with self._lock:
            handle = self._agents.get(aid)
            if handle is None:
                handle = AgentHandle(agent_id=aid, role="agent", run_id=self.run_id)
                self._agents[aid] = handle
                if aid not in self._order:
                    self._order.append(aid)
            inc_tc = updates.get("tool_calls", updates.get("tool_calls_increment", 0))
            inc_fr = updates.get("files_read", updates.get("files_read_increment", 0))
            inc_fp = updates.get("findings_produced", updates.get("findings_produced_increment", 0))
            absolute = bool(updates.get("absolute", False) or updates.get("set", False))
            if absolute:
                handle.stats.tool_calls = int(inc_tc or 0)
                handle.stats.files_read = int(inc_fr or 0)
                handle.stats.findings_produced = int(inc_fp or 0)
            else:
                handle.stats.increment(tool_calls=inc_tc or 0,
                                      files_read=inc_fr or 0,
                                      findings_produced=inc_fp or 0)
            for k, v in updates.items():
                if k in ("tool_calls", "files_read", "findings_produced",
                         "absolute", "set", "agent_id", "message"):
                    continue
                try:
                    if hasattr(handle.stats, k):
                        setattr(handle.stats, k, v)
                except Exception:
                    pass
            if updates.get("emit", True):
                evt = self._make_event(handle, AgentState.normalize(handle.state),
                                       message=updates.get("message", "progress"),
                                       progress=_stats_progress(handle),
                                       model=handle.model, error=handle.error)
                self.events.append(evt)
        if evt is not None and updates.get("emit", True):
            self._dispatch(evt)
        return handle

    def emit(self, event=None, **kw):
        evt = None
        with self._lock:
            if event is None:
                aid = _agent_id(kw.get("agent_id") or kw.get("id") or kw.get("agent"))
                handle = self._agents.get(aid) if aid else None
                state = kw.get("state", handle.state if handle else AgentState.pending)
                evt = self._make_event(
                    handle if handle else _handle_from_kw(kw, self.run_id),
                    state,
                    parent_stage=kw.get("parent_stage", handle.parent_stage if handle else ""),
                    role=kw.get("role", handle.role if handle else "agent"),
                    unit=kw.get("unit", handle.unit if handle else None),
                    run_id=kw.get("run_id", self.run_id),
                    model=kw.get("model", handle.model if handle else None),
                    message=kw.get("message", ""),
                    progress=kw.get("progress", _stats_progress(handle) if handle else {}),
                    error=kw.get("error", handle.error if handle else None),
                    ts=kw.get("ts"),
                    elapsed_s=kw.get("elapsed_s"),
                    agent_id=aid if aid else kw.get("agent_id"),
                )
            elif isinstance(event, AgentEvent):
                evt = event
                if not evt.run_id and self.run_id:
                    evt.run_id = self.run_id
            elif isinstance(event, dict):
                evt = AgentEvent(**{k: v for k, v in event.items()
                                   if k in AgentEvent.__dataclass_fields__})
                if not evt.run_id and self.run_id:
                    evt.run_id = self.run_id
            else:
                evt = self._make_event(event if isinstance(event, AgentHandle) else None,
                                       kw.get("state", AgentState.pending),
                                       **{k: v for k, v in kw.items() if k != "state"})
            if evt is not None:
                if not evt.run_id:
                    evt.run_id = self.run_id
                self.events.append(evt)
        if evt is not None:
            self._dispatch(evt)
        return evt

    @staticmethod
    def read_events(path) -> list:
        out = []
        try:
            from pathlib import Path as _Path
            import json as _json
            p = _Path(path)
            if not p.is_file():
                return out
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(_json.loads(line))
                except Exception:
                    continue
        except Exception:
            pass
        return out

    @staticmethod
    def poll_events(path, *, since=0):
        evs = AgentRegistry.read_events(path)
        try:
            since = int(since or 0)
        except Exception:
            since = 0
        if since < 0:
            since = 0
        return evs[since:]

    def dump(self):
        with self._lock:
            return [h.to_dict() for h in self.all()]

    def summary(self):
        handles = self.all()
        by_state = {}
        by_role = {}
        for h in handles:
            st = h.state.value if hasattr(h.state, "value") else str(h.state)
            by_state[st] = by_state.get(st, 0) + 1
            by_role[h.role] = by_role.get(h.role, 0) + 1
        failed = [h.agent_id for h in handles
                  if (h.state.value if hasattr(h.state, "value") else str(h.state)) == AgentState.failed.value]
        running = [h.agent_id for h in handles
                   if (h.state.value if hasattr(h.state, "value") else str(h.state)) == AgentState.running.value]
        return {
            "total": len(handles),
            "by_state": by_state,
            "by_role": by_role,
            "failed": failed,
            "running": running,
            "run_id": self.run_id,
        }

    counts = summary

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
            if handle is not None:
                try:
                    elapsed_s = handle.elapsed_s
                except Exception:
                    elapsed_s = 0.0
            else:
                elapsed_s = 0.0
        prog = progress if isinstance(progress, dict) else {}
        if prog is None:
            prog = {}
        try:
            prog = dict(prog)
        except Exception:
            prog = {}
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
        path = getattr(self, "events_path", None)
        if not path:
            return
        try:
            import json as _json
            from pathlib import Path as _Path
            p = _Path(path)
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
            d = evt.to_dict() if hasattr(evt, "to_dict") else (evt if isinstance(evt, dict) else {})
            with p.open("a", encoding="utf-8") as f:
                f.write(_json.dumps(d) + "\n")
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

def _handle_from_kw(kw, run_id):
    aid = _agent_id(kw.get("agent_id") or kw.get("id") or kw.get("agent"))
    if not aid:
        return None
    return AgentHandle(agent_id=aid, role=str(kw.get("role", "agent")),
                      unit=kw.get("unit"), model=kw.get("model"),
                      parent_stage=kw.get("parent_stage", ""),
                      run_id=run_id or kw.get("run_id", ""))

def _stats_progress(handle):
    if handle is None or not hasattr(handle, "stats"):
        return {}
    st = getattr(handle, "stats", None)
    if hasattr(st, "to_dict"):
        return st.to_dict()
    if hasattr(st, "__dataclass_fields__"):
        return asdict(st)
    try:
        return dict(st)
    except Exception:
        return {}

__all__ = ["AgentState", "AgentStats", "AgentHandle", "AgentEvent",
           "AgentRegistry", "ProgressSink", "PlainSink", "RichLiveSink",
           "TERMINAL_STATES"]
