"""Config loading with env interpolation. Never logs secrets."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

_ENV_PATTERN = re.compile(r"\$\{([^}:]+)(?::-([^}]*))?\}")


def _interpolate(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            name, default = m.group(1), m.group(2)
            if name in os.environ:
                return os.environ[name]
            if default is not None:
                return default
            return ""
        return _ENV_PATTERN.sub(repl, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


def _load_dotenv(path: Path | str = ".env") -> None:
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip("'\"")
        if v.startswith("$"):
            var_name = v[1:].strip("{}")
            v = os.environ.get(var_name, v)
        if k not in os.environ or not os.environ[k]:
            os.environ[k] = v


def load_config(path: str | Path = "config/default.yaml") -> dict:
    _load_dotenv()
    raw = yaml.safe_load(Path(path).read_text())
    cfg = _interpolate(raw)
    # Resolve api key via api_key_env pointer without logging value.
    key_env = cfg.get("api_key_env", "API_KEY")
    cfg["api_key_present"] = bool(os.environ.get(key_env))
    return cfg


EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")
EFFORT_RANK = {name: i for i, name in enumerate(EFFORT_LEVELS)}


def get_effort(cfg: dict) -> str:
    """Effort level, default max while testing."""
    eff = str((cfg or {}).get("effort", "max") or "max").strip().lower()
    return eff if eff in EFFORT_RANK else "max"


def meets_effort(cfg: dict, level: str) -> bool:
    """True when configured effort reaches at least `level`."""
    return EFFORT_RANK.get(get_effort(cfg), 4) >= EFFORT_RANK.get(level, 4)


def api_key_present(cfg: dict | None = None) -> bool:
    """True when an API key is configured.

    Honors the api_key_env pointer (custom key env) as well as API_KEY, so a
    scan configured with a non-default key variable does not silently take
    the no-key path in one stage while others proceed.
    """
    cfg = cfg or {}
    try:
        key_env = str(cfg.get("api_key_env", "API_KEY") or "API_KEY")
    except Exception:
        key_env = "API_KEY"
    return bool(os.environ.get(key_env) or os.environ.get("API_KEY"))


def get_concurrency(cfg: dict) -> int:
    """The single concurrency knob: max parallel agents at a time.

    Used for hunter fan-out (LangGraph max_concurrency), the validator pool,
    and the legacy hunter pool. Hunters and validators run in different
    phases, so one value caps concurrent agents everywhere.
    Tolerates legacy shapes (plain int or {hunters, validators} map —
    the map's max wins) but the canonical config is a single number.
    """
    cfg = cfg or {}
    raw = cfg.get("concurrency", 8)
    if isinstance(raw, dict):
        vals = []
        for v in raw.values():
            try:
                vals.append(int(v or 0))
            except (TypeError, ValueError):
                continue
        raw = max(vals) if vals else 8
    try:
        val = max(1, int(raw or 8))
    except (TypeError, ValueError):
        val = 8
    return min(val, 32)


# Thinking effort for models: reasoning depth per level, passed through
# verbatim — our backend accepts low/medium/high/xhigh/max (verified live).
# No token caps anywhere.


def get_reasoning_kwargs(cfg: dict, agent: str | None = None) -> dict:
    """Thinking-effort params. Per-agent override wins over global effort:

    effort_by_agent: {hunter: ..., validator: ..., partitioner: ...}.
    """
    cfg = cfg or {}
    level = ""
    if agent:
        by = cfg.get("effort_by_agent", {}) or {}
        level = str(by.get(agent, "") or "").strip().lower()
    if level not in EFFORT_RANK:
        level = get_effort(cfg)
    return {"reasoning_effort": level}


def get_model_kwargs(cfg: dict, role: str, agent: str | None = None) -> dict:
    """Return ChatOpenAI kwargs for hunter|validator. Lazy — no import here.

    Includes thinking-effort params (reasoning_effort) for the user-set
    effort level; builders forward them into ChatOpenAI.
    """
    model_key = f"{role}_model"
    out = {
        "base_url": os.environ.get("BASE_URL", cfg.get("base_url", "")),
        "api_key": os.environ.get(cfg.get("api_key_env", "API_KEY"), ""),
        "model": os.environ.get(model_key.upper(), cfg.get(model_key, "")),
        "timeout": int(os.environ.get("HARNESS_TIMEOUT", cfg.get("timeout", 60))),
        "max_retries": int(os.environ.get("HARNESS_MAX_RETRIES", cfg.get("max_retries", 3))),
        # Provider-outage fallback list (comma-separated model ids, same
        # provider as this role's primary). Consumed by
        # ``harness.agents.deep._fallback_models``; empty disables it.
        "fallback_models": os.environ.get("FALLBACK_MODELS", cfg.get("fallback_models", "")),
    }
    out.update(get_reasoning_kwargs(cfg, agent or role))
    return out
