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
    if not isinstance(raw, dict):
        raise ValueError(
            f"config file must contain a YAML mapping; got "
            f"{type(raw).__name__} from {path}")
    cfg = _interpolate(raw)
    # Resolve the key via api_key_env pointer; never log its value.
    key_env = cfg.get("api_key_env", "API_KEY")
    cfg["api_key_present"] = bool(os.environ.get(key_env))
    return cfg


def load_config_safe(path: str | Path = "config/default.yaml") -> tuple[dict, Exception | None]:
    """load_config() that never raises: returns ``(cfg, error)``. A config parse
    or read failure is an operator error and must be surfaced, not silently
    masked: callers print/log ``error``; ``cfg`` degrades to ``{}`` so the
    no-key path remains the single fallthrough. Call this instead of the
    ``try: load_config() / except: cfg = {}`` pattern."""
    try:
        return load_config(path), None
    except Exception as exc:
        return {}, exc


EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")
EFFORT_RANK = {name: i for i, name in enumerate(EFFORT_LEVELS)}


def get_effort(cfg: dict) -> str:
    """Effort level; defaults to ``max`` when unset or unknown."""
    eff = str((cfg or {}).get("effort", "max") or "max").strip().lower()
    return eff if eff in EFFORT_RANK else "max"


def meets_effort(cfg: dict, level: str) -> bool:
    """True when configured effort reaches at least `level`."""
    return EFFORT_RANK.get(get_effort(cfg), 4) >= EFFORT_RANK.get(level, 4)


def api_key_present(cfg: dict | None = None) -> bool:
    """True when a key is configured (honors api_key_env as well as API_KEY)."""
    cfg = cfg or {}
    try:
        key_env = str(cfg.get("api_key_env", "API_KEY") or "API_KEY")
    except Exception:
        key_env = "API_KEY"
    return bool(os.environ.get(key_env) or os.environ.get("API_KEY"))


def get_concurrency(cfg: dict) -> int:
    """The single concurrency knob: caps hunter fan-out, the validator pool,
    and the legacy hunter pool."""
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


# Reasoning effort is passed through verbatim; the backend accepts
# low/medium/high/xhigh/max (verified live), and no token caps are set.


def get_reasoning_kwargs(cfg: dict, agent: str | None = None) -> dict:
    """Thinking-effort params; effort_by_agent{hunter,validator,partitioner} wins over the
    global effort level."""
    cfg = cfg or {}
    level = ""
    if agent:
        by = cfg.get("effort_by_agent", {}) or {}
        level = str(by.get(agent, "") or "").strip().lower()
    if level not in EFFORT_RANK:
        level = get_effort(cfg)
    return {"reasoning_effort": level}


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    """Read an integer from the process environment, falling back safely."""
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        value = default
    else:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = default
    return max(minimum, int(value))


def get_harness_timeout(default: int = 60) -> int:
    """HARNESS_TIMEOUT in seconds, read directly from the environment."""
    return _env_int("HARNESS_TIMEOUT", default, minimum=1)


def get_harness_max_retries(default: int = 5) -> int:
    """HARNESS_MAX_RETRIES, read directly from the environment."""
    return _env_int("HARNESS_MAX_RETRIES", default, minimum=0)


def get_model_kwargs(cfg: dict, role: str, agent: str | None = None) -> dict:
    """ChatOpenAI kwargs for hunter|validator, incl. reasoning_effort; no
    langchain import happens here."""
    model_key = f"{role}_model"
    model_name = ""
    # Check agent-specific override first (e.g. PARTITIONER_MODEL, TRIAGE_MODEL, THREAT_MODEL)
    if agent:
        agent_env = f"{agent.upper().replace('-', '_')}_MODEL"
        model_name = os.environ.get(agent_env, "")
    if not model_name:
        model_name = os.environ.get(model_key.upper(), cfg.get(model_key, ""))

    base_url = os.environ.get("OPENAI_BASE_URL") or os.environ.get("BASE_URL", cfg.get("base_url", ""))
    api_key_name = cfg.get("api_key_env", "API_KEY")
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get(api_key_name, "")

    out = {
        "base_url": base_url,
        "api_key": api_key,
        "model": model_name,
        "timeout": int(os.environ.get("HARNESS_TIMEOUT", cfg.get("timeout", 60))),
        "max_retries": int(os.environ.get("HARNESS_MAX_RETRIES", cfg.get("max_retries", 5))),
        # Model-profile pins for a proxied base_url model (which ships no
        # profile data); consumed by make_llm as the ctor ``profile=``.
        "model_profile": (cfg.get("model_profile")
                          if isinstance(cfg.get("model_profile"), dict)
                          else {}),
    }
    out.update(get_reasoning_kwargs(cfg, agent or role))
    return out
