"""Config loading with env interpolation. Never logs secrets."""
from __future__ import annotations

import copy
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

_ENV_PATTERN = re.compile(r"\$\{([^}:]+)(?::-([^}]*))?\}")

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "config" / "default.yaml"
DEFAULT_DOTENV_PATH = Path(__file__).resolve().parent / ".env"


def _interpolate(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            name, default = m.group(1), m.group(2)
            env_value = os.environ.get(name)
            if env_value:
                return env_value
            if default is not None:
                return default
            return ""
        return _ENV_PATTERN.sub(repl, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


def _load_dotenv(path: Path | str = DEFAULT_DOTENV_PATH) -> None:
    if "pytest" in sys.modules or os.environ.get("PYTEST_CURRENT_TEST"):
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


def _read_config(config_path: Path, *, interpolate: bool = True) -> dict:
    raw = yaml.safe_load(config_path.read_text())
    if not isinstance(raw, dict):
        raise ValueError(
            f"config file must contain a YAML mapping; got "
            f"{type(raw).__name__} from {config_path}")
    return _interpolate(raw) if interpolate else raw


_RAW_DEFAULT: dict | None = None


def _raw_default_config() -> dict:
    """The packaged YAML, parsed once per process and never interpolated.

    ``harness/config/default.yaml`` is a repo invariant; a missing/unreadable
    file is a broken install, so it raises once with a message naming the file
    instead of failing later at every call site. Callers that need fresh
    ``${ENV}`` interpolation deepcopy this tree first.
    """
    global _RAW_DEFAULT
    if _RAW_DEFAULT is None:
        try:
            _RAW_DEFAULT = _read_config(DEFAULT_CONFIG_PATH, interpolate=False)
        except Exception as exc:
            raise RuntimeError(
                "harness/config/default.yaml is a repo invariant and is "
                f"missing/unreadable: {exc}") from exc
    return _RAW_DEFAULT


def _dotted(node: Any, path: list[str]) -> Any:
    """Walk a nested mapping; a missing/non-mapping node yields None."""
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def as_bool(value: Any, default: bool = False) -> bool:
    """Lenient bool: real bools, ``"1/true/yes/on"`` strings, numbers.

    ``None``/``""`` yield ``default``; anything else is parsed from its string
    form, so a YAML/env value that stringifies (``"0"``) still resolves.
    Accepts ``on`` — a deliberate widening over some pre-refactor call sites
    that only recognized ``1/true/yes``.
    """
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def int_setting(cfg: dict | None, key: str, *, fallback_path: str,
                minimum: int = 0, maximum: int | None = None,
                zero_is_unlimited: bool = False) -> int:
    """A clamped integer setting at dotted ``key`` (cfg wins) with a YAML fallback.

    Values are parsed from their stripped string form (env interpolation
    stringifies YAML); a malformed or empty value uses ``fallback_path``'s
    default, so an operator typo degrades instead of blocking. ``0`` (or a
    negative) yields the MED unlimited sentinel only when
    ``zero_is_unlimited``; otherwise the result is clamped to the bounds.
    """
    fallback = int(config_default(fallback_path))
    raw = _dotted(cfg if isinstance(cfg, dict) else {}, key.split("."))
    if raw is None:
        raw = fallback
    try:
        value = int(str(raw).strip() or fallback)
    except (TypeError, ValueError):
        value = fallback
    if zero_is_unlimited and value <= 0:
        return 10**9
    value = max(minimum, value)
    return value if maximum is None else min(maximum, value)


def load_config(path: str | Path | None = None) -> dict:
    _load_dotenv()
    return _read_config(Path(path or DEFAULT_CONFIG_PATH))


def load_config_safe(path: str | Path | None = None) -> tuple[dict, Exception | None]:
    """load_config() that never raises: returns ``(cfg, error)``. A config parse
    or read failure is an operator error and must be surfaced, not silently
    masked: callers print/log ``error``; ``cfg`` degrades to ``{}`` so the
    no-key path remains the single fallthrough. Call this instead of the
    ``try: load_config() / except: cfg = {}`` pattern."""
    try:
        return load_config(path), None
    except Exception as exc:
        return {}, exc


def default_config() -> dict:
    """The packaged harness/config/default.yaml, the single source of default values.

    This is for callers that have no cfg to
    thread (direct backend construction); scan paths pass the cfg they loaded
    once. Loads ``.env`` first, with the same precedence as ``load_config``:
    process environment > ``.env`` > ``${VAR:-default}`` in the YAML. The raw
    tree is parsed once and copied, so interpolation still reads the current
    environment per call.
    """
    _load_dotenv()
    return _interpolate(copy.deepcopy(_raw_default_config()))


def config_default(path: str) -> Any:
    """A default from harness/config/default.yaml by dotted path (``"partition.min_files"``).

    Use this instead of duplicating the default literal at a call site. The
    file is a repo invariant; a missing path returns None. Precedence is
    process environment > ``.env`` > the YAML ``${VAR:-default}`` value. The
    returned subtree is freshly allocated per call.
    """
    _load_dotenv()
    subtree = copy.deepcopy(_dotted(_raw_default_config(), path.split(".")))
    return _interpolate(subtree)


def get_default_config(path: str) -> Any:
    """A setting from harness/.env or harness/config/default.yaml."""
    val = config_default(path)
    if val is not None:
        return val
    node = _dotted(_raw_default_config(), path.split("."))
    if isinstance(node, str):
        match = _ENV_PATTERN.fullmatch(node)
        if match:
            return match.group(2) if match.group(2) is not None else ""
    return node


EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")
EFFORT_RANK = {name: i for i, name in enumerate(EFFORT_LEVELS)}


def get_effort(cfg: dict) -> str:
    """Effort level"""
    _load_dotenv()
    fallback = str(config_default("effort")).strip().lower()
    from_env = str(os.environ.get("EFFORT", "")).strip().lower()
    if from_env in EFFORT_RANK:
        return from_env
    eff = str((cfg or {}).get("effort", fallback) or fallback).strip().lower()
    return eff if eff in EFFORT_RANK else fallback


def meets_effort(cfg: dict, level: str) -> bool:
    """True when configured effort reaches at least `level`."""
    return EFFORT_RANK.get(get_effort(cfg), 4) >= EFFORT_RANK.get(level, 4)


def resolve_api_key(cfg: dict | None = None) -> str:
    """The API key source: env ``API_KEY`` only."""
    _load_dotenv()
    return os.environ.get("API_KEY", "")


def api_key_present(cfg: dict | None = None) -> bool:
    """True when ``API_KEY`` is configured; delegates to ``resolve_api_key``."""
    return bool(resolve_api_key(cfg))


def get_concurrency(cfg: dict) -> int:
    """The single concurrency knob: caps hunter fan-out, the validator pool,
    and the legacy hunter pool.
    """
    cfg = cfg or {}
    fallback = config_default("concurrency")
    raw = cfg.get("concurrency", fallback)
    if isinstance(raw, dict):
        vals = []
        for v in raw.values():
            try:
                vals.append(int(v or 0))
            except (TypeError, ValueError):
                continue
        raw = max(vals) if vals else fallback
    return int_setting({"concurrency": raw or fallback}, "concurrency",
                       fallback_path="concurrency", minimum=1, maximum=32)


# Reasoning effort is passed through verbatim; the backend accepts
# low/medium/high/xhigh/max (verified live), and no token caps are set.


def get_reasoning_kwargs(cfg: dict, agent: str | None = None) -> dict:
    """Thinking-effort params. Environment variables or ``effort_by_agent``
    (hunter, validator, triager, partitioner, threat) win over global effort."""
    _load_dotenv()
    cfg = cfg or {}
    level = ""
    if agent:
        clean_name = str(agent).upper().replace("-", "_")
        env_val = os.environ.get(f"{clean_name}_EFFORT", "").strip().lower()
        if not env_val and clean_name in ("TRIAGER", "TRIAGE", "SYNTHESIS"):
            env_val = (os.environ.get("TRIAGER_EFFORT")
                       or os.environ.get("TRIAGE_EFFORT")
                       or os.environ.get("SYNTHESIS_EFFORT")
                       or "").strip().lower()
        if env_val in EFFORT_RANK:
            level = env_val
        else:
            by = cfg.get("effort_by_agent")
            if not isinstance(by, dict):
                by = config_default("effort_by_agent") or {}
            level = str(by.get(agent, "") or "").strip().lower()
    if level not in EFFORT_RANK:
        level = get_effort(cfg)
    return {"reasoning_effort": level}


DEFAULT_TIMEOUT = int(get_default_config("timeout"))
DEFAULT_MAX_RETRIES = int(get_default_config("max_retries"))
DEFAULT_CONNECT_TIMEOUT = int(get_default_config("connect_timeout"))
DEFAULT_RECURSION_LIMIT = int(get_default_config("recursion_limit"))


def _int_or_none(value: Any) -> int | None:
    """Best-effort integer (bool/garbage/empty -> None); never raises."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        pass
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None


def _cfg_or_yaml_int(cfg: dict | None, key: str) -> int | None:
    """``cfg[key]`` as an int, else the anchored YAML's value, else None.

    A missing/empty ``cfg`` falls back to the anchored ``load_config_safe()``;
    any load error or non-integer value yields None so callers apply their
    emergency constant. Never raises."""
    if isinstance(cfg, dict):
        value = _int_or_none(cfg.get(key))
        if value is not None:
            return value
    try:
        loaded, _error = load_config_safe()
    except Exception:
        return None
    if not isinstance(loaded, dict):
        return None
    return _int_or_none(loaded.get(key))


_DEFAULT_BUDGETS = {"timeout": DEFAULT_TIMEOUT, "max_retries": DEFAULT_MAX_RETRIES}


def _budget_default(cfg: dict | None, cfg_key: str, floor: int) -> int:
    """YAML ``<cfg_key>`` (cfg wins) clamped to ``floor``; the packaged constant
    when unreadable."""
    value = _cfg_or_yaml_int(cfg, cfg_key)
    if value is None:
        value = _DEFAULT_BUDGETS[cfg_key]
    return max(floor, value)


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


def _resolve_budget(env_name: str, mk_key: str, cfg_key: str, floor: int,
                    mk: dict | None, cfg: dict | None) -> int:
    """One LLM-call budget: process env > model kwargs > cfg/YAML default."""
    from_env = _int_or_none(os.environ.get(env_name))
    if from_env is not None:
        return max(floor, from_env)
    if isinstance(mk, dict):
        from_mk = _int_or_none(mk.get(mk_key))
        if from_mk is not None:
            return max(floor, from_mk)
    return _budget_default(cfg, cfg_key, floor)


def resolve_call_timeout(mk: dict | None, cfg: dict | None = None) -> int:
    """Timeout for one LLM call."""
    return _resolve_budget("HARNESS_TIMEOUT", "timeout", "timeout", 1, mk, cfg)


def resolve_call_retries(mk: dict | None, cfg: dict | None = None) -> int:
    """Retries for one LLM call"""
    return _resolve_budget("HARNESS_MAX_RETRIES", "max_retries",
                           "max_retries", 0, mk, cfg)


def resolve_recursion_limit(cfg: dict | None = None) -> int:
    """Max LangGraph supersteps per agent, ONE value for every agent."""
    _load_dotenv()
    from_env = _int_or_none(os.environ.get("RECURSION_LIMIT"))
    if from_env is not None:
        return max(1, from_env)
    value = _cfg_or_yaml_int(cfg, "recursion_limit")
    return DEFAULT_RECURSION_LIMIT if value is None else max(1, value)


def get_harness_connect_timeout(default: int | None = None) -> int:
    """Connect-leg timeout."""
    if default is not None:
        base = _int_or_none(default)
    else:
        base = _cfg_or_yaml_int(None, "connect_timeout")
    if base is None:
        base = DEFAULT_CONNECT_TIMEOUT
    return _env_int("HARNESS_CONNECT_TIMEOUT", max(1, base), minimum=1)


def effective_model(cfg: dict | None, role: str,
                    agent: str | None = None) -> str:
    """The model name actually used for ``agent`` under ``role``."""
    _load_dotenv()
    cfg = cfg or default_config()
    model_key = f"{role}_model"
    agent_env = agent_key = ""
    if agent:
        agent_env = f"{agent.upper().replace('-', '_')}_MODEL"
        agent_key = f"{agent}_model"
    model_name = (
        (os.environ.get(agent_env, "") if agent_env else "")
        or (cfg.get(agent_key, "") if agent_key else "")
        or os.environ.get(model_key.upper(), "")
        or cfg.get(model_key, "")
        or ""
    )
    return str(model_name or "")


def get_model_kwargs(cfg: dict, role: str, agent: str | None = None) -> dict:
    """ChatOpenAI kwargs for an agent, incl. reasoning_effort; no langchain
    import happens here.

    Empty values never shadow the next source."""
    cfg = cfg or default_config()
    model_name = effective_model(cfg, role, agent)

    role_key = (agent or role or "").upper().replace("-", "_")
    base_url = (os.environ.get(f"{role_key}_BASE_URL", "")
                or os.environ.get("BASE_URL", "")
                or cfg.get("base_url", "")
                or config_default("base_url") or "")
    api_key = (os.environ.get(f"{role_key}_API_KEY", "")
               or resolve_api_key(cfg))

    # Auto-route provider base_url and api_key based on model name if not explicitly set
    if not os.environ.get(f"{role_key}_BASE_URL"):
        if "nemotron" in model_name.lower() or model_name.startswith("nvidia/"):
            base_url = os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
            if not os.environ.get(f"{role_key}_API_KEY"):
                api_key = os.environ.get("NVIDIA_API_KEY") or api_key
        elif "muse" in model_name.lower() or "spark" in model_name.lower():
            base_url = os.environ.get("META_BASE_URL", "https://api.meta.ai/v1")
            if not os.environ.get(f"{role_key}_API_KEY"):
                api_key = os.environ.get("META_API_KEY") or api_key

    profile = cfg.get("model_profile")
    if not isinstance(profile, dict):
        profile = config_default("model_profile")
    out = {
        "base_url": base_url,
        "api_key": api_key,
        "model": model_name,
        "timeout": resolve_call_timeout(None, cfg),
        "max_retries": resolve_call_retries(None, cfg),
        # Model-profile pins for a proxied base_url model (which ships no
        # profile data); consumed by make_llm as the ctor ``profile=``.
        "model_profile": profile if isinstance(profile, dict) else {},
    }
    out.update(get_reasoning_kwargs(cfg, agent or role))
    return out
