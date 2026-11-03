"""The one config: packaged YAML defaults + environment, resolved once.

``cerberus/config/default.yaml`` is the single source of default values.
``load_config()`` builds a full config from it; ``get_config()`` returns the
process-wide instance (loaded on first use, replaceable via ``set_config``).
Everything downstream reads ``cfg`` instead of re-reading YAML or env.
"""
from __future__ import annotations

import copy
import os
import re
import sys
import threading
from pathlib import Path
from typing import Any

import yaml

_ENV_PATTERN = re.compile(r"\$\{([^}:]+)(?::-([^}]*))?\}")

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "config" / "default.yaml"
DEFAULT_DOTENV_PATH = Path(__file__).resolve().parent / ".env"

_CFG: dict | None = None
_CFG_LOCK = threading.Lock()
_RAW_DEFAULT: dict | None = None


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


def _read_env() -> dict:
    """The process environment, after loading ``cerberus/.env`` (missing-only)."""
    _load_dotenv()
    return dict(os.environ)


def _read_yaml(path: Path | str = DEFAULT_CONFIG_PATH) -> dict:
    """Parse one YAML config file; no env substitution."""
    raw = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        raise ValueError(
            f"config file must contain a YAML mapping; got "
            f"{type(raw).__name__} from {path}")
    return raw


def _raw_default_config() -> dict:
    """The packaged YAML, parsed once per process and never interpolated."""
    global _RAW_DEFAULT
    if _RAW_DEFAULT is None:
        try:
            _RAW_DEFAULT = _read_yaml(DEFAULT_CONFIG_PATH)
        except Exception as exc:
            raise RuntimeError(
                "cerberus/config/default.yaml is a repo invariant and is "
                f"missing/unreadable: {exc}") from exc
    return _RAW_DEFAULT


def _interpolate(value: Any, env: dict) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            name, default = m.group(1), m.group(2)
            env_value = env.get(name)
            if env_value:
                return env_value
            if default is not None:
                return default
            return ""
        return _ENV_PATTERN.sub(repl, value)
    if isinstance(value, dict):
        return {k: _interpolate(v, env) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v, env) for v in value]
    return value


def _defaults(env: dict | None = None) -> dict:
    """The packaged defaults, env-substituted and normalized."""
    env = _read_env() if env is None else env
    return _normalize(_interpolate(copy.deepcopy(_raw_default_config()), env))


def load_config(path: str | Path | None = None, *,
                env: dict | None = None) -> dict:
    """Build one config from YAML defaults and environment.

    Precedence: process environment (or ``env``) > ``.env`` > the YAML
    ``${VAR:-default}`` value. ``path`` is for standalone configs; the
    packaged file is the production source and is parsed once per process.
    """
    env_map = _read_env() if env is None else env
    raw = (copy.deepcopy(_raw_default_config()) if path is None
           else _read_yaml(Path(path)))
    return _normalize(_interpolate(raw, env_map))


_DEFAULT_LOAD_CONFIG = load_config


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        elif isinstance(out.get(key), dict) and not isinstance(value, dict):
            continue
        else:
            out[key] = copy.deepcopy(value)
    return out


_MISSING = object()


def _get_path(node: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


def _set_path(cfg: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    node: Any = cfg
    for part in parts[:-1]:
        if not isinstance(node, dict):
            return
        node = node[part]
    if isinstance(node, dict):
        node[parts[-1]] = value


def _norm_int(value: Any, default: int, *, minimum: int = 0,
              maximum: int | None = None,
              zero_is_unlimited: bool = False) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    if zero_is_unlimited and number <= 0:
        return 10**9
    number = max(minimum, number)
    return number if maximum is None else min(maximum, number)


def _norm_concurrency(value: Any, default: int = 8) -> int:
    if isinstance(value, dict):
        values: list[int] = []
        for item in value.values():
            try:
                values.append(int(item or 0))
            except (TypeError, ValueError):
                continue
        value = max(values) if values else default
    try:
        number = int(str(value).strip() or 0)
    except (TypeError, ValueError):
        return default
    if number <= 0:
        return default
    return max(1, number)


def _norm_heartbeat(value: Any, default: int = 30) -> int:
    try:
        number = int(str(value).strip() or 0)
    except (TypeError, ValueError):
        return default
    return number if 5 <= number <= 600 else default


def _norm_effort(value: Any, default: str) -> str:
    text = str(value or "").strip().lower()
    return text if text in EFFORT_RANK else default


# (default, minimum, maximum, zero/negative -> unlimited sentinel)
_INT_BOUNDS: dict[str, tuple[int, int, int | None, bool]] = {
    "timeout": (300, 1, None, False),
    "max_retries": (3, 0, None, False),
    "retry_sleep_cap": (2, 0, None, False),
    "connect_timeout": (10, 1, None, False),
    "recursion_limit": (64000, 1, None, False),
    "model_call_limit": (16000, 1, None, False),
    "partition.loc_budget": (10000, 0, None, False),
    "partition.max_units": (20, 0, None, True),
    "partition.min_files": (10, 0, None, False),
    "partition.single_unit_max_files": (1000, 0, None, False),
    "hunter.reruns": (0, 0, None, False),
    "codegraph.chars": (20000, 0, None, False),
    "codegraph.candidates": (200, 0, None, False),
    "sandbox.command_timeout": (120, 1, None, False),
    "sandbox.max_output_bytes": (200000, 0, None, False),
    "sandbox.pids_limit": (512, 1, None, False),
    "sast.findings": (5000, 0, None, True),
    "verification.votes": (1, 1, 5, False),
    "verification.cell_size": (15, 1, 100, False),
    "poc.cell_size": (15, 1, 100, False),
    "triage.batch_size": (100, 1, 200, True),
    "poc.timeout": (600, 1, None, False),
    "poc.repro_runs": (3, 1, None, False),
}

_BOOL_PATHS: dict[str, bool] = {
    "partition.enable_agent": False,
    "partition.vendor_unit": True,
    "partition.misc_code_merge": True,
    "partition.framework_edges": True,
    "sandbox.pull_image": False,
    "sandbox.reset_agent_scratch": True,
    "sandbox.sweep_orphans": True,
    "threat.use_repo_file": True,
    "threat.write_artifact": True,
    "threat.llm_enrich": True,
    "verification.couple_remainders": False,
}


def _normalize(cfg: dict) -> dict:
    """Coerce and bound every typed setting once, at load."""
    for path, (default, minimum, maximum, unlimited) in _INT_BOUNDS.items():
        value = _get_path(cfg, path)
        if value is not _MISSING:
            _set_path(cfg, path, _norm_int(
                value, default, minimum=minimum, maximum=maximum,
                zero_is_unlimited=unlimited))
    for path, default in _BOOL_PATHS.items():
        value = _get_path(cfg, path)
        if value is not _MISSING:
            _set_path(cfg, path, as_bool(value, default))
    value = _get_path(cfg, "concurrency")
    if value is not _MISSING:
        _set_path(cfg, "concurrency", _norm_concurrency(value))
    value = _get_path(cfg, "ui.heartbeat_s")
    if value is not _MISSING:
        _set_path(cfg, "ui.heartbeat_s", _norm_heartbeat(value))
    value = _get_path(cfg, "effort")
    if value is not _MISSING:
        _set_path(cfg, "effort", _norm_effort(value, "max"))
    value = _get_path(cfg, "codegraph.partition.mode")
    if value is not _MISSING:
        mode = str(value or "").strip().lower()
        _set_path(cfg, "codegraph.partition.mode",
                  mode if mode in ("off", "primary") else "primary")
    by_agent = _get_path(cfg, "effort_by_agent")
    if isinstance(by_agent, dict):
        for name, level in list(by_agent.items()):
            by_agent[name] = _norm_effort(level, "")
    value = _get_path(cfg, "partition.bytes_per_loc")
    if value is not _MISSING:
        try:
            _set_path(cfg, "partition.bytes_per_loc", float(value))
        except (TypeError, ValueError):
            _set_path(cfg, "partition.bytes_per_loc", 40.0)
    value = _get_path(cfg, "observability.enabled")
    if value is not _MISSING:
        _set_path(cfg, "observability.enabled",
                  str(value or "auto").strip().lower())
    value = _get_path(cfg, "sandbox.backend")
    if value is not _MISSING:
        _set_path(cfg, "sandbox.backend",
                  str(value or "local").strip().lower())
    return cfg


def effective_config(cfg: dict | None = None) -> dict:
    """A complete, normalized cfg: ``cfg`` overrides merged over the process cfg."""
    active = get_config()
    if not isinstance(cfg, dict) or not cfg or cfg is active:
        return active
    return _normalize(_deep_merge(active, cfg))


def get_config() -> dict:
    """The one cfg. Loads it on first use; subsequent calls return the same dict."""
    global _CFG
    if _CFG is None:
        with _CFG_LOCK:
            if _CFG is None:
                if load_config is _DEFAULT_LOAD_CONFIG:
                    _CFG = load_config()
                else:
                    _CFG = _normalize(_deep_merge(_defaults(), load_config()))
    return _CFG


def reset_config() -> None:
    """Clear cached process configuration."""
    global _CFG
    with _CFG_LOCK:
        _CFG = None


def set_config(cfg: dict | None) -> dict:
    """Install a cfg; partial dicts are completed from defaults."""
    global _CFG
    if cfg is None:
        _CFG = None
        return get_config()
    if cfg is _CFG:
        return _CFG
    _CFG = _normalize(_deep_merge(_defaults(), cfg))
    return _CFG


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


EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")
EFFORT_RANK = {name: i for i, name in enumerate(EFFORT_LEVELS)}


def resolve_api_key(cfg: dict | None = None) -> str:
    """The API key source: env ``API_KEY`` only."""
    _load_dotenv()
    return os.environ.get("API_KEY", "")


def api_key_present(cfg: dict | None = None) -> bool:
    """True when ``API_KEY`` is configured; delegates to ``resolve_api_key``."""
    return bool(resolve_api_key(cfg))


# Reasoning effort is passed through verbatim; the backend accepts
# low/medium/high/xhigh/max, and no token caps are set.


def get_reasoning_kwargs(cfg: dict, agent: str | None = None) -> dict:
    """Thinking-effort params from the normalized cfg.

    ``effort_by_agent`` (hunter, validator, triager, partitioner, threat) wins
    over the global ``effort``.
    """
    cfg = effective_config(cfg)
    level = ""
    if agent:
        by = cfg.get("effort_by_agent")
        if isinstance(by, dict):
            level = str(by.get(agent, "") or "").strip().lower()
    if level not in EFFORT_RANK:
        level = str(cfg.get("effort") or "max").strip().lower()
    if level not in EFFORT_RANK:
        level = "max"
    return {"reasoning_effort": level}


def effective_model(cfg: dict | None, role: str,
                    agent: str | None = None) -> str:
    """The model name actually used for ``agent`` under ``role``."""
    cfg = effective_config(cfg)
    if agent:
        agent_model = cfg.get(f"{agent}_model")
        if agent_model:
            return str(agent_model)
    return str(cfg.get(f"{role}_model") or "")


def get_model_kwargs(cfg: dict, role: str, agent: str | None = None) -> dict:
    """ChatOpenAI kwargs for an agent, incl. reasoning_effort; no langchain
    import happens here.

    Empty values never shadow the next source."""
    # A caller-supplied profile is used verbatim; only a cfg without one falls
    # back to the process profile (partial caller configs stay partial).
    caller_profile = cfg.get("model_profile") if isinstance(cfg, dict) else None
    cfg = effective_config(cfg)
    model_name = effective_model(cfg, role, agent)

    role_key = (agent or role or "").upper().replace("-", "_")
    base_url = (os.environ.get(f"{role_key}_BASE_URL", "")
                or os.environ.get("BASE_URL", "")
                or cfg.get("base_url", "")
                or "")
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

    profile = (caller_profile if isinstance(caller_profile, dict)
               else get_config().get("model_profile"))
    out = {
        "base_url": base_url,
        "api_key": api_key,
        "model": model_name,
        "timeout": int(cfg["timeout"]),
        "max_retries": int(cfg["max_retries"]),
        "model_profile": profile if isinstance(profile, dict) else {},
    }
    out.update(get_reasoning_kwargs(cfg, agent or role))
    return out
