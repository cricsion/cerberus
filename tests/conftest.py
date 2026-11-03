"""Test hermeticity: no test may leak process-global scan state.

run_scan sets os.environ["TARGET_REPO"] globally and never unsets it. Without
isolation, a test that runs a scan re-roots every later test's path validation
to a stale (often deleted) tmp dir. Snapshot the scan-relevant env around
every test.

THREAT_LLM defaults to 0 here so scan-level tests never reach the
threat-model LLM swarm (offline, hermetic); threat tests opt in by setting
it to 1 where they assert enrichment happens.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The product tree lives one level up (cerberus/). pytest.ini's pythonpath
# covers normal runs; this keeps `import cerberus` working on bare-tree runs
# where pytest compiles without the ini (or from another cwd).
_REPO_PARENT = Path(__file__).resolve().parents[2]
if str(_REPO_PARENT) not in sys.path:
    sys.path.insert(0, str(_REPO_PARENT))

_SCAN_ENV_KEYS = (
    "TARGET_REPO",
    "API_KEY",
    "OPENAI_API_KEY",
    "LANGFUSE_PUBLIC_KEY",
    "LANGFUSE_SECRET_KEY",
    "LANGFUSE_BASE_URL",
    "LANGFUSE_ENABLED",
    "LANGFUSE_TRACING_ENVIRONMENT",
    "LANGFUSE_HOST",
    "LANGFUSE_TRACING_ENABLED",
)


@pytest.fixture(autouse=True)
def _isolate_scan_env(monkeypatch):
    for key in _SCAN_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    # Scan-driving tests need an API_KEY to exist; make_llm treats "dummy" as
    # a placeholder and real model calls are faked at the ChatOpenAI seam.
    monkeypatch.setenv("API_KEY", "dummy")
    monkeypatch.setenv("THREAT_LLM", "0")
    # The indexer's codegraph index stage runs a REAL CLI build; disable it so
    # the suite never writes .codegraph/ into a fixture. The P1 live tests drive
    # cerberus.codegraph._index directly, not through indexer_node.
    monkeypatch.setenv("CODEGRAPH_ENABLED", "0")
    yield


@pytest.fixture(autouse=True)
def _reset_config(_isolate_scan_env):
    """Reload the one cfg per test so monkeypatched env is always observed."""
    from cerberus.config import reset_config

    reset_config()
    yield
    reset_config()


@pytest.fixture(autouse=True)
def _clear_llm_provider_cache():
    """Reset langchain's process-wide chat-model creator cache.

    ``init_chat_model`` (used by ``cerberus.agents.deep.make_llm``)
    ``lru_cache``s its provider-name -> class resolution, freezing the
    first-resolved class for the rest of the process. The suite installs
    per-test ``langchain_openai.ChatOpenAI`` doubles, so a stale cache would
    ignore later doubles (or pin the real class and hit the network). Clear it
    around every test to keep the doubles effective.
    """

    def _clear():
        try:
            from langchain.chat_models.base import _get_chat_model_creator
        except Exception:  # pragma: no cover - langchain shape guard
            return
        cache_clear = getattr(_get_chat_model_creator, "cache_clear", None)
        if cache_clear is not None:
            cache_clear()

    _clear()
    yield
    _clear()
