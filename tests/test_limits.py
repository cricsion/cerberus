"""Agent budget contracts: cfg override, env precedence. No hardcoded
production values are pinned — expectations here are test-supplied."""
from __future__ import annotations

from cerberus.config import effective_config, get_config, reset_config


def test_recursion_limit_valid_cfg_override(monkeypatch):
    monkeypatch.delenv("RECURSION_LIMIT", raising=False)
    assert effective_config({"recursion_limit": 2500})["recursion_limit"] == 2500


def test_recursion_limit_env_wins(monkeypatch):
    monkeypatch.setenv("RECURSION_LIMIT", "2500")
    reset_config()
    assert get_config()["recursion_limit"] == 2500
