#!/usr/bin/env python3
"""Tool output budgets follow one YAML value: sast truncates at the
sandbox byte cap (SANDBOX_MAX_OUTPUT_BYTES). The value is test-supplied."""
from cerberus.tools.sast import _paginate


def test_tool_byte_caps_are_one_budget(monkeypatch):
    """Tool output budgets share one YAML value: sast truncates at the
    sandbox byte cap (SANDBOX_MAX_OUTPUT_BYTES). The value itself is
    test-supplied — no prod constant is pinned."""
    monkeypatch.setenv("SANDBOX_MAX_OUTPUT_BYTES", "750")
    monkeypatch.delenv("SAST_BYTES", raising=False)  # vestigial name
    from cerberus.config import get_config, reset_config

    reset_config()
    lim = int(get_config()["sandbox"]["max_output_bytes"])
    assert lim == 750
    out = _paginate("x" * (lim + 1), None)
    assert out.startswith("x" * lim + "\n")
    assert "+1 more chars" in out
