"""Error taxonomy at the fail-open boundaries.

Docs (thinking-in-langgraph#handle-errors-appropriately): transient errors are
retried, parse errors are fed back to the model, and *unexpected* errors should
bubble up rather than be swallowed. The scanner's fail-open chain absorbs
model, parse, and transport failures; operator misconfiguration and harness
defects stop the stage loudly.
"""
from __future__ import annotations

import pytest
from cerberus.agents.deep import is_config_error, is_fatal_error, is_programming_error
from cerberus.fallback import runner
from langchain_core.exceptions import ModelAuthenticationError


def test_programming_errors_classified():
    for exc in (TypeError("x"), KeyError("x"), AttributeError("x"),
                NameError("x"), IndexError("x"), AssertionError("x"),
                NotImplementedError("x")):
        assert is_programming_error(exc), exc
        assert is_fatal_error(exc)


def test_model_and_parse_and_transport_fail_open():
    # RuntimeError stands in for transport failures; ValueError for pydantic
    # ValidationError (a bad model reply is a parse failure, not a bug).
    for exc in (RuntimeError("down"), ValueError("bad json")):
        assert not is_programming_error(exc)
        assert not is_fatal_error(exc)


def test_config_error_is_fatal():
    err = ModelAuthenticationError("no key")
    assert is_config_error(err) and is_fatal_error(err)
    assert not is_programming_error(err)


def test_runner_reraises_programming_error():
    def _boom():
        raise TypeError("harness bug")

    with pytest.raises(TypeError):
        runner("test", _boom, default="fallback")


def test_run_cell_reraises_programming_error(monkeypatch):
    import cerberus.agents.validator as v

    def boom_batch(*a, **k):
        raise TypeError("harness bug")

    monkeypatch.setattr(v, "_validate_unit_batch", boom_batch)
    with pytest.raises(TypeError):
        v._run_cell("u", [{"id": "a", "path": "a.py", "snippet": "s",
                           "taint": {"sink": "q"}, "evidence": "e"}], 1, 1,
                    cfg={}, n_votes=1, threat_md="", repo=None)


def test_run_cell_fails_open_on_transport_error(monkeypatch):
    import cerberus.agents.validator as v

    def down_batch(*a, **k):
        raise RuntimeError("transport down")

    monkeypatch.setattr(v, "_validate_unit_batch", down_batch)
    out = v._run_cell("u", [{"id": "a", "path": "a.py", "snippet": "s",
                             "taint": {"sink": "q"}, "evidence": "e"}], 1, 1,
                      cfg={}, n_votes=1, threat_md="", repo=None)
    assert len(out) == 1 and out[0]["status"] == "needs-review"
    assert "cell fallback (RuntimeError)" in out[0]["evidence"]
